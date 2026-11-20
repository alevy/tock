// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! BLE link layer connection manager, peripheral role.
//!
//! Drives a connection once the advertising capsule has accepted a
//! `CONNECT_IND`: picks the channel for each connection event, keeps the
//! schedule anchored to the central, answers link-layer control procedures, and
//! gives up when the supervision timer expires.
//!
//! The radio driver owns everything that has to happen at packet timescales.
//! This capsule runs between connection events, on an alarm, and its only
//! real-time obligation is to be awake before the next event starts.
//!
//! References are to the Bluetooth Core Specification, Vol 6, Part B.

use core::cell::Cell;

use kernel::ErrorCode;
use kernel::hil::ble_advertising::RadioChannel;
use kernel::hil::ble_connection::{
    BleConnectionDriver, ConnectionEventClient, ConnectionParams, ConnectionSetupClient,
    DisconnectClient, TxBuffers,
};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks, Ticks};
use kernel::utilities::cells::{MapCell, OptionalCell};

/// Combined sleep clock accuracy of both devices, in parts per million.
///
/// Assumes the worst case the specification allows on each side (+/-500 ppm).
/// Used to widen the receive window as the schedule drifts away from the last
/// confirmed anchor point.
const COMBINED_SCA_PPM: u32 = 1000;

/// Smallest window widening to apply, in microseconds (Section 4.5.7).
const MIN_WIDENING_US: u32 = 16;

/// Extra margin on each side of the receive window, in microseconds.
const WINDOW_GUARD_US: u32 = 150;

/// How far ahead of a connection event the alarm should wake the CPU, in
/// microseconds.
///
/// The event itself opens in hardware; this only has to be early enough to
/// program it.
const EVENT_SETUP_US: u32 = 500;

/// Delay between the end of the `CONNECT_IND` and the transmit window, in
/// microseconds, for a connection set up over the primary advertising channels
/// (Section 4.5.3, Table 4.3).
const TRANSMIT_WINDOW_DELAY_US: u32 = 1250;

/// Largest link layer PDU this capsule builds, in bytes, and therefore the
/// size of the transmit buffer a board must supply.
///
/// Comfortably covers the 27-byte payload of a packet sent without the data
/// length extension, which this implementation does not negotiate.
pub const MAX_PDU_LEN: usize = 32;

/// Depth of the outbound response queue.
///
/// Requests can be pipelined by the central faster than stop-and-wait flow
/// control drains them; queueing avoids dropping the later ones.
const RESP_QUEUE_LEN: usize = 4;

/// Number of data channels (Section 1.4.1).
const NUM_DATA_CHANNELS: u8 = 37;

// Data channel PDU header, Section 2.4. The low two bits of the first header
// byte are the LLID.
/// Mask selecting the LLID field of a PDU header.
const LLID_MASK: u8 = 0b11;
/// LLID value marking a link-layer control PDU.
const LLID_CONTROL: u8 = 0b11;
/// LLID value marking an empty or continued data PDU.
const LLID_EMPTY: u8 = 0b01;
/// LLID value marking the start of a data PDU.
const LLID_DATA_START: u8 = 0b10;
/// Header byte for a control PDU we transmit.
const CONTROL_PDU_HEADER: u8 = LLID_CONTROL;

// Link-layer control PDU opcodes, Section 2.4.2.
/// `LL_CONNECTION_UPDATE_IND`.
const LL_CONNECTION_UPDATE_IND: u8 = 0x00;
/// `LL_CHANNEL_MAP_IND`.
const LL_CHANNEL_MAP_IND: u8 = 0x01;
/// `LL_TERMINATE_IND`.
const LL_TERMINATE_IND: u8 = 0x02;
/// `LL_UNKNOWN_RSP`.
const LL_UNKNOWN_RSP: u8 = 0x07;
/// `LL_FEATURE_REQ`.
const LL_FEATURE_REQ: u8 = 0x08;
/// `LL_FEATURE_RSP`.
const LL_FEATURE_RSP: u8 = 0x09;
/// `LL_VERSION_IND`.
const LL_VERSION_IND: u8 = 0x0C;
/// `LL_SLAVE_FEATURE_REQ`.
const LL_SLAVE_FEATURE_REQ: u8 = 0x0E;

/// Link layer version number reported in `LL_VERSION_IND`: Bluetooth 5.3.
const LL_VERSION_NUMBER: u8 = 0x0C;

/// Connection state.
#[derive(Copy, Clone, PartialEq)]
enum State {
    /// No connection.
    Idle,
    /// A connection is established.
    Connected,
}

/// One queued outbound PDU.
#[derive(Copy, Clone)]
struct RespEntry {
    /// The PDU, including its two header bytes.
    pdu: [u8; MAX_PDU_LEN],
    /// How much of `pdu` is in use.
    nbytes: u8,
}

impl RespEntry {
    /// An empty entry.
    const fn zero() -> Self {
        RespEntry {
            pdu: [0; MAX_PDU_LEN],
            nbytes: 0,
        }
    }
}

/// Handles the data a connection carries, above the link layer.
///
/// The link layer knows nothing about what rides on it: it hands up a frame
/// and sends back whatever it is given. In practice the implementor is an
/// L2CAP multiplexer.
pub trait DataClient {
    /// Build a reply to `frame` into `out`.
    ///
    /// Returns how many bytes of `out` the reply occupies, or `None` when the
    /// frame calls for no reply.
    fn data_received(&self, frame: &[u8], out: &mut [u8]) -> Option<usize>;

    /// Discard any per-connection state, because a new connection is starting.
    fn connection_reset(&self);
}

/// Selects the data channel for the next connection event.
///
/// Implements channel selection algorithm #1 (Section 4.5.8): advance the
/// unmapped channel by the hop increment, and if the result is not in the
/// channel map, remap it into the set of channels that are.
///
/// Returns the channel to use and the new unmapped channel, which is the state
/// carried to the next call.
fn next_channel(last_unmapped: u8, hop: u8, channel_map: u64) -> (u8, u8) {
    let unmapped_next =
        ((u16::from(last_unmapped) + u16::from(hop)) % u16::from(NUM_DATA_CHANNELS)) as u8;
    if channel_map & (1u64 << unmapped_next) != 0 {
        return (unmapped_next, unmapped_next);
    }
    let used_count = channel_map.count_ones() as u8;
    if used_count == 0 {
        // A channel map with no usable channels is malformed; fall back to
        // channel 0 rather than dividing by zero.
        return (0, unmapped_next);
    }
    let remap_index = unmapped_next % used_count;
    let physical = (0..NUM_DATA_CHANNELS)
        .filter(|&i| channel_map & (1u64 << i) != 0)
        .nth(remap_index as usize)
        .unwrap_or(0);
    (physical, unmapped_next)
}

/// How much earlier the receive window must open to tolerate clock drift, in
/// microseconds.
///
/// Drift accumulates with the time since the last confirmed anchor point, so
/// this grows with the number of events missed (Section 4.5.7).
fn window_widening(events_since_anchor: u32, conn_interval_us: u32) -> u32 {
    let drift = COMBINED_SCA_PPM
        .saturating_mul(events_since_anchor)
        .saturating_mul(conn_interval_us)
        / 1_000_000;
    drift.max(MIN_WIDENING_US)
}

/// Writes an empty PDU, which acknowledges the central without carrying data.
fn write_empty_ack(buf: &mut [u8]) {
    if buf.len() >= 2 {
        buf[0] = LLID_EMPTY;
        buf[1] = 0;
    }
}

/// Whether `buf` holds an `LL_TERMINATE_IND`, the central's request to close
/// the connection.
fn is_ll_terminate_ind(buf: &[u8]) -> bool {
    buf.len() >= 3 && (buf[0] & LLID_MASK) == LLID_CONTROL && buf[2] == LL_TERMINATE_IND
}

/// Maintains a BLE connection in the peripheral role.
///
/// `D` is the radio driver and `A` the alarm used to wake up before each
/// connection event.
pub struct ConnectionManager<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> {
    /// The radio.
    driver: &'a D,
    /// Wakes the CPU shortly before each connection event.
    alarm: &'a A,
    /// Whether a connection is established.
    state: Cell<State>,
    /// Parameters of the current connection.
    params: Cell<Option<ConnectionParams>>,
    /// Absolute time at which the next receive window should open.
    ///
    /// Computed once per event and read both when arming the alarm and when
    /// programming the radio, so the two cannot disagree.
    next_open_time: Cell<D::Ticks>,
    /// Time at which the central was last heard.
    last_anchor: Cell<D::Ticks>,
    /// Consecutive connection events in which the central was not heard.
    missed_events: Cell<u16>,
    /// Unmapped channel carried between channel selections.
    last_unmapped_channel: Cell<u8>,
    /// Whether an `LL_VERSION_IND` has been sent; the specification allows one
    /// per connection (Section 5.1.5).
    version_sent: Cell<bool>,
    /// Responses built but not yet transmitted.
    resp_queue: Cell<[RespEntry; RESP_QUEUE_LEN]>,
    /// Index of the oldest queued response.
    resp_head: Cell<usize>,
    /// Number of queued responses.
    resp_count: Cell<usize>,
    /// The outstanding payload and the one queued behind it.
    tx: MapCell<TxBuffers>,
    /// Notified when the connection ends.
    disconnect_client: OptionalCell<&'a dyn DisconnectClient>,
    /// Handles data the connection carries. Without one, the connection is
    /// maintained but carries nothing.
    data_client: OptionalCell<&'a dyn DataClient>,
}

impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionManager<'a, D, A> {
    pub fn new(
        driver: &'a D,
        alarm: &'a A,
        outstanding: &'static mut [u8],
        next: &'static mut [u8],
    ) -> Self {
        ConnectionManager {
            driver,
            alarm,
            state: Cell::new(State::Idle),
            params: Cell::new(None),
            next_open_time: Cell::new(D::Ticks::from(0)),
            last_anchor: Cell::new(D::Ticks::from(0)),
            missed_events: Cell::new(0),
            last_unmapped_channel: Cell::new(0),
            version_sent: Cell::new(false),
            resp_queue: Cell::new([RespEntry::zero(); RESP_QUEUE_LEN]),
            resp_head: Cell::new(0),
            resp_count: Cell::new(0),
            tx: MapCell::new(TxBuffers { outstanding, next }),
            disconnect_client: OptionalCell::empty(),
            data_client: OptionalCell::empty(),
        }
    }

    /// Set the client told when a connection ends.
    pub fn set_disconnect_client(&self, client: &'a dyn DisconnectClient) {
        self.disconnect_client.set(client);
    }

    /// Set the client that handles the data this connection carries.
    pub fn set_data_client(&self, client: &'a dyn DataClient) {
        self.data_client.set(client);
    }

    /// Register this capsule with the radio.
    ///
    /// Separate from [`ConnectionManager::new`] because it needs a reference
    /// that outlives construction.
    pub fn set_driver_client(&'a self) {
        self.driver.set_connection_event_client(self);
    }

    /// Whether a connection is currently established.
    pub fn is_connected(&self) -> bool {
        self.state.get() == State::Connected
    }

    /// Work out when the next connection event's receive window should open.
    ///
    /// The event being scheduled is `missed_events + 1` intervals past the last
    /// confirmed anchor, so both the offset and the widening scale with that
    /// count.
    fn compute_next_open_time(&self, params: &ConnectionParams) {
        let n = u32::from(self.missed_events.get()) + 1;
        let widening = window_widening(n, params.conn_interval_us);
        let offset = self
            .driver
            .ticks_from_us(params.conn_interval_us.saturating_mul(n));
        let back_off = self.driver.ticks_from_us(widening + WINDOW_GUARD_US);
        let expected_anchor = self.last_anchor.get().wrapping_add(offset);
        self.next_open_time
            .set(expected_anchor.wrapping_sub(back_off));
    }

    /// Arm the alarm to wake the CPU shortly before `next_open_time`.
    ///
    /// The receive window itself is opened by hardware; this only guarantees
    /// the CPU is awake in time to program it.
    fn schedule_next_event(&self, params: &ConnectionParams) {
        let setup = self.driver.ticks_from_us(EVENT_SETUP_US);
        let wakeup = self.next_open_time.get().wrapping_sub(setup);
        let remaining = wakeup.wrapping_sub(self.driver.now());
        // Cap the wait so a nonsensical computation cannot park the connection
        // indefinitely; the supervision timer then ends it in good order.
        let delay_us = self
            .driver
            .ticks_to_us(remaining)
            .min(params.conn_interval_us.saturating_mul(2));
        let dt = self.alarm.ticks_from_us(delay_us);
        self.alarm.set_alarm(self.alarm.now(), dt);
    }

    /// Append a built PDU to the outbound queue, dropping it if the queue is
    /// full.
    fn enqueue_response(&self, pdu: &[u8]) {
        let count = self.resp_count.get();
        if count >= RESP_QUEUE_LEN {
            return;
        }
        let n = pdu.len().min(MAX_PDU_LEN);
        let mut entry = RespEntry::zero();
        entry.pdu[..n].copy_from_slice(&pdu[..n]);
        entry.nbytes = n as u8;
        let mut queue = self.resp_queue.get();
        queue[(self.resp_head.get() + count) % RESP_QUEUE_LEN] = entry;
        self.resp_queue.set(queue);
        self.resp_count.set(count + 1);
    }

    /// Move the oldest queued response into `tx`, if there is one.
    fn dequeue_response_into(&self, tx: &mut [u8]) -> bool {
        let count = self.resp_count.get();
        if count == 0 {
            return false;
        }
        let head = self.resp_head.get();
        let entry = self.resp_queue.get()[head];
        let n = (entry.nbytes as usize).min(tx.len()).min(MAX_PDU_LEN);
        tx[..n].copy_from_slice(&entry.pdu[..n]);
        self.resp_head.set((head + 1) % RESP_QUEUE_LEN);
        self.resp_count.set(count - 1);
        true
    }

    /// Build the response owed to a received PDU, if any.
    ///
    /// Returns whether a PDU was written into `tx`; if not, the caller sends an
    /// empty PDU instead.
    fn build_response(&self, rx: &[u8], tx: &mut [u8]) -> bool {
        match rx.first().copied().unwrap_or(0) & LLID_MASK {
            LLID_CONTROL => self.build_control_response(rx.get(2).copied().unwrap_or(0), tx),
            LLID_DATA_START => self.build_data_response(rx, tx),
            _ => false,
        }
    }

    /// Hand a data PDU's payload to the data client and frame its reply.
    fn build_data_response(&self, rx: &[u8], tx: &mut [u8]) -> bool {
        if rx.len() < 2 || tx.len() < 3 {
            return false;
        }
        // The header's length field is authoritative, but a packet shorter
        // than it claims must not be read past its end.
        let payload_len = usize::from(rx[1]).min(rx.len() - 2);
        let frame = &rx[2..2 + payload_len];

        let Some(Some(n)) = self
            .data_client
            .map(|client| client.data_received(frame, &mut tx[2..]))
        else {
            return false;
        };
        if n > usize::from(u8::MAX) || n > tx.len() - 2 {
            return false;
        }
        tx[0] = LLID_DATA_START;
        tx[1] = n as u8;
        true
    }

    /// Build the reply to a link-layer control PDU with the given opcode.
    fn build_control_response(&self, opcode: u8, tx: &mut [u8]) -> bool {
        if tx.len() < 12 {
            return false;
        }
        match opcode {
            LL_FEATURE_REQ | LL_SLAVE_FEATURE_REQ => {
                // An all-zero feature set is valid and claims no optional
                // link-layer features.
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 9;
                tx[2] = LL_FEATURE_RSP;
                tx[3..11].fill(0);
                true
            }
            LL_VERSION_IND => {
                if self.version_sent.get() {
                    return false;
                }
                self.version_sent.set(true);
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 6;
                tx[2] = LL_VERSION_IND;
                tx[3] = LL_VERSION_NUMBER;
                // Company identifier 0xFFFF, which is the unassigned value.
                tx[4] = 0xFF;
                tx[5] = 0xFF;
                // Subversion number.
                tx[6] = 0x00;
                tx[7] = 0x00;
                true
            }
            LL_CONNECTION_UPDATE_IND | LL_CHANNEL_MAP_IND => {
                // These expect no reply, and the hardware has already
                // acknowledged them at the link layer.
                //
                // They are not yet *applied*. Both carry an instant, a
                // connection event count at which the change takes effect on
                // both sides, so handling them means stashing the new values
                // and swapping them in exactly at that instant — minding the
                // wraparound of the 16-bit instant against our event counter,
                // and, for a connection update, re-anchoring the whole
                // schedule. Until that is implemented, a central that really
                // does change the channel map or the connection parameters
                // mid-connection will desynchronise us, and the link will drop
                // on supervision timeout. Centrals observed so far send
                // `LL_CHANNEL_MAP_IND` but do not appear to switch, which is
                // also why this is hard to test.
                false
            }
            other => {
                // Decline anything else explicitly. Staying silent would stall
                // the central's procedure for its full timeout (Section 5.1.9).
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 2;
                tx[2] = LL_UNKNOWN_RSP;
                tx[3] = other;
                true
            }
        }
    }

    /// Record a connection event in which the central was not heard.
    ///
    /// Returns whether this has gone on long enough to give up on the link.
    fn note_missed_event(&self, params: &ConnectionParams) -> bool {
        let missed = self.missed_events.get().saturating_add(1);
        self.missed_events.set(missed);
        let elapsed_ms = u32::from(missed).saturating_mul(params.conn_interval_us) / 1000;
        elapsed_ms > params.supervision_timeout_ms
    }

    /// Tear down the connection and tell the disconnect client.
    fn declare_connection_lost(&self) {
        self.state.set(State::Idle);
        self.params.set(None);
        self.resp_head.set(0);
        self.resp_count.set(0);
        self.disconnect_client
            .map(|client| client.connection_lost());
    }

    /// Advance the outbound payloads after a connection event.
    ///
    /// Without an acknowledgement the outstanding payload went out again and
    /// stays where it is. With one, the driver transmitted `next`, so that
    /// becomes the outstanding payload and the buffer it displaces is free to
    /// take whatever follows.
    fn advance_tx(&self, buffers: TxBuffers, tx_acked: bool) -> TxBuffers {
        if !tx_acked {
            return buffers;
        }
        let TxBuffers { outstanding, next } = buffers;
        // `outstanding` has been delivered; `next` has just gone out.
        let (outstanding, next) = (next, outstanding);
        if !self.dequeue_response_into(next) {
            write_empty_ack(next);
        }
        TxBuffers { outstanding, next }
    }
}

impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionSetupClient
    for ConnectionManager<'a, D, A>
{
    fn connect_ind_received(&self, params: &ConnectionParams) {
        if self.driver.connection_configure(params).is_err() {
            return;
        }

        self.params.set(Some(*params));
        self.state.set(State::Connected);
        self.missed_events.set(0);
        self.last_unmapped_channel.set(0);
        self.version_sent.set(false);
        self.resp_head.set(0);
        self.resp_count.set(0);
        self.data_client.map(|client| client.connection_reset());
        self.tx.map(|buffers| {
            write_empty_ack(buffers.outstanding);
            write_empty_ack(buffers.next);
        });

        // The transmit window for the first connection event starts a fixed
        // delay plus the window offset after the end of the `CONNECT_IND`
        // (Section 4.5.3). We are called immediately after that packet, so the
        // clock now is a good approximation of its end.
        let now = self.driver.now();
        let win_start = now
            .wrapping_add(self.driver.ticks_from_us(TRANSMIT_WINDOW_DELAY_US))
            .wrapping_add(self.driver.ticks_from_us(params.win_offset_us));

        // Open a guard interval early. The radio's own window timeout covers
        // the rest of the uncertainty, so the usual anchor-relative
        // calculation, which assumes a point anchor, is not used here.
        self.next_open_time
            .set(win_start.wrapping_sub(self.driver.ticks_from_us(WINDOW_GUARD_US)));

        // Seed the anchor as though a successful event had happened one
        // interval before the centre of the transmit window. That makes the
        // schedule correct even if the first event is missed, and the real
        // captured anchor replaces it as soon as one succeeds.
        let win_centre = win_start.wrapping_add(self.driver.ticks_from_us(params.win_size_us / 2));
        self.last_anchor
            .set(win_centre.wrapping_sub(self.driver.ticks_from_us(params.conn_interval_us)));

        self.schedule_next_event(params);
    }
}

impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> AlarmClient for ConnectionManager<'a, D, A> {
    fn alarm(&self) {
        let Some(params) = self.params.get() else {
            return;
        };

        let (channel_index, next_unmapped) = next_channel(
            self.last_unmapped_channel.get(),
            params.hop_increment,
            params.channel_map,
        );
        self.last_unmapped_channel.set(next_unmapped);
        let channel = RadioChannel::from_data_channel_index(channel_index)
            .unwrap_or(RadioChannel::DataChannel0);

        let open_time = self.next_open_time.get();
        self.tx.take().map(|buffers| {
            if let Err((_, buffers)) = self
                .driver
                .connection_event_start(channel, buffers, open_time)
            {
                self.tx.put(buffers);
                // No event means no completion callback, so nothing else will
                // move the schedule along. Count it as an event in which the
                // central was not heard, which both advances the schedule and
                // lets the supervision timer end the connection if the radio
                // keeps refusing.
                if self.note_missed_event(&params) {
                    self.declare_connection_lost();
                } else {
                    self.compute_next_open_time(&params);
                    self.schedule_next_event(&params);
                }
            }
        });
    }
}

impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionEventClient<D::Ticks>
    for ConnectionManager<'a, D, A>
{
    fn connection_event_done(
        &self,
        rx: &[u8],
        buffers: TxBuffers,
        result: Result<(), ErrorCode>,
        anchor: D::Ticks,
        tx_acked: bool,
    ) {
        let Some(params) = self.params.get() else {
            self.tx.put(buffers);
            return;
        };

        let rx_ok = result.is_ok();

        // A central closing the connection sends `LL_TERMINATE_IND`. The
        // hardware has already sent the acknowledgement it waits for, so the
        // connection can be torn down here.
        if rx_ok && is_ll_terminate_ind(rx) {
            self.tx.put(buffers);
            self.declare_connection_lost();
            return;
        }

        if rx_ok {
            self.last_anchor.set(anchor);
            self.missed_events.set(0);
        } else if self.note_missed_event(&params) {
            self.tx.put(buffers);
            self.declare_connection_lost();
            return;
        }

        // Build any response now and queue it, rather than transmitting it
        // directly: a request that arrives while an earlier response is still
        // in flight would otherwise be dropped.
        if rx_ok && rx.len() >= 2 && rx[1] >= 1 {
            let mut scratch = [0u8; MAX_PDU_LEN];
            if self.build_response(rx, &mut scratch) {
                let n = (2 + scratch[1] as usize).min(MAX_PDU_LEN);
                self.enqueue_response(&scratch[..n]);
            }
        }

        self.tx.put(self.advance_tx(buffers, tx_acked));

        self.compute_next_open_time(&params);
        self.schedule_next_event(&params);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All 37 data channels in use.
    const ALL_CHANNELS: u64 = (1 << 37) - 1;

    #[test]
    fn hop_within_map() {
        assert_eq!(next_channel(0, 5, ALL_CHANNELS), (5, 5));
        assert_eq!(next_channel(5, 5, ALL_CHANNELS), (10, 10));
        assert_eq!(next_channel(10, 16, ALL_CHANNELS), (26, 26));
    }

    #[test]
    fn hop_wraps_at_37() {
        // 35 + 5 == 40, which wraps to 3.
        assert_eq!(next_channel(35, 5, ALL_CHANNELS), (3, 3));
        assert_eq!(next_channel(36, 16, ALL_CHANNELS), (15, 15));
    }

    #[test]
    fn unused_channel_is_remapped() {
        // Only channels 0, 1 and 2 are usable. 0 + 5 == 5 is not among them,
        // so it remaps to index 5 % 3 == 2, which is channel 2. The unmapped
        // channel carried forward stays 5.
        let map = 0b111;
        assert_eq!(next_channel(0, 5, map), (2, 5));
        // 5 + 5 == 10, remapping to index 10 % 3 == 1, which is channel 1.
        assert_eq!(next_channel(5, 5, map), (1, 10));
    }

    #[test]
    fn mapped_channel_is_not_remapped() {
        // Channel 5 is usable here, so it is used directly.
        let map = 0b111 | (1 << 5);
        assert_eq!(next_channel(0, 5, map), (5, 5));
    }

    #[test]
    fn empty_channel_map_does_not_divide_by_zero() {
        assert_eq!(next_channel(0, 5, 0), (0, 5));
    }

    #[test]
    fn widening_has_a_floor() {
        // 1000 ppm of one 7.5 ms interval is 7 us, below the floor.
        assert_eq!(window_widening(1, 7_500), MIN_WIDENING_US);
    }

    #[test]
    fn widening_grows_with_missed_events() {
        // 1000 ppm of ten 100 ms intervals is 1000 us.
        assert_eq!(window_widening(10, 100_000), 1000);
        assert!(window_widening(20, 100_000) > window_widening(10, 100_000));
    }

    #[test]
    fn widening_saturates_rather_than_overflowing() {
        assert!(window_widening(u32::MAX, u32::MAX) > 0);
    }

    #[test]
    fn empty_ack_is_an_empty_pdu() {
        let mut buf = [0xAAu8; 4];
        write_empty_ack(&mut buf);
        assert_eq!(buf[0] & LLID_MASK, LLID_EMPTY);
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn terminate_ind_is_recognised() {
        assert!(is_ll_terminate_ind(&[
            LLID_CONTROL,
            2,
            LL_TERMINATE_IND,
            0x13
        ]));
        // A data PDU with the same payload byte is not a terminate.
        assert!(!is_ll_terminate_ind(&[0b10, 2, LL_TERMINATE_IND, 0x13]));
        // A different control opcode is not a terminate.
        assert!(!is_ll_terminate_ind(&[LLID_CONTROL, 2, LL_FEATURE_REQ, 0]));
        // Too short to classify.
        assert!(!is_ll_terminate_ind(&[LLID_CONTROL, 2]));
    }
}

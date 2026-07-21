// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2024.

//! BLE Link Layer Connection Manager (Peripheral/Slave role)
//!
//! Implements the BLE peripheral connection state machine after a CONNECT_IND
//! is received.  Responsibilities:
//!
//! * Channel selection (CSA#1) — BT Core Spec Vol 6 Part B §4.5.8
//! * Window widening based on combined sleep-clock accuracy
//! * Supervision timeout detection
//! * Scheduling connection events via `BleConnectionDriver`
//!
//! ## Debug facilities
//!
//! * `single_channel_test` — freeze channel selection on DataChannel0 to
//!   isolate timing bugs from hopping bugs.
//! * `DebugEntry` ring buffer — last 16 events (channel, anchor, rx_ok,
//!   counter) readable via JTAG or a debug syscall.

use core::cell::Cell;

use kernel::ErrorCode;
use kernel::debug;
use kernel::hil::ble_advertising::{
    BleConnectionDriver, ConnectionEventClient, ConnectionParams, ConnectionSetupClient,
    RadioChannel,
};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::utilities::cells::{OptionalCell, TakeCell};

// Combined SCA: assume ±500 ppm master + ±500 ppm slave = ±1000 ppm worst-case.
const COMBINED_SCA_PPM: u32 = 1000;
// Minimum window widening per spec (µs).
const MIN_WIDENING_US: u32 = 16;
// Extra guard margin added on each side of the RX window (µs).
const WINDOW_GUARD_US: u32 = 150;
// How many TIMER0 ticks (µs) before expected anchor to arm PPI CH21.
const TIMER_SETUP_TICKS: u32 = 500;
// transmitWindowDelay for legacy (LE 1M primary advertising channel) connections
// (BT Core Spec Vol 6 Part B §4.5.3, Table 4.3): the first connection event's
// transmit window opens this many µs after the end of the CONNECT_IND, plus WinOffset.
const TRANSMIT_WINDOW_DELAY_US: u32 = 1250;

/// One entry in the debug ring buffer — populated after each connection event.
#[derive(Copy, Clone)]
pub struct DebugEntry {
    pub channel: u8,
    pub anchor_ticks: u32,
    pub rx_ok: bool,
    pub event_counter: u32,
    /// First received PDU header byte (`buf[0]`): LLID in the low two bits.
    pub header: u8,
    /// Received PDU payload length (`buf[1]`).
    pub len: u8,
    /// First payload byte (`buf[2]`): the control opcode when this is a control PDU.
    /// Only meaningful when `rx_ok` is true; otherwise reflects stale/corrupt bytes.
    pub opcode: u8,
    /// Whether the master acknowledged the PDU we transmitted in the previous event.
    pub tx_acked: bool,
}

impl DebugEntry {
    const fn zero() -> Self {
        DebugEntry {
            channel: 0,
            anchor_ticks: 0,
            rx_ok: false,
            event_counter: 0,
            header: 0,
            len: 0,
            opcode: 0,
            tx_acked: false,
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
enum State {
    Idle,
    Connected,
}

/// BLE peripheral connection manager.
///
/// Type parameters:
/// * `D` — hardware radio driver implementing `BleConnectionDriver<'a>`
/// * `A` — alarm used for coarse-wakeup scheduling between events
pub struct ConnectionManager<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> {
    driver: &'a D,
    alarm: &'a A,
    state: Cell<State>,
    params: Cell<Option<ConnectionParams>>,
    event_counter: Cell<u32>,
    last_anchor_ticks: Cell<u32>,
    /// Absolute TIMER0 tick (µs) at which the next RX window should open.
    /// Computed once per event; read both when arming the coarse alarm and when
    /// programming the hardware RX-open compare.
    next_open_time: Cell<u32>,
    /// Whether the PDU we last transmitted has been acknowledged by the master.
    /// Foundation for stop-and-wait flow control: a content-bearing PDU must be
    /// held (retransmitted) until this becomes true before the next is loaded.
    tx_acked: Cell<bool>,
    last_unmapped_channel: Cell<u8>,
    missed_events: Cell<u16>,

    rx_buf: TakeCell<'static, [u8]>,
    tx_buf: TakeCell<'static, [u8]>,

    // Debug
    debug_log: Cell<[DebugEntry; 16]>,
    debug_log_head: Cell<usize>,
    /// When true, always use DataChannel0 regardless of CSA#1.
    pub single_channel_test: Cell<bool>,

    disconnect_client: OptionalCell<&'a dyn DisconnectClient>,
}

/// Called when the supervision timeout expires (connection lost).
pub trait DisconnectClient {
    fn connection_lost(&self);
}

// CSA#1: BT Core Spec Vol 6 Part B §4.5.8
// Returns (physical_channel_number, new_last_unmapped_channel).
fn next_channel(last_unmapped: u8, hop: u8, channel_map: u64) -> (u8, u8) {
    let unmapped_next = ((last_unmapped as u16 + hop as u16) % 37) as u8;
    if channel_map & (1u64 << unmapped_next) != 0 {
        (unmapped_next, unmapped_next)
    } else {
        let used_count = channel_map.count_ones() as u8;
        let remap_index = unmapped_next % used_count;
        let physical = (0u8..37)
            .filter(|&i| channel_map & (1u64 << i) != 0)
            .nth(remap_index as usize)
            .unwrap_or(0);
        (physical, unmapped_next)
    }
}

fn window_widening(events_since_anchor: u32, conn_interval_us: u32) -> u32 {
    let drift = COMBINED_SCA_PPM
        .saturating_mul(events_since_anchor)
        .saturating_mul(conn_interval_us)
        / 1_000_000;
    drift.max(MIN_WIDENING_US)
}

// Data channel PDU header (BT Core Spec Vol 6 Part B §2.4): the low two bits of
// the first header byte are the LLID.
const LLID_MASK: u8 = 0b11;
// LLID = 0b11 marks an LL Control PDU.
const LLID_CONTROL: u8 = 0b11;
// LL Control PDU opcodes (BT Core Spec Vol 6 Part B §2.4.2).
const LL_TERMINATE_IND: u8 = 0x02;

// True if `buf` is an LL Control PDU carrying LL_TERMINATE_IND.
//
// `buf` layout: [0] = header (LLID in the low two bits), [1] = payload length,
// [2..] = payload whose first byte is the control opcode.
fn is_ll_terminate_ind(buf: &[u8]) -> bool {
    buf.len() >= 3
        && (buf[0] & LLID_MASK) == LLID_CONTROL
        && buf[1] >= 1
        && buf[2] == LL_TERMINATE_IND
}

// Prepare a LL_DATA empty ACK PDU in-place (LLID=0x01, NESN/SN/MD=0, len=0).
fn write_empty_ack(buf: &mut [u8]) {
    if buf.len() >= 2 {
        buf[0] = 0x01; // LLID = 0b01 (continuation or empty)
        buf[1] = 0x00; // len = 0
    }
}

impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionManager<'a, D, A> {
    pub fn new(
        driver: &'a D,
        alarm: &'a A,
        rx_buf: &'static mut [u8],
        tx_buf: &'static mut [u8],
    ) -> Self {
        ConnectionManager {
            driver,
            alarm,
            state: Cell::new(State::Idle),
            params: Cell::new(None),
            event_counter: Cell::new(0),
            last_anchor_ticks: Cell::new(0),
            next_open_time: Cell::new(0),
            tx_acked: Cell::new(false),
            last_unmapped_channel: Cell::new(0),
            missed_events: Cell::new(0),
            rx_buf: TakeCell::new(rx_buf),
            tx_buf: TakeCell::new(tx_buf),
            debug_log: Cell::new([DebugEntry::zero(); 16]),
            debug_log_head: Cell::new(0),
            single_channel_test: Cell::new(false),
            disconnect_client: OptionalCell::empty(),
        }
    }

    pub fn set_disconnect_client(&self, client: &'a dyn DisconnectClient) {
        self.disconnect_client.set(client);
    }

    pub fn set_driver_client(&'a self) {
        self.driver.set_connection_event_client(self);
    }

    /// Snapshot of the last 16 connection events for debugging.
    pub fn debug_snapshot(&self) -> [DebugEntry; 16] {
        self.debug_log.get()
    }

    // Compute the RX-window open time for the *next* connection event, relative to
    // the last known-good anchor.  The event being scheduled is (missed_events + 1)
    // intervals after that anchor, so both the interval offset and the window
    // widening scale with that count.  Used for every event after the first.
    fn compute_next_open_time(&self, params: &ConnectionParams) {
        let n = self.missed_events.get() as u32 + 1;
        let interval_us = params.conn_interval_us;
        let widening = window_widening(n, interval_us);
        let expected_anchor = self
            .last_anchor_ticks
            .get()
            .wrapping_add(interval_us.wrapping_mul(n));
        self.next_open_time
            .set(expected_anchor.wrapping_sub(widening + WINDOW_GUARD_US));
    }

    // Arm the coarse alarm so the CPU wakes up TIMER_SETUP_TICKS (µs) before the
    // absolute `next_open_time`.  The precise RX-window open is done in hardware via
    // TIMER0 CC[0]; this alarm only guarantees the CPU is awake to program it.
    // TIMER0 runs at 1 MHz (1 µs/tick); compute how many µs remain and convert to
    // the alarm's native tick frequency.
    fn schedule_next_event(&self, params: &ConnectionParams) {
        let wakeup_us = self.next_open_time.get().wrapping_sub(TIMER_SETUP_TICKS);
        let now_us = self.driver.get_timer0_now();
        let delta_us = wakeup_us
            .wrapping_sub(now_us)
            .min(params.conn_interval_us.saturating_mul(2));
        let dt = self.alarm.ticks_from_us(delta_us);
        self.alarm.set_alarm(self.alarm.now(), dt);
    }

    fn declare_connection_lost(&self) {
        // Diagnostic: dump the recent connection-event history so we can see whether
        // the master's PDUs (and any LL_TERMINATE_IND) were actually decoded.
        self.dump_debug_log();
        self.state.set(State::Idle);
        self.params.set(None);
        self.disconnect_client.map(|c| c.connection_lost());
    }

    #[allow(clippy::too_many_arguments)]
    fn log_event(
        &self,
        channel: u8,
        rx_ok: bool,
        anchor: u32,
        header: u8,
        len: u8,
        opcode: u8,
        tx_acked: bool,
    ) {
        let head = self.debug_log_head.get();
        let entry = DebugEntry {
            channel,
            anchor_ticks: anchor,
            rx_ok,
            event_counter: self.event_counter.get(),
            header,
            len,
            opcode,
            tx_acked,
        };
        let mut log = self.debug_log.get();
        log[head % 16] = entry;
        self.debug_log.set(log);
        self.debug_log_head.set(head.wrapping_add(1));
    }

    // Print the ring buffer oldest-to-newest.  Called on teardown (connection is
    // already over, so the cost of printing here does not perturb event timing).
    fn dump_debug_log(&self) {
        let log = self.debug_log.get();
        let head = self.debug_log_head.get();
        debug!("BLE conn debug log (oldest first):");
        for i in 0..16 {
            let e = log[head.wrapping_add(i) % 16];
            // Skip never-populated slots.
            if e.event_counter == 0 && e.header == 0 && !e.rx_ok {
                continue;
            }
            debug!(
                "  evt {} ch {} rx_ok {} hdr {:#04x} len {} op {:#04x} tx_acked {}",
                e.event_counter, e.channel, e.rx_ok, e.header, e.len, e.opcode, e.tx_acked
            );
        }
    }
}

// ConnectionSetupClient: called by the advertising driver when CONNECT_IND arrives.
impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionSetupClient
    for ConnectionManager<'a, D, A>
{
    fn connect_ind_received(&self, params: &ConnectionParams, timer0_now: u32) {
        // connection_configure was already called by the advertising driver;
        // TIMER0 is now running at 1 MHz.
        self.params.set(Some(*params));
        self.state.set(State::Connected);
        self.event_counter.set(0);
        self.missed_events.set(0);
        self.last_unmapped_channel.set(0);

        // First connection event (BT Core Spec Vol 6 Part B §4.5.3):
        //   transmitWindowStart = end_of_CONNECT_IND + transmitWindowDelay + WinOffset
        // and the master transmits somewhere within a WinSize-wide window from there.
        // timer0_now was captured right after CONNECT_IND, so it approximates the end
        // of that packet.
        let win_start = timer0_now
            .wrapping_add(TRANSMIT_WINDOW_DELAY_US)
            .wrapping_add(params.win_offset_us);

        // Open the RX window a guard interval before the window start; the radio's
        // 2 ms hardware window-timeout covers the full WinSize uncertainty (so we do
        // NOT go through compute_next_open_time, which assumes a point anchor).
        self.next_open_time
            .set(win_start.wrapping_sub(WINDOW_GUARD_US));

        // Provisional anchor reference: treat the window centre as anchor[0], and
        // seed last_anchor_ticks as if a successful event occurred one interval
        // earlier.  This makes compute_next_open_time correct even if the first
        // event is missed (it will target win_centre + interval next), and it is
        // overwritten by the real captured anchor as soon as an event succeeds.
        let win_centre = win_start.wrapping_add(params.win_size_us / 2);
        self.last_anchor_ticks
            .set(win_centre.wrapping_sub(params.conn_interval_us));

        // Prepare a TX buffer for the first event.
        self.tx_buf.map(write_empty_ack);

        // Schedule the first event.
        self.schedule_next_event(params);
    }
}

// AlarmClient: fires TIMER_SETUP_TICKS µs before the expected RX window opens.
impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> AlarmClient for ConnectionManager<'a, D, A> {
    fn alarm(&self) {
        let params = match self.params.get() {
            Some(p) => p,
            None => return,
        };

        // The absolute open time was computed when this event was scheduled
        // (connect_ind_received for the first event, compute_next_open_time after).
        let open_time = self.next_open_time.get();

        // Pick channel for this event.
        let (channel_num, new_unmapped) = if self.single_channel_test.get() {
            (0u8, self.last_unmapped_channel.get())
        } else {
            next_channel(
                self.last_unmapped_channel.get(),
                params.hop_increment,
                params.channel_map,
            )
        };
        self.last_unmapped_channel.set(new_unmapped);

        let channel = RadioChannel::from_data_channel_index(channel_num)
            .unwrap_or(RadioChannel::DataChannel0);

        self.tx_buf.take().map(|tx| {
            let _ = self.driver.connection_event_start(channel, tx, open_time);
        });
    }
}

// ConnectionEventClient: called by the radio driver after each RX+TX hardware sequence.
impl<'a, D: BleConnectionDriver<'a>, A: Alarm<'a>> ConnectionEventClient
    for ConnectionManager<'a, D, A>
{
    fn connection_event_done(
        &self,
        buf: &'static mut [u8],
        tx_buf: &'static mut [u8],
        result: Result<(), ErrorCode>,
        anchor_ticks: u32,
        tx_acked: bool,
    ) {
        // Record acknowledgement of our last transmitted PDU (stop-and-wait flow
        // control foundation; not yet acted on while we only send empty PDUs).
        self.tx_acked.set(tx_acked);

        let params = match self.params.get() {
            Some(p) => p,
            None => {
                self.rx_buf.replace(buf);
                self.tx_buf.replace(tx_buf);
                return;
            }
        };

        self.event_counter.set(self.event_counter.get() + 1);

        let rx_ok = result.is_ok();
        let channel = self.last_unmapped_channel.get(); // approximate for debug log
        let (header, len, opcode) = if buf.len() >= 3 {
            (buf[0], buf[1], buf[2])
        } else {
            (0, 0, 0)
        };
        self.log_event(channel, rx_ok, anchor_ticks, header, len, opcode, tx_acked);

        // A master-initiated disconnect arrives as an LL_TERMINATE_IND control PDU.
        // Our empty-PDU ACK for this event has already been sent by the hardware
        // (RX→TX turnaround), which is the acknowledgement the master waits for, so
        // we can tear the connection down now and resume advertising.
        if rx_ok && is_ll_terminate_ind(buf) {
            self.rx_buf.replace(buf);
            self.tx_buf.replace(tx_buf);
            self.declare_connection_lost();
            return;
        }

        if rx_ok {
            self.last_anchor_ticks.set(anchor_ticks);
            self.missed_events.set(0);
        } else {
            let missed = self.missed_events.get().saturating_add(1);
            self.missed_events.set(missed);
            // Supervision timeout check
            let elapsed_ms = missed as u32 * params.conn_interval_us / 1000;
            if elapsed_ms > params.supervision_timeout_ms {
                self.rx_buf.replace(buf);
                // tx_buf is returned here; put it back for potential reconnect
                self.tx_buf.replace(tx_buf);
                self.declare_connection_lost();
                return;
            }
        }

        // Prepare next TX PDU and return buffers to TakeCells.
        write_empty_ack(tx_buf);
        self.tx_buf.replace(tx_buf);
        self.rx_buf.replace(buf);

        // Compute the next event's open time from the (possibly just-corrected)
        // anchor, then arm the coarse alarm for it.
        self.compute_next_open_time(&params);
        self.schedule_next_event(&params);
    }
}

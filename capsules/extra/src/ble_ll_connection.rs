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

/// One entry in the non-empty-PDU diagnostic ring.
///
/// Records LL control PDUs *and* data (L2CAP/ATT) PDUs, in both directions.
/// Non-empty PDUs are rare enough that 16 entries capture a whole connection's
/// handshake without being flooded by empty keep-alive PDUs.
#[derive(Copy, Clone)]
pub struct CtrlEntry {
    pub event_counter: u32,
    /// false = received from master, true = transmitted by us.
    pub is_tx: bool,
    /// PDU header byte (`buf[0]`): LLID in the low two bits (0b01 data/empty,
    /// 0b10 data start, 0b11 control).
    pub header: u8,
    /// PDU payload length (`buf[1]`).
    pub len: u8,
    /// First payload bytes (`buf[2..8]`): control opcode, or L2CAP length + CID +
    /// ATT opcode for a data PDU.
    pub payload: [u8; 6],
}

impl CtrlEntry {
    const fn zero() -> Self {
        CtrlEntry {
            event_counter: 0,
            is_tx: false,
            header: 0,
            len: 0,
            payload: [0; 6],
        }
    }
}

/// Maximum size of a queued outbound PDU (header + payload).  Comfortably fits
/// our control PDUs and ATT responses at the default 23-byte MTU.
const RESP_PDU_MAX: usize = 32;
/// Depth of the outbound response queue.  Only a couple of responses are ever
/// in flight at once (e.g. an LL procedure response overlapping an ATT one), so
/// this is generous.
const RESP_QUEUE_LEN: usize = 4;

/// A pre-built outbound PDU awaiting transmission.
///
/// The stop-and-wait TX drains one queued response per acknowledged event, so
/// requests that arrive while a response is in flight are answered later rather
/// than dropped.
#[derive(Copy, Clone)]
struct RespEntry {
    pdu: [u8; RESP_PDU_MAX],
    nbytes: u8,
}

impl RespEntry {
    const fn zero() -> Self {
        RespEntry {
            pdu: [0; RESP_PDU_MAX],
            nbytes: 0,
        }
    }
}

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

/// Stop-and-wait state for the slave→master TX PDU.
#[derive(Copy, Clone, PartialEq)]
enum TxPhase {
    /// Sending empty keep-alive PDUs; ready to start a new response.
    Idle,
    /// A content PDU is loaded and will be transmitted in the next event.
    FreshContent,
    /// The content PDU has been transmitted; awaiting the master's acknowledgement
    /// (retransmit until then).
    AwaitingAck,
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
    /// Stop-and-wait phase for the outbound TX PDU.
    tx_phase: Cell<TxPhase>,
    /// Whether the currently-loaded TX PDU is fresh content (first transmission).
    /// Passed to the driver so a first send is not suppressed by the ack guard.
    tx_fresh: Cell<bool>,
    /// Whether we have already sent our LL_VERSION_IND this connection (spec: once).
    version_sent: Cell<bool>,

    // Outbound response queue: built responses awaiting transmission, drained one
    // at a time by the stop-and-wait TX so overlapping/pipelined requests are not
    // dropped.
    resp_queue: Cell<[RespEntry; RESP_QUEUE_LEN]>,
    resp_head: Cell<usize>,
    resp_count: Cell<usize>,

    // Value of the single read/write GATT characteristic (handle H_CHAR_VALUE).
    char_value: Cell<[u8; CHAR_VALUE_MAX]>,
    char_value_len: Cell<usize>,
    last_unmapped_channel: Cell<u8>,
    missed_events: Cell<u16>,

    rx_buf: TakeCell<'static, [u8]>,
    tx_buf: TakeCell<'static, [u8]>,

    // Debug
    debug_log: Cell<[DebugEntry; 16]>,
    debug_log_head: Cell<usize>,
    ctrl_log: Cell<[CtrlEntry; 16]>,
    ctrl_log_head: Cell<usize>,
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
// Base header byte for an LL Control PDU we transmit (LLID=0b11, MD=0); the radio
// stamps the SN/NESN bits during the RX→TX turnaround.
const CONTROL_PDU_HEADER: u8 = 0b11;

// LL Control PDU opcodes (BT Core Spec Vol 6 Part B §2.4.2).
const LL_UNKNOWN_RSP: u8 = 0x07;
const LL_TERMINATE_IND: u8 = 0x02;
const LL_FEATURE_REQ: u8 = 0x08;
const LL_FEATURE_RSP: u8 = 0x09;
const LL_SLAVE_FEATURE_REQ: u8 = 0x0E;
const LL_VERSION_IND: u8 = 0x0C;
const LL_CONNECTION_UPDATE_IND: u8 = 0x00;
const LL_CHANNEL_MAP_IND: u8 = 0x01;

// Bluetooth Core Specification version number for LL_VERSION_IND (5.3 = 0x0C).
const LL_VERSNR: u8 = 0x0C;

// LLID = 0b10 marks the start of (or a complete) L2CAP message on a data PDU.
const LLID_DATA_START: u8 = 0b10;
// Base header byte for an L2CAP data PDU we transmit (LLID=0b10, MD=0); the radio
// stamps the SN/NESN bits during the RX→TX turnaround.
const DATA_PDU_HEADER: u8 = 0b10;

// L2CAP / ATT constants for a minimal (attribute-less) GATT server whose only job
// is to complete the client's transactions so the connection is not torn down.
const L2CAP_CID_ATT: u16 = 0x0004;
const ATT_MTU_DEFAULT: u16 = 23; // default LE ATT MTU; keeps ATT PDUs unfragmented

// ATT opcodes (BT Core Spec Vol 3 Part F §3.4).
const ATT_ERROR_RSP: u8 = 0x01;
const ATT_EXCHANGE_MTU_REQ: u8 = 0x02;
const ATT_EXCHANGE_MTU_RSP: u8 = 0x03;
const ATT_READ_BY_TYPE_REQ: u8 = 0x08;
const ATT_READ_BY_TYPE_RSP: u8 = 0x09;
const ATT_READ_REQ: u8 = 0x0A;
const ATT_READ_RSP: u8 = 0x0B;
const ATT_READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
const ATT_READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
const ATT_WRITE_REQ: u8 = 0x12;
const ATT_WRITE_RSP: u8 = 0x13;

// ATT error codes.
const ATT_ERR_INVALID_HANDLE: u8 = 0x01;
const ATT_ERR_WRITE_NOT_PERMITTED: u8 = 0x03;
const ATT_ERR_ATTR_NOT_FOUND: u8 = 0x0A;

// GATT attribute-type UUIDs (BT Core Spec Vol 3 Part G).
const GATT_PRIMARY_SERVICE: u16 = 0x2800;
const GATT_CHARACTERISTIC: u16 = 0x2803;

// A single vendor service (0xFFF0) with one read/write characteristic (0xFFF1).
// Fixed handle layout: 0x0001 service decl, 0x0002 characteristic decl, 0x0003
// characteristic value.
const SVC_UUID: u16 = 0xFFF0;
const CHR_UUID: u16 = 0xFFF1;
const CHR_PROPS: u8 = 0x02 | 0x08; // Read | Write (with response)
const H_SERVICE: u16 = 0x0001;
const H_CHAR_DECL: u16 = 0x0002;
const H_CHAR_VALUE: u16 = 0x0003;

// Storage for the writable characteristic value.  Capped at MTU-3 so a read
// response always fits the default 23-byte ATT MTU without fragmentation.
const CHAR_VALUE_MAX: usize = 20;

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

// Wrap an ATT payload in an L2CAP header and an LL data-PDU header, writing the
// complete PDU into `tx`.  Returns false (no PDU written) if `tx` is too small.
// The SN/NESN bits of `tx[0]` are stamped later by the radio.
fn write_att_response(tx: &mut [u8], att: &[u8]) -> bool {
    let total = 6 + att.len(); // LL header(2) + L2CAP header(4) + ATT payload
    if tx.len() < total {
        return false;
    }
    let l2cap_len = att.len() as u16;
    tx[0] = DATA_PDU_HEADER;
    tx[1] = (4 + att.len()) as u8; // LL payload length = L2CAP header + ATT payload
    tx[2] = (l2cap_len & 0xff) as u8;
    tx[3] = (l2cap_len >> 8) as u8;
    tx[4] = (L2CAP_CID_ATT & 0xff) as u8;
    tx[5] = (L2CAP_CID_ATT >> 8) as u8;
    tx[6..total].copy_from_slice(att);
    true
}

// Write an ATT_ERROR_RSP for `req_op`/`handle` with error code `err` into `tx`.
fn write_att_error(tx: &mut [u8], req_op: u8, handle: u16, err: u8) -> bool {
    write_att_response(
        tx,
        &[
            ATT_ERROR_RSP,
            req_op,
            (handle & 0xff) as u8,
            (handle >> 8) as u8,
            err,
        ],
    )
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
            tx_phase: Cell::new(TxPhase::Idle),
            tx_fresh: Cell::new(false),
            version_sent: Cell::new(false),
            resp_queue: Cell::new([RespEntry::zero(); RESP_QUEUE_LEN]),
            resp_head: Cell::new(0),
            resp_count: Cell::new(0),
            // Default characteristic value: recognisable "DE AD BE EF".
            char_value: Cell::new([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            char_value_len: Cell::new(4),
            last_unmapped_channel: Cell::new(0),
            missed_events: Cell::new(0),
            rx_buf: TakeCell::new(rx_buf),
            tx_buf: TakeCell::new(tx_buf),
            debug_log: Cell::new([DebugEntry::zero(); 16]),
            debug_log_head: Cell::new(0),
            ctrl_log: Cell::new([CtrlEntry::zero(); 16]),
            ctrl_log_head: Cell::new(0),
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

    // Append a built PDU to the outbound response queue.  Dropped if the queue is
    // full (should not happen given the depth and the sequential request model).
    fn enqueue_response(&self, pdu: &[u8]) {
        let count = self.resp_count.get();
        if count >= RESP_QUEUE_LEN {
            return;
        }
        let n = pdu.len().min(RESP_PDU_MAX);
        let mut entry = RespEntry::zero();
        entry.pdu[..n].copy_from_slice(&pdu[..n]);
        entry.nbytes = n as u8;
        let slot = (self.resp_head.get() + count) % RESP_QUEUE_LEN;
        let mut q = self.resp_queue.get();
        q[slot] = entry;
        self.resp_queue.set(q);
        self.resp_count.set(count + 1);
    }

    // Pop the oldest queued response into `tx`, returning true if one was pending.
    fn dequeue_response_into(&self, tx: &mut [u8]) -> bool {
        let count = self.resp_count.get();
        if count == 0 {
            return false;
        }
        let head = self.resp_head.get();
        let entry = self.resp_queue.get()[head];
        let n = (entry.nbytes as usize).min(tx.len()).min(RESP_PDU_MAX);
        tx[..n].copy_from_slice(&entry.pdu[..n]);
        self.resp_head.set((head + 1) % RESP_QUEUE_LEN);
        self.resp_count.set(count - 1);
        true
    }

    // Decide and build a response to the master's PDU, dispatching on the LLID:
    // LL control PDUs (0b11) and L2CAP/ATT data PDUs (0b10).  Returns true if a
    // response was written into `tx`, false if none is needed (send empty instead).
    fn build_response(&self, rx: &[u8], tx: &mut [u8]) -> bool {
        match rx.first().copied().unwrap_or(0) & LLID_MASK {
            LLID_CONTROL => {
                self.build_control_response(rx[0], rx.get(2).copied().unwrap_or(0), tx)
            }
            LLID_DATA_START => self.build_att_response(rx, tx),
            _ => false,
        }
    }

    // Handle an ATT request on the L2CAP ATT channel for our minimal GATT server:
    // one vendor service (0xFFF0) with one read/write characteristic (0xFFF1).
    //
    // `rx` data PDU layout: [2..4] = L2CAP length, [4..6] = CID, [6..] = ATT PDU.
    fn build_att_response(&self, rx: &[u8], tx: &mut [u8]) -> bool {
        if rx.len() < 7 {
            return false;
        }
        let cid = u16::from_le_bytes([rx[4], rx[5]]);
        if cid != L2CAP_CID_ATT {
            return false; // not ATT (e.g. LE signalling channel); ignore for now
        }
        // Bound the ATT PDU to its actual length.  The L2CAP length field (rx[2..4])
        // is the ATT payload size; clamp it to the LL payload length (rx[1]) and the
        // buffer so we never read stale bytes past the received PDU — otherwise a
        // short write would store trailing garbage as the characteristic value.
        let l2cap_len = u16::from_le_bytes([rx[2], rx[3]]) as usize;
        let end = (6 + l2cap_len).min(2 + rx[1] as usize).min(rx.len());
        if end < 7 {
            return false;
        }
        let att = &rx[6..end];
        match att[0] {
            ATT_EXCHANGE_MTU_REQ => write_att_response(
                tx,
                &[
                    ATT_EXCHANGE_MTU_RSP,
                    (ATT_MTU_DEFAULT & 0xff) as u8,
                    (ATT_MTU_DEFAULT >> 8) as u8,
                ],
            ),
            ATT_READ_BY_GROUP_TYPE_REQ => self.att_read_by_group_type(att, tx),
            ATT_READ_BY_TYPE_REQ => self.att_read_by_type(att, tx),
            ATT_READ_REQ => self.att_read(att, tx),
            ATT_WRITE_REQ => self.att_write(att, tx),
            other => {
                // Other ATT methods (e.g. Find Information for descriptor
                // discovery): reply "Attribute Not Found" so the transaction
                // completes.  We expose no descriptors.
                let handle = att
                    .get(1)
                    .zip(att.get(2))
                    .map_or(0, |(lo, hi)| u16::from_le_bytes([*lo, *hi]));
                write_att_error(tx, other, handle, ATT_ERR_ATTR_NOT_FOUND)
            }
        }
    }

    // ATT_READ_BY_GROUP_TYPE_REQ: [op][start(2)][end(2)][group type(2)].
    // Used for primary-service discovery (group type 0x2800).
    fn att_read_by_group_type(&self, att: &[u8], tx: &mut [u8]) -> bool {
        if att.len() < 7 {
            return write_att_error(tx, ATT_READ_BY_GROUP_TYPE_REQ, 0, ATT_ERR_ATTR_NOT_FOUND);
        }
        let start = u16::from_le_bytes([att[1], att[2]]);
        let end = u16::from_le_bytes([att[3], att[4]]);
        let group_type = u16::from_le_bytes([att[5], att[6]]);
        if group_type == GATT_PRIMARY_SERVICE && start <= H_SERVICE && H_SERVICE <= end {
            // One element: handle range [H_SERVICE..H_CHAR_VALUE], value = SVC_UUID.
            write_att_response(
                tx,
                &[
                    ATT_READ_BY_GROUP_TYPE_RSP,
                    6, // per-element length: handle(2) + end group(2) + UUID(2)
                    (H_SERVICE & 0xff) as u8,
                    (H_SERVICE >> 8) as u8,
                    (H_CHAR_VALUE & 0xff) as u8,
                    (H_CHAR_VALUE >> 8) as u8,
                    (SVC_UUID & 0xff) as u8,
                    (SVC_UUID >> 8) as u8,
                ],
            )
        } else {
            // No (more) services in range: ends the client's service discovery.
            write_att_error(tx, ATT_READ_BY_GROUP_TYPE_REQ, start, ATT_ERR_ATTR_NOT_FOUND)
        }
    }

    // ATT_READ_BY_TYPE_REQ: [op][start(2)][end(2)][type(2)].
    // Used for characteristic discovery (type 0x2803).
    fn att_read_by_type(&self, att: &[u8], tx: &mut [u8]) -> bool {
        if att.len() < 7 {
            return write_att_error(tx, ATT_READ_BY_TYPE_REQ, 0, ATT_ERR_ATTR_NOT_FOUND);
        }
        let start = u16::from_le_bytes([att[1], att[2]]);
        let end = u16::from_le_bytes([att[3], att[4]]);
        let ty = u16::from_le_bytes([att[5], att[6]]);
        if ty == GATT_CHARACTERISTIC && start <= H_CHAR_DECL && H_CHAR_DECL <= end {
            // One element: handle = H_CHAR_DECL, value = properties + value handle +
            // characteristic UUID.
            write_att_response(
                tx,
                &[
                    ATT_READ_BY_TYPE_RSP,
                    7, // per-element length: handle(2) + value(5)
                    (H_CHAR_DECL & 0xff) as u8,
                    (H_CHAR_DECL >> 8) as u8,
                    CHR_PROPS,
                    (H_CHAR_VALUE & 0xff) as u8,
                    (H_CHAR_VALUE >> 8) as u8,
                    (CHR_UUID & 0xff) as u8,
                    (CHR_UUID >> 8) as u8,
                ],
            )
        } else {
            write_att_error(tx, ATT_READ_BY_TYPE_REQ, start, ATT_ERR_ATTR_NOT_FOUND)
        }
    }

    // ATT_READ_REQ: [op][handle(2)].
    fn att_read(&self, att: &[u8], tx: &mut [u8]) -> bool {
        if att.len() < 3 {
            return write_att_error(tx, ATT_READ_REQ, 0, ATT_ERR_INVALID_HANDLE);
        }
        let handle = u16::from_le_bytes([att[1], att[2]]);
        match handle {
            H_SERVICE => write_att_response(
                tx,
                &[ATT_READ_RSP, (SVC_UUID & 0xff) as u8, (SVC_UUID >> 8) as u8],
            ),
            H_CHAR_DECL => write_att_response(
                tx,
                &[
                    ATT_READ_RSP,
                    CHR_PROPS,
                    (H_CHAR_VALUE & 0xff) as u8,
                    (H_CHAR_VALUE >> 8) as u8,
                    (CHR_UUID & 0xff) as u8,
                    (CHR_UUID >> 8) as u8,
                ],
            ),
            H_CHAR_VALUE => {
                let value = self.char_value.get();
                let n = self.char_value_len.get().min(value.len());
                let mut pdu = [0u8; 1 + CHAR_VALUE_MAX];
                pdu[0] = ATT_READ_RSP;
                pdu[1..1 + n].copy_from_slice(&value[..n]);
                write_att_response(tx, &pdu[..1 + n])
            }
            _ => write_att_error(tx, ATT_READ_REQ, handle, ATT_ERR_INVALID_HANDLE),
        }
    }

    // ATT_WRITE_REQ: [op][handle(2)][value...].
    fn att_write(&self, att: &[u8], tx: &mut [u8]) -> bool {
        if att.len() < 3 {
            return write_att_error(tx, ATT_WRITE_REQ, 0, ATT_ERR_INVALID_HANDLE);
        }
        let handle = u16::from_le_bytes([att[1], att[2]]);
        if handle == H_CHAR_VALUE {
            let value = &att[3..];
            let n = value.len().min(CHAR_VALUE_MAX);
            let mut v = [0u8; CHAR_VALUE_MAX];
            v[..n].copy_from_slice(&value[..n]);
            self.char_value.set(v);
            self.char_value_len.set(n);
            write_att_response(tx, &[ATT_WRITE_RSP])
        } else {
            write_att_error(tx, ATT_WRITE_REQ, handle, ATT_ERR_WRITE_NOT_PERMITTED)
        }
    }

    // Build an LL control-PDU response into `tx` for a received control PDU, if one
    // is warranted.  Returns true if a response PDU was written (its length is in
    // `tx[1]`), false if no response is needed (caller should send an empty PDU).
    //
    // `rx_hdr` and `opcode` are the received PDU's header byte and first payload
    // byte.  Only LL Control PDUs (LLID = 0b11) produce a response.
    fn build_control_response(&self, rx_hdr: u8, opcode: u8, tx: &mut [u8]) -> bool {
        if (rx_hdr & LLID_MASK) != LLID_CONTROL || tx.len() < 12 {
            return false;
        }
        match opcode {
            LL_FEATURE_REQ | LL_SLAVE_FEATURE_REQ => {
                // LL_FEATURE_RSP: opcode + 8-byte FeatureSet.  We advertise no
                // optional LL features (all zero), which is valid.
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 9;
                tx[2] = LL_FEATURE_RSP;
                for b in tx[3..11].iter_mut() {
                    *b = 0;
                }
                true
            }
            LL_VERSION_IND => {
                // Reply with our LL_VERSION_IND once per connection (spec §5.1.5).
                if self.version_sent.get() {
                    return false;
                }
                self.version_sent.set(true);
                // opcode + VersNr(1) + CompId(2, LE) + SubVersNr(2, LE)
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 6;
                tx[2] = LL_VERSION_IND;
                tx[3] = LL_VERSNR;
                tx[4] = 0xFF; // CompId 0xFFFF (unassigned / test)
                tx[5] = 0xFF;
                tx[6] = 0x00; // SubVersNr
                tx[7] = 0x00;
                true
            }
            LL_CONNECTION_UPDATE_IND | LL_CHANNEL_MAP_IND => {
                // Master-initiated indications; no LL response is expected, so we
                // ack them at the LL level and send nothing here.
                //
                // TODO(connection updates): we do NOT yet *apply* these.  Both carry
                // an `Instant` (a connEventCount at which the change takes effect on
                // both sides); correct handling must:
                //   * LL_CHANNEL_MAP_IND — parse ChM(5) + Instant(2), stash them, and
                //     when our event counter reaches Instant swap params.channel_map
                //     (mind 16-bit wraparound of the instant vs. our counter).
                //   * LL_CONNECTION_UPDATE_IND — parse WinSize/WinOffset/Interval/
                //     Latency/Timeout + Instant, and at the Instant re-anchor and
                //     re-time the whole event schedule.
                // Until then, a master that actually switches maps/parameters mid-
                // connection will desync us (missed events → supervision timeout).
                // We have not been able to exercise this: observed masters send
                // LL_CHANNEL_MAP_IND but do not appear to switch.
                false
            }
            other => {
                // Any other control PDU is unsupported: reply LL_UNKNOWN_RSP with
                // the offending opcode so the master's procedure does not stall
                // for the full ~40 s response timeout (BT Core Spec §5.1.9).
                tx[0] = CONTROL_PDU_HEADER;
                tx[1] = 2;
                tx[2] = LL_UNKNOWN_RSP;
                tx[3] = other;
                true
            }
        }
    }

    // Record a non-empty PDU (received or transmitted) in the diagnostic ring.
    fn log_ctrl(&self, is_tx: bool, pdu: &[u8]) {
        let mut payload = [0u8; 6];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = pdu.get(2 + i).copied().unwrap_or(0);
        }
        let head = self.ctrl_log_head.get();
        let mut log = self.ctrl_log.get();
        log[head % 16] = CtrlEntry {
            event_counter: self.event_counter.get(),
            is_tx,
            header: pdu.first().copied().unwrap_or(0),
            len: pdu.get(1).copied().unwrap_or(0),
            payload,
        };
        self.ctrl_log.set(log);
        self.ctrl_log_head.set(head.wrapping_add(1));
    }

    fn declare_connection_lost(&self) {
        // Diagnostic: dump the recent connection-event history and the full control-
        // PDU handshake so we can see which LL procedure (if any) failed to complete.
        self.dump_debug_log();
        self.dump_ctrl_log();
        self.state.set(State::Idle);
        self.params.set(None);
        self.disconnect_client.map(|c| c.connection_lost());
    }

    fn dump_ctrl_log(&self) {
        let log = self.ctrl_log.get();
        let head = self.ctrl_log_head.get();
        debug!("BLE non-empty-PDU log (oldest first):");
        for i in 0..16 {
            let e = log[head.wrapping_add(i) % 16];
            if e.event_counter == 0 && e.header == 0 && !e.is_tx {
                continue;
            }
            debug!(
                "  evt {} {} hdr {:#04x} len {} payload {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
                e.event_counter,
                if e.is_tx { "TX" } else { "RX" },
                e.header,
                e.len,
                e.payload[0],
                e.payload[1],
                e.payload[2],
                e.payload[3],
                e.payload[4],
                e.payload[5],
            );
        }
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
        self.tx_phase.set(TxPhase::Idle);
        self.tx_fresh.set(false);
        self.version_sent.set(false);
        self.resp_head.set(0);
        self.resp_count.set(0);

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

        let tx_fresh = self.tx_fresh.get();
        self.tx_buf.take().map(|tx| {
            let _ = self
                .driver
                .connection_event_start(channel, tx, open_time, tx_fresh);
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

        // Diagnostic: record every received non-empty PDU (control or L2CAP/ATT
        // data), which is rare compared to empty keep-alive PDUs.
        if rx_ok && len >= 1 {
            self.log_ctrl(false, buf);
        }

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

        // If the master's PDU this event needs a response, build it and queue it.
        // Queuing (rather than sending it immediately) means a request that arrives
        // while an earlier response is still in flight — e.g. the ATT MTU request
        // pipelined right after the LL version exchange — is answered later instead
        // of dropped.
        if rx_ok && len >= 1 {
            let mut scratch = [0u8; RESP_PDU_MAX];
            if self.build_response(buf, &mut scratch) {
                let n = (2 + scratch[1] as usize).min(RESP_PDU_MAX);
                self.enqueue_response(&scratch[..n]);
            }
        }

        // Advance the stop-and-wait flow-control state, then (if we are free to load
        // a new payload) send the next queued response, or an empty keep-alive.
        let ready_for_next = match self.tx_phase.get() {
            TxPhase::AwaitingAck => {
                if tx_acked {
                    // Outstanding content was delivered (the radio transmitted an
                    // empty PDU in its place this event); free to load the next.
                    self.tx_phase.set(TxPhase::Idle);
                    true
                } else {
                    // Not yet acknowledged: retransmit by leaving tx_buf unchanged.
                    self.tx_fresh.set(false);
                    false
                }
            }
            TxPhase::FreshContent => {
                // The content PDU was transmitted once this event; keep it loaded
                // for possible retransmission and await its acknowledgement.
                self.tx_fresh.set(false);
                self.tx_phase.set(TxPhase::AwaitingAck);
                false
            }
            TxPhase::Idle => true,
        };

        if ready_for_next {
            if self.dequeue_response_into(tx_buf) {
                self.log_ctrl(true, tx_buf);
                self.tx_fresh.set(true);
                self.tx_phase.set(TxPhase::FreshContent);
            } else {
                write_empty_ack(tx_buf);
                self.tx_fresh.set(false);
            }
        }
        self.tx_buf.replace(tx_buf);
        self.rx_buf.replace(buf);

        // Compute the next event's open time from the (possibly just-corrected)
        // anchor, then arm the coarse alarm for it.
        self.compute_next_open_time(&params);
        self.schedule_next_event(&params);
    }
}

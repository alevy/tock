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
use kernel::hil::ble_advertising::{
    BleConnectionDriver, ConnectionEventClient, ConnectionParams, ConnectionSetupClient,
    RadioChannel,
};
use kernel::hil::time::{Alarm, AlarmClient};
use kernel::utilities::cells::{OptionalCell, TakeCell};

// Combined SCA: assume ±500 ppm master + ±500 ppm slave = ±1000 ppm worst-case.
const COMBINED_SCA_PPM: u32 = 1000;
// Minimum window widening per spec (µs).
const MIN_WIDENING_US: u32 = 16;
// Extra guard margin added on each side of the RX window (µs).
const WINDOW_GUARD_US: u32 = 150;
// How many TIMER0 ticks (µs) before expected anchor to arm PPI CH21.
const TIMER_SETUP_TICKS: u32 = 500;

/// One entry in the debug ring buffer — populated after each connection event.
#[derive(Copy, Clone)]
pub struct DebugEntry {
    pub channel: u8,
    pub anchor_ticks: u32,
    pub rx_ok: bool,
    pub event_counter: u32,
}

impl DebugEntry {
    const fn zero() -> Self {
        DebugEntry {
            channel: 0,
            anchor_ticks: 0,
            rx_ok: false,
            event_counter: 0,
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

    fn schedule_next_event(&self, params: &ConnectionParams) {
        let interval_us = params.conn_interval_us;
        let widening = window_widening(self.missed_events.get() as u32 + 1, interval_us);
        let open_time = self
            .last_anchor_ticks
            .get()
            .wrapping_add(interval_us)
            .wrapping_sub(widening + WINDOW_GUARD_US);

        // Arm the alarm so the CPU wakes up TIMER_SETUP_TICKS before open_time.
        let wakeup = open_time.wrapping_sub(TIMER_SETUP_TICKS);
        self.alarm.set_alarm(
            A::Ticks::from(wakeup),
            A::Ticks::from(0), // fire at exactly wakeup
        );
    }

    fn declare_connection_lost(&self) {
        self.state.set(State::Idle);
        self.params.set(None);
        self.disconnect_client.map(|c| c.connection_lost());
    }

    fn log_event(&self, channel: u8, rx_ok: bool, anchor: u32) {
        let head = self.debug_log_head.get();
        let entry = DebugEntry {
            channel,
            anchor_ticks: anchor,
            rx_ok,
            event_counter: self.event_counter.get(),
        };
        let mut log = self.debug_log.get();
        log[head % 16] = entry;
        self.debug_log.set(log);
        self.debug_log_head.set(head.wrapping_add(1));
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

        // Compute the anchor for the first connection event:
        //   anchor ≈ timer0_now + winOffset + winSize/2
        let first_anchor = timer0_now
            .wrapping_add(params.win_offset_us)
            .wrapping_add(params.win_size_us / 2);
        self.last_anchor_ticks.set(first_anchor);

        // Prepare a TX buffer for the first event.
        self.tx_buf.map(|buf| write_empty_ack(buf));

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

        let interval_us = params.conn_interval_us;
        let widening = window_widening(self.missed_events.get() as u32 + 1, interval_us);

        // RX window opens at last_anchor + connInterval - widening - guard
        let open_time = self
            .last_anchor_ticks
            .get()
            .wrapping_add(interval_us)
            .wrapping_sub(widening + WINDOW_GUARD_US);

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
        self.log_event(channel, rx_ok, anchor_ticks);

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

        // Schedule next connection event.
        self.schedule_next_event(&params);
    }
}

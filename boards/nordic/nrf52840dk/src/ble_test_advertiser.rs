// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2024.

//! Boot-time BLE connectable advertiser for hardware testing.
//!
//! Drives the nRF52 radio directly (bypasses the userspace BLE advertising
//! syscall driver) to cycle `ADV_IND` packets across the three advertising
//! channels (37 / 38 / 39) and accept the first `CONNECT_IND`.
//!
//! On receiving a `CONNECT_IND` the capsule calls
//! [`BleConnectionDriver::connection_configure`] to initialise TIMER0, reads
//! the current tick via [`BleConnectionDriver::get_timer0_now`], and hands the
//! [`ConnectionParams`] off to the registered [`ConnectionSetupClient`]
//! (typically [`ConnectionManager`][capsules_extra::ble_ll_connection::ConnectionManager]).
//!
//! This capsule is mutually exclusive with the userspace `BLE` advertising
//! driver as TX / RX client: `start()` overwrites whatever client the
//! advertising driver registered.

use core::cell::Cell;

use kernel::hil::ble_advertising::{
    BleAdvertisementDriver, BleConnectionDriver, ConnectionParams, ConnectionSetupClient,
    RadioChannel, RxClient, TxClient,
};
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

const ADV_CHANNELS: [RadioChannel; 3] = [
    RadioChannel::AdvertisingChannel37,
    RadioChannel::AdvertisingChannel38,
    RadioChannel::AdvertisingChannel39,
];

/// Boot-time connectable BLE advertiser.
///
/// Emits `ADV_IND` PDUs on advertising channels 37 / 38 / 39 in a round-robin
/// and listens up to 3 ms after each TX for a `CONNECT_IND` from a central.
/// After a successful `CONNECT_IND` the capsule stops advertising and the
/// `ConnectionSetupClient` drives the connection lifecycle.
pub struct BleTestAdvertiser<
    'a,
    R: BleAdvertisementDriver<'a> + BleConnectionDriver<'a>,
    A: Alarm<'a>,
> {
    radio: &'a R,
    alarm: &'a A,
    setup_client: OptionalCell<&'a dyn ConnectionSetupClient>,
    /// TX buffer — holds the pre-built `ADV_IND` PDU.
    buf: TakeCell<'static, [u8]>,
    channel_idx: Cell<usize>,
    /// True while waiting for a `CONNECT_IND` after an `ADV_IND` TX.
    listening: Cell<bool>,
}

impl<'a, R: BleAdvertisementDriver<'a> + BleConnectionDriver<'a>, A: Alarm<'a>>
    BleTestAdvertiser<'a, R, A>
{
    /// Create a new `BleTestAdvertiser`.  `buf` must be at least 64 bytes.
    pub fn new(radio: &'a R, alarm: &'a A, buf: &'static mut [u8]) -> Self {
        Self {
            radio,
            alarm,
            setup_client: OptionalCell::empty(),
            buf: TakeCell::new(buf),
            channel_idx: Cell::new(0),
            listening: Cell::new(false),
        }
    }

    /// Register the client that receives [`ConnectionParams`] when a
    /// `CONNECT_IND` is parsed.
    pub fn set_connection_setup_client(&self, client: &'a dyn ConnectionSetupClient) {
        self.setup_client.set(client);
    }

    /// Register `self` as the radio's TX / RX client and kick off advertising.
    ///
    /// Must be called once from board init code after all other radio clients
    /// have been registered (this overwrites whichever client was last set).
    pub fn start(&'a self) {
        self.radio.set_transmit_client(self);
        self.radio.set_receive_client(self);
        let dt = self.alarm.ticks_from_ms(10);
        self.alarm.set_alarm(self.alarm.now(), dt);
    }

    fn advertise_now(&self) {
        self.buf.take().map(|buf| {
            let len = build_adv_ind(buf);
            let ch = ADV_CHANNELS[self.channel_idx.get()];
            self.listening.set(false);
            self.radio.transmit_advertisement(buf, len, ch);
        });
    }
}

/// Builds a minimal `ADV_IND` PDU into `buf` and returns total byte count.
///
/// Advertising address: random-static `C0:FF:EE:BE:EF:42`.
/// AD payload: Flags (0x06) + Complete Local Name "TockBLE" (7 chars).
fn build_adv_ind(buf: &mut [u8]) -> usize {
    // Header byte 0: PDU type ADV_IND (0x00) | TxAdd=1 (random addr) → 0x40
    buf[0] = 0x40;
    // AdvA (6 bytes, LE): C0:FF:EE:BE:EF:42 — bits 47:46 = 11 → random static
    buf[2] = 0x42;
    buf[3] = 0xEF;
    buf[4] = 0xBE;
    buf[5] = 0xEE;
    buf[6] = 0xFF;
    buf[7] = 0xC0;
    // AD structure: Flags  len=2, type=0x01, value=0x06
    buf[8] = 0x02;
    buf[9] = 0x01;
    buf[10] = 0x06;
    // AD structure: Complete Local Name  len=8, type=0x09, "TockBLE"
    buf[11] = 0x08;
    buf[12] = 0x09;
    buf[13] = b'T';
    buf[14] = b'o';
    buf[15] = b'c';
    buf[16] = b'k';
    buf[17] = b'B';
    buf[18] = b'L';
    buf[19] = b'E';
    // Header byte 1 (PDU length): AdvA (6) + AdvData (12) = 18
    buf[1] = 18;
    20
}

/// Parse a `CONNECT_IND` PDU (BT Core Spec Vol 6 Part B §2.3.3.1).
///
/// `buf` must be the full PDU slice (header + payload), minimum 36 bytes.
fn parse_connect_ind(buf: &[u8]) -> Option<ConnectionParams> {
    if buf.len() < 36 || (buf[0] & 0x0F) != 0x05 {
        return None;
    }
    let aa = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
    let crc_init =
        (buf[18] as u32) | ((buf[19] as u32) << 8) | ((buf[20] as u32) << 16);
    let win_size_us = buf[21] as u32 * 1250;
    let win_offset_us = u16::from_le_bytes([buf[22], buf[23]]) as u32 * 1250;
    let interval_us = u16::from_le_bytes([buf[24], buf[25]]) as u32 * 1250;
    let latency = u16::from_le_bytes([buf[26], buf[27]]);
    let timeout_ms = u16::from_le_bytes([buf[28], buf[29]]) as u32 * 10;
    let channel_map = (buf[30] as u64)
        | ((buf[31] as u64) << 8)
        | ((buf[32] as u64) << 16)
        | ((buf[33] as u64) << 24)
        | ((buf[34] as u64 & 0x1F) << 32);
    let hop = buf[35] & 0x1F;
    if !(5..=16).contains(&hop) {
        return None;
    }
    Some(ConnectionParams {
        access_address: aa,
        crc_init,
        channel_map,
        hop_increment: hop,
        conn_interval_us: interval_us,
        slave_latency: latency,
        supervision_timeout_ms: timeout_ms,
        win_size_us,
        win_offset_us,
    })
}

impl<'a, R: BleAdvertisementDriver<'a> + BleConnectionDriver<'a>, A: Alarm<'a>> AlarmClient
    for BleTestAdvertiser<'a, R, A>
{
    fn alarm(&self) {
        if self.listening.get() {
            // 3 ms window expired; abort RX and rotate to next advertising channel.
            self.radio.stop_receive();
            self.channel_idx.set((self.channel_idx.get() + 1) % 3);
        }
        self.advertise_now();
    }
}

impl<'a, R: BleAdvertisementDriver<'a> + BleConnectionDriver<'a>, A: Alarm<'a>> TxClient
    for BleTestAdvertiser<'a, R, A>
{
    fn transmit_event(&self, buf: &'static mut [u8], _result: Result<(), ErrorCode>) {
        // Return the TX buffer and begin listening for CONNECT_IND.
        self.buf.replace(buf);
        let ch = ADV_CHANNELS[self.channel_idx.get()];
        self.listening.set(true);
        let dt = self.alarm.ticks_from_ms(3);
        self.alarm.set_alarm(self.alarm.now(), dt);
        self.radio.receive_advertisement(ch);
    }
}

impl<'a, R: BleAdvertisementDriver<'a> + BleConnectionDriver<'a>, A: Alarm<'a>> RxClient
    for BleTestAdvertiser<'a, R, A>
{
    fn receive_event(&self, buf: &'static mut [u8], len: u8, result: Result<(), ErrorCode>) {
        self.listening.set(false);
        // Cancel the 3 ms RX-window timeout.
        self.alarm.disarm().ok();

        if result.is_ok() {
            let pdu = &buf[..core::cmp::min(len as usize, buf.len())];
            if let Some(params) = parse_connect_ind(pdu) {
                // Start TIMER0 and capture current tick for the ConnectionManager.
                let _ = self.radio.connection_configure(&params);
                let timer0_now = self.radio.get_timer0_now();
                // `buf` here is the radio's internal PAYLOAD buffer; it is NOT
                // this capsule's TX buffer, so we don't store it.
                self.setup_client
                    .map(|c| c.connect_ind_received(&params, timer0_now));
                return; // stop advertising — ConnectionManager takes over
            }
        }

        // Not a CONNECT_IND: rotate channel and re-advertise after 50 ms.
        self.channel_idx.set((self.channel_idx.get() + 1) % 3);
        let dt = self.alarm.ticks_from_ms(50);
        self.alarm.set_alarm(self.alarm.now(), dt);
    }
}

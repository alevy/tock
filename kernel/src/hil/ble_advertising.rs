// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Bluetooth Low Energy HIL
//!
//! ```text
//! Application
//!
//!           +------------------------------------------------+
//!           | Applications                                   |
//!           +------------------------------------------------+
//!
//! ```
//!
//! ```text
//! Host
//!
//!           +------------------------------------------------+
//!           | Generic Access Profile                         |
//!           +------------------------------------------------+
//!
//!           +------------------------------------------------+
//!           | Generic Attribute Profile                      |
//!           +------------------------------------------------+
//!
//!           +--------------------+      +-------------------+
//!           | Attribute Protocol |      | Security Manager  |
//!           +--------------------+      +-------------------+
//!
//!           +-----------------------------------------------+
//!           | Logical Link and Adaptation Protocol          |
//!           +-----------------------------------------------+
//!
//! ```
//!
//! ```text
//! Controller
//!
//!           +--------------------------------------------+
//!           | Host Controller Interface                  |
//!           +--------------------------------------------+
//!
//!           +------------------+      +------------------+
//!           | Link Layer       |      | Direct Test Mode |
//!           +------------------+      +------------------+
//!
//!           +--------------------------------------------+
//!           | Physical Layer                             |
//!           +--------------------------------------------+
//!
//! ```

use crate::ErrorCode;

pub trait BleAdvertisementDriver<'a> {
    fn transmit_advertisement(&self, buf: &'static mut [u8], len: usize, channel: RadioChannel);
    fn receive_advertisement(&self, channel: RadioChannel);
    fn set_receive_client(&self, client: &'a dyn RxClient);
    fn set_transmit_client(&self, client: &'a dyn TxClient);
}

pub trait BleConfig {
    fn set_tx_power(&self, power: u8) -> Result<(), ErrorCode>;
}

pub trait RxClient {
    fn receive_event(&self, buf: &'static mut [u8], len: u8, result: Result<(), ErrorCode>);
}

pub trait TxClient {
    fn transmit_event(&self, buf: &'static mut [u8], result: Result<(), ErrorCode>);
}

/// Parameters extracted from a BLE CONNECT_IND PDU (Vol 6, Part B §2.3.3.1).
/// All timing values are in microseconds for hardware-independence.
#[derive(Copy, Clone)]
pub struct ConnectionParams {
    /// Per-connection access address (randomly assigned by the initiator).
    pub access_address: u32,
    /// 24-bit CRC initial value from the CONNECT_IND LLData field.
    pub crc_init: u32,
    /// 37-bit channel map: bit N set means data channel N is usable.
    pub channel_map: u64,
    /// Hop increment (5–16) for the CSA#1 channel selection algorithm.
    pub hop_increment: u8,
    /// Connection interval in microseconds (connInterval × 1250 µs).
    pub conn_interval_us: u32,
    /// Number of connection events the slave may skip (connSlaveLatency).
    pub slave_latency: u16,
    /// Supervision timeout in milliseconds (connSupervisionTimeout × 10 ms).
    pub supervision_timeout_ms: u32,
    /// Window size in microseconds (winSize × 1250 µs).
    pub win_size_us: u32,
    /// Window offset in microseconds (winOffset × 1250 µs).
    pub win_offset_us: u32,
}

/// Low-level driver interface for BLE connection-oriented (data) channel events.
///
/// The implementation uses TIMER0 + PPI hardware shortcuts to schedule radio
/// operations with sub-microsecond accuracy, bypassing kernel scheduling jitter.
/// TIMER0 runs at 1 MHz (1 µs/tick) once `connection_configure` is called.
pub trait BleConnectionDriver<'a> {
    /// Configure the radio for a specific connection.
    ///
    /// Sets per-connection access address, CRC init, TIFS=150 µs, and
    /// initialises TIMER0 at 1 MHz.  Must be called once after receiving
    /// a CONNECT_IND and before the first `connection_event_start`.
    fn connection_configure(&self, params: &ConnectionParams) -> Result<(), ErrorCode>;

    /// Schedule a connection event and arm the radio.
    ///
    /// The radio will begin ramping up for RX automatically via PPI when
    /// TIMER0 reaches `open_time_ticks` (1 µs ticks).  `tx_buf` must
    /// contain a pre-formatted LL PDU (the ACK/empty PDU for this event);
    /// it is swapped in as the TX DMA pointer during the hardware RX→TX
    /// transition.
    fn connection_event_start(
        &self,
        channel: RadioChannel,
        tx_buf: &'static mut [u8],
        open_time_ticks: u32,
    ) -> Result<(), ErrorCode>;

    /// Return the current TIMER0 counter value (1 µs ticks).
    fn get_timer0_now(&self) -> u32;

    fn set_connection_event_client(&self, client: &'a dyn ConnectionEventClient);
}

/// Callback fired once per connection event (after both RX and TX complete).
pub trait ConnectionEventClient {
    /// Called when the full RX-then-TX connection event hardware sequence is done.
    ///
    /// * `buf` — the static RX buffer containing the master's PDU (header + payload).
    /// * `tx_buf` — the TX buffer provided to `connection_event_start`, returned for reuse.
    /// * `result` — `Ok(())` if the master's PDU had a valid CRC, `Err(FAIL)` otherwise.
    /// * `anchor_ticks` — TIMER0 tick captured by hardware when the master's access
    ///   address was detected (PPI CH26).  Zero if the master was not heard.
    fn connection_event_done(
        &self,
        buf: &'static mut [u8],
        tx_buf: &'static mut [u8],
        result: Result<(), ErrorCode>,
        anchor_ticks: u32,
    );
}

/// Callback to hand off connection parameters from the advertising capsule
/// to a connection manager when a CONNECT_IND is received.
pub trait ConnectionSetupClient {
    fn connect_ind_received(&self, params: &ConnectionParams, timer0_now: u32);
}

// Bluetooth Core Specification:Vol. 6. Part B, section 1.4.1 Advertising and Data Channel Indices
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum RadioChannel {
    DataChannel0 = 4,
    DataChannel1 = 6,
    DataChannel2 = 8,
    DataChannel3 = 10,
    DataChannel4 = 12,
    DataChannel5 = 14,
    DataChannel6 = 16,
    DataChannel7 = 18,
    DataChannel8 = 20,
    DataChannel9 = 22,
    DataChannel10 = 24,
    DataChannel11 = 28,
    DataChannel12 = 30,
    DataChannel13 = 32,
    DataChannel14 = 34,
    DataChannel15 = 36,
    DataChannel16 = 38,
    DataChannel17 = 40,
    DataChannel18 = 42,
    DataChannel19 = 44,
    DataChannel20 = 46,
    DataChannel21 = 48,
    DataChannel22 = 50,
    DataChannel23 = 52,
    DataChannel24 = 54,
    DataChannel25 = 56,
    DataChannel26 = 58,
    DataChannel27 = 60,
    DataChannel28 = 62,
    DataChannel29 = 64,
    DataChannel30 = 66,
    DataChannel31 = 68,
    DataChannel32 = 70,
    DataChannel33 = 72,
    DataChannel34 = 74,
    DataChannel35 = 76,
    DataChannel36 = 78,
    AdvertisingChannel37 = 2,
    AdvertisingChannel38 = 26,
    AdvertisingChannel39 = 80,
}

impl RadioChannel {
    /// Returns the data channel (0-36) variant from a channel index, or None if out of range.
    pub fn from_data_channel_index(index: u8) -> Option<RadioChannel> {
        match index {
            0 => Some(RadioChannel::DataChannel0),
            1 => Some(RadioChannel::DataChannel1),
            2 => Some(RadioChannel::DataChannel2),
            3 => Some(RadioChannel::DataChannel3),
            4 => Some(RadioChannel::DataChannel4),
            5 => Some(RadioChannel::DataChannel5),
            6 => Some(RadioChannel::DataChannel6),
            7 => Some(RadioChannel::DataChannel7),
            8 => Some(RadioChannel::DataChannel8),
            9 => Some(RadioChannel::DataChannel9),
            10 => Some(RadioChannel::DataChannel10),
            11 => Some(RadioChannel::DataChannel11),
            12 => Some(RadioChannel::DataChannel12),
            13 => Some(RadioChannel::DataChannel13),
            14 => Some(RadioChannel::DataChannel14),
            15 => Some(RadioChannel::DataChannel15),
            16 => Some(RadioChannel::DataChannel16),
            17 => Some(RadioChannel::DataChannel17),
            18 => Some(RadioChannel::DataChannel18),
            19 => Some(RadioChannel::DataChannel19),
            20 => Some(RadioChannel::DataChannel20),
            21 => Some(RadioChannel::DataChannel21),
            22 => Some(RadioChannel::DataChannel22),
            23 => Some(RadioChannel::DataChannel23),
            24 => Some(RadioChannel::DataChannel24),
            25 => Some(RadioChannel::DataChannel25),
            26 => Some(RadioChannel::DataChannel26),
            27 => Some(RadioChannel::DataChannel27),
            28 => Some(RadioChannel::DataChannel28),
            29 => Some(RadioChannel::DataChannel29),
            30 => Some(RadioChannel::DataChannel30),
            31 => Some(RadioChannel::DataChannel31),
            32 => Some(RadioChannel::DataChannel32),
            33 => Some(RadioChannel::DataChannel33),
            34 => Some(RadioChannel::DataChannel34),
            35 => Some(RadioChannel::DataChannel35),
            36 => Some(RadioChannel::DataChannel36),
            _ => None,
        }
    }

    pub fn get_channel_index(&self) -> u32 {
        match *self {
            RadioChannel::DataChannel0 => 0,
            RadioChannel::DataChannel1 => 1,
            RadioChannel::DataChannel2 => 2,
            RadioChannel::DataChannel3 => 3,
            RadioChannel::DataChannel4 => 4,
            RadioChannel::DataChannel5 => 5,
            RadioChannel::DataChannel6 => 6,
            RadioChannel::DataChannel7 => 7,
            RadioChannel::DataChannel8 => 8,
            RadioChannel::DataChannel9 => 9,
            RadioChannel::DataChannel10 => 10,
            RadioChannel::DataChannel11 => 11,
            RadioChannel::DataChannel12 => 12,
            RadioChannel::DataChannel13 => 13,
            RadioChannel::DataChannel14 => 14,
            RadioChannel::DataChannel15 => 15,
            RadioChannel::DataChannel16 => 16,
            RadioChannel::DataChannel17 => 17,
            RadioChannel::DataChannel18 => 18,
            RadioChannel::DataChannel19 => 19,
            RadioChannel::DataChannel20 => 20,
            RadioChannel::DataChannel21 => 21,
            RadioChannel::DataChannel22 => 22,
            RadioChannel::DataChannel23 => 23,
            RadioChannel::DataChannel24 => 24,
            RadioChannel::DataChannel25 => 25,
            RadioChannel::DataChannel26 => 26,
            RadioChannel::DataChannel27 => 27,
            RadioChannel::DataChannel28 => 28,
            RadioChannel::DataChannel29 => 29,
            RadioChannel::DataChannel30 => 30,
            RadioChannel::DataChannel31 => 31,
            RadioChannel::DataChannel32 => 32,
            RadioChannel::DataChannel33 => 33,
            RadioChannel::DataChannel34 => 34,
            RadioChannel::DataChannel35 => 35,
            RadioChannel::DataChannel36 => 36,
            RadioChannel::AdvertisingChannel37 => 37,
            RadioChannel::AdvertisingChannel38 => 38,
            RadioChannel::AdvertisingChannel39 => 39,
        }
    }
}

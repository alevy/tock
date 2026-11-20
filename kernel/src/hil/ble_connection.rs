// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Interface for Bluetooth Low Energy connections (peripheral role).
//!
//! This is a *controller* interface for chips whose 2.4 GHz radio is directly
//! programmable, and on which the BLE link layer therefore runs in software.
//! Nordic's nRF5x family is the main example.
//!
//! Many BLE-capable parts instead run the link layer on dedicated hardware and
//! expose the Bluetooth SIG's Host Controller Interface (HCI). Nothing in this
//! module maps onto such a controller: it would be told "maintain a connection"
//! rather than handed a channel, a buffer and a deadline. This interface is
//! deliberately scoped to the programmable-radio case, and is expected to sit
//! alongside an HCI-shaped interface rather than to subsume one. See
//! `doc/reference/trd-ble-connection.md` and tock/tock#4400.
//!
//! # Timing
//!
//! A BLE peripheral must answer the central's packet exactly T_IFS = 150 µs
//! after receiving it (Bluetooth Core Specification, Vol 6, Part B, §4.1.1). No
//! software scheduler can meet that deadline reliably, so the receive-to-
//! transmit turnaround must be performed by hardware. An implementation of
//! [`BleConnectionDriver`] owns that mechanism; the client supplies the packet
//! to send ahead of time and is notified once the exchange has completed.
//!
//! This is why [`connection_event_start`](BleConnectionDriver::connection_event_start)
//! takes a transmit buffer rather than offering a separate transmit call: by the
//! time software could react to the received packet, the reply has already gone
//! out.

use crate::ErrorCode;
use crate::hil::ble_advertising::RadioChannel;
use crate::hil::time::{Ticks, Time};

/// Parameters of a BLE connection, as carried in the `LLData` field of a
/// `CONNECT_IND` PDU.
///
/// See Bluetooth Core Specification, Vol 6, Part B, §2.3.3.1.
///
/// Durations are given in microseconds or milliseconds rather than in the
/// specification's 1.25 ms and 10 ms units. Those units are a wire encoding; a
/// driver should not have to know them in order to arm a timer.
#[derive(Copy, Clone, Debug)]
pub struct ConnectionParams {
    /// Access address for this connection, chosen by the initiator.
    pub access_address: u32,
    /// Initial value for the 24-bit CRC.
    pub crc_init: u32,
    /// Bitmap of usable data channels: bit `n` set means channel `n` is used.
    ///
    /// Only the low 37 bits are meaningful.
    pub channel_map: u64,
    /// Increment used by channel selection algorithm #1, in the range 5..=16.
    pub hop_increment: u8,
    /// Time between the start of consecutive connection events, in microseconds.
    pub conn_interval_us: u32,
    /// Number of connection events the peripheral may skip.
    pub slave_latency: u16,
    /// Time without a successful exchange after which the link is considered
    /// lost, in milliseconds.
    pub supervision_timeout_ms: u32,
    /// Width of the transmit window for the first connection event, in
    /// microseconds.
    pub win_size_us: u32,
    /// Offset from the end of the transmit window delay to the start of the
    /// transmit window, in microseconds.
    pub win_offset_us: u32,
}

/// Describes the link-layer PDU a client has placed in a transmit buffer.
///
/// The link layer's acknowledgement scheme (Bluetooth Core Specification, Vol
/// 6, Part B, §4.5.9) requires that a peripheral which has just been
/// acknowledged must not retransmit the same payload: with the sequence number
/// advanced, the central would read it as a new and duplicate packet. A driver
/// therefore substitutes an empty PDU when it sees an acknowledgement.
///
/// That substitution must not happen for a payload which has never been sent.
/// This type lets a client say which case applies, rather than leaving the
/// driver to guess or the client to pass a bare flag.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TxPdu {
    /// The buffer holds no payload, or a payload that has already been
    /// transmitted at least once. The driver may replace it with an empty PDU
    /// if the incoming packet acknowledges it.
    Stale,
    /// The buffer holds a payload that has not yet been transmitted. It must be
    /// sent in this connection event regardless of acknowledgement state.
    Fresh,
}

/// Radio operations needed to maintain a BLE connection.
///
/// The [`Time`] supertrait provides the clock that connection events are
/// scheduled against: a client computes an absolute time from
/// [`Time::now`] and passes it to
/// [`connection_event_start`](BleConnectionDriver::connection_event_start).
/// Requiring `Time` rather than defining a bespoke accessor keeps the clock's
/// width and frequency in the type, so the standard
/// [`Ticks`](crate::hil::time::Ticks) and
/// [`ConvertTicks`](crate::hil::time::ConvertTicks) helpers apply.
///
/// Implementations should provide microsecond resolution. The clock is not
/// required to be running before
/// [`connection_configure`](BleConnectionDriver::connection_configure) is
/// called, so `now()` is only meaningful after that point.
pub trait BleConnectionDriver<'a>: Time {
    /// Prepare the radio for a connection.
    ///
    /// Applies the per-connection access address and CRC initial value and
    /// starts the clock read by [`Time::now`]. Must be called after a
    /// `CONNECT_IND` is received and before the first connection event.
    ///
    /// # Errors
    ///
    /// - `INVAL`: `params` describes a connection the driver cannot support.
    fn connection_configure(&self, params: &ConnectionParams) -> Result<(), ErrorCode>;

    /// Schedule one connection event.
    ///
    /// The radio begins receiving on `channel` at `open_time`, and replies with
    /// the contents of `tx_buf` one inter-frame space later. `pdu` describes
    /// whether `tx_buf` holds a payload that has already been transmitted; see
    /// [`TxPdu`].
    ///
    /// On `Ok(())` the driver has taken ownership of `tx_buf` and
    /// [`ConnectionEventClient::connection_event_done`] will be called, both
    /// when the exchange succeeds and when the central is not heard. On an
    /// error `tx_buf` is returned to the caller.
    ///
    /// # Errors
    ///
    /// - `BUSY`: a connection event is already in progress.
    /// - `OFF`: [`connection_configure`](Self::connection_configure) has not
    ///   been called.
    fn connection_event_start(
        &self,
        channel: RadioChannel,
        tx_buf: &'static mut [u8],
        open_time: Self::Ticks,
        pdu: TxPdu,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Set the client notified when a connection event completes.
    fn set_connection_event_client(&self, client: &'a dyn ConnectionEventClient<Self::Ticks>);
}

/// Handles completion of a connection event.
///
/// Generic over the driver's tick type, which is how the hardware-captured
/// anchor is reported in the same time base the client schedules against.
pub trait ConnectionEventClient<T: Ticks> {
    /// Called once per connection event, after both the reception and the
    /// reply have finished.
    ///
    /// - `rx` is the central's PDU. It is borrowed from the driver for the
    ///   duration of the call; the driver keeps ownership, because the radio
    ///   receives into the same buffer every event.
    /// - `tx_buf` is the buffer passed to
    ///   [`BleConnectionDriver::connection_event_start`], returned for reuse.
    /// - `result` is `Ok(())` if a packet was received with a valid CRC, and
    ///   `Err(FAIL)` if the central was not heard or the packet was corrupt.
    /// - `anchor` is the time at which the central's access address was
    ///   detected. It is captured in hardware: a timestamp taken in software
    ///   would carry enough jitter to accumulate into a dropped link. Its value
    ///   is meaningless when `result` is an error.
    /// - `tx_acked` reports whether the central acknowledged the payload sent
    ///   in the *previous* connection event, per Bluetooth Core Specification,
    ///   Vol 6, Part B, §4.5.9. A client uses this for flow control: a payload
    ///   may be replaced only once the outstanding one has been acknowledged.
    fn connection_event_done(
        &self,
        rx: &[u8],
        tx_buf: &'static mut [u8],
        result: Result<(), ErrorCode>,
        anchor: T,
        tx_acked: bool,
    );
}

/// Receives connection parameters from whichever component accepted the
/// `CONNECT_IND`.
///
/// This exists so that an advertising capsule and a connection capsule can hand
/// a connection between them without depending on each other. Both are
/// capsules; neither belongs above the other.
pub trait ConnectionSetupClient {
    /// A `CONNECT_IND` has been received and the connection described by
    /// `params` should be established.
    ///
    /// Called from the radio's interrupt context, promptly enough that the
    /// implementation may read [`Time::now`] itself to establish the reference
    /// point for the first connection event.
    fn connect_ind_received(&self, params: &ConnectionParams);
}

/// Reports that a connection has ended, so that advertising may resume.
pub trait DisconnectClient {
    /// The connection has terminated, either because the central sent
    /// `LL_TERMINATE_IND` or because the supervision timer expired.
    fn connection_lost(&self);
}

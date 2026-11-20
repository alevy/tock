// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Bluetooth Low Energy Advertising Driver
//!
//! A system call driver that exposes the Bluetooth Low Energy advertising
//! channel. The driver generates a unique static address for each process,
//! allowing each process to act as its own device and send or scan for
//! advertisements. Timing of advertising or scanning events is handled by the
//! driver but processes can request an advertising or scanning interval.
//! Processes can also control the TX power used for their advertisements.
//!
//! Data payloads are limited to 31 bytes since the maximum advertising channel
//! protocol data unit (PDU) is 37 bytes and includes a 6-byte header.
//!
//! ### Allow system calls
//!
//! There is one ReadWrite and one ReadOnly allow buffers, both at index `0`.
//!
//! * ReadOnly: Advertising data, containing the full _payload_ (i.e. excluding
//!   the header) the process wishes to advertise.
//! * ReadWrite: Passive scanning buffer, which is populated during BLE scans
//!   with complete (i.e. including headers) advertising packets received on
//!   channels 37, 38 and 39.
//!
//! The possible return codes from the 'allow' system call indicate the following:
//!
//! * Ok(()): The buffer has successfully been filled
//! * NOMEM: No sufficient memory available
//! * INVAL: Invalid address of the buffer or other error
//! * BUSY: The driver is currently busy with other tasks
//! * ENOSUPPORT: The operation is not supported
//! * ERROR: Operation `map` on Option failed
//!
//! ### Subscribe system call
//!
//!  The `subscribe` system call supports two arguments `subscribe number' and `callback`.
//!  The `subscribe` is used to specify the specific operation, currently:
//!
//! * 0: provides a callback user-space when a device scanning for
//!   advertisements and the callback is used to invoke user-space processes.
//!
//! The possible return codes from the `allow` system call indicate the following:
//!
//! * NOMEM:    Not sufficient amount memory
//! * INVAL:    Invalid operation
//!
//! ### Command system call
//!
//! The `command` system call supports two arguments `command number` and `subcommand number`.
//! `command number` is used to specify the specific operation, currently
//! the following commands are supported:
//!
//! * 0: start advertisement
//! * 1: stop advertisement or scanning
//! * 5: start scanning
//!
//! The possible return codes from the `command` system call indicate the following:
//!
//! * Ok(()):      The command was successful
//! * BUSY:        The driver is currently busy with other tasks
//! * ENOSUPPORT:   The operation is not supported
//!
//! Usage
//! -----
//!
//! You need a device that provides the `kernel::BleAdvertisementDriver` trait along with a virtual
//! timer to perform events and not block the entire kernel
//!
//! ```rust,ignore
//! # use kernel::static_init;
//! # use capsules::virtual_alarm::VirtualMuxAlarm;
//!
//! let ble_radio = static_init!(
//! nrf5x::ble_advertising_driver::BLE<
//!     'static,
//!     nrf52::radio::Radio, VirtualMuxAlarm<'static, Rtc>
//! >,
//! nrf5x::ble_advertising_driver::BLE::new(
//!     &mut nrf52::radio::RADIO,
//!     board_kernel.create_grant(&grant_cap),
//!     &mut nrf5x::ble_advertising_driver::BUF,
//!     ble_radio_virtual_alarm));
//! nrf5x::ble_advertising_hil::BleAdvertisementDriver::set_rx_client(&nrf52::radio::RADIO,
//!                                                                   ble_radio);
//! nrf5x::ble_advertising_hil::BleAdvertisementDriver::set_tx_client(&nrf52::radio::RADIO,
//!                                                                   ble_radio);
//! ble_radio_virtual_alarm.set_client(ble_radio);
//! ```
//!
//! ### Authors
//! * Niklas Adolfsson <niklasadolfsson1@gmail.com>
//! * Fredrik Nilsson <frednils@student.chalmers.se>
//! * Date: June 22, 2017

// # Implementation
//
// Advertising virtualization works by implementing a virtual periodic timer for each process. The
// timer is configured to fire at each advertising interval, as specified by the process. When a
// timer fires, we serialize the advertising packet for that process (using the provided AdvData
// payload, generated address and PDU type) and perform one advertising event (on each of three
// channels).
//
// This means that advertising events can collide. In this case, we just defer one of the
// advertisements. Because we add a pseudo random pad to the timer interval each time (as required
// by the Bluetooth specification) multiple collisions of the same processes are highly unlikely.

use core::cell::Cell;
use core::cmp;

use kernel::debug;
use kernel::grant::{AllowRoCount, AllowRwCount, Grant, GrantKernelData, UpcallCount};
use kernel::hil::ble_advertising;
use kernel::hil::ble_advertising::RadioChannel;
use kernel::hil::ble_connection::{ConnectionParams, ConnectionSetupClient, DisconnectClient};
use kernel::hil::time::{Frequency, Ticks};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::copy_slice::CopyOrErr;
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
use capsules_core::driver;
pub const DRIVER_NUM: usize = driver::NUM::BleAdvertising as usize;

/// Ids for read-only allow buffers
mod ro_allow {
    pub const ADV_DATA: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    pub const SCAN_BUFFER: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

const PACKET_ADDR_LEN: usize = 6;
pub const PACKET_LENGTH: usize = 39;
const ADV_HEADER_TXADD_OFFSET: usize = 6;

#[derive(PartialEq, Debug, Copy, Clone)]
enum BLEState {
    Idle,
    ScanningIdle,
    Scanning(RadioChannel),
    AdvertisingIdle,
    Advertising(RadioChannel),
    /// Listening for a `CONNECT_IND` on the channel just advertised on.
    AdvertisingRx(RadioChannel),
}

#[derive(Copy, Clone)]
enum Expiration {
    Disabled,
    Enabled(u32, u32),
}

#[derive(Copy, Clone)]
struct AlarmData {
    expiration: Expiration,
}

impl AlarmData {
    fn new() -> AlarmData {
        AlarmData {
            expiration: Expiration::Disabled,
        }
    }
}

type AdvPduType = u8;

// BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 2.3.3
const ADV_IND: AdvPduType = 0b0000;
#[allow(dead_code)]
const ADV_DIRECTED_IND: AdvPduType = 0b0001;
const ADV_NONCONN_IND: AdvPduType = 0b0010;
#[allow(dead_code)]
const SCAN_REQ: AdvPduType = 0b0011;
#[allow(dead_code)]
const SCAN_RESP: AdvPduType = 0b0100;
#[allow(dead_code)]
const CONNECT_IND: AdvPduType = 0b0101;
const ADV_SCAN_IND: AdvPduType = 0b0110;

/// Process specific memory
pub struct App {
    process_status: Option<BLEState>,
    alarm_data: AlarmData,

    // Advertising meta-data
    address: [u8; PACKET_ADDR_LEN],
    pdu_type: AdvPduType,
    advertisement_interval_ms: u32,
    tx_power: u8,
    /// The state of an app-specific pseudo random number.
    ///
    /// For example, it can be used for the pseudo-random `advDelay` parameter.
    /// It should be read using the `random_number` method, which updates it as
    /// well.
    random_nonce: u32,
}

impl Default for App {
    fn default() -> App {
        App {
            alarm_data: AlarmData::new(),
            address: [0; PACKET_ADDR_LEN],
            pdu_type: ADV_NONCONN_IND,
            process_status: Some(BLEState::Idle),
            tx_power: 0,
            advertisement_interval_ms: 200,
            // Just use any non-zero starting value by default
            random_nonce: 0xdeadbeef,
        }
    }
}

impl App {
    // Bluetooth Core Specification:Vol. 6, Part B, section 1.3.2.1 Static Device Address
    //
    // A static address is a 48-bit randomly generated address and shall meet the following
    // requirements:
    // • The two most significant bits of the address shall be equal to 1
    // • At least one bit of the random part of the address shall be 0
    // • At least one bit of the random part of the address shall be 1
    //
    // Note that endianness is a potential problem here as this is suppose to be platform
    // independent therefore use 0xf0 as both byte 1 and byte 6 i.e., the two most significant bits
    // are equal to one regardless of endianness
    //
    // Byte 1            0xf0
    // Byte 2-5          random
    // Byte 6            0xf0
    // FIXME: For now use ProcessId as "randomness"
    fn generate_random_address(&mut self, processid: kernel::ProcessId) -> Result<(), ErrorCode> {
        self.address = [
            0xf0,
            (processid.id() & 0xff) as u8,
            ((processid.id() << 8) & 0xff) as u8,
            ((processid.id() << 16) & 0xff) as u8,
            ((processid.id() << 24) & 0xff) as u8,
            0xf0,
        ];
        Ok(())
    }

    fn send_advertisement<'a, B, A>(
        &mut self,
        processid: kernel::ProcessId,
        kernel_data: &GrantKernelData,
        ble: &BLE<'a, B, A>,
        channel: RadioChannel,
    ) -> Result<(), ErrorCode>
    where
        B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
        A: kernel::hil::time::Alarm<'a>,
    {
        // Ensure we have an address set before advertisement
        self.generate_random_address(processid)?;
        kernel_data
            .get_readonly_processbuffer(ro_allow::ADV_DATA)
            .and_then(|adv_data| {
                adv_data.enter(|adv_data| {
                    ble.kernel_tx
                        .take()
                        .map_or(Err(ErrorCode::FAIL), |kernel_tx| {
                            let adv_data_len =
                                cmp::min(kernel_tx.len() - PACKET_ADDR_LEN - 2, adv_data.len());
                            let adv_data_corrected =
                                adv_data.get(..adv_data_len).ok_or(ErrorCode::SIZE)?;
                            let payload_len = adv_data_corrected.len() + PACKET_ADDR_LEN;
                            {
                                let (header, payload) = kernel_tx.split_at_mut(2);
                                header[0] = self.pdu_type;
                                match self.pdu_type {
                                    ADV_IND | ADV_NONCONN_IND | ADV_SCAN_IND => {
                                        // Set TxAdd because AdvA field is going to be a "random"
                                        // address
                                        header[0] |= 1 << ADV_HEADER_TXADD_OFFSET;
                                    }
                                    _ => {}
                                }
                                // The LENGTH field is 6-bits wide, so make sure to truncate it
                                header[1] = (payload_len & 0x3f) as u8;

                                let (adva, data) = payload.split_at_mut(6);
                                adva.copy_from_slice_or_err(&self.address)?;
                                adv_data_corrected.copy_to_slice(&mut data[..adv_data_len]);
                            }
                            let total_len = cmp::min(PACKET_LENGTH, payload_len + 2);
                            ble.radio
                                .transmit_advertisement(kernel_tx, total_len, channel);
                            Ok(())
                        })
                })
            })
            .unwrap_or(Err(ErrorCode::FAIL))
    }

    // Returns a new pseudo-random number and updates the randomness state.
    //
    // Uses the [Xorshift](https://en.wikipedia.org/wiki/Xorshift) algorithm to
    // produce pseudo-random numbers. Uses the `random_nonce` field to keep
    // state.
    fn random_nonce(&mut self) -> u32 {
        let mut next_nonce = ::core::num::Wrapping(self.random_nonce);
        next_nonce ^= next_nonce << 13;
        next_nonce ^= next_nonce >> 17;
        next_nonce ^= next_nonce << 5;
        self.random_nonce = next_nonce.0;
        self.random_nonce
    }

    // Set the next alarm for this app using the period and provided start time.
    fn set_next_alarm<F: Frequency>(&mut self, now: u32) {
        let nonce = self.random_nonce() % 10;

        let period_ms = (self.advertisement_interval_ms + nonce) * F::frequency() / 1000;
        self.alarm_data.expiration = Expiration::Enabled(now, period_ms);
    }
}

/// How long to listen for a `CONNECT_IND` after advertising, in milliseconds.
const CONNECT_IND_WINDOW_MS: u32 = 3;

/// How long to wait between rounds of connectable advertising, in milliseconds.
const CONNECTABLE_ADV_INTERVAL_MS: u32 = 50;

/// Longest device name that fits in an advertisement alongside the flags.
///
/// The payload is 37 bytes: 6 of address, 3 of flags, and 2 of name header.
pub const MAX_DEVICE_NAME_LEN: usize = 26;

/// Identity a board advertises when it accepts connections.
#[derive(Copy, Clone)]
pub struct ConnectableAdvConfig {
    /// Device address, most significant byte first.
    ///
    /// Treated as a random static address, so the two most significant bits
    /// should be set.
    pub address: [u8; 6],
    /// Name reported in the advertisement, truncated to
    /// [`MAX_DEVICE_NAME_LEN`].
    pub name: &'static str,
}

/// Build an `ADV_IND` PDU for `config` into `buf`, returning its total length.
///
/// `ADV_IND` is connectable undirected advertising: it invites any central to
/// connect.
fn build_connectable_adv_pdu(buf: &mut [u8], config: &ConnectableAdvConfig) -> usize {
    // PDU type ADV_IND with TxAdd set, marking the address as random.
    buf[0] = ADV_IND | 0x40;

    // The address goes out least significant byte first.
    for (i, b) in config.address.iter().rev().enumerate() {
        buf[2 + i] = *b;
    }
    let mut n = 8;

    // Flags: LE General Discoverable, BR/EDR not supported.
    buf[n] = 2;
    buf[n + 1] = 0x01;
    buf[n + 2] = 0x06;
    n += 3;

    // Complete local name.
    let name = config.name.as_bytes();
    let name_len = name.len().min(MAX_DEVICE_NAME_LEN).min(buf.len() - n - 2);
    buf[n] = (name_len + 1) as u8;
    buf[n + 1] = 0x09;
    buf[n + 2..n + 2 + name_len].copy_from_slice(&name[..name_len]);
    n += 2 + name_len;

    // The length field covers everything after the two header bytes.
    buf[1] = (n - 2) as u8;
    n
}

/// Smallest `CONNECT_IND`: two header bytes and a 34-byte payload.
const CONNECT_IND_LEN: usize = 36;

/// Parse a `CONNECT_IND` PDU, including its two header bytes.
///
/// See Bluetooth Core Specification, Vol 6, Part B, Section 2.3.3.1. Returns
/// `None` if the PDU is too short to be one.
fn parse_connect_ind(buf: &[u8]) -> Option<ConnectionParams> {
    if buf.len() < CONNECT_IND_LEN {
        return None;
    }
    // The payload is InitA (6) and AdvA (6) followed by LLData, so LLData
    // starts 14 bytes in.
    Some(ConnectionParams {
        access_address: u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]),
        crc_init: u32::from(buf[18]) | (u32::from(buf[19]) << 8) | (u32::from(buf[20]) << 16),
        win_size_us: u32::from(buf[21]) * 1250,
        win_offset_us: u32::from(u16::from_le_bytes([buf[22], buf[23]])) * 1250,
        conn_interval_us: u32::from(u16::from_le_bytes([buf[24], buf[25]])) * 1250,
        slave_latency: u16::from_le_bytes([buf[26], buf[27]]),
        supervision_timeout_ms: u32::from(u16::from_le_bytes([buf[28], buf[29]])) * 10,
        channel_map: u64::from(buf[30])
            | (u64::from(buf[31]) << 8)
            | (u64::from(buf[32]) << 16)
            | (u64::from(buf[33]) << 24)
            | (u64::from(buf[34]) << 32),
        hop_increment: buf[35] & 0x1F,
    })
}

pub struct BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    radio: &'a B,
    busy: Cell<bool>,
    app: Grant<
        App,
        UpcallCount<1>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,
    kernel_tx: kernel::utilities::cells::TakeCell<'static, [u8]>,
    alarm: &'a A,
    sending_app: OptionalCell<kernel::ProcessId>,
    receiving_app: OptionalCell<kernel::ProcessId>,
    /// Takes over once a `CONNECT_IND` is accepted.
    ///
    /// Connectable advertising is only offered when this is set: without
    /// somewhere to hand a connection, there is no reason to listen for one,
    /// and a radio that cannot receive would be asked to.
    setup_client: OptionalCell<&'a dyn ConnectionSetupClient>,
    /// Identity advertised in kernel-driven connectable advertising.
    connectable_config: OptionalCell<ConnectableAdvConfig>,
    /// State of kernel-driven connectable advertising, which runs without any
    /// process involved.
    kernel_adv_state: Cell<Option<BLEState>>,
    /// Timer for kernel-driven connectable advertising.
    kernel_adv_expiration: Cell<Expiration>,
}

impl<'a, B, A> BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    pub fn new(
        radio: &'a B,
        container: Grant<
            App,
            UpcallCount<1>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        tx_buf: &'static mut [u8],
        alarm: &'a A,
    ) -> BLE<'a, B, A> {
        BLE {
            radio,
            busy: Cell::new(false),
            app: container,
            kernel_tx: kernel::utilities::cells::TakeCell::new(tx_buf),
            alarm,
            sending_app: OptionalCell::empty(),
            receiving_app: OptionalCell::empty(),
            setup_client: OptionalCell::empty(),
            connectable_config: OptionalCell::empty(),
            kernel_adv_state: Cell::new(None),
            kernel_adv_expiration: Cell::new(Expiration::Disabled),
        }
    }

    /// Set the capsule that drives a connection once one is accepted.
    ///
    /// Until this is called, the driver advertises but never listens for a
    /// `CONNECT_IND`, which is also what keeps the behaviour of boards without
    /// connection support unchanged.
    pub fn set_connection_client(&self, client: &'a dyn ConnectionSetupClient) {
        self.setup_client.set(client);
    }

    /// Start advertising as connectable, driven by the kernel rather than by a
    /// process.
    ///
    /// Sends `ADV_IND` on each of the three advertising channels in turn and
    /// accepts the first `CONNECT_IND` that arrives. Does nothing if the radio
    /// is busy or if no connection client has been set.
    pub fn start_connectable_advertising(&self, config: ConnectableAdvConfig) {
        self.connectable_config.set(config);
        self.resume_connectable_advertising();
    }

    /// Begin a round of connectable advertising using the stored identity.
    fn resume_connectable_advertising(&self) {
        if self.busy.get() || self.setup_client.is_none() {
            return;
        }
        let Some(config) = self.connectable_config.get() else {
            return;
        };
        self.busy.set(true);
        self.kernel_adv_state.set(Some(BLEState::Advertising(
            RadioChannel::AdvertisingChannel37,
        )));
        self.kernel_adv_expiration.set(Expiration::Disabled);
        self.kernel_tx.take().map(|buf| {
            let len = build_connectable_adv_pdu(buf, &config);
            self.radio
                .transmit_advertisement(buf, len, RadioChannel::AdvertisingChannel37);
        });
    }

    /// Transmit the stored advertisement on `channel`.
    fn send_kernel_advertisement(&self, channel: RadioChannel) {
        let Some(config) = self.connectable_config.get() else {
            return;
        };
        self.kernel_adv_state
            .set(Some(BLEState::Advertising(channel)));
        self.kernel_tx.take().map(|buf| {
            let len = build_connectable_adv_pdu(buf, &config);
            self.radio.transmit_advertisement(buf, len, channel);
        });
    }

    // Determines which app timer will expire next and sets the underlying alarm
    // to it.
    //
    // This method iterates through all grants so it should be used somewhat
    // sparingly. Moreover, it should _not_ be called from within a grant,
    // since any open grant will not be iterated over and the wrong timer will
    // likely be chosen.
    fn reset_active_alarm(&self) {
        let now = self.alarm.now();
        let mut next_ref = u32::MAX;
        let mut next_dt = u32::MAX;
        let mut next_dist = u32::MAX;

        if let Expiration::Enabled(reference, dt) = self.kernel_adv_expiration.get() {
            let exp = reference.wrapping_add(dt);
            let t_dist = exp.wrapping_sub(now.into_u32());
            if next_dist > t_dist {
                next_ref = reference;
                next_dt = dt;
                next_dist = t_dist;
            }
        }

        for app in self.app.iter() {
            app.enter(|app, _| match app.alarm_data.expiration {
                Expiration::Enabled(reference, dt) => {
                    let exp = reference.wrapping_add(dt);
                    let t_dist = exp.wrapping_sub(now.into_u32());
                    if next_dist > t_dist {
                        next_ref = reference;
                        next_dt = dt;
                        next_dist = t_dist;
                    }
                }
                Expiration::Disabled => {}
            });
        }
        if next_ref != u32::MAX {
            self.alarm
                .set_alarm(A::Ticks::from(next_ref), A::Ticks::from(next_dt));
        }
    }
}

// A connection ending frees the radio, so go back to advertising and let the
// device be found and reconnected without a reset.
impl<'a, B, A> DisconnectClient for BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    fn connection_lost(&self) {
        self.busy.set(false);
        self.resume_connectable_advertising();
    }
}

// Timer alarm
impl<'a, B, A> kernel::hil::time::AlarmClient for BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    // When an alarm is fired, we find which apps have expired timers. Expired
    // timers indicate a desire to perform some operation (e.g. start an
    // advertising or scanning event). We know which operation based on the
    // current app's state.
    //
    // In case of collision---if there is already an event happening---we'll
    // just delay the operation for next time and hope for the best. Since some
    // randomness is added for each period in an app's timer, collisions should
    // be rare in practice.
    //
    // TODO: perhaps break ties more fairly by prioritizing apps that have least
    // recently performed an operation.
    fn alarm(&self) {
        let now = self.alarm.now();

        if let Expiration::Enabled(reference, dt) = self.kernel_adv_expiration.get() {
            let exp = A::Ticks::from(reference.wrapping_add(dt));
            let t0 = A::Ticks::from(reference);
            if !now.within_range(t0, exp) {
                self.kernel_adv_expiration.set(Expiration::Disabled);
                match self.kernel_adv_state.get() {
                    // The listening window closed without a `CONNECT_IND`, so
                    // advertise on the next channel.
                    Some(BLEState::AdvertisingRx(channel)) => {
                        self.radio.stop_receive();
                        match channel {
                            RadioChannel::AdvertisingChannel37 => {
                                self.send_kernel_advertisement(RadioChannel::AdvertisingChannel38);
                            }
                            RadioChannel::AdvertisingChannel38 => {
                                self.send_kernel_advertisement(RadioChannel::AdvertisingChannel39);
                            }
                            // All three channels done; pause before the next round.
                            _ => {
                                let delay =
                                    CONNECTABLE_ADV_INTERVAL_MS * A::Frequency::frequency() / 1000;
                                self.kernel_adv_expiration
                                    .set(Expiration::Enabled(now.into_u32(), delay));
                                self.kernel_adv_state.set(Some(BLEState::AdvertisingIdle));
                            }
                        }
                    }
                    // The pause is over; start the next round.
                    Some(BLEState::AdvertisingIdle) => {
                        self.send_kernel_advertisement(RadioChannel::AdvertisingChannel37);
                    }
                    _ => {}
                }
            }
        }

        self.app.each(|processid, app, kernel_data| {
            if let Expiration::Enabled(reference, dt) = app.alarm_data.expiration {
                let exp = A::Ticks::from(reference.wrapping_add(dt));
                let t0 = A::Ticks::from(reference);
                let expired = !now.within_range(t0, exp);
                if expired {
                    if self.busy.get() {
                        // The radio is currently busy, so we won't be able to start the
                        // operation at the appropriate time. Instead, reschedule the
                        // operation for later. This is _kind_ of simulating actual
                        // on-air interference. 3 seems like a small number of ticks.
                        debug!("BLE: operation delayed for app {:?}", processid);
                        app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                        return;
                    }

                    app.alarm_data.expiration = Expiration::Disabled;

                    match app.process_status {
                        // The listening window closed without a `CONNECT_IND`;
                        // carry on to the next advertising channel.
                        Some(BLEState::AdvertisingRx(channel)) => {
                            self.radio.stop_receive();
                            self.receiving_app.take();
                            match channel {
                                RadioChannel::AdvertisingChannel37
                                | RadioChannel::AdvertisingChannel38 => {
                                    let next = if channel == RadioChannel::AdvertisingChannel37 {
                                        RadioChannel::AdvertisingChannel38
                                    } else {
                                        RadioChannel::AdvertisingChannel39
                                    };
                                    app.process_status = Some(BLEState::Advertising(next));
                                    self.sending_app.set(processid);
                                    let _ = self.radio.set_tx_power(app.tx_power);
                                    let _ =
                                        app.send_advertisement(processid, kernel_data, self, next);
                                }
                                _ => {
                                    self.busy.set(false);
                                    app.process_status = Some(BLEState::AdvertisingIdle);
                                    app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                                }
                            }
                        }
                        Some(BLEState::AdvertisingIdle) => {
                            self.busy.set(true);
                            app.process_status =
                                Some(BLEState::Advertising(RadioChannel::AdvertisingChannel37));
                            self.sending_app.set(processid);
                            let _ = self.radio.set_tx_power(app.tx_power);
                            let _ = app.send_advertisement(
                                processid,
                                kernel_data,
                                self,
                                RadioChannel::AdvertisingChannel37,
                            );
                        }
                        Some(BLEState::ScanningIdle) => {
                            self.busy.set(true);
                            app.process_status =
                                Some(BLEState::Scanning(RadioChannel::AdvertisingChannel37));
                            self.receiving_app.set(processid);
                            let _ = self.radio.set_tx_power(app.tx_power);
                            self.radio
                                .receive_advertisement(RadioChannel::AdvertisingChannel37);
                        }
                        _ => debug!(
                            "app: {:?} \t invalid state {:?}",
                            processid, app.process_status
                        ),
                    }
                }
            }
        });
        self.reset_active_alarm();
    }
}

// Callback from the radio once a RX event occur
impl<'a, B, A> ble_advertising::RxClient for BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    fn receive_event(&self, buf: &'static mut [u8], len: u8, result: Result<(), ErrorCode>) {
        // A central answering our advertisement with a `CONNECT_IND` ends
        // advertising and starts a connection.
        if result.is_ok()
            && (len as usize) >= CONNECT_IND_LEN
            && (buf[0] & 0x0F) == CONNECT_IND
            && self.setup_client.is_some()
        {
            if let Some(params) = parse_connect_ind(&buf[..len as usize]) {
                self.kernel_adv_state.set(None);
                self.kernel_adv_expiration.set(Expiration::Disabled);
                self.receiving_app.map(|processid| {
                    let _ = self.app.enter(processid, |app, _| {
                        app.process_status = Some(BLEState::Idle);
                        app.alarm_data.expiration = Expiration::Disabled;
                    });
                });
                self.receiving_app.take();
                self.busy.set(false);
                self.setup_client
                    .map(|client| client.connect_ind_received(&params));
                return;
            }
        }

        // Anything else arriving in a listening window is most likely a
        // `SCAN_REQ`: a central doing an active scan sends one after seeing an
        // advertisement, and will not report the device until it gets a
        // response. We cannot answer one in software within the inter-frame
        // space, but we can at least stay on the channel, so the central does
        // not see the device vanish and can still choose to connect. Only the
        // timer moves us on to the next channel.
        if self.receiving_app.is_none() {
            if let Some(BLEState::AdvertisingRx(channel)) = self.kernel_adv_state.get() {
                self.radio.receive_advertisement(channel);
                return;
            }
        }

        self.receiving_app.map(|processid| {
            let _ = self.app.enter(processid, |app, kernel_data| {
                // Validate the received data, because ordinary BLE packets can be bigger than 39
                // bytes. Thus, we need to check for that!
                // Moreover, we use the packet header to find size but the radio reads maximum
                // 39 bytes.
                // Therefore, we ignore payloads with a header size bigger than 39 because the
                // channels 37, 38 and 39 should only be used for advertisements!
                // Packets that are bigger than 39 bytes are likely `Channel PDUs` which should
                // only be sent on the other 37 RadioChannel channels.

                if len <= PACKET_LENGTH as u8 && result == Ok(()) {
                    // write to buffer in userland

                    let success = kernel_data
                        .get_readwrite_processbuffer(rw_allow::SCAN_BUFFER)
                        .and_then(|scan_buffer| {
                            scan_buffer.mut_enter(|userland| {
                                userland[0..len as usize]
                                    .copy_from_slice_or_err(&buf[0..len as usize])
                                    .is_ok()
                            })
                        })
                        .unwrap_or(false);

                    if success {
                        let _ = kernel_data.schedule_upcall(
                            0,
                            (kernel::errorcode::into_statuscode(result), len as usize, 0),
                        );
                    }
                }

                match app.process_status {
                    Some(BLEState::Scanning(RadioChannel::AdvertisingChannel37)) => {
                        app.process_status =
                            Some(BLEState::Scanning(RadioChannel::AdvertisingChannel38));
                        self.receiving_app.set(processid);
                        let _ = self.radio.set_tx_power(app.tx_power);
                        self.radio
                            .receive_advertisement(RadioChannel::AdvertisingChannel38);
                    }
                    Some(BLEState::Scanning(RadioChannel::AdvertisingChannel38)) => {
                        app.process_status =
                            Some(BLEState::Scanning(RadioChannel::AdvertisingChannel39));
                        self.receiving_app.set(processid);
                        self.radio
                            .receive_advertisement(RadioChannel::AdvertisingChannel39);
                    }
                    Some(BLEState::Scanning(RadioChannel::AdvertisingChannel39)) => {
                        self.busy.set(false);
                        app.process_status = Some(BLEState::ScanningIdle);
                        app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                    }
                    // Something other than a `CONNECT_IND` arrived while
                    // listening after an advertisement; move on to the next
                    // channel rather than waiting out the window.
                    Some(BLEState::AdvertisingRx(channel)) => {
                        app.alarm_data.expiration = Expiration::Disabled;
                        self.receiving_app.take();
                        match channel {
                            RadioChannel::AdvertisingChannel37
                            | RadioChannel::AdvertisingChannel38 => {
                                let next = if channel == RadioChannel::AdvertisingChannel37 {
                                    RadioChannel::AdvertisingChannel38
                                } else {
                                    RadioChannel::AdvertisingChannel39
                                };
                                app.process_status = Some(BLEState::Advertising(next));
                                self.sending_app.set(processid);
                                let _ = self.radio.set_tx_power(app.tx_power);
                                let _ = app.send_advertisement(processid, kernel_data, self, next);
                            }
                            _ => {
                                self.busy.set(false);
                                app.process_status = Some(BLEState::AdvertisingIdle);
                                app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                            }
                        }
                    }
                    // Invalid state => don't care
                    _ => (),
                }
            });
            self.reset_active_alarm();
        });
    }
}

// Callback from the radio once a TX event occur
impl<'a, B, A> ble_advertising::TxClient for BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    // The Result<(), ErrorCode> indicates valid CRC or not, not used yet but could be used for
    // re-transmissions for invalid CRCs
    fn transmit_event(&self, buf: &'static mut [u8], _crc_ok: Result<(), ErrorCode>) {
        self.kernel_tx.replace(buf);

        // Kernel-driven connectable advertising: having just advertised, listen
        // on the same channel for a central's reply.
        if self.sending_app.is_none() {
            if let Some(BLEState::Advertising(channel)) = self.kernel_adv_state.get() {
                let window = CONNECT_IND_WINDOW_MS * A::Frequency::frequency() / 1000;
                self.kernel_adv_expiration
                    .set(Expiration::Enabled(self.alarm.now().into_u32(), window));
                self.kernel_adv_state
                    .set(Some(BLEState::AdvertisingRx(channel)));
                self.radio.receive_advertisement(channel);
                self.reset_active_alarm();
                return;
            }
        }

        self.sending_app.map(|processid| {
            let _ = self.app.enter(processid, |app, kernel_data| {
                // `ADV_IND` invites a connection, so when this driver can
                // actually hand one off, listen for a `CONNECT_IND` before
                // moving to the next channel. Without a connection client this
                // is skipped entirely, which keeps behaviour identical for
                // boards that only advertise -- including those whose radio
                // cannot receive at all.
                if app.pdu_type == ADV_IND && self.setup_client.is_some() {
                    if let Some(BLEState::Advertising(channel)) = app.process_status {
                        let window = CONNECT_IND_WINDOW_MS * A::Frequency::frequency() / 1000;
                        app.alarm_data.expiration =
                            Expiration::Enabled(self.alarm.now().into_u32(), window);
                        app.process_status = Some(BLEState::AdvertisingRx(channel));
                        self.sending_app.take();
                        self.receiving_app.set(processid);
                        self.radio.receive_advertisement(channel);
                        return;
                    }
                }

                match app.process_status {
                    Some(BLEState::Advertising(RadioChannel::AdvertisingChannel37)) => {
                        app.process_status =
                            Some(BLEState::Advertising(RadioChannel::AdvertisingChannel38));
                        self.sending_app.set(processid);
                        let _ = self.radio.set_tx_power(app.tx_power);
                        let _ = app.send_advertisement(
                            processid,
                            kernel_data,
                            self,
                            RadioChannel::AdvertisingChannel38,
                        );
                    }

                    Some(BLEState::Advertising(RadioChannel::AdvertisingChannel38)) => {
                        app.process_status =
                            Some(BLEState::Advertising(RadioChannel::AdvertisingChannel39));
                        self.sending_app.set(processid);
                        let _ = app.send_advertisement(
                            processid,
                            kernel_data,
                            self,
                            RadioChannel::AdvertisingChannel39,
                        );
                    }

                    Some(BLEState::Advertising(RadioChannel::AdvertisingChannel39)) => {
                        self.busy.set(false);
                        app.process_status = Some(BLEState::AdvertisingIdle);
                        app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                    }
                    // Invalid state => don't care
                    _ => (),
                }
            });
            self.reset_active_alarm();
        });
    }
}

// System Call implementation
impl<'a, B, A> SyscallDriver for BLE<'a, B, A>
where
    B: ble_advertising::BleAdvertisementDriver<'a> + ble_advertising::BleConfig,
    A: kernel::hil::time::Alarm<'a>,
{
    fn command(
        &self,
        command_num: usize,
        data: usize,
        interval: usize,
        processid: kernel::ProcessId,
    ) -> CommandReturn {
        match command_num {
            // Start periodic advertisements
            0 => {
                self.app
                    .enter(processid, |app, _| {
                        if let Some(BLEState::Idle) = app.process_status {
                            let pdu_type = data as AdvPduType;
                            match pdu_type {
                                ADV_IND | ADV_NONCONN_IND | ADV_SCAN_IND => {
                                    app.pdu_type = pdu_type;
                                    app.process_status = Some(BLEState::AdvertisingIdle);
                                    app.random_nonce = self.alarm.now().into_u32();
                                    app.advertisement_interval_ms = cmp::max(20, interval as u32);
                                    app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                                    Ok(())
                                }
                                _ => Err(ErrorCode::INVAL),
                            }
                        } else {
                            Err(ErrorCode::BUSY)
                        }
                    })
                    .map_or_else(
                        |err| CommandReturn::failure(err.into()),
                        |res| match res {
                            Ok(()) => {
                                // must be called outside closure passed to grant region!
                                self.reset_active_alarm();
                                CommandReturn::success()
                            }
                            Err(e) => CommandReturn::failure(e),
                        },
                    )
            }

            // Stop periodic advertisements or passive scanning
            1 => self
                .app
                .enter(processid, |app, _| match app.process_status {
                    Some(BLEState::AdvertisingIdle) | Some(BLEState::ScanningIdle) => {
                        app.process_status = Some(BLEState::Idle);
                        CommandReturn::success()
                    }
                    _ => CommandReturn::failure(ErrorCode::BUSY),
                })
                .unwrap_or_else(|err| err.into()),

            // Configure transmitted power
            // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part A], section 3
            //
            // Minimum Output Power:    0.01 mW (-20 dBm)
            // Maximum Output Power:    10 mW (+10 dBm)
            //
            // data - Transmitting power in dBm
            2 => {
                self.app
                    .enter(processid, |app, _| {
                        if app.process_status != Some(BLEState::ScanningIdle)
                            && app.process_status != Some(BLEState::AdvertisingIdle)
                        {
                            match data as u8 {
                                tx_power @ 0..=10 | tx_power @ 0xec..=0xff => {
                                    // query the underlying chip if the power level is supported
                                    let status = self.radio.set_tx_power(tx_power);
                                    if let Ok(()) = status {
                                        app.tx_power = tx_power;
                                    }
                                    status.into()
                                }
                                _ => CommandReturn::failure(ErrorCode::INVAL),
                            }
                        } else {
                            CommandReturn::failure(ErrorCode::BUSY)
                        }
                    })
                    .unwrap_or_else(|err| err.into())
            }

            // Passive scanning mode
            5 => {
                self.app
                    .enter(processid, |app, _| {
                        if let Some(BLEState::Idle) = app.process_status {
                            app.process_status = Some(BLEState::ScanningIdle);
                            app.set_next_alarm::<A::Frequency>(self.alarm.now().into_u32());
                            Ok(())
                        } else {
                            Err(ErrorCode::BUSY)
                        }
                    })
                    .map_or_else(
                        |err| err.into(),
                        |res| match res {
                            Ok(()) => {
                                // must be called outside closure passed to grant region!
                                self.reset_active_alarm();
                                CommandReturn::success()
                            }
                            Err(e) => CommandReturn::failure(e),
                        },
                    )
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.app.enter(processid, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `CONNECT_IND` with recognisable values in every LLData field.
    fn connect_ind() -> [u8; CONNECT_IND_LEN] {
        let mut pdu = [0u8; CONNECT_IND_LEN];
        pdu[0] = CONNECT_IND;
        pdu[1] = 34;
        // InitA occupies bytes 2..8 and AdvA bytes 8..14; LLData follows.
        pdu[14..18].copy_from_slice(&0xAF9A_B4C6u32.to_le_bytes()); // access address
        pdu[18] = 0x11; // CRCInit, little endian
        pdu[19] = 0x22;
        pdu[20] = 0x33;
        pdu[21] = 3; // WinSize, units of 1.25 ms
        pdu[22..24].copy_from_slice(&5u16.to_le_bytes()); // WinOffset
        pdu[24..26].copy_from_slice(&24u16.to_le_bytes()); // Interval
        pdu[26..28].copy_from_slice(&4u16.to_le_bytes()); // Latency
        pdu[28..30].copy_from_slice(&500u16.to_le_bytes()); // Timeout, units of 10 ms
        pdu[30..35].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]); // all 37 channels
        pdu[35] = 0xE5; // SCA in the top three bits, hop increment in the low five
        pdu
    }

    #[test]
    fn connect_ind_fields_are_decoded() {
        let params = parse_connect_ind(&connect_ind()).expect("should parse");
        assert_eq!(params.access_address, 0xAF9A_B4C6);
        assert_eq!(params.crc_init, 0x0033_2211);
        assert_eq!(params.win_size_us, 3 * 1250);
        assert_eq!(params.win_offset_us, 5 * 1250);
        assert_eq!(params.conn_interval_us, 24 * 1250);
        assert_eq!(params.slave_latency, 4);
        assert_eq!(params.supervision_timeout_ms, 5000);
        assert_eq!(params.channel_map, (1u64 << 37) - 1);
        // Only the low five bits are the hop increment: 0xE5 & 0x1F == 5.
        assert_eq!(params.hop_increment, 5);
    }

    #[test]
    fn short_connect_ind_is_rejected() {
        let pdu = connect_ind();
        assert!(parse_connect_ind(&pdu[..CONNECT_IND_LEN - 1]).is_none());
        assert!(parse_connect_ind(&[]).is_none());
    }

    #[test]
    fn advertisement_is_well_formed() {
        let config = ConnectableAdvConfig {
            address: [0xC0, 0xFF, 0xEE, 0xBE, 0xEF, 0x42],
            name: "Tock",
        };
        let mut buf = [0u8; PACKET_LENGTH];
        let len = build_connectable_adv_pdu(&mut buf, &config);

        // Connectable undirected advertising with a random address.
        assert_eq!(buf[0] & 0x0F, ADV_IND);
        assert_eq!(buf[0] & 0x40, 0x40);
        // The length field covers everything but the two header bytes.
        assert_eq!(buf[1] as usize, len - 2);
        // The address goes out least significant byte first.
        assert_eq!(&buf[2..8], &[0x42, 0xEF, 0xBE, 0xEE, 0xFF, 0xC0]);
        // Flags, then the complete local name.
        assert_eq!(&buf[8..11], &[2, 0x01, 0x06]);
        assert_eq!(buf[11] as usize, "Tock".len() + 1);
        assert_eq!(buf[12], 0x09);
        assert_eq!(&buf[13..17], b"Tock");
        assert_eq!(len, 17);
    }

    #[test]
    fn long_name_is_truncated_to_fit() {
        let config = ConnectableAdvConfig {
            address: [0xC0, 0, 0, 0, 0, 1],
            name: "a name that is far too long to fit in an advertisement",
        };
        let mut buf = [0u8; PACKET_LENGTH];
        let len = build_connectable_adv_pdu(&mut buf, &config);
        assert!(len <= PACKET_LENGTH);
        assert_eq!(buf[11] as usize, MAX_DEVICE_NAME_LEN + 1);
    }
}

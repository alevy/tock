// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Radio driver, Bluetooth Low Energy, NRF52
//!
//! The generic radio configuration i.e., not specific to Bluetooth are
//! functions and similar which do not start with `ble`. Moreover, Bluetooth
//! Low Energy specific radio configuration starts with `ble`
//!
//! For more readability the Bluetooth specific configuration may be moved to
//! separate trait
//!
//! ### Author
//! * Niklas Adolfsson <niklasadolfsson1@gmail.com>
//! * Date: July 18, 2017
//!
//! ### Packet Configuration
//! ```txt
//! +----------+------+--------+----+--------+----+---------+-----+
//! | Preamble | Base | Prefix | S0 | Length | S1 | Payload | CRC |
//! +----------+------+--------+----+--------+----+---------+-----+
//! ```
//!
//! * Preamble - 1 byte
//!
//! * Base and prefix forms together the access address
//!
//! * S0, an optional parameter that is configured to indicate how many bytes of
//!   the payload is the PDU Type. Configured as 1 byte!
//!
//! * Length, an optional parameter that is configured to indicate how many bits
//!   of the payload is the length field. Configured as 8 bits!
//!
//! * S1, Not used
//!
//! * Payload - 2 to 255 bytes
//!
//! * CRC - 3 bytes

use crate::ppi::{Channel, Ppi, PpiRegisters};
use core::cell::Cell;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;
use kernel::ErrorCode;
use kernel::hil::ble_advertising;
use kernel::hil::ble_advertising::RadioChannel;
use kernel::hil::ble_connection::{
    BleConnectionDriver, ConnectionEventClient, ConnectionParams, TxBuffers,
};
use kernel::hil::time::{Freq1MHz, Ticks, Ticks32, Time};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::TakeCell;
use kernel::utilities::cells::{MapCell, OptionalCell};
use nrf5x::constants::TxPower;
use nrf5x::timer::{BitmodeValue, CaptureCompare, Timer, TimerRegisters};
use tock_registers_v0::interfaces::{Readable, Writeable};
use tock_registers_v0::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers_v0::{register_bitfields, register_structs};

register_structs! {
    pub RadioRegisters {
        /// Enable Radio in TX mode
        (0x000 => task_txen: WriteOnly<u32, Task::Register>),
        /// Enable Radio in RX mode
        (0x004 => task_rxen: WriteOnly<u32, Task::Register>),
        /// Start Radio
        (0x008 => task_start: WriteOnly<u32, Task::Register>),
        /// Stop Radio
        (0x00C => task_stop: WriteOnly<u32, Task::Register>),
        /// Disable Radio
        (0x010 => task_disable: WriteOnly<u32, Task::Register>),
        /// Start the RSSI and take one single sample of the receive signal strength
        (0x014 => task_rssistart: WriteOnly<u32, Task::Register>),
        /// Stop the RSSI measurement
        (0x018 => task_rssistop: WriteOnly<u32, Task::Register>),
        /// Start the bit counter
        (0x01C => task_bcstart: WriteOnly<u32, Task::Register>),
        /// Stop the bit counter
        (0x020 => task_bcstop: WriteOnly<u32, Task::Register>),
        (0x024 => _reserved1),
        /// Radio has ramped up and is ready to be started
        (0x100 => event_ready: ReadWrite<u32, Event::Register>),
        /// Address sent or received
        (0x104 => event_address: ReadWrite<u32, Event::Register>),
        /// Packet payload sent or received
        (0x108 => event_payload: ReadWrite<u32, Event::Register>),
        /// Packet sent or received
        (0x10C => event_end: ReadWrite<u32, Event::Register>),
        /// Radio has been disabled
        (0x110 => event_disabled: ReadWrite<u32, Event::Register>),
        /// A device address match occurred on the last received packet
        (0x114 => event_devmatch: ReadWrite<u32>),
        /// No device address match occurred on the last received packet
        (0x118 => event_devmiss: ReadWrite<u32, Event::Register>),
        /// Sampling of receive signal strength complete
        (0x11C => event_rssiend: ReadWrite<u32, Event::Register>),
        (0x120 => _reserved2),
        /// Bit counter reached bit count value
        (0x128 => event_bcmatch: ReadWrite<u32, Event::Register>),
        (0x12C => _reserved3),
        /// Packet received with CRC ok
        (0x130 => event_crcok: ReadWrite<u32, Event::Register>),
        /// Packet received with CRC error
        (0x134 => crcerror: ReadWrite<u32, Event::Register>),
        (0x138 => _reserved4),
        /// Shortcut register
        (0x200 => shorts: ReadWrite<u32, Shortcut::Register>),
        (0x204 => _reserved5),
        /// Enable interrupt
        (0x304 => intenset: ReadWrite<u32, Interrupt::Register>),
        /// Disable interrupt
        (0x308 => intenclr: ReadWrite<u32, Interrupt::Register>),
        (0x30C => _reserved6),
        /// CRC status
        (0x400 => crcstatus: ReadOnly<u32, Event::Register>),
        (0x404 => _reserved7),
        /// Received address
        (0x408 => rxmatch: ReadOnly<u32, ReceiveMatch::Register>),
        /// CRC field of previously received packet
        (0x40C => rxcrc: ReadOnly<u32, ReceiveCrc::Register>),
        /// Device address match index
        (0x410 => dai: ReadOnly<u32, DeviceAddressIndex::Register>),
        (0x414 => _reserved8),
        /// Packet pointer
        (0x504 => packetptr: ReadWrite<u32, PacketPointer::Register>),
        /// Frequency
        (0x508 => frequency: ReadWrite<u32, Frequency::Register>),
        /// Output power
        (0x50C => txpower: ReadWrite<u32, TransmitPower::Register>),
        /// Data rate and modulation
        (0x510 => mode: ReadWrite<u32, Mode::Register>),
        /// Packet configuration register 0
        (0x514 => pcnf0: ReadWrite<u32, PacketConfiguration0::Register>),
        /// Packet configuration register 1
        (0x518 => pcnf1: ReadWrite<u32, PacketConfiguration1::Register>),
        /// Base address 0
        (0x51C => base0: ReadWrite<u32, BaseAddress::Register>),
        /// Base address 1
        (0x520 => base1: ReadWrite<u32, BaseAddress::Register>),
        /// Prefix bytes for logical addresses 0-3
        (0x524 => prefix0: ReadWrite<u32, Prefix0::Register>),
        /// Prefix bytes for logical addresses 4-7
        (0x528 => prefix1: ReadWrite<u32, Prefix1::Register>),
        /// Transmit address select
        (0x52C => txaddress: ReadWrite<u32, TransmitAddress::Register>),
        /// Receive address select
        (0x530 => rxaddresses: ReadWrite<u32, ReceiveAddresses::Register>),
        /// CRC configuration
        (0x534 => crccnf: ReadWrite<u32, CrcConfiguration::Register>),
        /// CRC polynomial
        (0x538 => crcpoly: ReadWrite<u32, CrcPolynomial::Register>),
        /// CRC initial value
        (0x53C => crcinit: ReadWrite<u32, CrcInitialValue::Register>),
        (0x540 => _reserved9),
        /// Interframe spacing in microseconds
        (0x544 => tifs: ReadWrite<u32, InterFrameSpacing::Register>),
        /// RSSI sample
        (0x548 => rssisample: ReadWrite<u32, RssiSample::Register>),
        (0x54C => _reserved10),
        /// Current radio state
        (0x550 => state: ReadOnly<u32, State::Register>),
        /// Data whitening initial value
        (0x554 => datawhiteiv: ReadWrite<u32, DataWhiteIv::Register>),
        (0x558 => _reserved11),
        /// Bit counter compare
        (0x560 => bcc: ReadWrite<u32, BitCounterCompare::Register>),
        (0x564 => _reserved12),
        /// Device address base segments
        (0x600 => dab: [ReadWrite<u32, DeviceAddressBase::Register>; 8]),
        /// Device address prefix
        (0x620 => dap: [ReadWrite<u32, DeviceAddressPrefix::Register>; 8]),
        /// Device address match configuration
        (0x640 => dacnf: ReadWrite<u32, DeviceAddressMatch::Register>),
        (0x644 => _reserved13),
        /// Radio mode configuration register
        (0x650 => modecnf0: ReadWrite<u32, RadioModeConfig::Register>),
        (0x654 => _reserved14),
        /// Peripheral power control
        (0xFFC => power: ReadWrite<u32, Task::Register>),
        (0x1000 => @END),
    }
}

register_bitfields! [u32,
    /// Task register
    Task [
        /// Enable task
        ENABLE OFFSET(0) NUMBITS(1)
    ],
    /// Event register
    Event [
        /// Ready event
        READY OFFSET(0) NUMBITS(1)
    ],
    /// Shortcut register
    Shortcut [
        /// Shortcut between READY event and START task
        READY_START OFFSET(0) NUMBITS(1),
        /// Shortcut between END event and DISABLE task
        END_DISABLE OFFSET(1) NUMBITS(1),
        /// Shortcut between DISABLED event and TXEN task
        DISABLED_TXEN OFFSET(2) NUMBITS(1),
        /// Shortcut between DISABLED event and RXEN task
        DISABLED_RXEN OFFSET(3) NUMBITS(1),
        /// Shortcut between ADDRESS event and RSSISTART task
        ADDRESS_RSSISTART OFFSET(4) NUMBITS(1),
        /// Shortcut between END event and START task
        END_START OFFSET(5) NUMBITS(1),
        /// Shortcut between ADDRESS event and BCSTART task
        ADDRESS_BCSTART OFFSET(6) NUMBITS(1),
        /// Shortcut between DISABLED event and RSSISTOP task
        DISABLED_RSSISTOP OFFSET(8) NUMBITS(1)
    ],
    /// Interrupt register
    Interrupt [
        /// READY event
        READY OFFSET(0) NUMBITS(1),
        /// ADDRESS event
        ADDRESS OFFSET(1) NUMBITS(1),
        /// PAYLOAD event
        PAYLOAD OFFSET(2) NUMBITS(1),
        /// END event
        END OFFSET(3) NUMBITS(1),
        /// DISABLED event
        DISABLED OFFSET(4) NUMBITS(1),
        /// DEVMATCH event
        DEVMATCH OFFSET(5) NUMBITS(1),
        /// DEVMISS event
        DEVMISS OFFSET(6) NUMBITS(1),
        /// RSSIEND event
        RSSIEND OFFSET(7) NUMBITS(1),
        /// BCMATCH event
        BCMATCH OFFSET(10) NUMBITS(1),
        /// CRCOK event
        CRCOK OFFSET(12) NUMBITS(1),
        /// CRCERROR event
        CRCERROR OFFSET(13) NUMBITS(1)
    ],
    /// Receive match register
    ReceiveMatch [
        /// Logical address of which previous packet was received
        MATCH OFFSET(0) NUMBITS(3)
    ],
    /// Received CRC register
    ReceiveCrc [
        /// CRC field of previously received packet
        CRC OFFSET(0) NUMBITS(24)
    ],
    /// Device address match index register
    DeviceAddressIndex [
        /// Device address match index
        /// Index (n) of device address, see DAB\[n\] and DAP\[n\], that got an
        /// address match
        INDEX OFFSET(0) NUMBITS(3)
    ],
    /// Packet pointer register
    PacketPointer [
        /// Packet address to be used for the next transmission or reception. When transmitting, the packet pointed to by this
        /// address will be transmitted and when receiving, the received packet will be written to this address. This address is a byte
        /// aligned ram address.
        POINTER OFFSET(0) NUMBITS(32)
    ],
    /// Frequency register
    Frequency [
        /// Radio channel frequency
        /// Frequency = 2400 + FREQUENCY (MHz)
        FREQUENCY OFFSET(0) NUMBITS(7) [],
        /// Channel map selection.
        /// Channel map between 2400 MHZ .. 2500 MHZ
        MAP OFFSET(8) NUMBITS(1) [
            DEFAULT = 0,
            LOW = 1
        ]
    ],
    /// Transmitting power register
    TransmitPower [
        /// Radio output power
        POWER OFFSET(0) NUMBITS(8) [
            POS4DBM = 4,
            POS3DBM = 3,
            ODBM = 0,
            NEG4DBM = 0xfc,
            NEG8DBM = 0xf8,
            NEG12DBM = 0xf4,
            NEG16DBM = 0xf0,
            NEG20DBM = 0xec,
            NEG40DBM = 0xd8
        ]
    ],
    /// Data rate and modulation register
    Mode [
        /// Radio data rate and modulation setting.
        /// The radio supports Frequency-shift Keying (FSK) modulation
        MODE OFFSET(0) NUMBITS(4) [
            NRF_1MBIT = 0,
            NRF_2MBIT = 1,
            NRF_250KBIT = 2,
            BLE_1MBIT = 3
        ]
    ],
    /// Packet configuration register 0
    PacketConfiguration0 [
        /// Length on air of LENGTH field in number of bits
        LFLEN OFFSET(0) NUMBITS(4) [],
        /// Length on air of S0 field in number of bytes
        S0LEN OFFSET(8) NUMBITS(1) [],
        /// Length on air of S1 field in number of bits.
        S1LEN OFFSET(16) NUMBITS(4) [],
        /// Include or exclude S1 field in RAM
        S1INCL OFFSET(20) NUMBITS(1) [
            AUTOMATIC = 0,
            INCLUDE = 1
        ],
        /// Length of preamble on air. Decision point: TASKS_START task
        PLEN OFFSET(24) NUMBITS(1) [
            EIGHT = 0,
            SIXTEEN = 1
        ]
    ],
    /// Packet configuration register 1
    PacketConfiguration1 [
        /// Maximum length of packet payload
        MAXLEN OFFSET(0) NUMBITS(8) [],
        /// Static length in number of bytes
        STATLEN OFFSET(8) NUMBITS(8) [],
        /// Base address length in number of bytes
        BALEN OFFSET(16) NUMBITS(3) [],
        /// On air endianness
        ENDIAN OFFSET(24) NUMBITS(1) [
            LITTLE = 0,
            BIG = 1
        ],
        /// Enable or disable packet whitening
        WHITEEN OFFSET(25) NUMBITS(1) [
            DISABLED = 0,
            ENABLED = 1
        ]
    ],
    /// Radio base address register
    BaseAddress [
        /// BASE0 or BASE1
        BASE OFFSET(0) NUMBITS(32)
    ],
    /// Radio prefix0 registers
    Prefix0 [
        /// Address prefix 0
        AP0 OFFSET(0) NUMBITS(8),
        /// Address prefix 1
        AP1 OFFSET(8) NUMBITS(8),
        /// Address prefix 2
        AP2 OFFSET(16) NUMBITS(8),
        /// Address prefix 3
        AP3 OFFSET(24) NUMBITS(8)
    ],
    /// Radio prefix0 registers
    Prefix1 [
        /// Address prefix 4
        AP4 OFFSET(0) NUMBITS(8),
        /// Address prefix 5
        AP5 OFFSET(8) NUMBITS(8),
        /// Address prefix 6
        AP6 OFFSET(16) NUMBITS(8),
        /// Address prefix 7
        AP7 OFFSET(24) NUMBITS(8)
    ],
    /// Transmit address register
    TransmitAddress [
        /// Logical address to be used when transmitting a packet
        ADDRESS OFFSET(0) NUMBITS(3)
    ],
    /// Receive addresses register
    ReceiveAddresses [
        /// Enable or disable reception on logical address 0-7
        ADDRESS OFFSET(0) NUMBITS(8)
    ],
    /// CRC configuration register
    CrcConfiguration [
        /// CRC length in bytes
        LEN OFFSET(0) NUMBITS(2) [
            DISABLED = 0,
            ONE = 1,
            TWO = 2,
            THREE = 3
        ],
        /// Include or exclude packet field from CRC calculation
        SKIPADDR OFFSET(8) NUMBITS(1) [
            INCLUDE = 0,
            EXCLUDE = 1
        ]
    ],
    /// CRC polynomial register
    CrcPolynomial [
        /// CRC polynomial
        CRCPOLY OFFSET(0) NUMBITS(24)
    ],
    /// CRC initial value register
    CrcInitialValue [
       /// Initial value for CRC calculation
       CRCINIT OFFSET(0) NUMBITS(24)
    ],
    /// Inter Frame Spacing in us register
    InterFrameSpacing [
        /// Inter Frame Spacing in us
        /// Inter frame space is the time interval between two consecutive packets. It is defined as the time, in micro seconds, from the
        /// end of the last bit of the previous packet to the start of the first bit of the subsequent packet
        TIFS OFFSET(0) NUMBITS(8)
    ],
    /// RSSI sample register
    RssiSample [
        /// RSSI sample result
        RSSISAMPLE OFFSET(0) NUMBITS(7)
    ],
    /// Radio state register
    State [
        /// Current radio state
        STATE OFFSET(0) NUMBITS(4) [
            DISABLED = 0,
            RXRU = 1,
            RXIDLE = 2,
            RX = 3,
            RXDISABLED = 4,
            TXRU = 9,
            TXIDLE = 10,
            TX = 11,
            TXDISABLED = 12
        ]
    ],
    /// Data whitening initial value register
    DataWhiteIv [
        /// Data whitening initial value. Bit 6 is hard-wired to '1', writing '0'
        /// to it has no effect, and it will always be read back and used by the device as '1'
        DATEWHITEIV OFFSET(0) NUMBITS(7)
    ],
    /// Bit counter compare register
    BitCounterCompare [
        /// Bit counter compare
        BCC OFFSET(0) NUMBITS(32)
    ],
    /// Device address base register
    DeviceAddressBase [
        /// Device address base 0-7
        DAB OFFSET(0) NUMBITS(32)
    ],
    /// Device address prefix register
    DeviceAddressPrefix [
        /// Device address prefix 0-7
        DAP OFFSET(0) NUMBITS(32)
    ],
    /// Device address match configuration register
    DeviceAddressMatch [
        /// Enable or disable device address matching on 0-7
        ENA OFFSET(0) NUMBITS(8),
        /// TxAdd for device address 0-7
        TXADD OFFSET(8) NUMBITS(8)
    ],
    /// Radio mode configuration register
    RadioModeConfig [
        /// Radio ramp-up time
        RU OFFSET(0) NUMBITS(1) [
            DEFAULT = 0,
            FAST = 1
        ],
        /// Default TX value
        /// Specifies what the RADIO will transmit when it is not started, i.e. between:
        /// RADIO.EVENTS_READY and RADIO.TASKS_START
        /// RADIO.EVENTS_END and RADIO.TASKS_START
        DTX OFFSET(8) NUMBITS(2) [
            B1 = 0,
            B0 = 1,
            CENTER = 2
        ]
    ]
];

static mut PAYLOAD: [u8; nrf5x::constants::RADIO_PAYLOAD_LENGTH] =
    [0x00; nrf5x::constants::RADIO_PAYLOAD_LENGTH];

// ---------------------------------------------------------------------------
// Connection event timing.
//
// A connection event is driven almost entirely by hardware, because the reply
// to the central's packet is due exactly T_IFS = 150 us after it arrives. The
// CPU only arms the sequence beforehand and adjusts two header bits partway
// through; see `connection_event_start` and `handle_interrupt`.
//
// The sequence uses TIMER0 and three pre-programmed PPI channels:
//
//   CC[0]  open time    ch 21:  TIMER0 COMPARE[0] -> RADIO RXEN
//   CC[1]  deadline     ch 22:  TIMER0 COMPARE[1] -> RADIO DISABLE
//          anchor       ch 26:  RADIO ADDRESS -> TIMER0 CAPTURE[1]
//   CC[3]  software reads of the current time
//
// CC[1] carries the receive window deadline and the anchor point in turn, and
// that is the whole trick: detecting the central's address captures the
// counter into CC[1], which records the anchor and in the same instant retires
// the deadline, because a compare cannot match a value the counter has just
// passed. Hardware disarms the timeout exactly when the packet starts
// arriving, with no software involved.
//
// All three channels are fixed in hardware, which is why this driver uses
// TIMER0 specifically rather than any free timer, and why it needs no
// programmable PPI channel at all.
// ---------------------------------------------------------------------------

/// Capture/compare register holding a connection event's open time.
const CC_OPEN_TIME: CaptureCompare = CaptureCompare::Cc0;
/// Capture/compare register holding the receive window deadline.
///
/// Hardware overwrites this with the anchor point when the central's address
/// is detected, which retires the deadline at the same time; see
/// [`CC_ANCHOR`].
const CC_WINDOW_TIMEOUT: CaptureCompare = CaptureCompare::Cc1;
/// Capture/compare register hardware stamps with the anchor point.
///
/// Deliberately the same register as [`CC_WINDOW_TIMEOUT`].
const CC_ANCHOR: CaptureCompare = CC_WINDOW_TIMEOUT;
/// Capture/compare register used to read the current time.
const CC_NOW: CaptureCompare = CaptureCompare::Cc3;

/// TIMER0 prescaler giving a 1 MHz tick: 16 MHz / 2^4.
const TIMER_PRESCALER_1MHZ: u32 = 4;

/// How long to keep receiving before giving up on the central, in microseconds.
///
/// Generous relative to the window widening the client applies; it exists so a
/// connection event always ends, not to bound the window precisely.
const RX_WINDOW_TIMEOUT_US: u32 = 2000;

/// Inter-frame space between a received packet and its reply, in microseconds.
///
/// Bluetooth Core Specification, Vol 6, Part B, Section 4.1.1.
const T_IFS_US: u32 = 150;

/// Link-layer header bit positions, Bluetooth Core Specification, Vol 6, Part B,
/// Section 2.4.
mod ll_header {
    /// Next expected sequence number.
    pub const NESN: u8 = 2;
    /// Sequence number.
    pub const SN: u8 = 3;
    /// Mask covering both sequence number bits.
    pub const SEQ_MASK: u8 = (1 << NESN) | (1 << SN);
}

/// Phase of an in-progress connection event.
#[derive(Copy, Clone, PartialEq)]
enum ConnPhase {
    /// No connection event in progress.
    Idle,
    /// Receiving the central's packet.
    Rx,
    /// Transmitting the reply, which hardware started via a shortcut.
    Tx,
}

pub struct Radio<'a> {
    registers: StaticRef<RadioRegisters>,
    /// TIMER0, used only for connection event timing.
    timer: Timer,
    ppi: Ppi,
    tx_power: Cell<TxPower>,
    rx_client: OptionalCell<&'a dyn ble_advertising::RxClient>,
    tx_client: OptionalCell<&'a dyn ble_advertising::TxClient>,
    buffer: TakeCell<'static, [u8]>,
    conn_client: OptionalCell<&'a dyn ConnectionEventClient<Ticks32>>,
    /// The outstanding payload and the one that follows it.
    conn_tx: MapCell<TxBuffers>,
    conn_phase: Cell<ConnPhase>,
    /// Parameters of the current connection; `None` until configured.
    conn_params: Cell<Option<ConnectionParams>>,
    conn_rx_ok: Cell<bool>,
    conn_anchor: Cell<u32>,
    /// Our transmit sequence number, one bit.
    conn_sn: Cell<u8>,
    /// The sequence number we expect from the central next, one bit.
    conn_nesn: Cell<u8>,
    /// Whether the central acknowledged the packet we sent in the previous
    /// connection event. Decides which of the two buffers goes out, and is
    /// reported to the client. Reset at the start of each event.
    conn_tx_acked: Cell<bool>,
}

impl<'a> Radio<'a> {
    pub const fn new(
        registers: StaticRef<RadioRegisters>,
        timer: StaticRef<TimerRegisters>,
        ppi: StaticRef<PpiRegisters>,
    ) -> Radio<'a> {
        Radio {
            registers,
            timer: Timer::new(timer),
            ppi: Ppi::new(ppi),
            tx_power: Cell::new(TxPower::ZerodBm),
            rx_client: OptionalCell::empty(),
            tx_client: OptionalCell::empty(),
            buffer: TakeCell::empty(),
            conn_client: OptionalCell::empty(),
            conn_tx: MapCell::empty(),
            conn_phase: Cell::new(ConnPhase::Idle),
            conn_params: Cell::new(None),
            conn_rx_ok: Cell::new(false),
            conn_anchor: Cell::new(0),
            conn_sn: Cell::new(0),
            conn_nesn: Cell::new(0),
            conn_tx_acked: Cell::new(false),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.registers.mode.matches_all(Mode::MODE::BLE_1MBIT)
    }

    fn tx(&self) {
        self.registers.event_ready.write(Event::READY::CLEAR);
        self.registers.task_txen.write(Task::ENABLE::SET);
    }

    fn rx(&self) {
        self.registers.event_ready.write(Event::READY::CLEAR);
        self.registers.task_rxen.write(Task::ENABLE::SET);
    }

    fn set_rx_address(&self) {
        self.registers
            .rxaddresses
            .write(ReceiveAddresses::ADDRESS.val(1));
    }

    fn set_tx_address(&self) {
        self.registers
            .txaddress
            .write(TransmitAddress::ADDRESS.val(0));
    }

    fn radio_on(&self) {
        // reset and enable power
        self.registers.power.write(Task::ENABLE::CLEAR);
        self.registers.power.write(Task::ENABLE::SET);
    }

    fn radio_off(&self) {
        self.registers.power.write(Task::ENABLE::CLEAR);
    }

    fn set_tx_power(&self) {
        self.registers.txpower.set(self.tx_power.get() as u32);
    }

    fn set_dma_ptr(&self) {
        self.registers.packetptr.set(addr_of!(PAYLOAD) as u32);
    }

    #[inline(never)]
    pub fn handle_interrupt(&self) {
        self.disable_all_interrupts();

        if self.conn_phase.get() != ConnPhase::Idle {
            self.handle_connection_interrupt();
            return;
        }

        if self.registers.event_ready.is_set(Event::READY) {
            self.registers.event_ready.write(Event::READY::CLEAR);
            self.registers.event_end.write(Event::READY::CLEAR);
            self.registers.task_start.write(Task::ENABLE::SET);
        }

        if self.registers.event_address.is_set(Event::READY) {
            self.registers.event_address.write(Event::READY::CLEAR);
        }
        if self.registers.event_payload.is_set(Event::READY) {
            self.registers.event_payload.write(Event::READY::CLEAR);
        }

        // tx or rx finished!
        if self.registers.event_end.is_set(Event::READY) {
            self.registers.event_end.write(Event::READY::CLEAR);

            let result = if self.registers.crcstatus.is_set(Event::READY) {
                Ok(())
            } else {
                Err(ErrorCode::FAIL)
            };

            match self.registers.state.get() {
                nrf5x::constants::RADIO_STATE_TXRU
                | nrf5x::constants::RADIO_STATE_TXIDLE
                | nrf5x::constants::RADIO_STATE_TXDISABLE
                | nrf5x::constants::RADIO_STATE_TX => {
                    self.radio_off();
                    self.tx_client
                        .map(|client| client.transmit_event(self.buffer.take().unwrap(), result));
                }
                nrf5x::constants::RADIO_STATE_RXRU
                | nrf5x::constants::RADIO_STATE_RXIDLE
                | nrf5x::constants::RADIO_STATE_RXDISABLE
                | nrf5x::constants::RADIO_STATE_RX => {
                    self.radio_off();
                    unsafe {
                        self.rx_client.map(|client| {
                            // Length is: S0 (1 Byte) + Length (1 Byte) + S1 (0 Bytes) + Payload
                            // And because the length field is directly read from the packet
                            // We need to add 2 to length to get the total length
                            client.receive_event(
                                &mut *addr_of_mut!(PAYLOAD),
                                PAYLOAD[1] + 2,
                                result,
                            )
                        });
                    }
                }
                // Radio state - Disabled
                _ => (),
            }
        }
        self.enable_interrupts();
    }

    pub fn enable_interrupts(&self) {
        self.registers.intenset.write(
            Interrupt::READY::SET
                + Interrupt::ADDRESS::SET
                + Interrupt::PAYLOAD::SET
                + Interrupt::END::SET,
        );
    }

    pub fn enable_interrupt(&self, intr: u32) {
        self.registers.intenset.set(intr);
    }

    pub fn clear_interrupt(&self, intr: u32) {
        self.registers.intenclr.set(intr);
    }

    pub fn disable_all_interrupts(&self) {
        // disable all possible interrupts
        self.registers.intenclr.set(0xffffffff);
    }

    fn replace_radio_buffer(&self, buf: &'static mut [u8]) -> &'static mut [u8] {
        // set payload
        for (i, c) in buf.as_ref().iter().enumerate() {
            unsafe {
                PAYLOAD[i] = *c;
            }
        }
        buf
    }

    fn ble_initialize(&self, channel: RadioChannel) {
        self.radio_on();

        self.ble_set_tx_power();

        self.ble_set_channel_rate();

        self.ble_set_channel_freq(channel);
        self.ble_set_data_whitening(channel);

        self.set_tx_address();
        self.set_rx_address();

        self.ble_set_packet_config();
        self.ble_set_advertising_access_address();

        self.ble_set_crc_config();

        self.set_dma_ptr();
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 3.1.1 CRC Generation
    fn ble_set_crc_config(&self) {
        self.registers
            .crccnf
            .write(CrcConfiguration::LEN::THREE + CrcConfiguration::SKIPADDR::EXCLUDE);
        self.registers
            .crcinit
            .set(nrf5x::constants::RADIO_CRCINIT_BLE);
        self.registers
            .crcpoly
            .set(nrf5x::constants::RADIO_CRCPOLY_BLE);
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 2.1.2 Access Address
    // Set access address to 0x8E89BED6
    fn ble_set_advertising_access_address(&self) {
        self.registers.prefix0.set(0x0000008e);
        self.registers.base0.set(0x89bed600);
    }

    // Packet configuration
    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 2.1 Packet Format
    //
    // LSB                                                      MSB
    // +----------+   +----------------+   +---------------+   +------------+
    // | Preamble | - | Access Address | - | PDU           | - | CRC        |
    // | (1 byte) |   | (4 bytes)      |   | (2-255 bytes) |   | (3 bytes)  |
    // +----------+   +----------------+   +---------------+   +------------+
    //
    fn ble_set_packet_config(&self) {
        // sets the header of PDU TYPE to 1 byte
        // sets the header length to 1 byte
        self.registers.pcnf0.write(
            PacketConfiguration0::LFLEN.val(8)
                + PacketConfiguration0::S0LEN.val(1)
                + PacketConfiguration0::S1LEN::CLEAR
                + PacketConfiguration0::S1INCL::CLEAR
                + PacketConfiguration0::PLEN::EIGHT,
        );

        self.registers.pcnf1.write(
            PacketConfiguration1::WHITEEN::ENABLED
                + PacketConfiguration1::ENDIAN::LITTLE
                + PacketConfiguration1::BALEN.val(3)
                + PacketConfiguration1::STATLEN::CLEAR
                + PacketConfiguration1::MAXLEN.val(255),
        );
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part A], 4.6 REFERENCE SIGNAL DEFINITION
    // Bit Rate = 1 Mb/s ±1 ppm
    fn ble_set_channel_rate(&self) {
        self.registers.mode.write(Mode::MODE::BLE_1MBIT);
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 3.2 Data Whitening
    // Configure channel index to the LFSR and the hardware solves the rest
    fn ble_set_data_whitening(&self, channel: RadioChannel) {
        self.registers.datawhiteiv.set(channel.get_channel_index());
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 1.4.1
    // RF Channels:     0 - 39
    // Data:            0 - 36
    // Advertising:     37, 38, 39
    fn ble_set_channel_freq(&self, channel: RadioChannel) {
        self.registers
            .frequency
            .write(Frequency::FREQUENCY.val(channel as u32));
    }

    // BLUETOOTH SPECIFICATION Version 4.2 [Vol 6, Part B], section 3 TRANSMITTER CHARACTERISTICS
    // Minimum Output Power : -20dBm
    // Maximum Output Power : +10dBm
    //
    // no check is required because the BleConfig::set_tx_power() method ensures that only
    // valid tranmitting power is configured!
    fn ble_set_tx_power(&self) {
        self.set_tx_power();
    }
    /// Service a radio interrupt belonging to a connection event.
    ///
    /// Two `DISABLED` interrupts arrive per event. After the reception, the
    /// radio is already ramping up to transmit (the `DISABLED_TXEN` shortcut),
    /// which leaves roughly 40 us to stamp the acknowledgement bits into the
    /// reply and point the radio at it. After the transmission, the event is
    /// over and the client is notified.
    fn handle_connection_interrupt(&self) {
        // The anchor point is captured by hardware on the access address; read
        // it out once the packet has finished arriving.
        if self.registers.event_end.is_set(Event::READY) && self.conn_phase.get() == ConnPhase::Rx {
            self.registers.event_end.write(Event::READY::CLEAR);
            self.conn_rx_ok
                .set(self.registers.crcstatus.is_set(Event::READY));
            self.conn_anchor.set(self.timer.compare_value(CC_ANCHOR));
        }

        if !self.registers.event_disabled.is_set(Event::READY) {
            // Nothing to do yet; wait for the next edge.
            self.registers
                .intenset
                .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
            return;
        }
        self.registers.event_disabled.write(Event::READY::CLEAR);

        match self.conn_phase.get() {
            ConnPhase::Rx => self.finish_connection_rx(),
            ConnPhase::Tx => self.finish_connection_tx(),
            ConnPhase::Idle => {}
        }
    }

    /// Reception is done and the reply is ramping up.
    ///
    /// Updates the link-layer sequence numbers from the packet just received
    /// and stamps them into the reply, so that the acknowledgement the central
    /// sees refers to that packet. See Bluetooth Core Specification, Vol 6,
    /// Part B, Section 4.5.9.
    fn finish_connection_rx(&self) {
        // A corrupt or absent packet must not advance the sequence numbers.
        if self.conn_rx_ok.get() {
            // ### Safety
            //
            // `PAYLOAD` is the radio's receive buffer. The packet finished
            // arriving before the `END` event handled above, so the DMA engine
            // is no longer writing to it, and this interrupt handler is the
            // only reader.
            let rx_hdr = unsafe { (*addr_of!(PAYLOAD))[0] };
            let rx_nesn = (rx_hdr >> ll_header::NESN) & 1;
            let rx_sn = (rx_hdr >> ll_header::SN) & 1;

            // The central acknowledged our packet if its next-expected
            // sequence number moved past our sequence number.
            if rx_nesn != self.conn_sn.get() {
                self.conn_sn.set(rx_nesn);
                self.conn_tx_acked.set(true);
            }
            // A packet that is not a retransmission carries the sequence
            // number we were expecting; acknowledge it.
            if rx_sn == self.conn_nesn.get() {
                self.conn_nesn.set(self.conn_nesn.get() ^ 1);
            }
        }

        let sn = self.conn_sn.get();
        let nesn = self.conn_nesn.get();
        let acknowledged = self.conn_tx_acked.get();
        if let Some(ptr) = self.conn_tx.map(|tx| {
            // An acknowledged payload must not go out again: our sequence
            // number has advanced, so the central would read the same bytes
            // as a new and duplicate packet. Move on to what follows instead.
            // Anything else is retransmitted until it is acknowledged.
            let pdu: &mut [u8] = if acknowledged {
                tx.next
            } else {
                tx.outstanding
            };
            pdu[0] =
                (pdu[0] & !ll_header::SEQ_MASK) | (nesn << ll_header::NESN) | (sn << ll_header::SN);
            pdu.as_ptr() as u32
        }) {
            self.registers.packetptr.set(ptr);
        }

        // Drop DISABLED_TXEN so that finishing the transmission does not start
        // another one.
        self.registers
            .shorts
            .write(Shortcut::READY_START::SET + Shortcut::END_DISABLE::SET);
        // The receive window is over either way, so the deadline is moot.
        self.ppi.disable(Channel::CH22::SET);
        self.conn_phase.set(ConnPhase::Tx);
        self.registers
            .intenset
            .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
    }

    /// The reply has gone out; tear down and report the event.
    fn finish_connection_tx(&self) {
        self.ppi.disable(Channel::CH21::SET + Channel::CH26::SET);
        self.registers.shorts.write(Shortcut::READY_START::CLEAR);
        self.conn_phase.set(ConnPhase::Idle);
        self.radio_off();

        let result = if self.conn_rx_ok.get() {
            Ok(())
        } else {
            Err(ErrorCode::FAIL)
        };
        let anchor = Ticks32::from(self.conn_anchor.get());
        let acked = self.conn_tx_acked.get();

        if let Some(buffers) = self.conn_tx.take() {
            self.conn_client.map(|client| {
                // ### Safety
                //
                // `PAYLOAD` is the radio's receive buffer. The radio is powered
                // off above, so no DMA is in flight, and the shared reference
                // does not outlive this call.
                let rx = unsafe { &*addr_of!(PAYLOAD) };
                client.connection_event_done(rx, buffers, result, anchor, acked);
            });
        }
    }

    /// Apply the radio configuration that stays fixed for a connection event.
    ///
    /// The radio is power-cycled at the start of every event, which resets its
    /// registers, so this runs once per event rather than once per connection.
    fn configure_connection_radio(&self, params: &ConnectionParams, channel: RadioChannel) {
        // Access address: BALEN=3 puts the low three bytes in BASE0, with the
        // most significant byte in the address prefix.
        self.registers
            .base0
            .set((params.access_address & 0x00FF_FFFF) << 8);
        self.registers
            .prefix0
            .set((params.access_address >> 24) & 0xFF);

        self.registers
            .crccnf
            .write(CrcConfiguration::LEN::THREE + CrcConfiguration::SKIPADDR::EXCLUDE);
        self.registers
            .crcpoly
            .set(nrf5x::constants::RADIO_CRCPOLY_BLE);
        self.registers
            .crcinit
            .write(CrcInitialValue::CRCINIT.val(params.crc_init));

        // Hardware enforces the inter-frame space on the receive-to-transmit
        // turnaround, which is what makes the 150 us deadline achievable.
        self.registers
            .tifs
            .write(InterFrameSpacing::TIFS.val(T_IFS_US));

        self.registers.mode.write(Mode::MODE::BLE_1MBIT);
        self.registers.pcnf0.write(
            PacketConfiguration0::LFLEN.val(8)
                + PacketConfiguration0::S0LEN.val(1)
                + PacketConfiguration0::S1LEN::CLEAR
                + PacketConfiguration0::S1INCL::CLEAR
                + PacketConfiguration0::PLEN::EIGHT,
        );
        self.registers.pcnf1.write(
            PacketConfiguration1::WHITEEN::ENABLED
                + PacketConfiguration1::ENDIAN::LITTLE
                + PacketConfiguration1::BALEN.val(3)
                + PacketConfiguration1::STATLEN::CLEAR
                + PacketConfiguration1::MAXLEN.val(255),
        );
        self.registers
            .txaddress
            .write(TransmitAddress::ADDRESS.val(0));
        self.registers
            .rxaddresses
            .write(ReceiveAddresses::ADDRESS.val(1));

        self.set_tx_power();
        self.ble_set_channel_freq(channel);
        self.ble_set_data_whitening(channel);
        self.set_dma_ptr();
    }
}

impl<'a> ble_advertising::BleAdvertisementDriver<'a> for Radio<'a> {
    fn transmit_advertisement(&self, buf: &'static mut [u8], _len: usize, channel: RadioChannel) {
        let res = self.replace_radio_buffer(buf);
        self.buffer.replace(res);
        self.ble_initialize(channel);
        self.tx();
        self.enable_interrupts();
    }

    fn receive_advertisement(&self, channel: RadioChannel) {
        self.ble_initialize(channel);
        self.rx();
        self.enable_interrupts();
    }

    fn set_receive_client(&self, client: &'a dyn ble_advertising::RxClient) {
        self.rx_client.set(client);
    }

    fn set_transmit_client(&self, client: &'a dyn ble_advertising::TxClient) {
        self.tx_client.set(client);
    }

    fn stop_receive(&self) {
        self.radio_off();
    }
}

impl ble_advertising::BleConfig for Radio<'_> {
    // The BLE Advertising Driver validates that the `tx_power` is between -20 to 10 dBm but then
    // underlying chip must validate if the current `tx_power` is supported as well
    fn set_tx_power(&self, tx_power: u8) -> Result<(), ErrorCode> {
        // Convert u8 to TxPower
        match nrf5x::constants::TxPower::try_from(tx_power) {
            // Invalid transmitting power, propogate error
            Err(()) => Err(ErrorCode::NOSUPPORT),
            // Valid transmitting power, propogate success
            Ok(res) => {
                self.tx_power.set(res);
                Ok(())
            }
        }
    }
}

impl Time for Radio<'_> {
    type Frequency = Freq1MHz;
    type Ticks = Ticks32;

    /// The connection event clock.
    ///
    /// Reads zero until [`BleConnectionDriver::connection_configure`] starts
    /// the timer.
    fn now(&self) -> Ticks32 {
        // Capturing latches the running counter into a compare register, which
        // is the only way to read it.
        Ticks32::from(self.timer.capture(CC_NOW))
    }
}

impl<'a> BleConnectionDriver<'a> for Radio<'a> {
    fn connection_configure(&self, params: &ConnectionParams) -> Result<(), ErrorCode> {
        self.conn_params.set(Some(*params));
        self.conn_sn.set(0);
        self.conn_nesn.set(0);
        self.conn_tx_acked.set(false);

        // A free-running microsecond counter for the whole connection.
        self.timer
            .start(TIMER_PRESCALER_1MHZ, BitmodeValue::Size32Bits);
        Ok(())
    }

    fn connection_event_start(
        &self,
        channel: RadioChannel,
        buffers: TxBuffers,
        open_time: Ticks32,
    ) -> Result<(), (ErrorCode, TxBuffers)> {
        if self.conn_phase.get() != ConnPhase::Idle {
            return Err((ErrorCode::BUSY, buffers));
        }
        let Some(params) = self.conn_params.get() else {
            return Err((ErrorCode::OFF, buffers));
        };

        self.conn_tx.put(buffers);
        self.conn_rx_ok.set(false);
        self.conn_tx_acked.set(false);

        // Power-cycling clears every radio register, so the whole packet
        // configuration is reapplied for each event.
        self.radio_on();
        self.configure_connection_radio(&params, channel);

        // READY_START starts the radio once it has ramped up, END_DISABLE ends
        // the packet, and DISABLED_TXEN turns the end of the reception into the
        // start of the reply without software involvement.
        self.registers.shorts.write(
            Shortcut::READY_START::SET + Shortcut::END_DISABLE::SET + Shortcut::DISABLED_TXEN::SET,
        );

        let open = open_time.into_u32();
        self.timer.clear_compare_event(CC_OPEN_TIME);
        self.timer.clear_compare_event(CC_WINDOW_TIMEOUT);
        self.timer.set_compare(CC_OPEN_TIME, open);
        self.timer
            .set_compare(CC_WINDOW_TIMEOUT, open.wrapping_add(RX_WINDOW_TIMEOUT_US));

        self.ppi
            .enable(Channel::CH21::SET + Channel::CH22::SET + Channel::CH26::SET);

        self.registers
            .intenset
            .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
        self.conn_phase.set(ConnPhase::Rx);

        Ok(())
    }

    fn set_connection_event_client(&self, client: &'a dyn ConnectionEventClient<Ticks32>) {
        self.conn_client.set(client);
    }
}

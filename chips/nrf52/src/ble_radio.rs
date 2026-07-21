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

use core::cell::Cell;
use core::ptr::addr_of;
use core::ptr::addr_of_mut;
use kernel::ErrorCode;
use kernel::hil::ble_advertising;
use kernel::hil::ble_advertising::{ConnectionParams, RadioChannel};
use kernel::utilities::StaticRef;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{ReadOnly, ReadWrite, WriteOnly, register_bitfields};
use nrf5x::constants::TxPower;

const RADIO_BASE: StaticRef<RadioRegisters> =
    unsafe { StaticRef::new(0x40001000 as *const RadioRegisters) };

#[repr(C)]
struct RadioRegisters {
    /// Enable Radio in TX mode
    /// - Address: 0x000 - 0x004
    task_txen: WriteOnly<u32, Task::Register>,
    /// Enable Radio in RX mode
    /// - Address: 0x004 - 0x008
    task_rxen: WriteOnly<u32, Task::Register>,
    /// Start Radio
    /// - Address: 0x008 - 0x00c
    task_start: WriteOnly<u32, Task::Register>,
    /// Stop Radio
    /// - Address: 0x00c - 0x010
    task_stop: WriteOnly<u32, Task::Register>,
    /// Disable Radio
    /// - Address: 0x010 - 0x014
    task_disable: WriteOnly<u32, Task::Register>,
    /// Start the RSSI and take one single sample of the receive signal strength
    /// - Address: 0x014- 0x018
    task_rssistart: WriteOnly<u32, Task::Register>,
    /// Stop the RSSI measurement
    /// - Address: 0x018 - 0x01c
    task_rssistop: WriteOnly<u32, Task::Register>,
    /// Start the bit counter
    /// - Address: 0x01c - 0x020
    task_bcstart: WriteOnly<u32, Task::Register>,
    /// Stop the bit counter
    /// - Address: 0x020 - 0x024
    task_bcstop: WriteOnly<u32, Task::Register>,
    /// Reserved
    _reserved1: [u32; 55],
    /// Radio has ramped up and is ready to be started
    /// - Address: 0x100 - 0x104
    event_ready: ReadWrite<u32, Event::Register>,
    /// Address sent or received
    /// - Address: 0x104 - 0x108
    event_address: ReadWrite<u32, Event::Register>,
    /// Packet payload sent or received
    /// - Address: 0x108 - 0x10c
    event_payload: ReadWrite<u32, Event::Register>,
    /// Packet sent or received
    /// - Address: 0x10c - 0x110
    event_end: ReadWrite<u32, Event::Register>,
    /// Radio has been disabled
    /// - Address: 0x110 - 0x114
    event_disabled: ReadWrite<u32, Event::Register>,
    /// A device address match occurred on the last received packet
    /// - Address: 0x114 - 0x118
    event_devmatch: ReadWrite<u32>,
    /// No device address match occurred on the last received packet
    /// - Address: 0x118 - 0x11c
    event_devmiss: ReadWrite<u32, Event::Register>,
    /// Sampling of receive signal strength complete
    /// - Address: 0x11c - 0x120
    event_rssiend: ReadWrite<u32, Event::Register>,
    /// Reserved
    _reserved2: [u32; 2],
    /// Bit counter reached bit count value
    /// - Address: 0x128 - 0x12c
    event_bcmatch: ReadWrite<u32, Event::Register>,
    /// Reserved
    _reserved3: [u32; 1],
    /// Packet received with CRC ok
    /// - Address: 0x130 - 0x134
    event_crcok: ReadWrite<u32, Event::Register>,
    /// Packet received with CRC error
    /// - Address: 0x134 - 0x138
    crcerror: ReadWrite<u32, Event::Register>,
    /// Reserved
    _reserved4: [u32; 50],
    /// Shortcut register
    /// - Address: 0x200 - 0x204
    shorts: ReadWrite<u32, Shortcut::Register>,
    /// Reserved
    _reserved5: [u32; 64],
    /// Enable interrupt
    /// - Address: 0x304 - 0x308
    intenset: ReadWrite<u32, Interrupt::Register>,
    /// Disable interrupt
    /// - Address: 0x308 - 0x30c
    intenclr: ReadWrite<u32, Interrupt::Register>,
    /// Reserved
    _reserved6: [u32; 61],
    /// CRC status
    /// - Address: 0x400 - 0x404
    crcstatus: ReadOnly<u32, Event::Register>,
    /// Reserved
    _reserved7: [u32; 1],
    /// Received address
    /// - Address: 0x408 - 0x40c
    rxmatch: ReadOnly<u32, ReceiveMatch::Register>,
    /// CRC field of previously received packet
    /// - Address: 0x40c - 0x410
    rxcrc: ReadOnly<u32, ReceiveCrc::Register>,
    /// Device address match index
    /// - Address: 0x410 - 0x414
    dai: ReadOnly<u32, DeviceAddressIndex::Register>,
    /// Reserved
    _reserved8: [u32; 60],
    /// Packet pointer
    /// - Address: 0x504 - 0x508
    packetptr: ReadWrite<u32, PacketPointer::Register>,
    /// Frequency
    /// - Address: 0x508 - 0x50c
    frequency: ReadWrite<u32, Frequency::Register>,
    /// Output power
    /// - Address: 0x50c - 0x510
    txpower: ReadWrite<u32, TransmitPower::Register>,
    /// Data rate and modulation
    /// - Address: 0x510 - 0x514
    mode: ReadWrite<u32, Mode::Register>,
    /// Packet configuration register 0
    /// - Address 0x514 - 0x518
    pcnf0: ReadWrite<u32, PacketConfiguration0::Register>,
    /// Packet configuration register 1
    /// - Address: 0x518 - 0x51c
    pcnf1: ReadWrite<u32, PacketConfiguration1::Register>,
    /// Base address 0
    /// - Address: 0x51c - 0x520
    base0: ReadWrite<u32, BaseAddress::Register>,
    /// Base address 1
    /// - Address: 0x520 - 0x524
    base1: ReadWrite<u32, BaseAddress::Register>,
    /// Prefix bytes for logical addresses 0-3
    /// - Address: 0x524 - 0x528
    prefix0: ReadWrite<u32, Prefix0::Register>,
    /// Prefix bytes for logical addresses 4-7
    /// - Address: 0x528 - 0x52c
    prefix1: ReadWrite<u32, Prefix1::Register>,
    /// Transmit address select
    /// - Address: 0x52c - 0x530
    txaddress: ReadWrite<u32, TransmitAddress::Register>,
    /// Receive address select
    /// - Address: 0x530 - 0x534
    rxaddresses: ReadWrite<u32, ReceiveAddresses::Register>,
    /// CRC configuration
    /// - Address: 0x534 - 0x538
    crccnf: ReadWrite<u32, CrcConfiguration::Register>,
    /// CRC polynomial
    /// - Address: 0x538 - 0x53c
    crcpoly: ReadWrite<u32, CrcPolynomial::Register>,
    /// CRC initial value
    /// - Address: 0x53c - 0x540
    crcinit: ReadWrite<u32, CrcInitialValue::Register>,
    /// Reserved
    _reserved9: [u32; 1],
    /// Interframe spacing in microseconds
    /// - Address: 0x544 - 0x548
    tifs: ReadWrite<u32, InterFrameSpacing::Register>,
    /// RSSI sample
    /// - Address: 0x548 - 0x54c
    rssisample: ReadWrite<u32, RssiSample::Register>,
    /// Reserved
    _reserved10: [u32; 1],
    /// Current radio state
    /// - Address: 0x550 - 0x554
    state: ReadOnly<u32, State::Register>,
    /// Data whitening initial value
    /// - Address: 0x554 - 0x558
    datawhiteiv: ReadWrite<u32, DataWhiteIv::Register>,
    /// Reserved
    _reserved11: [u32; 2],
    /// Bit counter compare
    /// - Address: 0x560 - 0x564
    bcc: ReadWrite<u32, BitCounterCompare::Register>,
    /// Reserved
    _reserved12: [u32; 39],
    /// Device address base segments
    /// - Address: 0x600 - 0x620
    dab: [ReadWrite<u32, DeviceAddressBase::Register>; 8],
    /// Device address prefix
    /// - Address: 0x620 - 0x640
    dap: [ReadWrite<u32, DeviceAddressPrefix::Register>; 8],
    /// Device address match configuration
    /// - Address: 0x640 - 0x644
    dacnf: ReadWrite<u32, DeviceAddressMatch::Register>,
    /// Reserved
    _reserved13: [u32; 3],
    /// Radio mode configuration register
    /// - Address: 0x650 - 0x654
    modecnf0: ReadWrite<u32, RadioModeConfig::Register>,
    /// Reserved
    _reserved14: [u32; 618],
    /// Peripheral power control
    /// - Address: 0xFFC - 0x1000
    power: ReadWrite<u32, Task::Register>,
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

// ---------------------------------------------------------------------------
// Minimal TIMER0 register map (base 0x40008000).
// TIMER0 is used exclusively for BLE connection event timing when connected.
// Prescaler is set to 4 (1 MHz = 1 µs/tick) on first connection_configure().
//
// CC register assignments during connection events:
//   CC[0]  – radio open_time  (PPI CH21: TIMER0_CC0 → RADIO_RXEN)
//   CC[1]  – anchor capture   (PPI CH26: RADIO_ADDRESS → TIMER0_CAPTURE[1])
//   CC[2]  – window timeout   (PPI CH0 programmable: TIMER0_CC2 → RADIO_DISABLE)
//   CC[3]  – software "now"   (write TASKS_CAPTURE[3], read CC[3])
// ---------------------------------------------------------------------------

const TIMER0_BASE: u32 = 0x40008000;

#[inline(always)]
unsafe fn timer0_write(offset: u32, val: u32) {
    core::ptr::write_volatile((TIMER0_BASE + offset) as *mut u32, val);
}

#[inline(always)]
fn timer0_read(offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile((TIMER0_BASE + offset) as *const u32) }
}

// TIMER0 register offsets
const T0_TASKS_START: u32 = 0x000;
const T0_TASKS_STOP: u32 = 0x004;
const T0_TASKS_CLEAR: u32 = 0x00C;
const T0_TASKS_CAPTURE_BASE: u32 = 0x040; // [n] = 0x040 + n*4
const T0_BITMODE: u32 = 0x508;
const T0_PRESCALER: u32 = 0x510;
const T0_CC_BASE: u32 = 0x540; // [n] = 0x540 + n*4
const T0_EVENTS_COMPARE_BASE: u32 = 0x140; // [n] = 0x140 + n*4

// PPI register helpers
const PPI_BASE: u32 = 0x4001F000;
const PPI_CHENSET: u32 = 0x504;
const PPI_CHENCLR: u32 = 0x508;
const PPI_CH_EEP_BASE: u32 = 0x510; // CH[0].EEP; CH[n].EEP = 0x510 + n*8

// Absolute hardware addresses used for PPI CH0 endpoint configuration:
//   EEP: TIMER0 EVENTS_COMPARE[2] = 0x40008000 + 0x148
//   TEP: RADIO  TASKS_DISABLE     = 0x40001000 + 0x010
const TIMER0_EVENTS_COMPARE2_ADDR: u32 = 0x40008148;
const RADIO_TASKS_DISABLE_ADDR: u32 = 0x40001010;

// PPI channel masks for chenset/chenclr
const PPI_CH0: u32 = 1 << 0; // programmable: TIMER0_CC2 → RADIO_DISABLE
const PPI_CH21: u32 = 1 << 21; // pre-programmed: TIMER0_CC0 → RADIO_RXEN
const PPI_CH26: u32 = 1 << 26; // pre-programmed: RADIO_ADDRESS → TIMER0_CAPTURE[1]

#[inline(always)]
fn ppi_enable(mask: u32) {
    unsafe {
        core::ptr::write_volatile((PPI_BASE + PPI_CHENSET) as *mut u32, mask);
    }
}

#[inline(always)]
fn ppi_disable(mask: u32) {
    unsafe {
        core::ptr::write_volatile((PPI_BASE + PPI_CHENCLR) as *mut u32, mask);
    }
}

#[inline(always)]
unsafe fn ppi_configure_ch0(eep: u32, tep: u32) {
    // CH[0].EEP = PPI_BASE + 0x510, CH[0].TEP = PPI_BASE + 0x514
    core::ptr::write_volatile((PPI_BASE + PPI_CH_EEP_BASE) as *mut u32, eep);
    core::ptr::write_volatile((PPI_BASE + PPI_CH_EEP_BASE + 4) as *mut u32, tep);
}

/// Phase of the current connection event.
#[derive(Copy, Clone, PartialEq)]
enum ConnPhase {
    Idle,
    Rx, // listening for master's PDU
    Tx, // transmitting ACK (hardware-driven via SHORTS)
}

static mut PAYLOAD: [u8; nrf5x::constants::RADIO_PAYLOAD_LENGTH] =
    [0x00; nrf5x::constants::RADIO_PAYLOAD_LENGTH];

pub struct Radio<'a> {
    registers: StaticRef<RadioRegisters>,
    tx_power: Cell<TxPower>,
    rx_client: OptionalCell<&'a dyn ble_advertising::RxClient>,
    tx_client: OptionalCell<&'a dyn ble_advertising::TxClient>,
    buffer: TakeCell<'static, [u8]>,
    // Connection mode fields
    conn_client: OptionalCell<&'a dyn ble_advertising::ConnectionEventClient>,
    conn_tx_buf: TakeCell<'static, [u8]>,
    conn_phase: Cell<ConnPhase>,
    conn_rx_ok: Cell<bool>,
    conn_anchor_ticks: Cell<u32>,
    conn_params: Cell<Option<ConnectionParams>>,
    // Link-layer acknowledgement state (BT Core Spec Vol 6 Part B §4.5.9):
    // our transmit sequence number and next-expected sequence number, each 1 bit.
    conn_sn: Cell<u8>,
    conn_nesn: Cell<u8>,
    // Set during an event when the master acknowledged the PDU we transmitted in
    // the previous event (its NESN advanced past our SN).  Reported to the client
    // for stop-and-wait flow control; reset at the start of each event.
    conn_tx_acked: Cell<bool>,
    // True when this event's pre-loaded TX PDU is fresh content being sent for the
    // first time; suppresses the "empty on ack" retransmit guard for that event.
    conn_tx_fresh: Cell<bool>,
}

impl<'a> Radio<'a> {
    pub const fn new() -> Radio<'a> {
        Radio {
            registers: RADIO_BASE,
            tx_power: Cell::new(TxPower::ZerodBm),
            rx_client: OptionalCell::empty(),
            tx_client: OptionalCell::empty(),
            buffer: TakeCell::empty(),
            conn_client: OptionalCell::empty(),
            conn_tx_buf: TakeCell::empty(),
            conn_phase: Cell::new(ConnPhase::Idle),
            conn_rx_ok: Cell::new(false),
            conn_anchor_ticks: Cell::new(0),
            conn_params: Cell::new(None),
            conn_sn: Cell::new(0),
            conn_nesn: Cell::new(0),
            conn_tx_acked: Cell::new(false),
            conn_tx_fresh: Cell::new(false),
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

        // ---------------------------------------------------------------
        // Connection-event path: hardware handles RX→TX via SHORTS.
        // We handle two DISABLED interrupts per event:
        //   1st DISABLED (after RX): swap PACKETPTR to tx_buf for the TX.
        //   2nd DISABLED (after TX): notify the client.
        // ---------------------------------------------------------------
        if self.conn_phase.get() != ConnPhase::Idle {
            // Record CRC result once, after the RX END event.
            if self.registers.event_end.is_set(Event::READY)
                && self.conn_phase.get() == ConnPhase::Rx
            {
                self.registers.event_end.write(Event::READY::CLEAR);
                self.conn_rx_ok
                    .set(self.registers.crcstatus.is_set(Event::READY));
                // Capture anchor: PPI CH26 wrote TIMER0 CC[1] on RADIO_ADDRESS.
                // Read it now while still in the RX END interrupt context.
                self.conn_anchor_ticks.set(timer0_read(T0_CC_BASE + 1 * 4));
            }

            if self.registers.event_disabled.is_set(Event::READY) {
                self.registers.event_disabled.write(Event::READY::CLEAR);

                match self.conn_phase.get() {
                    ConnPhase::Rx => {
                        // RX done, DISABLED_TXEN shortcut has already started TX
                        // ramp-up.  We have ~40 µs before READY fires to update the
                        // pre-loaded TX PDU and swap PACKETPTR to it.

                        // Link-layer acknowledgement / flow control
                        // (BT Core Spec Vol 6 Part B §4.5.9).  Only act on a
                        // good-CRC reception; a corrupt or absent packet must not
                        // advance our sequence numbers.  The received header was
                        // DMA'd into PAYLOAD before the RX END event.
                        if self.conn_rx_ok.get() {
                            let rx_hdr = unsafe { (*addr_of!(PAYLOAD))[0] };
                            let rx_nesn = (rx_hdr >> 2) & 1; // acks our transmitted SN
                            let rx_sn = (rx_hdr >> 3) & 1; // master's sequence number
                            // Master acknowledged our last PDU iff its NESN moved
                            // past our SN; advance (flip) our SN so we send new data.
                            if rx_nesn != self.conn_sn.get() {
                                self.conn_sn.set(rx_nesn);
                                self.conn_tx_acked.set(true);
                            }
                            // A new (non-retransmitted) PDU has SN == the value we
                            // expect next; flip NESN to acknowledge it.
                            if rx_sn == self.conn_nesn.get() {
                                self.conn_nesn.set(self.conn_nesn.get() ^ 1);
                            }
                        }
                        // Stamp the current SN/NESN into the pre-loaded TX PDU
                        // header (bit 2 = NESN, bit 3 = SN) and point the radio at
                        // it.  This happens before the TX ramp completes, so the
                        // ACK bits the master sees reflect the packet just received.
                        let sn = self.conn_sn.get();
                        let nesn = self.conn_nesn.get();
                        let acked = self.conn_tx_acked.get();
                        let fresh = self.conn_tx_fresh.get();
                        if let Some(ptr) = self.conn_tx_buf.map(|b| {
                            // If the master acknowledged our previous (already-
                            // transmitted) PDU, don't retransmit its content with
                            // the advanced SN — that would look like a new,
                            // duplicate PDU.  Send an empty PDU instead.  Fresh
                            // content (not yet transmitted) is exempt: it must go
                            // out even though the prior PDU was just acked.
                            if acked && !fresh && b.len() >= 2 {
                                b[0] = 0x01; // LLID = 0b01 (empty)
                                b[1] = 0x00; // length 0
                            }
                            b[0] = (b[0] & !0b0000_1100) | (nesn << 2) | (sn << 3);
                            b.as_ptr() as u32
                        }) {
                            self.registers.packetptr.set(ptr);
                        }
                        // Remove DISABLED_TXEN so the post-TX DISABLED doesn't
                        // re-trigger another TX automatically.
                        self.registers
                            .shorts
                            .write(Shortcut::READY_START::SET + Shortcut::END_DISABLE::SET);
                        // Disable the window-timeout PPI now that RX succeeded
                        // (or timed out—either way the radio is past the RX phase).
                        ppi_disable(PPI_CH0);
                        self.conn_phase.set(ConnPhase::Tx);
                        self.registers
                            .intenset
                            .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
                    }
                    ConnPhase::Tx => {
                        // TX done.  Clean up and notify the client.
                        ppi_disable(PPI_CH21 | PPI_CH26);
                        self.registers
                            .shorts
                            .write(/* clear */ Shortcut::READY_START::CLEAR);
                        self.conn_phase.set(ConnPhase::Idle);
                        self.radio_off();

                        let result = if self.conn_rx_ok.get() {
                            Ok(())
                        } else {
                            Err(ErrorCode::FAIL)
                        };
                        let anchor = self.conn_anchor_ticks.get();

                        unsafe {
                            self.conn_client.map(|client| {
                                client.connection_event_done(
                                    &mut *addr_of_mut!(PAYLOAD),
                                    self.conn_tx_buf.take().unwrap(),
                                    result,
                                    anchor,
                                    self.conn_tx_acked.get(),
                                )
                            });
                        }
                    }
                    ConnPhase::Idle => {}
                }
            } else {
                // Re-arm interrupts if we didn't handle DISABLED yet.
                self.registers
                    .intenset
                    .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
            }
            return;
        }

        // ---------------------------------------------------------------
        // Advertising / scanning path (unchanged).
        // ---------------------------------------------------------------
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

    fn timer0_init(&self) {
        unsafe {
            timer0_write(T0_TASKS_STOP, 1);
            timer0_write(T0_PRESCALER, 4); // 16 MHz / 2^4 = 1 MHz (1 µs/tick)
            timer0_write(T0_BITMODE, 3); // 32-bit
            timer0_write(T0_TASKS_CLEAR, 1);
            timer0_write(T0_TASKS_START, 1);
        }
    }

    fn connection_configure_impl(&self, params: &ConnectionParams) {
        self.conn_params.set(Some(*params));
        // Reset link-layer sequence numbers for the new connection.
        self.conn_sn.set(0);
        self.conn_nesn.set(0);
        self.conn_tx_acked.set(false);
        self.timer0_init();
        // PPI CH0 (programmable): TIMER0_EVENTS_COMPARE[2] → RADIO_TASKS_DISABLE
        unsafe {
            ppi_configure_ch0(TIMER0_EVENTS_COMPARE2_ADDR, RADIO_TASKS_DISABLE_ADDR);
        }
    }

    fn connection_event_start_impl(
        &self,
        channel: RadioChannel,
        tx_buf: &'static mut [u8],
        open_time_ticks: u32,
        tx_fresh: bool,
    ) -> Result<(), ErrorCode> {
        let params = match self.conn_params.get() {
            Some(p) => p,
            None => return Err(ErrorCode::FAIL),
        };

        if self.conn_phase.get() != ConnPhase::Idle {
            return Err(ErrorCode::BUSY);
        }

        self.conn_tx_buf.replace(tx_buf);
        self.conn_rx_ok.set(false);
        self.conn_tx_acked.set(false);
        self.conn_tx_fresh.set(tx_fresh);

        // Power-cycle resets all radio registers; reconfigure fully each event.
        self.radio_on();

        // Per-connection access address (BALEN=3: base0 = lower 3 bytes << 8,
        // prefix0 AP0 = MSB of access address).
        self.registers
            .base0
            .set((params.access_address & 0x00FF_FFFF) << 8);
        self.registers
            .prefix0
            .set((params.access_address >> 24) & 0xFF);

        // CRC: 3 bytes, exclude access address, per-connection init value
        self.registers
            .crccnf
            .write(CrcConfiguration::LEN::THREE + CrcConfiguration::SKIPADDR::EXCLUDE);
        self.registers
            .crcpoly
            .set(nrf5x::constants::RADIO_CRCPOLY_BLE);
        self.registers
            .crcinit
            .write(CrcInitialValue::CRCINIT.val(params.crc_init));

        // T_IFS = 150 µs (hardware-enforced inter-frame spacing for RX→TX)
        self.registers.tifs.write(InterFrameSpacing::TIFS.val(150));

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

        // SHORTS: READY→START (auto-start on ramp-up), END→DISABLE (packet done),
        // DISABLED→TXEN (hardware T_IFS transition for the ACK).
        self.registers.shorts.write(
            Shortcut::READY_START::SET + Shortcut::END_DISABLE::SET + Shortcut::DISABLED_TXEN::SET,
        );

        unsafe {
            // Clear any stale compare events before (re-)enabling PPI channels.
            timer0_write(T0_EVENTS_COMPARE_BASE, 0);
            timer0_write(T0_EVENTS_COMPARE_BASE + 2 * 4, 0);

            // CC[0]: PPI CH21 fires RADIO_RXEN when TIMER0 reaches this value.
            timer0_write(T0_CC_BASE, open_time_ticks);

            // CC[2]: window-timeout guard (2 ms after open_time).
            // PPI CH0 fires RADIO_TASKS_DISABLE if the master never arrives.
            timer0_write(T0_CC_BASE + 2 * 4, open_time_ticks.wrapping_add(2000));
        }

        ppi_enable(PPI_CH0 | PPI_CH21 | PPI_CH26);

        self.registers
            .intenset
            .write(Interrupt::END::SET + Interrupt::DISABLED::SET);
        self.conn_phase.set(ConnPhase::Rx);

        Ok(())
    }

    fn get_timer0_now_impl(&self) -> u32 {
        // Trigger TASKS_CAPTURE[3] to latch current counter into CC[3], then read CC[3].
        unsafe {
            timer0_write(T0_TASKS_CAPTURE_BASE + 3 * 4, 1);
        }
        timer0_read(T0_CC_BASE + 3 * 4)
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

impl<'a> ble_advertising::BleConnectionDriver<'a> for Radio<'a> {
    fn connection_configure(&self, params: &ConnectionParams) -> Result<(), ErrorCode> {
        self.connection_configure_impl(params);
        Ok(())
    }

    fn connection_event_start(
        &self,
        channel: RadioChannel,
        tx_buf: &'static mut [u8],
        open_time_ticks: u32,
        tx_fresh: bool,
    ) -> Result<(), ErrorCode> {
        self.connection_event_start_impl(channel, tx_buf, open_time_ticks, tx_fresh)
    }

    fn get_timer0_now(&self) -> u32 {
        self.get_timer0_now_impl()
    }

    fn set_connection_event_client(&self, client: &'a dyn ble_advertising::ConnectionEventClient) {
        self.conn_client.set(client);
    }
}

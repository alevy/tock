// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Programmable peripheral interconnect, nRF52
//!
//! Chapter 20 of the nRF52832 Objective Product Specification v0.6.3:
//!
//! The PPI provides a mechanism to automatically trigger a task in one peripheral
//! as a result of an event occurring in another peripheral. A task is connected to
//! an event through a PPI channel.
//! The PPI channel is composed of three end point registers, one event end point (EEP)
//! and two task end points (TEP).
//! A peripheral task is connected to a TEP using the address of the task register
//! associated with the task. Similarly, a peripheral event is connected to an EEP using
//! the address of the event register associated with the event.
//!
//! Pre-programmed Channels
//! (Channel EEP TEP):
//!
//! * 20        `TIMER0->EVENTS_COMPARE[0]`       `RADIO->TASKS_TXEN`
//! * 21        `TIMER0->EVENTS_COMPARE[0]`       `RADIO->TASKS_RXEN`
//! * 22        `TIMER0->EVENTS_COMPARE[1]`       `RADIO->TASKS_DISABLE`
//! * 23        `RADIO->EVENTS_BCMATCH`           `AAR->TASKS_START`
//! * 24        `RADIO->EVENTS_READY`             `CCM->TASKS_KSGEN`
//! * 25        `RADIO->EVENTS_ADDRESS`           `CCM->TASKS_CRYPT`
//! * 26        `RADIO->EVENTS_ADDRESS`           `TIMER0->TASKS_CAPTURE[1]`
//! * 27        `RADIO->EVENTS_END`               `TIMER0->TASKS_CAPTURE[2]`
//! * 28        `RTC0->EVENTS_COMPARE[0]`         `RADIO->TASKS_TXEN`
//! * 29        `RTC0->EVENTS_COMPARE[0]`         `RADIO->TASKS_RXEN`
//! * 30        `RTC0->EVENTS_COMPARE[0]`         `TIMER0->TASKS_CLEAR`
//! * 31        `RTC0->EVENTS_COMPARE[0]`         `TIMER0->TASKS_START`
//!
//! Authors
//! ---------
//! * Johan Lindskogen
//! * Francine Mäkelä
//! * Date: May 04, 2018

use kernel::ErrorCode;
use kernel::utilities::StaticRef;
use tock_registers_v0::fields::FieldValue;
use tock_registers_v0::interfaces::Writeable;
use tock_registers_v0::registers::ReadWrite;
use tock_registers_v0::{register_bitfields, register_structs};

/// Number of freely programmable PPI channels.
///
/// Channels at and above this index are pre-programmed in hardware and cannot
/// have their endpoints reassigned.
pub const NUM_PROGRAMMABLE_CHANNELS: usize = 20;

register_structs! {
    /// Endpoint registers for one programmable PPI channel.
    pub PpiChannelRegisters {
        /// Address of the event register that triggers this channel.
        (0x000 => eep: ReadWrite<u32, EventEndPoint::Register>),
        /// Address of the task register this channel triggers.
        (0x004 => tep: ReadWrite<u32, TaskEndPoint::Register>),
        (0x008 => @END),
    }
}

// Note the reserved word at 0x50C: the channel endpoint array starts at
// 0x510, not immediately after CHENCLR.
register_structs! {
    pub PpiRegisters {
        (0x000 => tasks_chg0_en: ReadWrite<u32, Control::Register>),
        (0x004 => tasks_chg0_dis: ReadWrite<u32, Control::Register>),
        (0x008 => tasks_chg1_en: ReadWrite<u32, Control::Register>),
        (0x00C => tasks_chg1_dis: ReadWrite<u32, Control::Register>),
        (0x010 => tasks_chg2_en: ReadWrite<u32, Control::Register>),
        (0x014 => tasks_chg2_dis: ReadWrite<u32, Control::Register>),
        (0x018 => tasks_chg3_en: ReadWrite<u32, Control::Register>),
        (0x01C => tasks_chg3_dis: ReadWrite<u32, Control::Register>),
        (0x020 => tasks_chg4_en: ReadWrite<u32, Control::Register>),
        (0x024 => tasks_chg4_dis: ReadWrite<u32, Control::Register>),
        (0x028 => tasks_chg5_en: ReadWrite<u32, Control::Register>),
        (0x02C => tasks_chg5_dis: ReadWrite<u32, Control::Register>),
        (0x030 => _reserved1),
        (0x500 => chen: ReadWrite<u32, Channel::Register>),
        (0x504 => chenset: ReadWrite<u32, Channel::Register>),
        (0x508 => chenclr: ReadWrite<u32, Channel::Register>),
        (0x50C => _reserved_ch_endpoints),
        (0x510 => ch: [PpiChannelRegisters; NUM_PROGRAMMABLE_CHANNELS]),
        (0x5B0 => _reserved2),
        (0x7FC => chg: [ReadWrite<u32, Channel::Register>; 6]),
        (0x814 => _reserved3),
        (0x90C => fork_tep: [ReadWrite<u32, TaskEndPoint::Register>; 32]),
        (0x98C => @END),
    }
}

register_bitfields! [u32,
    Control [
        ENABLE OFFSET(0) NUMBITS(1)
    ],
    pub Channel [
         CH0 OFFSET(0) NUMBITS(1),
         CH1 OFFSET(1) NUMBITS(1),
         CH2 OFFSET(2) NUMBITS(1),
         CH3 OFFSET(3) NUMBITS(1),
         CH4 OFFSET(4) NUMBITS(1),
         CH5 OFFSET(5) NUMBITS(1),
         CH6 OFFSET(6) NUMBITS(1),
         CH7 OFFSET(7) NUMBITS(1),
         CH8 OFFSET(8) NUMBITS(1),
         CH9 OFFSET(9) NUMBITS(1),
         CH10 OFFSET(10) NUMBITS(1),
         CH11 OFFSET(11) NUMBITS(1),
         CH12 OFFSET(12) NUMBITS(1),
         CH13 OFFSET(13) NUMBITS(1),
         CH14 OFFSET(14) NUMBITS(1),
         CH15 OFFSET(15) NUMBITS(1),
         CH16 OFFSET(16) NUMBITS(1),
         CH17 OFFSET(17) NUMBITS(1),
         CH18 OFFSET(18) NUMBITS(1),
         CH19 OFFSET(19) NUMBITS(1),
         CH20 OFFSET(20) NUMBITS(1),
         CH21 OFFSET(21) NUMBITS(1),
         CH22 OFFSET(22) NUMBITS(1),
         CH23 OFFSET(23) NUMBITS(1),
         CH24 OFFSET(24) NUMBITS(1),
         CH25 OFFSET(25) NUMBITS(1),
         CH26 OFFSET(26) NUMBITS(1),
         CH27 OFFSET(27) NUMBITS(1),
         CH28 OFFSET(28) NUMBITS(1),
         CH29 OFFSET(29) NUMBITS(1),
         CH30 OFFSET(30) NUMBITS(1),
         CH31 OFFSET(31) NUMBITS(1)
    ],
    TaskEndPoint [
        ADDRESS OFFSET(0) NUMBITS(32)
    ],
    EventEndPoint [
        ADDRESS OFFSET(0) NUMBITS(32)
    ]
];

pub struct Ppi {
    registers: StaticRef<PpiRegisters>,
}

impl Ppi {
    pub const fn new(registers: StaticRef<PpiRegisters>) -> Ppi {
        Ppi { registers }
    }

    pub fn enable(&self, channels: FieldValue<u32, Channel::Register>) {
        self.registers.chenset.write(channels);
    }

    pub fn disable(&self, channels: FieldValue<u32, Channel::Register>) {
        self.registers.chenclr.write(channels);
    }

    /// Route `event` to `task` on programmable channel `channel`.
    ///
    /// `event` and `task` are the addresses of the peripherals' event and task
    /// registers. Configuring a channel does not enable it; see
    /// [`Ppi::enable`].
    ///
    /// # Errors
    ///
    /// - `INVAL`: `channel` is not a programmable channel, i.e. it is not less
    ///   than [`NUM_PROGRAMMABLE_CHANNELS`].
    pub fn configure(&self, channel: usize, event: u32, task: u32) -> Result<(), ErrorCode> {
        let ch = self.registers.ch.get(channel).ok_or(ErrorCode::INVAL)?;
        ch.eep.write(EventEndPoint::ADDRESS.val(event));
        ch.tep.write(TaskEndPoint::ADDRESS.val(task));
        Ok(())
    }
}

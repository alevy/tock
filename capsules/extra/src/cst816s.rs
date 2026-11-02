// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Driver for the Hynitron CST816S capacitive touch controller.
//!
//! The CST816S is a single-touch controller with basic gesture detection,
//! used, e.g., on the SMA Q3 / Bangle.js 2 and PineTime smartwatches. It is
//! connected over I2C (address 0x15) and has an active-low interrupt line,
//! which it pulses for each touch report (every ~10ms while touched), and an
//! active-low reset line.
//!
//! Register map (as used here; the datasheet is sparse):
//!
//! | Register | Contents                                                   |
//! |----------|------------------------------------------------------------|
//! | 0x01     | Gesture ID (0 = none, 1-4 = slide down/up/left/right)      |
//! | 0x02     | Number of fingers (0 or 1)                                 |
//! | 0x03     | Event (bits 7:6: 0 = down, 1 = up, 2 = contact), X[11:8]   |
//! | 0x04     | X[7:0]                                                     |
//! | 0x05     | Touch ID (bits 7:4), Y[11:8]                               |
//! | 0x06     | Y[7:0]                                                     |
//!
//! The controller goes to sleep when not touched and then does not respond
//! on I2C; it only needs to be read in response to an interrupt.
//!
//! The controller does not reliably report the finger being lifted, so this
//! driver also reports a release when no touch report has been received for
//! [`RELEASE_TIMEOUT_MS`].
//!
//! Usage
//! -----
//!
//! See `components::cst816s::Cst816sComponent`.

use core::cell::Cell;

use kernel::ErrorCode;
use kernel::hil::gpio;
use kernel::hil::i2c;
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::hil::touch::{self, GestureEvent, TouchEvent, TouchStatus};
use kernel::utilities::cells::{OptionalCell, TakeCell};

/// Default 7-bit I2C address.
pub const I2C_ADDRESS: u8 = 0x15;

/// Size of the buffer the driver needs.
pub const BUFFER_LEN: usize = 6;

/// Report a release if no touch report arrives for this long while touched.
pub const RELEASE_TIMEOUT_MS: u32 = 50;

/// How long to hold the controller in reset.
const RESET_ASSERT_MS: u32 = 20;
/// How long to wait for the controller to boot after reset.
const RESET_BOOT_MS: u32 = 100;

/// First register read on each interrupt; the 6 report registers are read in
/// one transfer.
const REG_GESTURE_ID: u8 = 0x01;

// Values of the gesture ID register. The controller also reports single
// clicks (0x05), double clicks (0x0B) and long presses (0x0C), which have no
// `GestureEvent` equivalent (clients see them as touch events anyway).
const GESTURE_SLIDE_DOWN: u8 = 0x01;
const GESTURE_SLIDE_UP: u8 = 0x02;
const GESTURE_SLIDE_LEFT: u8 = 0x03;
const GESTURE_SLIDE_RIGHT: u8 = 0x04;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum State {
    /// `init` has not been called yet.
    Uninitialized,
    /// Holding the reset line low.
    Resetting,
    /// Waiting for the controller to boot after reset.
    Booting,
    /// Ready; touch reports are handled while `enabled`.
    Ready,
}

pub struct Cst816s<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> {
    i2c: &'a I,
    interrupt_pin: &'a dyn gpio::InterruptPin<'a>,
    reset_pin: Option<&'a dyn gpio::Pin>,
    alarm: &'a A,
    touch_client: OptionalCell<&'a dyn touch::TouchClient>,
    gesture_client: OptionalCell<&'a dyn touch::GestureClient>,
    buffer: TakeCell<'static, [u8]>,
    state: Cell<State>,
    enabled: Cell<bool>,
    /// Whether a finger is currently down (a Pressed event was reported and
    /// no Released event yet).
    touching: Cell<bool>,
    /// Last reported position, used for the Released event.
    last: Cell<(u16, u16)>,
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> Cst816s<'a, I, A> {
    pub fn new(
        i2c: &'a I,
        interrupt_pin: &'a dyn gpio::InterruptPin<'a>,
        reset_pin: Option<&'a dyn gpio::Pin>,
        alarm: &'a A,
        buffer: &'static mut [u8],
    ) -> Self {
        Cst816s {
            i2c,
            interrupt_pin,
            reset_pin,
            alarm,
            touch_client: OptionalCell::empty(),
            gesture_client: OptionalCell::empty(),
            buffer: TakeCell::new(buffer),
            state: Cell::new(State::Uninitialized),
            enabled: Cell::new(false),
            touching: Cell::new(false),
            last: Cell::new((0, 0)),
        }
    }

    /// Reset the controller and start listening for touch reports. Must be
    /// called once, after the I2C, GPIO and alarm clients have been set.
    pub fn init(&self) {
        self.interrupt_pin.make_input();
        match self.reset_pin {
            Some(reset) => {
                reset.make_output();
                reset.clear();
                self.state.set(State::Resetting);
                self.alarm
                    .set_alarm(self.alarm.now(), self.alarm.ticks_from_ms(RESET_ASSERT_MS));
            }
            None => self.ready(),
        }
    }

    fn ready(&self) {
        self.state.set(State::Ready);
        self.interrupt_pin
            .enable_interrupts(gpio::InterruptEdge::FallingEdge);
    }

    fn report(&self, status: TouchStatus, x: u16, y: u16, id: usize) {
        self.touch_client.map(|client| {
            client.touch_event(TouchEvent {
                status,
                x,
                y,
                id,
                size: None,
                pressure: None,
            })
        });
    }

    fn release(&self) {
        if self.touching.get() {
            self.touching.set(false);
            let (x, y) = self.last.get();
            self.report(TouchStatus::Released, x, y, 0);
        }
    }

    fn handle_report(&self, buffer: &[u8]) {
        let gesture = buffer[0];
        let fingers = buffer[1] & 0x0F;
        let event = buffer[2] >> 6;
        let x = (((buffer[2] & 0x0F) as u16) << 8) | buffer[3] as u16;
        let y = (((buffer[4] & 0x0F) as u16) << 8) | buffer[5] as u16;

        if fingers == 0 || event == 1 {
            self.release();
        } else {
            let status = if self.touching.get() {
                TouchStatus::Moved
            } else {
                TouchStatus::Pressed
            };
            self.touching.set(true);
            self.last.set((x, y));
            self.report(status, x, y, 0);
            // Release if no further report arrives.
            self.alarm.set_alarm(
                self.alarm.now(),
                self.alarm.ticks_from_ms(RELEASE_TIMEOUT_MS),
            );
        }

        let gesture = match gesture {
            GESTURE_SLIDE_DOWN => Some(GestureEvent::SwipeDown),
            GESTURE_SLIDE_UP => Some(GestureEvent::SwipeUp),
            GESTURE_SLIDE_LEFT => Some(GestureEvent::SwipeLeft),
            GESTURE_SLIDE_RIGHT => Some(GestureEvent::SwipeRight),
            _ => None,
        };
        if let Some(gesture) = gesture {
            self.gesture_client
                .map(|client| client.gesture_event(gesture));
        }
    }
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> gpio::Client for Cst816s<'a, I, A> {
    fn fired(&self) {
        if self.state.get() != State::Ready || !self.enabled.get() {
            return;
        }
        // If a read is still in progress, skip this report: the controller
        // sends another one ~10ms later.
        self.buffer.take().map(|buffer| {
            buffer[0] = REG_GESTURE_ID;
            if let Err((_err, buffer)) = self.i2c.write_read(buffer, 1, BUFFER_LEN) {
                self.buffer.replace(buffer);
            }
        });
    }
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> i2c::I2CClient for Cst816s<'a, I, A> {
    fn command_complete(&self, buffer: &'static mut [u8], status: Result<(), i2c::Error>) {
        if status.is_ok() && self.enabled.get() {
            self.handle_report(buffer);
        }
        self.buffer.replace(buffer);
    }
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> AlarmClient for Cst816s<'a, I, A> {
    fn alarm(&self) {
        match self.state.get() {
            State::Resetting => {
                self.reset_pin.map(|reset| reset.set());
                self.state.set(State::Booting);
                self.alarm
                    .set_alarm(self.alarm.now(), self.alarm.ticks_from_ms(RESET_BOOT_MS));
            }
            State::Booting => self.ready(),
            // Release timeout.
            State::Ready => self.release(),
            State::Uninitialized => {}
        }
    }
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> touch::Touch<'a> for Cst816s<'a, I, A> {
    fn enable(&self) -> Result<(), ErrorCode> {
        self.enabled.set(true);
        Ok(())
    }

    fn disable(&self) -> Result<(), ErrorCode> {
        self.enabled.set(false);
        self.release();
        Ok(())
    }

    fn set_client(&self, client: &'a dyn touch::TouchClient) {
        self.touch_client.replace(client);
    }
}

impl<'a, I: i2c::I2CDevice<'a>, A: Alarm<'a>> touch::Gesture<'a> for Cst816s<'a, I, A> {
    fn set_client(&self, client: &'a dyn touch::GestureClient) {
        self.gesture_client.replace(client);
    }
}

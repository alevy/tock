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
//! By default, the controller may only pulse its interrupt line once it has
//! recognized a gesture (e.g., after a tap has ended). After reset, this
//! driver therefore configures it (register 0xFA) to also pulse the
//! interrupt line periodically while touched and on touch changes, as other
//! drivers (e.g., InfiniTime's) do. It then reads the chip ID (register
//! 0xA7) and prints it with `debug!`, or prints an error if the controller
//! does not respond, which helps diagnosing wiring issues.
//!
//! Should the controller still only report a tap once it is over, the tap
//! is reported as a touch press followed by a release.
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
///
/// This is also how long a tap reported only as a gesture is held down, so
/// it must be long enough for clients polling the touch state (e.g., LVGL,
/// every 30ms by default) to see the press.
pub const RELEASE_TIMEOUT_MS: u32 = 80;

/// How long to hold the controller in reset.
const RESET_ASSERT_MS: u32 = 10;
/// How long to wait for the controller to boot after reset. It goes to sleep
/// (and stops responding on I2C) after a while, so it must be configured
/// soon after reset.
const RESET_BOOT_MS: u32 = 50;

/// Report an error if an I2C transfer during initialization does not
/// complete within this time (e.g., if the bus is held low).
const I2C_TIMEOUT_MS: u32 = 100;

/// Interrupt control register.
const REG_IRQ_CTL: u8 = 0xFA;
/// EnTouch (0x40): pulse periodically while touched; EnChange (0x20): pulse
/// when the touch state changes; EnMotion (0x10): pulse on gestures.
const IRQ_CTL_VALUE: u8 = 0x70;
/// Chip ID register (0xB4, 0xB5 or 0xB6 for CST816S variants).
const REG_CHIP_ID: u8 = 0xA7;

/// First register read on each interrupt; the 6 report registers are read in
/// one transfer.
const REG_GESTURE_ID: u8 = 0x01;

// Values of the gesture ID register. The controller also reports double
// clicks (0x0B) and long presses (0x0C), which have no `GestureEvent`
// equivalent (clients see them as touch events anyway).
const GESTURE_SLIDE_DOWN: u8 = 0x01;
const GESTURE_SLIDE_UP: u8 = 0x02;
const GESTURE_SLIDE_LEFT: u8 = 0x03;
const GESTURE_SLIDE_RIGHT: u8 = 0x04;
const GESTURE_SINGLE_CLICK: u8 = 0x05;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum State {
    /// `init` has not been called yet.
    Uninitialized,
    /// Holding the reset line low.
    Resetting,
    /// Waiting for the controller to boot after reset.
    Booting,
    /// Writing the interrupt control register.
    ConfiguringIrq,
    /// Reading the chip ID.
    ReadingChipId,
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
    /// Coordinate scaling: (raw maximum, width, height). See `set_scaling`.
    scaling: Cell<Option<(u16, u16, u16)>>,
    /// Whether the first interrupt / failed read has been logged, for
    /// diagnosing wiring issues without flooding the console.
    logged_interrupt: Cell<bool>,
    logged_read_error: Cell<bool>,
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
            scaling: Cell::new(None),
            logged_interrupt: Cell::new(false),
            logged_read_error: Cell::new(false),
        }
    }

    /// Scale raw coordinates, which range from 0 to `raw_max` on some panels
    /// (e.g., 160 on the SMA Q3), to a `width` x `height` screen. Raw values
    /// above `raw_max` are clamped to the screen edge, except for x values of
    /// 250 or more, which some panels report for touches at the very top of
    /// the screen, and which are treated as 0.
    pub fn set_scaling(&self, raw_max: u16, width: u16, height: u16) {
        self.scaling.set(Some((raw_max, width, height)));
    }

    fn scale(&self, x: u16, y: u16) -> (u16, u16) {
        match self.scaling.get() {
            None => (x, y),
            Some((raw_max, width, height)) => {
                let x = if x >= 250 { 0 } else { x.min(raw_max) };
                let y = y.min(raw_max);
                // Map 0..=raw_max onto 0..=size-1.
                let scale = |v: u16, size: u16| {
                    (v as u32 * (size as u32 - 1) / raw_max.max(1) as u32) as u16
                };
                (scale(x, width), scale(y, height))
            }
        }
    }

    /// Reset the controller and start listening for touch reports. Must be
    /// called once, after the I2C, GPIO and alarm clients have been set.
    pub fn init(&self) {
        self.interrupt_pin.make_input();
        self.interrupt_pin
            .set_floating_state(gpio::FloatingState::PullUp);
        match self.reset_pin {
            Some(reset) => {
                reset.make_output();
                reset.clear();
                self.state.set(State::Resetting);
                self.alarm
                    .set_alarm(self.alarm.now(), self.alarm.ticks_from_ms(RESET_ASSERT_MS));
            }
            None => self.configure(),
        }
    }

    /// Configure the controller's interrupt line, then read its chip ID.
    fn configure(&self) {
        match self.buffer.take() {
            Some(buffer) => {
                buffer[0] = REG_IRQ_CTL;
                buffer[1] = IRQ_CTL_VALUE;
                self.state.set(State::ConfiguringIrq);
                match self.i2c.write(buffer, 2) {
                    Ok(()) => self.start_i2c_timeout(),
                    Err((err, buffer)) => {
                        kernel::debug!("cst816s: cannot configure interrupts: {:?}", err);
                        self.buffer.replace(buffer);
                        self.ready();
                    }
                }
            }
            None => self.ready(),
        }
    }

    fn read_chip_id(&self, buffer: &'static mut [u8]) {
        buffer[0] = REG_CHIP_ID;
        self.state.set(State::ReadingChipId);
        match self.i2c.write_read(buffer, 1, 1) {
            Ok(()) => self.start_i2c_timeout(),
            Err((err, buffer)) => {
                kernel::debug!("cst816s: cannot read chip ID: {:?}", err);
                self.buffer.replace(buffer);
                self.ready();
            }
        }
    }

    fn start_i2c_timeout(&self) {
        self.alarm
            .set_alarm(self.alarm.now(), self.alarm.ticks_from_ms(I2C_TIMEOUT_MS));
    }

    fn ready(&self) {
        // Cancel any initialization timeout.
        let _ = self.alarm.disarm();
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
        let (x, y) = self.scale(
            (((buffer[2] & 0x0F) as u16) << 8) | buffer[3] as u16,
            (((buffer[4] & 0x0F) as u16) << 8) | buffer[5] as u16,
        );

        if (fingers == 0 || event == 1) && !self.touching.get() && gesture == GESTURE_SINGLE_CLICK {
            // The controller only reported the tap once it was over. Report
            // it as a press, released after `RELEASE_TIMEOUT_MS` such that
            // clients polling the touch state see it.
            self.touching.set(true);
            self.last.set((x, y));
            self.report(TouchStatus::Pressed, x, y, 0);
            self.alarm.set_alarm(
                self.alarm.now(),
                self.alarm.ticks_from_ms(RELEASE_TIMEOUT_MS),
            );
        } else if fingers == 0 || event == 1 {
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
        if !self.logged_interrupt.get() {
            self.logged_interrupt.set(true);
            kernel::debug!("cst816s: first touch interrupt");
        }
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
        match self.state.get() {
            State::ConfiguringIrq => {
                if let Err(err) = status {
                    kernel::debug!("cst816s: configuring interrupts failed: {:?}", err);
                }
                self.read_chip_id(buffer);
            }
            State::ReadingChipId => {
                match status {
                    Ok(()) => kernel::debug!("cst816s: chip ID {:#04x}", buffer[0]),
                    Err(err) => kernel::debug!(
                        "cst816s: no response to chip ID read ({:?}), check the I2C wiring",
                        err
                    ),
                }
                self.buffer.replace(buffer);
                self.ready();
            }
            _ => {
                match status {
                    Ok(()) if self.enabled.get() => self.handle_report(buffer),
                    Ok(()) => {}
                    Err(err) => {
                        if !self.logged_read_error.get() {
                            self.logged_read_error.set(true);
                            kernel::debug!("cst816s: reading touch report failed: {:?}", err);
                        }
                    }
                }
                self.buffer.replace(buffer);
            }
        }
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
            State::Booting => self.configure(),
            // Release timeout.
            State::Ready => self.release(),
            State::ConfiguringIrq | State::ReadingChipId => {
                // The transfer is still in progress, and the I2C HIL offers
                // no way to abort it: report it, the driver cannot proceed.
                kernel::debug!(
                    "cst816s: I2C transfer did not complete within {}ms; is the bus held low (missing pull-ups on SDA/SCL)?",
                    I2C_TIMEOUT_MS
                );
            }
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::RefCell;
    use kernel::hil::gpio::Client as _;
    use kernel::hil::gpio::{Configuration, FloatingState, InterruptEdge};
    use kernel::hil::i2c::I2CClient as _;
    use kernel::hil::time::{Freq32KHz, Ticks, Ticks32, Time};
    use std::boxed::Box;
    use std::vec::Vec;

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum I2cOp {
        Write { reg: u8, value: u8 },
        WriteRead { reg: u8, read_len: usize },
    }

    struct MockI2c {
        pending: TakeCell<'static, [u8]>,
        ops: RefCell<Vec<I2cOp>>,
    }

    impl Default for MockI2c {
        fn default() -> Self {
            MockI2c {
                pending: TakeCell::empty(),
                ops: RefCell::new(Vec::new()),
            }
        }
    }

    impl<'a> i2c::I2CDevice<'a> for MockI2c {
        fn enable(&self) {}
        fn disable(&self) {}
        fn write_read(
            &self,
            data: &'static mut [u8],
            _write_len: usize,
            read_len: usize,
        ) -> Result<(), (i2c::Error, &'static mut [u8])> {
            self.ops.borrow_mut().push(I2cOp::WriteRead {
                reg: data[0],
                read_len,
            });
            self.pending.replace(data);
            Ok(())
        }
        fn write(
            &self,
            data: &'static mut [u8],
            _len: usize,
        ) -> Result<(), (i2c::Error, &'static mut [u8])> {
            self.ops.borrow_mut().push(I2cOp::Write {
                reg: data[0],
                value: data[1],
            });
            self.pending.replace(data);
            Ok(())
        }
        fn read(
            &self,
            buffer: &'static mut [u8],
            _len: usize,
        ) -> Result<(), (i2c::Error, &'static mut [u8])> {
            Err((i2c::Error::NotSupported, buffer))
        }
        fn set_client(&'a self, _client: &'a dyn i2c::I2CClient) {}
    }

    #[derive(Default)]
    struct MockPin {
        level: Cell<bool>,
        output: Cell<bool>,
        interrupts: Cell<Option<InterruptEdge>>,
        pull_up: Cell<bool>,
    }

    impl gpio::Configure for MockPin {
        fn configuration(&self) -> Configuration {
            Configuration::Input
        }
        fn make_output(&self) -> Configuration {
            self.output.set(true);
            Configuration::Output
        }
        fn disable_output(&self) -> Configuration {
            Configuration::Input
        }
        fn make_input(&self) -> Configuration {
            Configuration::Input
        }
        fn disable_input(&self) -> Configuration {
            Configuration::Output
        }
        fn deactivate_to_low_power(&self) {}
        fn set_floating_state(&self, state: FloatingState) {
            self.pull_up.set(matches!(state, FloatingState::PullUp));
        }
        fn floating_state(&self) -> FloatingState {
            FloatingState::PullNone
        }
    }
    impl gpio::Output for MockPin {
        fn set(&self) {
            self.level.set(true);
        }
        fn clear(&self) {
            self.level.set(false);
        }
        fn toggle(&self) -> bool {
            self.level.set(!self.level.get());
            self.level.get()
        }
    }
    impl gpio::Input for MockPin {
        fn read(&self) -> bool {
            self.level.get()
        }
    }
    impl<'a> gpio::Interrupt<'a> for MockPin {
        fn set_client(&self, _client: &'a dyn gpio::Client) {}
        fn enable_interrupts(&self, mode: InterruptEdge) {
            self.interrupts.set(Some(mode));
        }
        fn disable_interrupts(&self) {
            self.interrupts.set(None);
        }
        fn is_pending(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct MockAlarm {
        armed: Cell<Option<u32>>,
    }
    impl Time for MockAlarm {
        type Frequency = Freq32KHz;
        type Ticks = Ticks32;
        fn now(&self) -> Ticks32 {
            0.into()
        }
    }
    impl<'a> Alarm<'a> for MockAlarm {
        fn set_alarm_client(&self, _client: &'a dyn AlarmClient) {}
        fn set_alarm(&self, _reference: Ticks32, dt: Ticks32) {
            self.armed.set(Some(dt.into_u32()));
        }
        fn get_alarm(&self) -> Ticks32 {
            0.into()
        }
        fn disarm(&self) -> Result<(), ErrorCode> {
            self.armed.set(None);
            Ok(())
        }
        fn is_armed(&self) -> bool {
            self.armed.get().is_some()
        }
        fn minimum_dt(&self) -> Ticks32 {
            1.into()
        }
    }

    #[derive(Default)]
    struct Recorder {
        touches: RefCell<Vec<(&'static str, u16, u16)>>,
        gestures: RefCell<Vec<&'static str>>,
    }
    impl touch::TouchClient for Recorder {
        fn touch_event(&self, e: TouchEvent) {
            let status = match e.status {
                TouchStatus::Pressed => "pressed",
                TouchStatus::Moved => "moved",
                TouchStatus::Released => "released",
                TouchStatus::Unstarted => "unstarted",
            };
            self.touches.borrow_mut().push((status, e.x, e.y));
        }
    }
    impl touch::GestureClient for Recorder {
        fn gesture_event(&self, g: GestureEvent) {
            let name = match g {
                GestureEvent::SwipeUp => "up",
                GestureEvent::SwipeDown => "down",
                GestureEvent::SwipeLeft => "left",
                GestureEvent::SwipeRight => "right",
                GestureEvent::ZoomIn => "zoom in",
                GestureEvent::ZoomOut => "zoom out",
            };
            self.gestures.borrow_mut().push(name);
        }
    }

    struct Fixture {
        i2c: &'static MockI2c,
        int: &'static MockPin,
        rst: &'static MockPin,
        alarm: &'static MockAlarm,
        rec: &'static Recorder,
        dev: &'static Cst816s<'static, MockI2c, MockAlarm>,
    }

    impl Fixture {
        fn new() -> Self {
            let i2c: &'static MockI2c = Box::leak(Box::default());
            let int: &'static MockPin = Box::leak(Box::default());
            let rst: &'static MockPin = Box::leak(Box::default());
            rst.level.set(true);
            let alarm: &'static MockAlarm = Box::leak(Box::default());
            let rec: &'static Recorder = Box::leak(Box::default());
            let buffer: &'static mut [u8] = Box::leak(Box::new([0u8; BUFFER_LEN]));
            let dev: &'static Cst816s<'static, MockI2c, MockAlarm> =
                Box::leak(Box::new(Cst816s::new(i2c, int, Some(rst), alarm, buffer)));
            touch::Touch::set_client(dev, rec);
            touch::Gesture::set_client(dev, rec);
            Fixture {
                i2c,
                int,
                rst,
                alarm,
                rec,
                dev,
            }
        }

        fn fire_alarm(&self) {
            assert!(self.alarm.armed.take().is_some(), "alarm not armed");
            self.dev.alarm();
        }

        /// Complete the pending I2C operation, with `data` read back.
        fn complete_i2c(&self, data: &[u8], status: Result<(), i2c::Error>) {
            let buffer = self.i2c.pending.take().expect("no pending I2C operation");
            buffer[..data.len()].copy_from_slice(data);
            self.dev.command_complete(buffer, status);
        }

        fn last_op(&self) -> I2cOp {
            *self.i2c.ops.borrow().last().unwrap()
        }

        /// Run the startup sequence, with the controller responding.
        fn init(&self) {
            self.dev.init();
            self.fire_alarm(); // end of reset
            self.fire_alarm(); // booted
            self.complete_i2c(&[], Ok(())); // IRQ_CTL written
            self.complete_i2c(&[0xB5], Ok(())); // chip ID
        }

        /// Interrupt followed by a touch report.
        fn report(&self, gesture: u8, fingers: u8, event: u8, x: u16, y: u16) {
            self.dev.fired();
            assert_eq!(
                self.last_op(),
                I2cOp::WriteRead {
                    reg: REG_GESTURE_ID,
                    read_len: BUFFER_LEN
                }
            );
            self.complete_i2c(
                &[
                    gesture,
                    fingers,
                    (event << 6) | (x >> 8) as u8,
                    x as u8,
                    (y >> 8) as u8,
                    y as u8,
                ],
                Ok(()),
            );
        }

        fn touches(&self) -> Vec<(&'static str, u16, u16)> {
            self.rec.touches.take()
        }
    }

    #[test]
    fn init_resets_configures_and_enables_interrupts() {
        let f = Fixture::new();
        f.dev.init();
        assert!(f.int.pull_up.get());
        assert!(f.rst.output.get());
        assert!(!f.rst.level.get(), "reset asserted");
        assert!(f.int.interrupts.get().is_none());

        f.fire_alarm();
        assert!(f.rst.level.get(), "reset released");
        assert_eq!(f.i2c.ops.borrow().len(), 0);

        f.fire_alarm();
        assert_eq!(
            f.last_op(),
            I2cOp::Write {
                reg: REG_IRQ_CTL,
                value: IRQ_CTL_VALUE
            }
        );
        f.complete_i2c(&[], Ok(()));
        assert_eq!(
            f.last_op(),
            I2cOp::WriteRead {
                reg: REG_CHIP_ID,
                read_len: 1
            }
        );
        assert!(f.int.interrupts.get().is_none());
        f.complete_i2c(&[0xB5], Ok(()));
        assert!(matches!(
            f.int.interrupts.get(),
            Some(InterruptEdge::FallingEdge)
        ));
    }

    #[test]
    fn init_continues_when_controller_does_not_respond() {
        let f = Fixture::new();
        f.dev.init();
        f.fire_alarm();
        f.fire_alarm();
        f.complete_i2c(&[], Err(i2c::Error::AddressNak));
        f.complete_i2c(&[], Err(i2c::Error::AddressNak));
        assert!(f.int.interrupts.get().is_some());
        // The buffer is available again for touch reports.
        touch::Touch::enable(f.dev).unwrap();
        f.report(0, 1, 2, 10, 20);
        assert_eq!(f.touches(), [("pressed", 10, 20)]);
    }

    #[test]
    fn stuck_i2c_transfer_times_out() {
        let f = Fixture::new();
        f.dev.init();
        f.fire_alarm();
        f.fire_alarm();
        // The interrupt control register write never completes.
        f.fire_alarm();
        assert!(f.int.interrupts.get().is_none());
        // Should it eventually complete, initialization resumes.
        f.complete_i2c(&[], Ok(()));
        f.complete_i2c(&[0xB5], Ok(()));
        assert!(f.int.interrupts.get().is_some());
        assert!(f.alarm.armed.get().is_none(), "timeout cancelled");
    }

    #[test]
    fn press_move_release() {
        let f = Fixture::new();
        f.init();
        touch::Touch::enable(f.dev).unwrap();
        f.report(0, 1, 0, 10, 20);
        f.report(0, 1, 2, 11, 21);
        f.report(0, 1, 2, 300, 260);
        f.report(0, 0, 1, 300, 260);
        assert_eq!(
            f.touches(),
            [
                ("pressed", 10, 20),
                ("moved", 11, 21),
                ("moved", 300, 260),
                ("released", 300, 260)
            ]
        );
    }

    #[test]
    fn release_reported_on_timeout() {
        let f = Fixture::new();
        f.init();
        touch::Touch::enable(f.dev).unwrap();
        f.report(0, 1, 0, 10, 20);
        f.fire_alarm();
        assert_eq!(f.touches(), [("pressed", 10, 20), ("released", 10, 20)]);
        // No further release once released.
        f.dev.alarm();
        assert_eq!(f.touches().len(), 0);
    }

    #[test]
    fn tap_reported_only_as_gesture_becomes_press_and_release() {
        let f = Fixture::new();
        f.init();
        touch::Touch::enable(f.dev).unwrap();
        f.report(GESTURE_SINGLE_CLICK, 0, 1, 88, 40);
        assert_eq!(f.touches(), [("pressed", 88, 40)]);
        assert!(f.alarm.armed.get().is_some(), "release scheduled");
        f.fire_alarm();
        assert_eq!(f.touches(), [("released", 88, 40)]);
    }

    #[test]
    fn swipes_are_reported_as_gestures() {
        let f = Fixture::new();
        f.init();
        touch::Touch::enable(f.dev).unwrap();
        for g in [
            GESTURE_SLIDE_DOWN,
            GESTURE_SLIDE_UP,
            GESTURE_SLIDE_LEFT,
            GESTURE_SLIDE_RIGHT,
        ] {
            f.report(g, 0, 1, 0, 0);
        }
        assert_eq!(f.rec.gestures.take(), ["down", "up", "left", "right"]);
    }

    #[test]
    fn coordinates_are_scaled() {
        let f = Fixture::new();
        f.dev.set_scaling(160, 176, 176);
        f.init();
        touch::Touch::enable(f.dev).unwrap();
        f.report(0, 1, 0, 0, 0);
        f.report(0, 1, 2, 80, 160);
        f.report(0, 1, 2, 200, 170);
        f.report(0, 1, 2, 252, 10);
        assert_eq!(
            f.touches(),
            [
                ("pressed", 0, 0),
                ("moved", 87, 175),
                ("moved", 175, 175),
                ("moved", 0, 10)
            ]
        );
    }

    #[test]
    fn no_events_while_disabled() {
        let f = Fixture::new();
        f.init();
        f.dev.fired();
        assert!(f.i2c.pending.is_none(), "no read while disabled");
        touch::Touch::enable(f.dev).unwrap();
        f.report(0, 1, 0, 10, 20);
        touch::Touch::disable(f.dev).unwrap();
        // Disabling releases an ongoing touch.
        assert_eq!(f.touches(), [("pressed", 10, 20), ("released", 10, 20)]);
    }
}

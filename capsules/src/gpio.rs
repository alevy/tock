//! GPIO Capsule
//!
//! Provides a driver for userspace applications to control GPIO pins.  GPIOs
//! are presented through a driver interface with synchronous comands and a
//! callback for interrupts.

use kernel::{AppId, Callback, Container, Driver, ReturnCode};
use kernel::hil::gpio::{Pin, PinCtl, InputMode, InterruptMode, Client};

#[derive(Default)]
pub struct App {
    callback: Option<Callback>,
    subscribe_map: u32
}

pub struct GPIO<'a, G: Pin + 'a> {
    pins: &'a [&'a G],
    app: Container<App>,
}

impl<'a, G: Pin + PinCtl> GPIO<'a, G> {
    pub fn new(pins: &'a [&'a G], container: Container<App>) -> GPIO<'a, G> {
        GPIO {
            pins: pins,
            app: container,
        }
    }

    fn configure_input_pin(&self, pin: &G, config: usize) -> ReturnCode {
        pin.make_input();
        match config {
            0 => {
                pin.set_input_mode(InputMode::PullUp);
                ReturnCode::SUCCESS
            }

            1 => {
                pin.set_input_mode(InputMode::PullDown);
                ReturnCode::SUCCESS
            }

            2 => {
                pin.set_input_mode(InputMode::PullNone);
                ReturnCode::SUCCESS
            }

            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn configure_interrupt(&self, pin_num: usize, pin: &G, config: usize) -> ReturnCode {
        match config {
            0 => {
                pin.enable_interrupt(pin_num, InterruptMode::EitherEdge);
                ReturnCode::SUCCESS
            }

            1 => {
                pin.enable_interrupt(pin_num, InterruptMode::RisingEdge);
                ReturnCode::SUCCESS
            }

            2 => {
                pin.enable_interrupt(pin_num, InterruptMode::FallingEdge);
                ReturnCode::SUCCESS
            }

            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

impl<'a, G: Pin> Client for GPIO<'a, G> {
    fn fired(&self, pin_num: usize) {
        // read the value of the pin
        self.pins.get(pin_num).map(|pin| {
            let pin_state = pin.read();
            // schedule callback with the pin number and value
            self.app.each(|app| {
                app.callback.map(|mut cb| {
                    if app.subscribe_map | 1 << pin_num != 0 {
                        cb.schedule(pin_num, pin_state as usize, 0);
                    }
                });
            });
        }).unwrap_or(());

    }
}

impl<'a, G: Pin + PinCtl> Driver for GPIO<'a, G> {
    fn subscribe(&self, subscribe_num: usize, callback: Callback) -> ReturnCode {
        match subscribe_num {
            // subscribe to all pin interrupts
            // (no affect or reliance on individual pins being configured as
            // interrupts)
            0 => {
                self.app.enter(callback.app_id(), |app, _| {
                    app.callback = Some(callback);
                }).unwrap_or(());
                ReturnCode::SUCCESS
            }

            // default
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn command(&self, command_num: usize, data: usize, app_id: AppId) -> ReturnCode {
        let pins = self.pins;
        match command_num {
            // number of pins
            0 => ReturnCode::SuccessWithValue { value: pins.len() as usize },

            // enable output
            1 => {
                pins.get(data).map(|pin| {
                    pin.make_output();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // set pin
            2 => {
                pins.get(data).map(|pin| {
                    pin.set();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // clear pin
            3 => {
                pins.get(data).map(|pin| {
                    pin.clear();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // toggle pin
            4 => {
                pins.get(data).map(|pin| {
                    pin.toggle();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // enable and configure input
            5 => {
                // XXX: this is clunky
                // data == ((pin_config << 8) | pin)
                // this allows two values to be passed into a command interface
                let pin_num = data & 0xFF;
                let pin_config = (data >> 8) & 0xFF;
                pins.get(pin_num).map(|pin| {
                    self.configure_input_pin(pin, pin_config)
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // read input
            6 => {
                pins.get(data).map(|pin| {
                    let pin_state = pin.read();
                    ReturnCode::SuccessWithValue { value: pin_state as usize }
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // enable and configure interrupts on pin, also sets pin as input
            // (no affect or reliance on registered callback)
            7 => {
                // TODO(brghena): this is clunky
                // data == ((irq_config << 16) | (pin_config << 8) | pin)
                // this allows three values to be passed into a command interface
                let pin_num = data & 0xFF;
                let pin_config = (data >> 8) & 0xFF;
                let irq_config = (data >> 16) & 0xFF;
                pins.get(pin_num).map(|pin| {
                    self.app.enter(app_id, |app, _| {
                        app.subscribe_map |= 1 << pin_num;
                    }).unwrap_or(());

                    let mut err_code = self.configure_input_pin(pin, pin_config);
                    if err_code == ReturnCode::SUCCESS {
                        err_code = self.configure_interrupt(pin_num, pin, irq_config);
                    }
                    err_code
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // disable interrupts on pin, also disables pin
            // (no affect or reliance on registered callback)
            8 => {
                pins.get(data).map(|pin| {
                    pin.disable_interrupt();
                    pin.disable();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // disable pin
            9 => {
                pins.get(data).map(|pin| {
                    pin.disable();
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)
            }

            // default
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

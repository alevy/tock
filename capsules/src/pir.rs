//! PIR Capsule
//!
//! Provides a driver for userspace applications to control PIR sensors.

use kernel::{AppId, Callback, Container, Driver, ReturnCode};
use kernel::hil::gpio::{Pin, PinCtl, InputMode, InterruptMode, Client};

#[derive(Default)]
pub struct App {
    callback: Option<Callback>,
    subscribe: bool
}

pub struct PIR<'a, G: Pin + 'a> {
    pin: &'a G,
    app: Container<App>,
}

impl<'a, G: Pin + PinCtl> PIR<'a, G> {
    pub fn new(pin: &'a G, container: Container<App>) -> PIR<'a, G> {
        pin.make_input();
        pin.set_input_mode(InputMode::PullUp);
        PIR {
            pin: pin,
            app: container,
        }
    }
}

impl<'a, G: Pin> Client for PIR<'a, G> {
    fn fired(&self, _: usize) {
        let pin_state = self.pin.read();
        // schedule callback with value of the PIR pin
        self.app.each(|app| {
            app.callback.map(|mut cb| {
                if app.subscribe {
                    cb.schedule(pin_state as usize, 0, 0);
                }
            });
        });
    }
}

impl<'a, G: Pin + PinCtl> Driver for PIR<'a, G> {
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

    fn command(&self, command_num: usize, _: usize, app_id: AppId) -> ReturnCode {
        match command_num {
            // driver present
            0 => ReturnCode::SUCCESS,

            // enable and configure interrupts on pin, also sets pin as input
            // (no affect or reliance on registered callback)
            1 => {
                self.app.enter(app_id, |app, _| {
                    self.pin.enable_interrupt(0, InterruptMode::EitherEdge);
                    app.subscribe = true;
                    ReturnCode::SUCCESS
                }).unwrap_or(ReturnCode::EINVAL)

            }

            // default
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

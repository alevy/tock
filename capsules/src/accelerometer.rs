//! Provides userspace with virtualized access to 9DOF sensors.
//!
//! Usage
//! -----
//!
//! You need a device that provides the `hil::sensors::Accelerometer` trait.
//!
//! ``rust
//! let ninedof = static_init!(
//!     capsules::ninedof::Accelerometer<'static>,
//!     capsules::ninedof::Accelerometer::new(fxos8700, kernel::Container::create()));
//! hil::sensors::Accelerometer::set_client(fxos8700, ninedof);
//! ```

use core::cell::Cell;
use kernel::{AppId, Callback, Container, Driver};
use kernel::ReturnCode;
use kernel::hil;

/// Syscall number
pub const DRIVER_NUM: usize = 0x60000;


pub struct App {
    callback: Option<Callback>,
    pending_command: bool,
}

impl Default for App {
    fn default() -> App {
        App {
            callback: None,
            pending_command: false,
        }
    }
}

pub struct Accelerometer<'a> {
    driver: &'a hil::sensors::Accelerometer,
    apps: Container<App>,
    current_app: Cell<Option<AppId>>,
}

impl<'a> Accelerometer<'a> {
    pub fn new(driver: &'a hil::sensors::Accelerometer,
               container: Container<App>)
               -> Accelerometer<'a> {
        Accelerometer {
            driver: driver,
            apps: container,
            current_app: Cell::new(None),
        }
    }

    // Check so see if we are doing something. If not,
    // go ahead and do this command. If so, this is queued
    // and will be run when the pending command completes.
    fn enqueue_command(&self, appid: AppId) -> ReturnCode {
        self.apps
            .enter(appid, |app, _| if app.pending_command {
                ReturnCode::ENOMEM
            } else {
                app.pending_command = true;
                if self.current_app.get().is_none() {
                    self.current_app.set(Some(appid));
                    self.driver.read();
                }
                ReturnCode::SUCCESS
            })
            .unwrap_or_else(|err| err.into())
    }
}

impl<'a> hil::sensors::AccelerometerClient for Accelerometer<'a> {
    fn callback(&self, arg1: usize, arg2: usize, arg3: usize) {
        self.current_app.set(None);
        self.apps.each(|app| if app.pending_command {
            app.pending_command = false;
            app.callback.map(|mut cb| { cb.schedule(arg1, arg2, arg3); });
        });
    }
}

impl<'a> Driver for Accelerometer<'a> {
    fn subscribe(&self, subscribe_num: usize, callback: Callback) -> ReturnCode {
        match subscribe_num {
            0 => {
                self.apps
                    .enter(callback.app_id(), |app, _| {
                        app.callback = Some(callback);
                        ReturnCode::SUCCESS
                    })
                    .unwrap_or_else(|err| err.into())
            }
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn command(&self, command_num: usize, _: usize, appid: AppId) -> ReturnCode {
        match command_num {
            0 => /* This driver exists. */ ReturnCode::SUCCESS,

            // Single acceleration reading.
            1 => self.enqueue_command(appid),
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Component for the Hynitron CST816S touch controller.
//!
//! Usage
//! -----
//! ```rust
//! let cst816s = components::cst816s::Cst816sComponent::new(
//!     i2c_mux,
//!     capsules_extra::cst816s::I2C_ADDRESS,
//!     &gpio_port[TOUCH_INT_PIN],
//!     Some(&gpio_port[TOUCH_RST_PIN]),
//!     mux_alarm,
//! )
//! .finalize(components::cst816s_component_static!(nrf52840::i2c::TWI, AlarmHw));
//! ```

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_core::virtualizers::virtual_i2c::{I2CDevice, MuxI2C};
use capsules_extra::cst816s::{BUFFER_LEN, Cst816s};
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::gpio;
use kernel::hil::i2c;
use kernel::hil::i2c::I2CDevice as _;
use kernel::hil::time::{self, Alarm};

#[macro_export]
macro_rules! cst816s_component_static {
    ($I:ty, $A:ty $(,)?) => {{
        let i2c_device =
            kernel::static_buf!(capsules_core::virtualizers::virtual_i2c::I2CDevice<'static, $I>);
        let alarm = kernel::static_buf!(
            capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<'static, $A>
        );
        let buffer = kernel::static_buf!([u8; capsules_extra::cst816s::BUFFER_LEN]);
        let cst816s = kernel::static_buf!(
            capsules_extra::cst816s::Cst816s<
                'static,
                capsules_core::virtualizers::virtual_i2c::I2CDevice<'static, $I>,
                capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<'static, $A>,
            >
        );
        (i2c_device, alarm, buffer, cst816s)
    }};
}

pub type Cst816sComponentType<I, A> =
    Cst816s<'static, I2CDevice<'static, I>, VirtualMuxAlarm<'static, A>>;

pub struct Cst816sComponent<I: 'static + i2c::I2CMaster<'static>, A: 'static + time::Alarm<'static>>
{
    i2c_mux: &'static MuxI2C<'static, I>,
    i2c_address: u8,
    interrupt_pin: &'static dyn gpio::InterruptPin<'static>,
    reset_pin: Option<&'static dyn gpio::Pin>,
    alarm_mux: &'static MuxAlarm<'static, A>,
}

impl<I: 'static + i2c::I2CMaster<'static>, A: 'static + time::Alarm<'static>>
    Cst816sComponent<I, A>
{
    pub fn new(
        i2c_mux: &'static MuxI2C<'static, I>,
        i2c_address: u8,
        interrupt_pin: &'static dyn gpio::InterruptPin<'static>,
        reset_pin: Option<&'static dyn gpio::Pin>,
        alarm_mux: &'static MuxAlarm<'static, A>,
    ) -> Self {
        Cst816sComponent {
            i2c_mux,
            i2c_address,
            interrupt_pin,
            reset_pin,
            alarm_mux,
        }
    }
}

impl<I: 'static + i2c::I2CMaster<'static>, A: 'static + time::Alarm<'static>> Component
    for Cst816sComponent<I, A>
{
    type StaticInput = (
        &'static mut MaybeUninit<I2CDevice<'static, I>>,
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<[u8; BUFFER_LEN]>,
        &'static mut MaybeUninit<Cst816sComponentType<I, A>>,
    );
    type Output = &'static Cst816sComponentType<I, A>;

    fn finalize(self, s: Self::StaticInput) -> Self::Output {
        let i2c_device = s.0.write(I2CDevice::new(self.i2c_mux, self.i2c_address));
        let alarm = s.1.write(VirtualMuxAlarm::new(self.alarm_mux));
        alarm.setup();
        let buffer = s.2.write([0; BUFFER_LEN]);

        let cst816s = s.3.write(Cst816s::new(
            i2c_device,
            self.interrupt_pin,
            self.reset_pin,
            alarm,
            buffer,
        ));
        i2c_device.set_client(cst816s);
        self.interrupt_pin.set_client(cst816s);
        alarm.set_alarm_client(cst816s);
        cst816s.init();

        cst816s
    }
}

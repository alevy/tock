// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Component for a BLE link layer connection manager.
//!
//! Builds the capsule that maintains a connection once one is accepted. The
//! board still has to say what the connection carries, by giving the manager a
//! data client, and has to point the advertising driver at it so that an
//! accepted connection is handed over.
//!
//! Usage
//! -----
//! ```rust
//! let conn = BleConnectionComponent::new(&base_peripherals.ble_radio, mux_alarm)
//!     .finalize(ble_connection_component_static!(AlarmHw, BleHw));
//! conn.set_data_client(l2cap);
//! conn.set_disconnect_client(ble_radio);
//! ble_radio.set_connection_client(conn);
//! ```

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_extra::ble_connection::link_layer::{ConnectionManager, MAX_PDU_LEN};
use core::mem::MaybeUninit;
use kernel::component::Component;
use kernel::hil::ble_connection::BleConnectionDriver;
use kernel::hil::time::Alarm;

#[macro_export]
macro_rules! ble_connection_component_static {
    ($A:ty, $B:ty $(,)?) => {{
        let alarm = kernel::static_buf!(
            capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<'static, $A>
        );
        let manager = kernel::static_buf!(
            capsules_extra::ble_connection::link_layer::ConnectionManager<
                'static,
                $B,
                capsules_core::virtualizers::virtual_alarm::VirtualMuxAlarm<'static, $A>,
            >
        );
        // Two: the payload awaiting acknowledgement, and the one behind it.
        let outstanding =
            kernel::static_buf!([u8; capsules_extra::ble_connection::link_layer::MAX_PDU_LEN]);
        let next =
            kernel::static_buf!([u8; capsules_extra::ble_connection::link_layer::MAX_PDU_LEN]);
        (alarm, manager, outstanding, next)
    }};
}

pub type BleConnectionComponentType<B, A> =
    ConnectionManager<'static, B, VirtualMuxAlarm<'static, A>>;

pub struct BleConnectionComponent<
    A: Alarm<'static> + 'static,
    B: BleConnectionDriver<'static> + 'static,
> {
    radio: &'static B,
    mux_alarm: &'static MuxAlarm<'static, A>,
}

impl<A: Alarm<'static> + 'static, B: BleConnectionDriver<'static> + 'static>
    BleConnectionComponent<A, B>
{
    pub fn new(radio: &'static B, mux_alarm: &'static MuxAlarm<'static, A>) -> Self {
        BleConnectionComponent { radio, mux_alarm }
    }
}

impl<A: Alarm<'static> + 'static, B: BleConnectionDriver<'static> + 'static> Component
    for BleConnectionComponent<A, B>
{
    type StaticInput = (
        &'static mut MaybeUninit<VirtualMuxAlarm<'static, A>>,
        &'static mut MaybeUninit<BleConnectionComponentType<B, A>>,
        &'static mut MaybeUninit<[u8; MAX_PDU_LEN]>,
        &'static mut MaybeUninit<[u8; MAX_PDU_LEN]>,
    );
    type Output = &'static BleConnectionComponentType<B, A>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let alarm = static_buffer.0.write(VirtualMuxAlarm::new(self.mux_alarm));
        alarm.setup();

        let outstanding = static_buffer.2.write([0; MAX_PDU_LEN]);
        let next = static_buffer.3.write([0; MAX_PDU_LEN]);
        let manager =
            static_buffer
                .1
                .write(ConnectionManager::new(self.radio, alarm, outstanding, next));

        alarm.set_alarm_client(manager);
        manager.set_driver_client();
        manager
    }
}

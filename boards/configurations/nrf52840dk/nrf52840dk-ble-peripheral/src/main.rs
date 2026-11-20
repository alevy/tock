// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Tock kernel for the nRF52840 development kit, as a BLE peripheral.
//!
//! Advertises as connectable, accepts a connection, and serves the GATT
//! service defined below. The service is board configuration: change
//! `SERVICE_UUID`, `CHARACTERISTIC_UUID` and the table built in `main` to
//! expose something else.
//!
//! The 802.15.4 radio is deliberately left unused. Both it and BLE are views
//! of the single 2.4 GHz radio, and a connection has to be on the air at every
//! connection event, so there is no room to share. See
//! `doc/reference/trd-ble-connection.md`.

#![no_std]
#![no_main]
#![deny(missing_docs)]

use capsules_extra::ble_advertising_driver::ConnectableAdvConfig;
use capsules_extra::ble_connection::att::AttServer;
use capsules_extra::ble_connection::gatt::{
    BufferedValue, Characteristic, GattServer, Service, properties,
};
use capsules_extra::ble_connection::l2cap::L2capMux;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::static_init;

/// Address this device advertises.
///
/// A random static address, which is why the two most significant bits are
/// set.
const DEVICE_ADDRESS: [u8; 6] = [0xC0, 0xFF, 0xEE, 0xBE, 0xEF, 0x42];

/// Name this device advertises.
const DEVICE_NAME: &str = "Tock BLE";

/// UUID of the service exposed here, from the range reserved for
/// vendor-specific use.
const SERVICE_UUID: u16 = 0xFFF0;

/// UUID of the one characteristic in that service.
const CHARACTERISTIC_UUID: u16 = 0xFFF1;

/// Longest value the characteristic holds.
///
/// Kept within the default ATT payload so that a value is never fragmented.
const CHARACTERISTIC_LEN: usize = 20;

/// Value the characteristic starts out holding.
const CHARACTERISTIC_INITIAL: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

type ChipHw = nrf52840dk_test_base_lib::ChipHw;
type AlarmHw = nrf52840::rtc::Rtc<'static>;
type BleHw = nrf52840::ble_radio::Radio<'static>;
type BleDriver = components::ble::BLEComponentType<BleHw, AlarmHw>;

/// Supported drivers by the platform
pub struct Platform {
    base: nrf52840dk_test_base_lib::Platform,
    ble_radio: &'static BleDriver,
}

impl SyscallDriverLookup for Platform {
    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        match driver_num {
            capsules_extra::ble_advertising_driver::DRIVER_NUM => f(Some(self.ble_radio)),
            _ => self.base.with_driver(driver_num, f),
        }
    }
}

impl KernelResources<ChipHw> for Platform {
    type SyscallDriverLookup = Self;
    type SyscallFilter =
        <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::SyscallFilter;
    type ProcessFault =
        <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::ProcessFault;
    type Scheduler = <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::Scheduler;
    type SchedulerTimer =
        <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::SchedulerTimer;
    type WatchDog = <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::WatchDog;
    type ContextSwitchCallback =
        <nrf52840dk_test_base_lib::Platform as KernelResources<ChipHw>>::ContextSwitchCallback;

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup {
        self
    }
    fn syscall_filter(&self) -> &Self::SyscallFilter {
        self.base.syscall_filter()
    }
    fn process_fault(&self) -> &Self::ProcessFault {
        self.base.process_fault()
    }
    fn scheduler(&self) -> &Self::Scheduler {
        self.base.scheduler()
    }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer {
        self.base.scheduler_timer()
    }
    fn watchdog(&self) -> &Self::WatchDog {
        self.base.watchdog()
    }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback {
        self.base.context_switch_callback()
    }
}

/// Main function called after RAM initialized.
///
/// # Safety
///
/// ## `no_mangle`
///
/// We use `main` as a symbol in the arch crate's initialization routine to jump
/// here. We guarantee no other symbol has the same name.
///
/// Note: this requires a global/uniqueness guarantee.
/// See <https://github.com/tock/tock/issues/5250>.
#[unsafe(no_mangle)]
pub unsafe fn main() {
    let (board_kernel, base_platform, chip, default_peripherals, mux_uart, mux_alarm) =
        nrf52840dk_test_base_lib::start();
    let base_peripherals = &default_peripherals.nrf52;

    // Route `debug!()` and panic output to the console. The base configuration
    // sets up a console for processes but no debug writer, so without this the
    // kernel is silent -- including when it panics.
    components::debug_writer::DebugWriterComponent::new::<
        <ChipHw as kernel::platform::chip::Chip>::ThreadIdProvider,
    >(
        mux_uart,
        create_capability!(capabilities::SetDebugWriterCapability),
    )
    .finalize(components::debug_writer_component_static!());

    //--------------------------------------------------------------------------
    // GATT TABLE
    //--------------------------------------------------------------------------

    // One service with one characteristic a central can read and write.
    // Handles are assigned by position: 1 for the service declaration, 2 for
    // the characteristic declaration, 3 for its value.
    let characteristic_value = static_init!(
        BufferedValue<CHARACTERISTIC_LEN>,
        BufferedValue::writable(&CHARACTERISTIC_INITIAL)
    );
    let characteristics = static_init!(
        [Characteristic<'static>; 1],
        [Characteristic {
            uuid: CHARACTERISTIC_UUID,
            properties: properties::READ | properties::WRITE,
            value: characteristic_value,
        }]
    );
    let services = static_init!(
        [Service<'static>; 1],
        [Service {
            uuid: SERVICE_UUID,
            characteristics,
        }]
    );
    let l2cap = static_init!(
        L2capMux<'static>,
        L2capMux::new(AttServer::new(GattServer::new(services)))
    );

    //--------------------------------------------------------------------------
    // BLE
    //--------------------------------------------------------------------------

    let ble_radio = components::ble::BLEComponent::new(
        board_kernel,
        capsules_extra::ble_advertising_driver::DRIVER_NUM,
        &base_peripherals.ble_radio,
        mux_alarm,
        create_capability!(capabilities::MemoryAllocationCapability),
    )
    .finalize(components::ble_component_static!(AlarmHw, BleHw));

    let connection = components::ble_connection::BleConnectionComponent::new(
        &base_peripherals.ble_radio,
        mux_alarm,
    )
    .finalize(components::ble_connection_component_static!(AlarmHw, BleHw));

    // An accepted connection goes to the connection manager, what it carries
    // goes to L2CAP, and the end of it goes back to the advertising driver so
    // the device can be found again.
    connection.set_data_client(l2cap);
    connection.set_disconnect_client(ble_radio);
    ble_radio.set_connection_client(connection);

    ble_radio.start_connectable_advertising(ConnectableAdvConfig {
        address: DEVICE_ADDRESS,
        name: DEVICE_NAME,
    });

    //--------------------------------------------------------------------------
    // PLATFORM
    //--------------------------------------------------------------------------

    let platform = Platform {
        base: base_platform,
        ble_radio,
    };

    //--------------------------------------------------------------------------
    // PROCESS LOADING
    //--------------------------------------------------------------------------

    // These symbols are defined in the standard Tock linker script.
    extern "C" {
        /// Beginning of the ROM region containing app images.
        static _sapps: u8;
        /// End of the ROM region containing app images.
        static _eapps: u8;
        /// Beginning of the RAM region for app memory.
        static mut _sappmem: u8;
        /// End of the RAM region for app memory.
        static _eappmem: u8;
    }

    let app_flash = core::slice::from_raw_parts(
        core::ptr::addr_of!(_sapps),
        core::ptr::addr_of!(_eapps) as usize - core::ptr::addr_of!(_sapps) as usize,
    );
    let app_memory = core::slice::from_raw_parts_mut(
        core::ptr::addr_of_mut!(_sappmem),
        core::ptr::addr_of!(_eappmem) as usize - core::ptr::addr_of!(_sappmem) as usize,
    );

    let process_management_capability =
        create_capability!(capabilities::ProcessManagementCapability);
    kernel::process::load_processes(
        board_kernel,
        chip,
        app_flash,
        app_memory,
        &nrf52840dk_test_base_lib::FAULT_RESPONSE,
        &process_management_capability,
    )
    .unwrap_or_else(|err| {
        kernel::debug!("Error loading processes!");
        kernel::debug!("{:?}", err);
    });

    //--------------------------------------------------------------------------
    // PLATFORM SETUP, SCHEDULER, AND START KERNEL LOOP
    //--------------------------------------------------------------------------

    let main_loop_capability = create_capability!(kernel::capabilities::MainLoopCapability);
    board_kernel.kernel_loop(
        &platform,
        chip,
        None::<&kernel::ipc::IPC<0>>,
        &main_loop_capability,
    );
}

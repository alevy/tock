// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use core::panic::PanicInfo;
//use core::fmt::Write;
//use core::str;
//use earlgrey::chip_config::EarlGreyConfig;
//use kernel::debug;
//use kernel::debug::IoWrite;
//
//use crate::CHIP;
//use crate::PROCESSES;
//use crate::PROCESS_PRINTER;
//
//struct Writer {}
//
//static mut WRITER: Writer = Writer {};
//
//impl Write for Writer {
//    fn write_str(&mut self, s: &str) -> ::core::fmt::Result {
//        self.write(s.as_bytes());
//        Ok(())
//    }
//}
//
//impl IoWrite for Writer {
//    fn write(&mut self, buf: &[u8]) -> usize {
//        // This creates a second instance of the UART peripheral, and should only be used
//        // during panic.
//        earlgrey::uart::Uart::new(
//            earlgrey::uart::UART0_BASE,
//            crate::ChipConfig::PERIPHERAL_FREQ,
//        )
//        .transmit_sync(buf);
//        buf.len()
//    }
//}
//
//#[cfg(not(test))]
//use kernel::hil::gpio::Configure;
//#[cfg(not(test))]
//use kernel::hil::led;

/// Panic handler.
#[cfg(not(test))]
#[no_mangle]
#[panic_handler]
pub unsafe extern "C" fn panic_fmt(pi: &PanicInfo) -> ! {
    loop {}
}


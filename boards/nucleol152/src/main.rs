#![no_std]
#![no_main]
#![feature(asm,compiler_builtins_lib,lang_items)]

extern crate compiler_builtins;
extern crate kernel;
extern crate stm32;
extern crate stm32l1;

pub mod io;

struct NucleoL152;

impl kernel::Platform for NucleoL152 {
    fn with_driver<F, R>(&self, _: usize, f: F) -> R
            where F: FnOnce(Option<&kernel::Driver>) -> R {
        f(None)
    }
}

#[no_mangle]
pub unsafe fn reset_handler() {
    stm32l1::init();
    
    kernel::main(&mut NucleoL152, &mut stm32l1::STM32L1::new(), &mut [],&kernel::ipc::IPC::new());
}

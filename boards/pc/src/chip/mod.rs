use std::sync::mpsc::{channel, Receiver};

pub mod alarm;

use self::alarm::UnixAlarm;


#[derive(Copy, Clone)]
pub enum Event {
    Alarm,
}

pub struct Chip<'a> {
    syscall: crate::arch::syscall::SysCall,
    event_receiver: Receiver<Event>,
    pub alarm: UnixAlarm<'a>,
}

impl<'a> Chip<'a> {
    pub unsafe fn new() -> Self {
        let (sender, reciever) = channel();
        Chip {
            syscall: crate::arch::syscall::SysCall::new(),
            event_receiver: reciever,

            alarm: UnixAlarm::new(sender.clone()),
        }
    }

    fn service_event(&self, event: Event) {
        match event {
            Event::Alarm => self.alarm.handle_interrupt()
        }
    }
}

impl<'a> kernel::Chip for Chip<'a> {
    type MPU = ();
    type SysTick = ();
    type UserspaceKernelBoundary = crate::arch::syscall::SysCall;

    fn mpu(&self) -> &Self::MPU {
        &()
    }

    fn systick(&self) -> &Self::SysTick {
        &()
    }

    fn userspace_kernel_boundary(&self) -> &Self::UserspaceKernelBoundary {
        &self.syscall
    }

    unsafe fn atomic<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        //TODO(alevy)
        f()
    }

    fn sleep(&self) {
        println!("Sleeping");
        self.service_event(self.event_receiver.recv().unwrap());
    }

    fn has_pending_interrupts(&self) -> bool {
        false
    }

    fn service_pending_interrupts(&self) {
        for event in self.event_receiver.try_iter() {
            self.service_event(event);
        }
    }
}


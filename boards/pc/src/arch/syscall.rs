//! Implementation of the architecture-specific portions of the kernel-userland
//! system call interface.

use core::fmt::Write;

pub struct SysCall();

impl SysCall {
    pub const unsafe fn new() -> SysCall {
        SysCall()
    }
}

impl kernel::syscall::UserspaceKernelBoundary for SysCall {
    type StoredState = ();

    /// Get the syscall that the process called.
    unsafe fn get_syscall(&self, _stack_pointer: *const usize) -> Option<kernel::syscall::Syscall> {
        None
    }

    unsafe fn set_syscall_return_value(&self, _stack_pointer: *const usize, _return_value: isize) {
    }

    unsafe fn pop_syscall_stack_frame(
        &self,
        stack_pointer: *const usize,
        _state: &mut Self::StoredState,
    ) -> *mut usize {
        (stack_pointer as *mut usize).offset(8)
    }

    unsafe fn push_function_call(
        &self,
        stack_pointer: *const usize,
        _remaining_stack_memory: usize,
        _callback: kernel::procs::FunctionCall,
        _state: &Self::StoredState,
    ) -> Result<*mut usize, *mut usize> {
        Err((stack_pointer as *mut usize).offset(-8))
    }

    unsafe fn switch_to_process(
        &self,
        stack_pointer: *const usize,
        _state: &mut Self::StoredState,
    ) -> (*mut usize, kernel::syscall::ContextSwitchReason) {
        (stack_pointer as *mut usize, kernel::syscall::ContextSwitchReason::Fault)
    }

    unsafe fn fault_fmt(&self, _writer: &mut Write) {
    }

    unsafe fn process_detail_fmt(
        &self,
        _stack_pointer: *const usize,
        _state: &Self::StoredState,
        _writer: &mut Write,
    ) {
    }
}

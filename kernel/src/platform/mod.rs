use driver::Driver;

pub mod mpu;
pub mod systick;

pub trait Platform {
    type Chip: Chip;

    fn chip(&self) -> &Self::Chip;

    fn with_driver<F, R>(&self, driver_num: usize, f: F) -> R where F: FnOnce(Option<&Driver>) -> R;
}

pub trait Chip {
    type MPU: mpu::MPU;
    type SysTick: systick::SysTick;

    fn service_pending_interrupts(&self);
    fn has_pending_interrupts(&self) -> bool;
    fn mpu(&self) -> &Self::MPU;
    fn systick(&self) -> &Self::SysTick;
}

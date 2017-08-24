//! Interfaces for environment sensors

use returncode::ReturnCode;

/// A basic interface for a temperature sensor
pub trait TemperatureDriver {
    fn set_client(&self, client: &'static TemperatureClient);
    fn read_temperature(&self) -> ReturnCode;
}

/// Client for receiving temperature readings.
pub trait TemperatureClient {
    /// Called when a temperature reading has completed.
    ///
    /// - `value`: the most recently read temperature in hundredths of degrees
    /// centigrate.
    fn callback(&self, value: usize);
}

/// A basic interface for a humidity sensor
pub trait HumidityDriver {
    fn set_client(&self, client: &'static HumidityClient);
    fn read_humidity(&self) -> ReturnCode;
}

/// Client for receiving humidity readings.
pub trait HumidityClient {
    /// Called when a humidity reading has completed.
    ///
    /// - `value`: the most recently read humidity in hundredths of percent.
    fn callback(&self, value: usize);
}

/// A basic interface for an ambient light sensor.
pub trait AmbientLight {
    /// Set the client to be notified when the capsule has data ready or has
    /// finished some command.  This is likely called in a board's `main.rs`.
    fn set_client(&self, client: &'static AmbientLightClient);

    /// Get a single instantaneous reading of the ambient light intensity.
    fn read_light_intensity(&self) -> ReturnCode {
        ReturnCode::ENODEVICE
    }
}

/// Client for receiving light intensity readings.
pub trait AmbientLightClient {
    /// Called when an ambient light reading has completed.
    ///
    /// - `lux`: the most recently read ambient light reading in lux (lx).
    fn callback(&self, lux: usize);
}

/// A basic interface for a 9-DOF compatible chip.
///
/// This trait provides a standard interface for chips that implement
/// some or all of a nine degrees of freedom (accelerometer, magnetometer,
/// gyroscope) sensor. Any interface functions that a chip cannot implement
/// can be ignored by the chip capsule and an error will automatically be
/// returned.
pub trait Accelerometer {
    /// Set the client to be notified when the capsule has data ready or
    /// has finished some command. This is likely called in a board's main.rs
    /// and is set to the virtual_ninedof.rs driver.
    fn set_client(&self, client: &'static AccelerometerClient);

    /// Get a single instantaneous reading of the acceleration in the
    /// X,Y,Z directions.
    fn read(&self) -> ReturnCode {
        ReturnCode::ENODEVICE
    }
}

pub trait Magnetometer {
    /// Set the client to be notified when the capsule has data ready or
    /// has finished some command. This is likely called in a board's main.rs
    /// and is set to the virtual_ninedof.rs driver.
    fn set_client(&self, client: &'static MagnetometerClient);

    /// Get a single instantaneous reading of the acceleration in the
    /// X,Y,Z directions.
    fn read(&self) -> ReturnCode {
        ReturnCode::ENODEVICE
    }
}

pub trait Gyroscope {
    /// Set the client to be notified when the capsule has data ready or
    /// has finished some command. This is likely called in a board's main.rs
    /// and is set to the virtual_ninedof.rs driver.
    fn set_client(&self, client: &'static GyroscopeClient);

    /// Get a single instantaneous reading of the acceleration in the
    /// X,Y,Z directions.
    fn read(&self) -> ReturnCode {
        ReturnCode::ENODEVICE
    }
}

/// Client for receiving done events from the chip.
pub trait AccelerometerClient {
    /// Signals a command has finished. The arguments will most likely be passed
    /// over the syscall interface to an application.
    fn callback(&self, arg1: usize, arg2: usize, arg3: usize);
}

/// Client for receiving done events from the chip.
pub trait MagnetometerClient {
    /// Signals a command has finished. The arguments will most likely be passed
    /// over the syscall interface to an application.
    fn callback(&self, arg1: usize, arg2: usize, arg3: usize);
}

/// Client for receiving done events from the chip.
pub trait GyroscopeClient {
    /// Signals a command has finished. The arguments will most likely be passed
    /// over the syscall interface to an application.
    fn callback(&self, arg1: usize, arg2: usize, arg3: usize);
}

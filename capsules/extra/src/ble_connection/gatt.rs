// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! GATT server: the attributes a BLE peripheral exposes.
//!
//! A board describes what it offers as a list of [`Service`]s, each holding a
//! list of [`Characteristic`]s, and the values themselves come from
//! [`AttributeProvider`] implementations. Handles are assigned by position, so
//! a board never has to pick them or keep them consistent with the table.
//!
//! The indirection through `AttributeProvider` is what lets this be extended
//! beyond board-defined attributes: a capsule that multiplexes GATT across
//! processes implements the trait for attributes a process owns, and neither
//! the ATT layer nor this one changes. Dispatch is synchronous, so such a
//! capsule serves reads from memory a process has already shared rather than
//! asking the process at request time.
//!
//! References are to the Bluetooth Core Specification, Vol 3, Part G.

use core::cell::Cell;

/// Error codes an attribute operation can fail with.
///
/// The discriminants are the ATT error codes (Vol 3, Part F, Section 3.4.1.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AttError {
    /// The handle is not valid on this server.
    InvalidHandle = 0x01,
    /// The attribute cannot be read.
    ReadNotPermitted = 0x02,
    /// The attribute cannot be written.
    WriteNotPermitted = 0x03,
    /// The server does not support this request.
    RequestNotSupported = 0x06,
    /// The offset is past the end of the value.
    InvalidOffset = 0x07,
    /// No attribute matched the request.
    AttributeNotFound = 0x0A,
    /// The value is the wrong length for this attribute.
    InvalidAttributeValueLength = 0x0D,
    /// The request could not be completed for an unlisted reason.
    UnlikelyError = 0x0E,
}

/// Characteristic property bits (Vol 3, Part G, Section 3.3.1.1).
pub mod properties {
    /// The value may be read.
    pub const READ: u8 = 0x02;
    /// The value may be written without a response.
    pub const WRITE_WITHOUT_RESPONSE: u8 = 0x04;
    /// The value may be written, with a response.
    pub const WRITE: u8 = 0x08;
}

/// Supplies the value of a characteristic.
pub trait AttributeProvider {
    /// Read the value from `offset` into `buf`, returning how much was written.
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, AttError>;

    /// Replace the value from `offset`.
    ///
    /// The default rejects the write, which suits read-only attributes.
    fn write(&self, offset: usize, value: &[u8]) -> Result<(), AttError> {
        let _ = (offset, value);
        Err(AttError::WriteNotPermitted)
    }
}

/// An attribute value of up to `N` bytes held in kernel memory.
///
/// Enough for a board that just wants somewhere for a central to read from and
/// write to.
pub struct BufferedValue<const N: usize> {
    /// The value.
    value: Cell<[u8; N]>,
    /// How much of `value` is in use.
    len: Cell<usize>,
    /// Whether a central may change it.
    writable: bool,
}

impl<const N: usize> BufferedValue<N> {
    /// A value a central may read and write, initially `initial`.
    pub fn writable(initial: &[u8]) -> Self {
        Self::build(initial, true)
    }

    /// A value a central may read but not write.
    pub fn read_only(initial: &[u8]) -> Self {
        Self::build(initial, false)
    }

    /// Build a value, truncating `initial` to fit.
    fn build(initial: &[u8], writable: bool) -> Self {
        let mut value = [0u8; N];
        let len = initial.len().min(N);
        value[..len].copy_from_slice(&initial[..len]);
        BufferedValue {
            value: Cell::new(value),
            len: Cell::new(len),
            writable,
        }
    }

    /// The current value, copied into `buf`, returning how much was written.
    pub fn get(&self, buf: &mut [u8]) -> usize {
        let len = self.len.get().min(buf.len());
        buf[..len].copy_from_slice(&self.value.get()[..len]);
        len
    }

    /// Replace the value from kernel code, truncating to fit.
    pub fn set(&self, new: &[u8]) {
        let mut value = [0u8; N];
        let len = new.len().min(N);
        value[..len].copy_from_slice(&new[..len]);
        self.value.set(value);
        self.len.set(len);
    }
}

impl<const N: usize> AttributeProvider for BufferedValue<N> {
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, AttError> {
        let len = self.len.get();
        if offset > len {
            return Err(AttError::InvalidOffset);
        }
        let available = len - offset;
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.value.get()[offset..offset + n]);
        Ok(n)
    }

    fn write(&self, offset: usize, value: &[u8]) -> Result<(), AttError> {
        if !self.writable {
            return Err(AttError::WriteNotPermitted);
        }
        if offset != 0 {
            // Long writes are not supported; a value either fits or it does not.
            return Err(AttError::InvalidOffset);
        }
        if value.len() > N {
            return Err(AttError::InvalidAttributeValueLength);
        }
        self.set(value);
        Ok(())
    }
}

/// One characteristic of a service.
pub struct Characteristic<'a> {
    /// 16-bit UUID identifying what this characteristic means.
    pub uuid: u16,
    /// What a central is allowed to do with it; see [`properties`].
    pub properties: u8,
    /// Where its value comes from.
    pub value: &'a dyn AttributeProvider,
}

/// A primary service and the characteristics it contains.
pub struct Service<'a> {
    /// 16-bit UUID identifying the service.
    pub uuid: u16,
    /// The service's characteristics, in the order they are exposed.
    pub characteristics: &'a [Characteristic<'a>],
}

/// First valid attribute handle; handle 0 is reserved as invalid.
const FIRST_HANDLE: u16 = 0x0001;

/// Handles consumed by a characteristic: its declaration and its value.
const HANDLES_PER_CHARACTERISTIC: u16 = 2;

/// What a handle refers to.
pub enum Resolved<'a> {
    /// A service declaration, whose value is the service UUID.
    ServiceDeclaration(&'a Service<'a>),
    /// A characteristic declaration, whose value describes the characteristic.
    CharacteristicDeclaration {
        /// Handle of the characteristic's value.
        value_handle: u16,
        /// The characteristic being declared.
        characteristic: &'a Characteristic<'a>,
    },
    /// A characteristic's value.
    CharacteristicValue(&'a Characteristic<'a>),
}

/// The attributes a peripheral exposes.
///
/// Handles are assigned by walking the table: each service takes one handle for
/// its declaration, and each of its characteristics takes two, one for its
/// declaration and one for its value.
pub struct GattServer<'a> {
    /// The services, in handle order.
    services: &'a [Service<'a>],
}

impl<'a> GattServer<'a> {
    pub const fn new(services: &'a [Service<'a>]) -> Self {
        GattServer { services }
    }

    /// Handle of the service declaration at `index`, and the last handle in
    /// that service's group.
    fn service_range(&self, index: usize) -> (u16, u16) {
        let mut handle = FIRST_HANDLE;
        for service in &self.services[..index] {
            handle += 1 + service.characteristics.len() as u16 * HANDLES_PER_CHARACTERISTIC;
        }
        let group_end =
            handle + self.services[index].characteristics.len() as u16 * HANDLES_PER_CHARACTERISTIC;
        (handle, group_end)
    }

    /// The first service whose declaration handle falls within `start..=end`.
    ///
    /// Returns the declaration handle, the last handle of the group, and the
    /// service.
    pub fn find_service(&self, start: u16, end: u16) -> Option<(u16, u16, &'a Service<'a>)> {
        for index in 0..self.services.len() {
            let (handle, group_end) = self.service_range(index);
            if handle >= start && handle <= end {
                return Some((handle, group_end, &self.services[index]));
            }
        }
        None
    }

    /// The first characteristic whose declaration handle falls within
    /// `start..=end`.
    ///
    /// Returns the declaration handle, the value handle, and the
    /// characteristic.
    pub fn find_characteristic(
        &self,
        start: u16,
        end: u16,
    ) -> Option<(u16, u16, &'a Characteristic<'a>)> {
        let mut handle = FIRST_HANDLE;
        for service in self.services {
            handle += 1;
            for characteristic in service.characteristics {
                if handle >= start && handle <= end {
                    return Some((handle, handle + 1, characteristic));
                }
                handle += HANDLES_PER_CHARACTERISTIC;
            }
        }
        None
    }

    /// What `handle` refers to, if anything.
    pub fn resolve(&self, handle: u16) -> Option<Resolved<'a>> {
        let mut next = FIRST_HANDLE;
        for service in self.services {
            if next == handle {
                return Some(Resolved::ServiceDeclaration(service));
            }
            next += 1;
            for characteristic in service.characteristics {
                if next == handle {
                    return Some(Resolved::CharacteristicDeclaration {
                        value_handle: next + 1,
                        characteristic,
                    });
                }
                if next + 1 == handle {
                    return Some(Resolved::CharacteristicValue(characteristic));
                }
                next += HANDLES_PER_CHARACTERISTIC;
            }
        }
        None
    }

    /// The highest handle in use, or [`FIRST_HANDLE`] if the table is empty.
    pub fn last_handle(&self) -> u16 {
        let mut handle = FIRST_HANDLE;
        for service in self.services {
            handle += 1 + service.characteristics.len() as u16 * HANDLES_PER_CHARACTERISTIC;
        }
        handle.saturating_sub(1).max(FIRST_HANDLE)
    }
}

/// Write a characteristic declaration's value into `buf`.
///
/// The value is the properties, the value handle, and the characteristic UUID
/// (Vol 3, Part G, Section 3.3.1). Returns how much was written.
pub fn write_characteristic_declaration(
    buf: &mut [u8],
    properties: u8,
    value_handle: u16,
    uuid: u16,
) -> usize {
    if buf.len() < 5 {
        return 0;
    }
    buf[0] = properties;
    buf[1..3].copy_from_slice(&value_handle.to_le_bytes());
    buf[3..5].copy_from_slice(&uuid.to_le_bytes());
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with two services, the first holding two characteristics and
    /// the second one. Handles therefore run:
    ///
    /// 1 service A, 2/3 characteristic A1, 4/5 characteristic A2,
    /// 6 service B, 7/8 characteristic B1.
    fn server() -> (BufferedValue<4>, BufferedValue<4>, BufferedValue<4>) {
        (
            BufferedValue::writable(&[1, 2, 3, 4]),
            BufferedValue::read_only(&[5]),
            BufferedValue::writable(&[6]),
        )
    }

    #[test]
    fn handles_are_assigned_by_position() {
        let (a1, a2, b1) = server();
        let svc_a = [
            Characteristic {
                uuid: 0xFF01,
                properties: properties::READ,
                value: &a1,
            },
            Characteristic {
                uuid: 0xFF02,
                properties: properties::READ,
                value: &a2,
            },
        ];
        let svc_b = [Characteristic {
            uuid: 0xFF11,
            properties: properties::READ,
            value: &b1,
        }];
        let services = [
            Service {
                uuid: 0xFF00,
                characteristics: &svc_a,
            },
            Service {
                uuid: 0xFF10,
                characteristics: &svc_b,
            },
        ];
        let gatt = GattServer::new(&services);

        // Service A declares at handle 1 and its group ends at 5.
        let (handle, group_end, service) = gatt.find_service(1, 0xFFFF).unwrap();
        assert_eq!((handle, group_end, service.uuid), (1, 5, 0xFF00));

        // Searching past it finds service B at 6, ending at 8.
        let (handle, group_end, service) = gatt.find_service(6, 0xFFFF).unwrap();
        assert_eq!((handle, group_end, service.uuid), (6, 8, 0xFF10));

        // And past that, nothing, which is how discovery terminates.
        assert!(gatt.find_service(9, 0xFFFF).is_none());

        assert_eq!(gatt.last_handle(), 8);
    }

    #[test]
    fn characteristics_are_found_in_order() {
        let (a1, a2, b1) = server();
        let svc_a = [
            Characteristic {
                uuid: 0xFF01,
                properties: properties::READ,
                value: &a1,
            },
            Characteristic {
                uuid: 0xFF02,
                properties: properties::READ,
                value: &a2,
            },
        ];
        let svc_b = [Characteristic {
            uuid: 0xFF11,
            properties: properties::READ,
            value: &b1,
        }];
        let services = [
            Service {
                uuid: 0xFF00,
                characteristics: &svc_a,
            },
            Service {
                uuid: 0xFF10,
                characteristics: &svc_b,
            },
        ];
        let gatt = GattServer::new(&services);

        let (decl, value, ch) = gatt.find_characteristic(1, 0xFFFF).unwrap();
        assert_eq!((decl, value, ch.uuid), (2, 3, 0xFF01));
        let (decl, value, ch) = gatt.find_characteristic(4, 0xFFFF).unwrap();
        assert_eq!((decl, value, ch.uuid), (4, 5, 0xFF02));
        let (decl, value, ch) = gatt.find_characteristic(6, 0xFFFF).unwrap();
        assert_eq!((decl, value, ch.uuid), (7, 8, 0xFF11));
        assert!(gatt.find_characteristic(9, 0xFFFF).is_none());
    }

    #[test]
    fn handles_resolve_to_the_right_attribute() {
        let (a1, _, _) = server();
        let chars = [Characteristic {
            uuid: 0xFF01,
            properties: properties::READ | properties::WRITE,
            value: &a1,
        }];
        let services = [Service {
            uuid: 0xFF00,
            characteristics: &chars,
        }];
        let gatt = GattServer::new(&services);

        assert!(matches!(
            gatt.resolve(1),
            Some(Resolved::ServiceDeclaration(_))
        ));
        assert!(matches!(
            gatt.resolve(2),
            Some(Resolved::CharacteristicDeclaration {
                value_handle: 3,
                ..
            })
        ));
        assert!(matches!(
            gatt.resolve(3),
            Some(Resolved::CharacteristicValue(_))
        ));
        assert!(gatt.resolve(0).is_none());
        assert!(gatt.resolve(4).is_none());
    }

    #[test]
    fn buffered_value_reads_and_writes() {
        let value = BufferedValue::<8>::writable(&[1, 2, 3]);
        let mut buf = [0u8; 8];
        assert_eq!(value.read(0, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);

        value.write(0, &[9, 9]).unwrap();
        assert_eq!(value.read(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[9, 9]);

        // Reading from the end yields nothing rather than failing.
        assert_eq!(value.read(2, &mut buf).unwrap(), 0);
        assert_eq!(value.read(3, &mut buf), Err(AttError::InvalidOffset));
    }

    #[test]
    fn read_only_value_rejects_writes() {
        let value = BufferedValue::<8>::read_only(&[1]);
        assert_eq!(value.write(0, &[2]), Err(AttError::WriteNotPermitted));
    }

    #[test]
    fn oversized_write_is_rejected() {
        let value = BufferedValue::<2>::writable(&[]);
        assert_eq!(
            value.write(0, &[1, 2, 3]),
            Err(AttError::InvalidAttributeValueLength)
        );
    }

    #[test]
    fn initial_value_is_truncated_to_capacity() {
        let value = BufferedValue::<2>::writable(&[1, 2, 3, 4]);
        let mut buf = [0u8; 8];
        assert_eq!(value.read(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[1, 2]);
    }

    #[test]
    fn characteristic_declaration_layout() {
        let mut buf = [0u8; 5];
        assert_eq!(
            write_characteristic_declaration(&mut buf, 0x0A, 0x0003, 0xFF01),
            5
        );
        assert_eq!(buf, [0x0A, 0x03, 0x00, 0x01, 0xFF]);
    }
}

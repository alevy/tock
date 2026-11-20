// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Attribute protocol: the requests a central makes of a GATT server.
//!
//! Translates ATT requests into lookups against a
//! [`GattServer`](crate::ble_connection::gatt::GattServer) and builds the
//! replies. It knows about handles and opcodes; what the attributes mean is
//! the GATT layer's business, and getting the bytes on and off the air is the
//! link layer's.
//!
//! References are to the Bluetooth Core Specification, Vol 3, Part F.

use core::cell::Cell;

use crate::ble_connection::gatt::{
    AttError, GattServer, Resolved, properties, write_characteristic_declaration,
};

/// Default ATT maximum transmission unit (Section 3.2.8).
///
/// Chosen so that an ATT PDU plus its L2CAP header fits in one link layer
/// packet, which is what lets this implementation avoid fragmentation
/// entirely.
pub const ATT_MTU_DEFAULT: u16 = 23;

// ATT opcodes (Section 3.4.8).
/// Error response.
const ERROR_RSP: u8 = 0x01;
/// Exchange MTU request.
const EXCHANGE_MTU_REQ: u8 = 0x02;
/// Exchange MTU response.
const EXCHANGE_MTU_RSP: u8 = 0x03;
/// Find information request, used to discover descriptors.
const FIND_INFORMATION_REQ: u8 = 0x04;
/// Read by type request, used to discover characteristics.
const READ_BY_TYPE_REQ: u8 = 0x08;
/// Read by type response.
const READ_BY_TYPE_RSP: u8 = 0x09;
/// Read request.
const READ_REQ: u8 = 0x0A;
/// Read response.
const READ_RSP: u8 = 0x0B;
/// Read by group type request, used to discover services.
const READ_BY_GROUP_TYPE_REQ: u8 = 0x10;
/// Read by group type response.
const READ_BY_GROUP_TYPE_RSP: u8 = 0x11;
/// Write request.
const WRITE_REQ: u8 = 0x12;
/// Write response.
const WRITE_RSP: u8 = 0x13;
/// Write command, which expects no response.
const WRITE_CMD: u8 = 0x52;

// GATT attribute type UUIDs (Vol 3, Part G, Section 3.1).
/// Primary service declaration.
const GATT_PRIMARY_SERVICE: u16 = 0x2800;
/// Characteristic declaration.
const GATT_CHARACTERISTIC: u16 = 0x2803;

/// Length of a service entry in a read-by-group-type response: handle, group
/// end handle, and a 16-bit UUID.
const SERVICE_ENTRY_LEN: u8 = 6;

/// Length of a characteristic entry in a read-by-type response: handle plus a
/// five-byte declaration value.
const CHARACTERISTIC_ENTRY_LEN: u8 = 7;

/// Answers ATT requests against a GATT server.
pub struct AttServer<'a> {
    /// The attributes being served.
    gatt: GattServer<'a>,
    /// Negotiated MTU for this connection.
    mtu: Cell<u16>,
}

impl<'a> AttServer<'a> {
    pub fn new(gatt: GattServer<'a>) -> Self {
        AttServer {
            gatt,
            mtu: Cell::new(ATT_MTU_DEFAULT),
        }
    }

    /// Forget any negotiated state, ready for a new connection.
    pub fn reset(&self) {
        self.mtu.set(ATT_MTU_DEFAULT);
    }

    /// Build the reply to `request` into `out`.
    ///
    /// Returns how many bytes of `out` the reply occupies, or `None` when the
    /// request calls for no reply.
    pub fn handle_request(&self, request: &[u8], out: &mut [u8]) -> Option<usize> {
        let &opcode = request.first()?;
        // Every response has to fit the MTU as well as the caller's buffer.
        let limit = out.len().min(self.mtu.get() as usize);
        if limit < 5 {
            return None;
        }
        let out = &mut out[..limit];

        match opcode {
            EXCHANGE_MTU_REQ => {
                // Both sides use the smaller of the two MTUs. This server only
                // offers the default, so that is the outcome regardless.
                out[0] = EXCHANGE_MTU_RSP;
                out[1..3].copy_from_slice(&ATT_MTU_DEFAULT.to_le_bytes());
                Some(3)
            }
            READ_BY_GROUP_TYPE_REQ => Some(self.read_by_group_type(request, out)),
            READ_BY_TYPE_REQ => Some(self.read_by_type(request, out)),
            READ_REQ => Some(self.read(request, out)),
            WRITE_REQ => Some(self.write(request, out)),
            WRITE_CMD => {
                // A command is unacknowledged: apply it and say nothing.
                let _ = self.apply_write(request);
                None
            }
            FIND_INFORMATION_REQ => {
                // This server exposes no descriptors, so there is never
                // anything to find. Saying so ends the client's discovery.
                let handle = request_handle(request);
                Some(write_error(
                    out,
                    opcode,
                    handle,
                    AttError::AttributeNotFound,
                ))
            }
            other => {
                let handle = request_handle(request);
                Some(write_error(
                    out,
                    other,
                    handle,
                    AttError::RequestNotSupported,
                ))
            }
        }
    }

    /// Service discovery: report the first service in the requested range.
    ///
    /// One service per response is permitted; the client asks again from the
    /// next handle until the server reports that none is left.
    fn read_by_group_type(&self, request: &[u8], out: &mut [u8]) -> usize {
        let Some((start, end, group_type)) = parse_typed_range(request) else {
            return write_error(out, READ_BY_GROUP_TYPE_REQ, 0, AttError::InvalidHandle);
        };
        if group_type != GATT_PRIMARY_SERVICE {
            return write_error(
                out,
                READ_BY_GROUP_TYPE_REQ,
                start,
                AttError::AttributeNotFound,
            );
        }
        match self.gatt.find_service(start, end) {
            Some((handle, group_end, service)) => {
                out[0] = READ_BY_GROUP_TYPE_RSP;
                out[1] = SERVICE_ENTRY_LEN;
                out[2..4].copy_from_slice(&handle.to_le_bytes());
                out[4..6].copy_from_slice(&group_end.to_le_bytes());
                out[6..8].copy_from_slice(&service.uuid.to_le_bytes());
                8
            }
            None => write_error(
                out,
                READ_BY_GROUP_TYPE_REQ,
                start,
                AttError::AttributeNotFound,
            ),
        }
    }

    /// Characteristic discovery: report the first characteristic in range.
    fn read_by_type(&self, request: &[u8], out: &mut [u8]) -> usize {
        let Some((start, end, attribute_type)) = parse_typed_range(request) else {
            return write_error(out, READ_BY_TYPE_REQ, 0, AttError::InvalidHandle);
        };
        if attribute_type != GATT_CHARACTERISTIC {
            return write_error(out, READ_BY_TYPE_REQ, start, AttError::AttributeNotFound);
        }
        match self.gatt.find_characteristic(start, end) {
            Some((handle, value_handle, characteristic)) => {
                out[0] = READ_BY_TYPE_RSP;
                out[1] = CHARACTERISTIC_ENTRY_LEN;
                out[2..4].copy_from_slice(&handle.to_le_bytes());
                let n = write_characteristic_declaration(
                    &mut out[4..],
                    characteristic.properties,
                    value_handle,
                    characteristic.uuid,
                );
                4 + n
            }
            None => write_error(out, READ_BY_TYPE_REQ, start, AttError::AttributeNotFound),
        }
    }

    /// Read one attribute by handle.
    fn read(&self, request: &[u8], out: &mut [u8]) -> usize {
        if request.len() < 3 {
            return write_error(out, READ_REQ, 0, AttError::InvalidHandle);
        }
        let handle = u16::from_le_bytes([request[1], request[2]]);
        let Some(resolved) = self.gatt.resolve(handle) else {
            return write_error(out, READ_REQ, handle, AttError::InvalidHandle);
        };

        out[0] = READ_RSP;
        let body = &mut out[1..];
        let written = match resolved {
            Resolved::ServiceDeclaration(service) => {
                body[..2].copy_from_slice(&service.uuid.to_le_bytes());
                2
            }
            Resolved::CharacteristicDeclaration {
                value_handle,
                characteristic,
            } => write_characteristic_declaration(
                body,
                characteristic.properties,
                value_handle,
                characteristic.uuid,
            ),
            Resolved::CharacteristicValue(characteristic) => {
                if characteristic.properties & properties::READ == 0 {
                    return write_error(out, READ_REQ, handle, AttError::ReadNotPermitted);
                }
                match characteristic.value.read(0, body) {
                    Ok(n) => n,
                    Err(e) => return write_error(out, READ_REQ, handle, e),
                }
            }
        };
        1 + written
    }

    /// Write one attribute by handle and acknowledge it.
    fn write(&self, request: &[u8], out: &mut [u8]) -> usize {
        match self.apply_write(request) {
            Ok(()) => {
                out[0] = WRITE_RSP;
                1
            }
            Err(e) => write_error(out, WRITE_REQ, request_handle(request), e),
        }
    }

    /// Apply a write request or command, without building a reply.
    fn apply_write(&self, request: &[u8]) -> Result<(), AttError> {
        if request.len() < 3 {
            return Err(AttError::InvalidHandle);
        }
        let handle = u16::from_le_bytes([request[1], request[2]]);
        match self.gatt.resolve(handle) {
            Some(Resolved::CharacteristicValue(characteristic)) => {
                let writable = properties::WRITE | properties::WRITE_WITHOUT_RESPONSE;
                if characteristic.properties & writable == 0 {
                    return Err(AttError::WriteNotPermitted);
                }
                characteristic.value.write(0, &request[3..])
            }
            // Declarations describe the table and are never writable.
            Some(_) => Err(AttError::WriteNotPermitted),
            None => Err(AttError::InvalidHandle),
        }
    }
}

/// The handle a request refers to, or zero if it has none.
fn request_handle(request: &[u8]) -> u16 {
    if request.len() < 3 {
        0
    } else {
        u16::from_le_bytes([request[1], request[2]])
    }
}

/// Parse a request of the form opcode, start handle, end handle, 16-bit type.
fn parse_typed_range(request: &[u8]) -> Option<(u16, u16, u16)> {
    if request.len() < 7 {
        return None;
    }
    Some((
        u16::from_le_bytes([request[1], request[2]]),
        u16::from_le_bytes([request[3], request[4]]),
        u16::from_le_bytes([request[5], request[6]]),
    ))
}

/// Write an error response naming the request that failed.
fn write_error(out: &mut [u8], opcode: u8, handle: u16, error: AttError) -> usize {
    out[0] = ERROR_RSP;
    out[1] = opcode;
    out[2..4].copy_from_slice(&handle.to_le_bytes());
    out[4] = error as u8;
    5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_connection::gatt::{BufferedValue, Characteristic, Service};

    /// Build a server with one service holding one readable and writable
    /// characteristic. Handles: 1 service, 2 declaration, 3 value.
    fn with_server<F: FnOnce(&AttServer<'_>)>(f: F) {
        let value = BufferedValue::<8>::writable(&[0xDE, 0xAD]);
        let characteristics = [Characteristic {
            uuid: 0xFF01,
            properties: properties::READ | properties::WRITE,
            value: &value,
        }];
        let services = [Service {
            uuid: 0xFF00,
            characteristics: &characteristics,
        }];
        f(&AttServer::new(GattServer::new(&services)));
    }

    #[test]
    fn mtu_exchange_reports_the_default() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let n = att
                .handle_request(&[EXCHANGE_MTU_REQ, 0x00, 0x01], &mut out)
                .unwrap();
            assert_eq!(&out[..n], &[EXCHANGE_MTU_RSP, 23, 0]);
        });
    }

    #[test]
    fn service_discovery_then_termination() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let req = [READ_BY_GROUP_TYPE_REQ, 1, 0, 0xFF, 0xFF, 0x00, 0x28];
            let n = att.handle_request(&req, &mut out).unwrap();
            assert_eq!(out[0], READ_BY_GROUP_TYPE_RSP);
            assert_eq!(out[1], SERVICE_ENTRY_LEN);
            // Service at handle 1, group ending at 3, UUID 0xFF00.
            assert_eq!(&out[2..8], &[1, 0, 3, 0, 0x00, 0xFF]);
            assert_eq!(n, 8);

            // Asking past the end terminates discovery with an error.
            let req = [READ_BY_GROUP_TYPE_REQ, 4, 0, 0xFF, 0xFF, 0x00, 0x28];
            let n = att.handle_request(&req, &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
            assert_eq!(out[4], AttError::AttributeNotFound as u8);
            assert_eq!(n, 5);
        });
    }

    #[test]
    fn characteristic_discovery() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let req = [READ_BY_TYPE_REQ, 1, 0, 0xFF, 0xFF, 0x03, 0x28];
            let n = att.handle_request(&req, &mut out).unwrap();
            assert_eq!(out[0], READ_BY_TYPE_RSP);
            assert_eq!(out[1], CHARACTERISTIC_ENTRY_LEN);
            // Declaration at handle 2; value handle 3; UUID 0xFF01.
            assert_eq!(&out[2..4], &[2, 0]);
            assert_eq!(out[4], properties::READ | properties::WRITE);
            assert_eq!(&out[5..9], &[3, 0, 0x01, 0xFF]);
            assert_eq!(n, 9);
        });
    }

    #[test]
    fn read_and_write_round_trip() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let n = att.handle_request(&[READ_REQ, 3, 0], &mut out).unwrap();
            assert_eq!(&out[..n], &[READ_RSP, 0xDE, 0xAD]);

            let n = att
                .handle_request(&[WRITE_REQ, 3, 0, 1, 2, 3], &mut out)
                .unwrap();
            assert_eq!(&out[..n], &[WRITE_RSP]);

            let n = att.handle_request(&[READ_REQ, 3, 0], &mut out).unwrap();
            assert_eq!(&out[..n], &[READ_RSP, 1, 2, 3]);
        });
    }

    #[test]
    fn write_command_is_applied_without_a_reply() {
        with_server(|att| {
            let mut out = [0u8; 23];
            assert!(
                att.handle_request(&[WRITE_CMD, 3, 0, 7], &mut out)
                    .is_none()
            );
            let n = att.handle_request(&[READ_REQ, 3, 0], &mut out).unwrap();
            assert_eq!(&out[..n], &[READ_RSP, 7]);
        });
    }

    #[test]
    fn declarations_are_readable_but_not_writable() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let n = att.handle_request(&[READ_REQ, 1, 0], &mut out).unwrap();
            assert_eq!(&out[..n], &[READ_RSP, 0x00, 0xFF]);

            att.handle_request(&[WRITE_REQ, 1, 0, 9], &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
            assert_eq!(out[4], AttError::WriteNotPermitted as u8);
        });
    }

    #[test]
    fn unknown_handle_is_rejected() {
        with_server(|att| {
            let mut out = [0u8; 23];
            let n = att.handle_request(&[READ_REQ, 9, 0], &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
            assert_eq!(out[1], READ_REQ);
            assert_eq!(&out[2..4], &[9, 0]);
            assert_eq!(out[4], AttError::InvalidHandle as u8);
            assert_eq!(n, 5);
        });
    }

    #[test]
    fn descriptor_discovery_finds_nothing() {
        with_server(|att| {
            let mut out = [0u8; 23];
            att.handle_request(&[FIND_INFORMATION_REQ, 1, 0, 0xFF, 0xFF], &mut out)
                .unwrap();
            assert_eq!(out[0], ERROR_RSP);
            assert_eq!(out[4], AttError::AttributeNotFound as u8);
        });
    }

    #[test]
    fn unsupported_opcode_is_declined() {
        with_server(|att| {
            let mut out = [0u8; 23];
            // Read Blob Request, which this server does not implement.
            att.handle_request(&[0x0C, 3, 0, 0, 0], &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
            assert_eq!(out[1], 0x0C);
            assert_eq!(out[4], AttError::RequestNotSupported as u8);
        });
    }

    #[test]
    fn truncated_requests_do_not_panic() {
        with_server(|att| {
            let mut out = [0u8; 23];
            assert!(att.handle_request(&[], &mut out).is_none());
            att.handle_request(&[READ_REQ], &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
            att.handle_request(&[READ_BY_TYPE_REQ, 1], &mut out)
                .unwrap();
            assert_eq!(out[0], ERROR_RSP);
            att.handle_request(&[WRITE_REQ, 3], &mut out).unwrap();
            assert_eq!(out[0], ERROR_RSP);
        });
    }

    #[test]
    fn a_buffer_too_small_for_an_error_yields_no_reply() {
        with_server(|att| {
            let mut out = [0u8; 4];
            assert!(att.handle_request(&[READ_REQ, 3, 0], &mut out).is_none());
        });
    }
}

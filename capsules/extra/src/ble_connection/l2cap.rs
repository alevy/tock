// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! L2CAP: routing a connection's data to the protocol that owns it.
//!
//! On a low energy connection, L2CAP is thin. Frames carry a length and a
//! channel identifier, and the fixed channels have no segmentation of their
//! own; what fragmentation there is happens at the link layer. The job here is
//! simply to look at the channel identifier and hand the payload to the right
//! protocol.
//!
//! Only the attribute protocol channel is served. The signalling and security
//! manager channels, and the connection-oriented channels that make L2CAP a
//! real stream multiplexer, are not implemented.
//!
//! References are to the Bluetooth Core Specification, Vol 3, Part A.

use crate::ble_connection::att::AttServer;
use crate::ble_connection::link_layer::DataClient;

/// Fixed channel identifier of the attribute protocol (Section 2.1).
pub const CID_ATT: u16 = 0x0004;

/// Bytes of L2CAP header before the payload: a length and a channel
/// identifier.
const HEADER_LEN: usize = 4;

/// Routes a connection's data frames by channel identifier.
pub struct L2capMux<'a> {
    /// Serves the attribute protocol channel.
    att: AttServer<'a>,
}

impl<'a> L2capMux<'a> {
    pub fn new(att: AttServer<'a>) -> Self {
        L2capMux { att }
    }

    /// The attribute protocol server on this connection.
    pub fn att(&self) -> &AttServer<'a> {
        &self.att
    }
}

impl DataClient for L2capMux<'_> {
    fn data_received(&self, frame: &[u8], out: &mut [u8]) -> Option<usize> {
        if frame.len() < HEADER_LEN || out.len() <= HEADER_LEN {
            return None;
        }
        let length = usize::from(u16::from_le_bytes([frame[0], frame[1]]));
        let cid = u16::from_le_bytes([frame[2], frame[3]]);
        if cid != CID_ATT {
            return None;
        }
        // Trust the shorter of the declared length and what actually arrived,
        // so a payload can never be read past the end of the frame.
        let end = (HEADER_LEN + length).min(frame.len());
        let payload = &frame[HEADER_LEN..end];

        let n = self.att.handle_request(payload, &mut out[HEADER_LEN..])?;
        out[0..2].copy_from_slice(&(n as u16).to_le_bytes());
        out[2..4].copy_from_slice(&CID_ATT.to_le_bytes());
        Some(HEADER_LEN + n)
    }

    fn connection_reset(&self) {
        self.att.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble_connection::gatt::{
        BufferedValue, Characteristic, GattServer, Service, properties,
    };

    /// One service with one readable, writable characteristic: service
    /// declaration at handle 1, characteristic declaration at 2, value at 3.
    fn with_mux<F: FnOnce(&L2capMux<'_>)>(f: F) {
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
        f(&L2capMux::new(AttServer::new(GattServer::new(&services))));
    }

    /// Wrap `payload` in an L2CAP header addressed to `cid`.
    fn frame(cid: u16, payload: &[u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        buf[2..4].copy_from_slice(&cid.to_le_bytes());
        buf[4..4 + payload.len()].copy_from_slice(payload);
        buf
    }

    #[test]
    fn att_frames_are_answered_with_an_att_frame() {
        with_mux(|mux| {
            let request = frame(CID_ATT, &[0x0A, 3, 0]); // Read Request, handle 3
            let mut out = [0u8; 32];
            let n = mux.data_received(&request[..7], &mut out).unwrap();
            // Three bytes of ATT response inside a four-byte L2CAP header.
            assert_eq!(&out[0..2], &[3, 0]);
            assert_eq!(&out[2..4], &CID_ATT.to_le_bytes());
            assert_eq!(&out[4..7], &[0x0B, 0xDE, 0xAD]);
            assert_eq!(n, 7);
        });
    }

    #[test]
    fn other_channels_are_ignored() {
        with_mux(|mux| {
            // The security manager channel, which this does not implement.
            let request = frame(0x0006, &[0x01, 0x03, 0x00, 0x01, 0x10]);
            let mut out = [0u8; 32];
            assert!(mux.data_received(&request[..9], &mut out).is_none());
        });
    }

    #[test]
    fn an_overlong_length_field_cannot_read_past_the_frame() {
        with_mux(|mux| {
            // Claim 20 bytes of payload but supply only the three that follow.
            // Reading past them would hand stale bytes to the write.
            let mut request = frame(CID_ATT, &[0x12, 3, 0, 0x01]);
            request[0] = 20;
            let mut out = [0u8; 32];
            let n = mux.data_received(&request[..8], &mut out).unwrap();
            // The write is accepted with exactly the byte that arrived.
            assert_eq!(&out[4..4 + n - 4], &[0x13]);

            let read = frame(CID_ATT, &[0x0A, 3, 0]);
            let n = mux.data_received(&read[..7], &mut out).unwrap();
            assert_eq!(&out[4..n], &[0x0B, 0x01]);
        });
    }

    #[test]
    fn truncated_frames_do_not_panic() {
        with_mux(|mux| {
            let mut out = [0u8; 32];
            assert!(mux.data_received(&[], &mut out).is_none());
            assert!(mux.data_received(&[0, 0, 4], &mut out).is_none());
            // A header with no payload is a well-formed but empty request.
            assert!(mux.data_received(&[0, 0, 4, 0], &mut out).is_none());
        });
    }
}

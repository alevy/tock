// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2026.

//! Bluetooth Low Energy connections.
//!
//! These capsules implement the part of a BLE peripheral that sits above the
//! radio: the link layer's connection state machine, and the protocols carried
//! over an established connection.
//!
//! Nothing here touches chip registers. The timing-critical work -- answering
//! the central's packet within the inter-frame space -- belongs to a
//! [`BleConnectionDriver`](kernel::hil::ble_connection::BleConnectionDriver)
//! implementation in a chip crate. See `doc/reference/trd-ble-connection.md`.
//!
//! Advertising is handled separately, by
//! [`ble_advertising_driver`](crate::ble_advertising_driver), which hands a
//! connection over once it has accepted a `CONNECT_IND`.

pub mod link_layer;

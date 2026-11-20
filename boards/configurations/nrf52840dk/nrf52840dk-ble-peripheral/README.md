nRF52840-DK BLE Peripheral
===================================

A kernel that advertises as a connectable BLE peripheral and serves a GATT
service defined here in the board, in `src/main.rs`. A central can discover the
device, connect to it, and read and write the characteristic.

This board deliberately does **not** bring up the 802.15.4 radio. The nRF52840
has one 2.4 GHz radio, and a BLE connection has to be on the air at every
connection event, so the two protocols cannot share it. See
`doc/reference/trd-ble-connection.md`.

Testing
-------

With BlueZ:

```
bluetoothctl
> connect C0:FF:EE:BE:EF:42
> menu gatt
> list-attributes C0:FF:EE:BE:EF:42
> select-attribute <path to the 0xFFF1 characteristic>
> read
> write "0x01 0x02 0x03"
> read
> disconnect
```

Note that the device is not yet reliably discoverable from Android, because it
does not answer the scan requests an active scan sends.

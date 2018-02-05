---
driver number: 0xfffff
---

# Bluetooth Low Energy Advertising

## Overview

## Command

  * ### Command number: `0`

    **Description**: Does the driver exist?

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: SUCCESS if it exists, otherwise ENODEVICE

  * ### Command number: `0`

    **Description**: Start periodic advertisements

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: EBUSY if advertisements for the process have already been
    started. SUCCESS if the command completes without error.

  * ### Command number: `1`

    **Description**: Stop periodic advertisements and passive scanning.

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: `EBUSY` if an advertisement or scan is currently underway or
    if neither is configured. SUCCESS if advertisements and passive scanning
    were stopped.

  * ### Command number: `2`

    **Description**: Configure transmitter power

    **Argument 1**: Transmission power in dBm. Valid values are in the range
    -20 dBm to 10 dBm.

    **Argument 2**: unused

    **Returns**: `EINVAL` if the requested transmission power is invalid. EBUSY
    if the transmission power cannot be configured. SUCCESS if transmission
    power was adjusted successfully.

  * ### Command number: `3`

    **Description**: Configure advertising interval

    **Argument 1**: Advertising interval as an unsigned integer multiple of
    0.625ms in the range of 20ms to 10240ms.

    **Argument 2**: unused

    **Returns**: `EINVAL` if the requested transmission power is invalid. EBUSY
    if the transmission power cannot be configured. SUCCESS if transmission
    power was adjusted successfully.

  * ### Command number: `4`

    **Description**: Reset advertising payload

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: EBUSY if in the middle of a transmission. SUCCESS if
    payload reset successfully.

  * ### Command number: `5`

    **Description**: Enable passive scanning mode

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: EBUSY if in the middle of a transmission. SUCCESS if
    passive scanning started successfully.

  * ### Command number: `6`

    **Description**: Initialize driver. Creates a unique, random Bluetooth
    device address for the processes.

    **Argument 1**: unused

    **Argument 2**: unused

    **Returns**: EINVAL if in the middle of a transmission. SUCCESS if
    driver initialized successfully.

## Subscribe

  * ### Subscribe number: `0`

    **Description**: Subscribe to scanning callback

    **Callback signature**: The callback receives an error code as the first
    argument and the length of the recieved packet as the second argument.

    **Returns**: SUCCESS if the subscribe was successful or ENOMEM if the
    driver failed to allocate memory to store the callback.


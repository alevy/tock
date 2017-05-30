# Driver Number Assignments

## Current (tip, non-standardized)

| Driver Number | Driver           | Description                                |
|---------------|------------------|--------------------------------------------|
| 0             | Console          | UART console                               |
| 1             | GPIO             |                                            |
| 2             | TMP006           | Temperature sensor                         |
| 3             | Timer            |                                            |
| 4             | SPI              | Raw SPI interface                          |
| 5             | nRF51822         | nRF serialization link to nRF51822 BLE SoC |
| 6             | ISL29035         | Light sensor                               |
| 7             | ADC              |                                            |
| 8             | LED              |                                            |
| 9             | Button           |                                            |
| 10            | SI7021           | Temperature sensor                         |
| 11            | Ninedof          | Virtualized accelerometer/magnetometer/gyroscope |
| 12            | TSL2561          | Light sensor                               |
| 13            | I2C Master/Slave | Raw I2C interface                          |
| 14            | RNG              | Random number generator                    |
| 15            | SDCard           | Raw block access to an SD card             |
| 16            | CRC              | Cyclic Redundancy Check computation        |
| 17            | AES              | AES encryption and decryption              |
| 18            | LTC294X          | Battery gauge IC                           |
| 22            | LPS25HB          | Pressure sensor                            |
| 154           | Radio            | 15.4 radio interface                       |
| 255           | IPC              | Inter-process communication                |

## Proposed Tock userland 1.0

| Driver Number | Driver                     | Examples                                 |
|---------------|----------------------------|------------------------------------------|
| **Base**                                                                              |
| 0             | Timer                      | Asynchronous Timer                       |
| 1             | Console                    | UART console                             |
| 2             | LED                        |                                          |
| 3             | Button                     |                                          |
| 4             | GPIO                       |                                          |
| 5             | ADC                        |                                          |
| **Crypto**                                                                            |
| 10            | Random number generator    | SAM4L/NRF RNG, imix RNG                  |
| 11            | CRC                        | Cyclic Redundancy Check computation      |
| 12            | Symmetric Encryption       | AES                                      |
| **Communication**                                                                     |
| 20            | UART                       |                                          |
| 21            | SPI                        |                                          |
| 22            | I2C Master/Slave           |                                          |
| **Sensors**                                                                           |
| 30            | Nine degrees of freedom    | FXO8700CQ                                |
| 31            | Temperature Sensor         | SI7021, TMP006                           |
| 32            | Humidity Sensor            | SI7021                                   |
| 33            | Light Sensor               | TSL2561, ISL29035                        |
| 34            | Pressure Sensor            | LPS25HB                                  |
| **Misc**                                                                              |
| 252           | nRF51 Serialization        |                                          |
| 253           | SDCard block device        |                                          |
| 254           | 15.4 Radio                 |                                          |
| **IPC**                                                                               |
| 255           | Interprocess communication |                                          |


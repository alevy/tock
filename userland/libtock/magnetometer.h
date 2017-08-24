#pragma once

#include "tock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRIVER_NUM_MAGNETOMETER 0x60001

// function to be called when the magnetometer measurement is finished
//
// callback       - pointer to function to be called
// callback_args  - pointer to data provided to the callback
int magnetometer_set_callback (subscribe_cb callback, void* callback_args);


// initiate an magnetometer measurement used both for syncronous and asyncronous readings
int magnetometer_read(void);

// initiate a syncronous magnetometer measurement
//
// humi           - pointer/address where the result of the magnetometer reading should be stored
int magnetometer_read_sync (int* x, int* y, int* z);

#ifdef __cplusplus
}
#endif

#pragma once

#include "tock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRIVER_NUM_ACCELEROMETER 0x60000

// function to be called when the accelerometer measurement is finished
//
// callback       - pointer to function to be called
// callback_args  - pointer to data provided to the callback
int accelerometer_set_callback (subscribe_cb callback, void* callback_args);


// initiate an accelerometer measurement used both for syncronous and asyncronous readings
int accelerometer_read(void);

// initiate a syncronous accelerometer measurement
//
// humi           - pointer/address where the result of the accelerometer reading should be stored
int accelerometer_read_sync (int* x, int* y, int* z);

double accelerometer_read_magnitude(void);

#ifdef __cplusplus
}
#endif

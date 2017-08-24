#pragma once

#include "tock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRIVER_NUM_GYROSCOPE 0x60002

// function to be called when the gyroscope measurement is finished
//
// callback       - pointer to function to be called
// callback_args  - pointer to data provided to the callback
int gyroscope_set_callback (subscribe_cb callback, void* callback_args);


// initiate an gyroscope measurement used both for syncronous and asyncronous readings
int gyroscope_read(void);

// initiate a syncronous gyroscope measurement
//
// humi           - pointer/address where the result of the gyroscope reading should be stored
int gyroscope_read_sync (int* x, int* y, int* z);

#ifdef __cplusplus
}
#endif

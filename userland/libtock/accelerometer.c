#include <stdio.h>

#include "accelerometer.h"
#include "math.h"

struct accelerometer_data {
  int x;
  int y;
  int z;
  bool fired;
};

static struct accelerometer_data res = { .fired = false };

// internal callback for faking synchronous reads
static void accelerometer_cb(int x, int y, int z, void* ud) {
  struct accelerometer_data* result = (struct accelerometer_data*) ud;
  result->x     = x;
  result->y     = y;
  result->z     = z;
  result->fired = true;
}

int accelerometer_set_callback(subscribe_cb callback, void* userdata) {
  return subscribe(DRIVER_NUM_ACCELEROMETER, 0, callback, userdata);
}

int accelerometer_read(void) {
  return command(DRIVER_NUM_ACCELEROMETER, 1, 0);
}

int accelerometer_read_sync(int* x, int* y, int* z) {
  int err;
  res.fired = false;
  res.x     = 0xde;

  err = accelerometer_set_callback(accelerometer_cb, (void*) &res);
  if (err < 0) return err;

  err = accelerometer_read();
  if (err < 0) return err;

  // Wait for the callback.
  yield_for(&res.fired);

  *x = res.x;
  *y = res.y;
  *z = res.z;

  return 0;
}

double accelerometer_read_magnitude(void) {
  struct accelerometer_data result = { .fired = false };
  int err;

  err = accelerometer_set_callback(accelerometer_cb, (void*)(&result));
  if (err < 0) {
    return err;
  }

  err = accelerometer_read();
  if (err < 0) {
    return err;
  }

  yield_for(&result.fired);

  return sqrt(result.x * result.x + result.y * result.y + result.z * result.z);
}

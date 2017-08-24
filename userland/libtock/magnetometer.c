#include <stdio.h>

#include "magnetometer.h"
#include "math.h"

struct magnetometer_data {
  int x;
  int y;
  int z;
  bool fired;
};

static struct magnetometer_data res = { .fired = false };

// internal callback for faking synchronous reads
static void magnetometer_cb(int x, int y, int z, void* ud) {
  struct magnetometer_data* result = (struct magnetometer_data*) ud;
  result->x     = x;
  result->y     = y;
  result->z     = z;
  result->fired = true;
}

int magnetometer_set_callback(subscribe_cb callback, void* userdata) {
  return subscribe(DRIVER_NUM_MAGNETOMETER, 0, callback, userdata);
}

int magnetometer_read(void) {
  return command(DRIVER_NUM_MAGNETOMETER, 1, 0);
}

int magnetometer_read_sync(int* x, int* y, int* z) {
  int err;
  res.fired = false;

  err = magnetometer_set_callback(magnetometer_cb, (void*) &res);
  if (err < 0) return err;

  err = magnetometer_read();
  if (err < 0) return err;

  // Wait for the callback.
  yield_for(&res.fired);

  *x = res.x;
  *y = res.y;
  *z = res.z;

  return 0;
}

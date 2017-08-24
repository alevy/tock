#include <stdio.h>

#include "gyroscope.h"
#include "math.h"

struct gyroscope_data {
  int x;
  int y;
  int z;
  bool fired;
};

static struct gyroscope_data res = { .fired = false };

// internal callback for faking synchronous reads
static void gyroscope_cb(int x, int y, int z, void* ud) {
  struct gyroscope_data* result = (struct gyroscope_data*) ud;
  result->x     = x;
  result->y     = y;
  result->z     = z;
  result->fired = true;
}

int gyroscope_set_callback(subscribe_cb callback, void* userdata) {
  return subscribe(DRIVER_NUM_GYROSCOPE, 0, callback, userdata);
}

int gyroscope_read(void) {
  return command(DRIVER_NUM_GYROSCOPE, 1, 0);
}

int gyroscope_read_sync(int* x, int* y, int* z) {
  int err;
  res.fired = false;

  err = gyroscope_set_callback(gyroscope_cb, (void*) &res);
  if (err < 0) return err;

  err = gyroscope_read();
  if (err < 0) return err;

  // Wait for the callback.
  yield_for(&res.fired);

  *x = res.x;
  *y = res.y;
  *z = res.z;

  return 0;
}

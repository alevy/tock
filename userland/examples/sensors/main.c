#include <stdbool.h>
#include <stdio.h>

#include <accelerometer.h>
#include <ambient_light.h>
#include <gyroscope.h>
#include <humidity.h>
#include <magnetometer.h>
#include <temperature.h>
#include <timer.h>
#include <tock.h>

static bool ambient_light = false;
static bool temperature   = false;
static bool humidity      = false;
static bool accelerometer = false;
static bool magnetometer  = false;
static bool gyroscope     = false;

static void timer_fired(__attribute__ ((unused)) int arg0,
                        __attribute__ ((unused)) int arg1,
                        __attribute__ ((unused)) int arg2,
                        __attribute__ ((unused)) void* ud) {
  int light = 0;
  int temp = 0;
  unsigned humi = 0;
  int accel_x = 0, accel_y = 0, accel_z = 0;
  int magnet_x = 0, magnet_y = 0, magnet_z = 0;
  int gyro_x = 0, gyro_y = 0, gyro_z = 0;

  /* *INDENT-OFF* */
  if (ambient_light) light = ambient_light_read_intensity();
  if (temperature)   temperature_read_sync(&temp);
  if (humidity)      humidity_read_sync(&humi);
  if (accelerometer) accelerometer_read_sync(&accel_x, &accel_y, &accel_z);
  if (magnetometer)  magnetometer_read_sync(&magnet_x, &magnet_y, &magnet_z);
  if (gyroscope)     gyroscope_read_sync(&gyro_x, &gyro_y, &gyro_z);

  if (ambient_light)  printf("Light Intensity: %d\n", light);
  if (temperature)    printf("Temperature:     %d deg C\n", temp/100);
  if (humidity)       printf("Humidity:        %u%%\n", humi/100);
  if (accelerometer)  printf("Acceleration:    (%d, %d, %d)\n", accel_x, accel_y, accel_z);
  if (magnetometer)   printf("Magnetism:       (%d, %d, %d)\n", magnet_x, magnet_y, magnet_z);
  if (gyroscope)      printf("Gyroscope:       (%d, %d, %d)\n", gyro_x, gyro_y, gyro_z);

  /* *INDENT-ON* */

  printf("\n");
}

int main(void) {
  printf("[Sensors] Starting Sensors App.\n");
  printf("[Sensors] All available sensors on the platform will be sampled.\n");

  ambient_light = driver_exists(DRIVER_NUM_AMBIENT_LIGHT);
  temperature   = driver_exists(DRIVER_NUM_TEMPERATURE);
  humidity      = driver_exists(DRIVER_NUM_HUMIDITY);
  accelerometer = driver_exists(DRIVER_NUM_ACCELEROMETER);
  magnetometer  = driver_exists(DRIVER_NUM_MAGNETOMETER);
  gyroscope     = driver_exists(DRIVER_NUM_GYROSCOPE);

  // Setup periodic timer to sample the sensors.
  static tock_timer_t timer;
  timer_every(1000, timer_fired, NULL, &timer);

  return 0;
}

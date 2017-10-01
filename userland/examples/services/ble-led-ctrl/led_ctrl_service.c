#include <stdint.h>
#include <string.h>

#include <app_error.h>
#include <ble.h>

#include <ipc.h>

#include "led_ctrl_service.h"

static uint16_t service_handle;

static ble_gatts_char_handles_t btn_char_handle;
static led_update_t led_update_buffer;

static volatile int g_pid = 0;
static volatile char* g_buf = 0;
static volatile int g_buf_len = 0;

bool btn_ctrl_tx_arm(int pid, char* buf, int len) {
    if ((g_pid != 0) || (g_buf != 0)) {
        return false;
    } else {
        g_pid = pid;
        g_buf = buf;
        g_buf_len = len;
        return true;
    }
}

void btn_ctrl_service_init(void) {
  uint32_t   err_code;

  ///////////////////////////////////////////
  // Set up service
  ///////////////////////////////////////////
  ble_uuid_t        service_uuid;
  ble_uuid128_t     base_uuid = BASE_LED_UUID_128_SERVICE;

  service_uuid.uuid = 0x1024;
  err_code = sd_ble_uuid_vs_add(&base_uuid, &service_uuid.type);

  APP_ERROR_CHECK(err_code);

  err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                      &service_uuid,
                                      &service_handle);
  APP_ERROR_CHECK(err_code);

  ///////////////////////////////////////////
  // Set up characteristic(s)
  ///////////////////////////////////////////
  ble_gatts_char_md_t char_md;
  ble_gatts_attr_t attr_char_value;
  ble_uuid_t char_uuid;
  ble_gatts_attr_md_t attr_md;

  // set characteristic metadata
  memset(&char_md, 0, sizeof(char_md));
  char_md.char_props.write   = true;

  // set characteristic uuid
  char_uuid.type = service_uuid.type;
  char_uuid.uuid = 0x2048;

  // set attribute metadata
  memset(&attr_md, 0, sizeof(attr_md));
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
  BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
  attr_md.vloc = BLE_GATTS_VLOC_STACK;

  // set attribute data
  memset(&attr_char_value, 0, sizeof(attr_char_value));
  attr_char_value.p_uuid    = &char_uuid;
  attr_char_value.p_attr_md = &attr_md;
  attr_char_value.init_len  = sizeof(led_update_t);
  attr_char_value.init_offs = 0;
  attr_char_value.max_len   = sizeof(led_update_t);
  attr_char_value.p_value   = (uint8_t*)&led_update_buffer;

  err_code = sd_ble_gatts_characteristic_add(service_handle,
                                             &char_md,
                                             &attr_char_value,
                                             &btn_char_handle);
  APP_ERROR_CHECK(err_code);

  g_buf = 0;
  g_pid = 0;
}

void btn_ctrl_handle_write(ble_gatts_evt_write_t* context) {

  if ((context->handle == btn_char_handle.value_handle) &&
      (context->offset == 0) &&
      (context-> len == 2)) {

      led_update_t updt = {
        .led_id = context->data[0],
        .cmd = context->data[1]
      };

      // TODO - send this somewhere over IPC
      printf("GOT BLE: %02X %02X\n", updt.led_id, updt.cmd);

      if((g_pid != 0) && (g_buf != 0)) {
          int pid = g_pid;
          g_buf[g_buf_len - 1] = 0;
          *(led_update_t*)(g_buf) = updt;
          g_buf = 0;
          g_pid = 0;
          ipc_notify_client(pid);
      } else {
        printf("Not armed...\n");
      }
  }
}

// static uint32_t notify(uint16_t conn, uint16_t handle) {
//   uint32_t err_code;
//   ble_gatts_hvx_params_t hvx_params;
//   hvx_params.handle = handle;
//   hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
//   hvx_params.offset = 0;
//   hvx_params.p_len  = NULL; // notify full length. No response wanted
//   hvx_params.p_data = NULL; // use existing value

//   err_code = sd_ble_gatts_hvx(conn, &hvx_params);
//   if (err_code == NRF_ERROR_INVALID_STATE) {
//     // error means notify is not enabled by the client. IGNORE
//     return NRF_SUCCESS;
//   }
//   return err_code;
// }

// static uint32_t env_sense_update(uint16_t conn, uint8_t* new_value, uint16_t handle) {
//   uint32_t err_code;

//   ble_gatts_value_t value = {
//     .len     = 2,
//     .offset  = 0,
//     .p_value = new_value,
//   };
//   err_code = sd_ble_gatts_value_set(BLE_CONN_HANDLE_INVALID, handle, &value);
//   if (err_code != NRF_SUCCESS) return err_code;

//   return notify(conn, handle);
// }

// uint32_t env_sense_update_irradiance(uint16_t conn, uint16_t new_irradiance) {
//   return env_sense_update(conn, (uint8_t*) &new_irradiance, irradiance_char_handle.value_handle);
// }

// uint32_t env_sense_update_temperature(uint16_t conn, int16_t new_temperature) {
//   return env_sense_update(conn, (uint8_t*) &new_temperature, temp_char_handle.value_handle);
// }

// uint32_t env_sense_update_humidity(uint16_t conn, uint16_t new_humidity) {
//   return env_sense_update(conn, (uint8_t*) &new_humidity, humidity_char_handle.value_handle);
// }

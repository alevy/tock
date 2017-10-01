#include <stdint.h>
#include <stdbool.h>

#define BASE_LED_UUID_128_SERVICE                   \
{                                                   \
    {                                               \
        0x01, 0x00, 0xCB, 0x4A, 0x27, 0xD3,         \
        0x7D, 0xB9,                                 \
        0xB1, 0x44,                                 \
        0x25, 0x32,                                 \
        0x00, 0x00,     /* Maskable bytes! */       \
        0x05, 0x0F                                  \
    }                                               \
}   // Base UUID: 0F05xxxx-3225-44B1-B97D-D3274ACB0001

typedef struct {
    uint8_t led_id;
    uint8_t cmd;
} led_update_t;

// Ensure that our message type is consistently sized and arranged
STATIC_ASSERT(sizeof(led_update_t) == 2);
STATIC_ASSERT(offsetof(led_update_t, led_id)==0);
STATIC_ASSERT(offsetof(led_update_t, cmd)==1);

void btn_ctrl_service_init(void);
void btn_ctrl_handle_write(ble_gatts_evt_write_t* context);
bool btn_ctrl_tx_arm(int pid, char* buf, int len);

// uint32_t env_sense_update_irradiance(uint16_t conn, uint16_t irradiance);
// uint32_t env_sense_update_temperature(uint16_t conn, int16_t temperature);
// uint32_t env_sense_update_humidity(uint16_t conn, uint16_t humidity);

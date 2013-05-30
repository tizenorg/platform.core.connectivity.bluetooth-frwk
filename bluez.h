#ifndef __BLUEZ_H__
#define __BLUEZ_H__
struct _bluez_adapter;

typedef struct _bluez_adapter bluez_adapter_t;

typedef void (*bluez_adapter_powered_cb_t) (bluez_adapter_t *adapter,
						gboolean powered,
						gpointer user_data);

typedef void (*bluez_adapter_alias_cb_t) (bluez_adapter_t *adapter,
						const gchar **alias,
						gpointer user_data);

struct _bluez_device;
typedef struct _bluez_device bluez_device_t;
#endif

#ifndef __BLUEZ_H__
#define __BLUEZ_H__
struct _bluez_adapter;

typedef struct _bluez_adapter bluez_adapter_t;

typedef void (*bluez_adapter_powered_cb_t) (bluez_adapter_t *adapter, gboolean powered, gpointer user_data);
#endif

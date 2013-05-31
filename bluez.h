#ifndef __BLUEZ_H__
#define __BLUEZ_H__

struct _bluez_adapter;
typedef struct _bluez_adapter bluez_adapter_t;

struct _bluez_device;
typedef struct _bluez_device bluez_device_t;


void bluez_lib_deinit(void);
int bluez_lib_init(void);

/* adapter functions */
struct _bluez_adapter *bluez_adapter_get_adapter(
				const char *name);

void bluez_adapter_start_discovery(
				struct _bluez_adapter *adapter);
void bluez_adapter_stop_discovery(
				struct _bluez_adapter *adapter);

struct _bluez_device *bluez_adapter_get_device(
				struct _bluez_adapter *adapter,
				const char *addr);
void bluez_adapter_remove_device(
				struct _bluez_adapter *adapter,
				struct _bluez_device *device);

int bluez_adapter_get_property_powered(
				struct _bluez_adapter *adapter,
				gboolean *powered);
void bluez_adapter_set_powered(struct _bluez_adapter *adapter,
				gboolean powered);
typedef void (*bluez_adapter_powered_cb_t)(
				bluez_adapter_t *adapter,
				gboolean powered,
				gpointer user_data);
void bluez_adapter_set_powered_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_powered_cb_t cb,
				gpointer user_data);

void bluez_adapter_set_alias(
				struct _bluez_adapter *adapter,
				const gchar *alias);
typedef void (*bluez_adapter_alias_cb_t)(
				bluez_adapter_t *adapter,
				const gchar **alias,
				gpointer user_data);
void bluez_adapter_set_alias_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_alias_cb_t cb,
				gpointer user_data);

/* device functions */
void bluez_device_pair(struct _bluez_device *device);

int bluez_device_property_get_adapter(
				struct _bluez_device *device,
				const char **adapter_path);
#endif

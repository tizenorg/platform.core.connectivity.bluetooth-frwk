#ifndef __BLUETOOTH_MEDIA__
#define __BLUETOOTH_MEDIA__

#include <gio/gio.h>

#include "bluez.h"

void bt_service_media_init(GDBusObjectSkeleton *object,
					GDBusConnection *connection,
					bluez_adapter_t *adapter);

void bt_service_media_deinit(void);

#endif

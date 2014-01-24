#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "media.h"
#include "vertical.h"

void bt_service_media_init(GDBusObjectSkeleton *gdbus_object_skeleton,
						GDBusConnection *connection,
						bluez_adapter_t *adapter)
{
	DBG("");
}

void bt_service_media_deinit(void)
{
	DBG("");
}

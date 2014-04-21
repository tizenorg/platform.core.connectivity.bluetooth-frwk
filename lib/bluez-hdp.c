#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "common.h"
#include "bluez.h"

int bluetooth_hdp_activate(unsigned short data_type,
					bt_hdp_role_type_t role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	int ret;

	DBG("");

	ret = BT_ERROR_NONE;
	return ret;
}

int bluetooth_hdp_deactivate(const char *app_handle)
{
	int ret;

	DBG("");

	ret = BT_ERROR_NONE;
	return ret;
}

int bluetooth_hdp_send_data(unsigned int channel_id,
					const char *buffer,
					unsigned int size)
{
	int ret;

	DBG("");

	ret = BT_ERROR_NONE;
	return ret;
}

int bluetooth_hdp_connect(const char *app_handle,
			bt_hdp_qos_type_t channel_type,
			const bluetooth_device_address_t *device_address)
{
	int ret;

	DBG("");

	ret = BT_ERROR_NONE;
	return ret;
}

int bluetooth_hdp_disconnect(unsigned int channel_id,
		const bluetooth_device_address_t *device_address)
{
	int ret;

	DBG("");

	ret = BT_ERROR_NONE;
	return ret;
}

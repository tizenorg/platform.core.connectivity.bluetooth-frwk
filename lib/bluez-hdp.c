#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "common.h"
#include "bluez.h"

static bluez_hdp_state_changed_t hdp_state_changed_cb;
static gpointer hdp_state_changed_cb_data;
static bluez_set_data_received_changed_t data_received_changed_cb;
static gpointer data_received_changed_data;

void bluez_set_hdp_state_changed_cb(
				bluez_hdp_state_changed_t cb,
				gpointer user_data)
{
	hdp_state_changed_cb = cb;
	hdp_state_changed_cb_data = user_data;
}

void bluez_unset_hdp_state_changed_cb()
{
	hdp_state_changed_cb = NULL;
	hdp_state_changed_cb_data = NULL;
}

void bluez_set_data_received_changed_cb(
				bluez_set_data_received_changed_t cb,
				gpointer user_data)
{
	data_received_changed_cb = cb;
	data_received_changed_data = user_data;
}

void bluez_unset_data_received_changed_cb()
{
	data_received_changed_cb = NULL;
	data_received_changed_data = NULL;
}

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

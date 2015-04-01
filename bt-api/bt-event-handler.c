/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *              http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <dlog.h>
#include <vconf.h>

#include "bluetooth-api.h"
#include "bluetooth-audio-api.h"
#include "bt-internal-types.h"

#include "bt-common.h"
#include "bt-event-handler.h"
#include "bt-request-sender.h"

typedef struct {
	int server_fd;
} bt_server_info_t;

typedef struct {
	int request_id;
} bt_sending_info_t;

static int obex_server_id;
static gboolean is_initialized;
static GSList *sending_list = NULL;
static GSList *server_list = NULL;
static GSList *event_list = NULL;

void _bt_add_push_request_id(int request_id)
{
	bt_sending_info_t *info;

	info = g_new0(bt_sending_info_t, 1);
	info->request_id = request_id;

	sending_list = g_slist_append(sending_list, info);
}

static gboolean __bt_is_request_id_exist(int request_id)
{
	GSList *l;
	bt_sending_info_t *info;

	for (l = sending_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		retv_if(info->request_id == request_id, TRUE);
	}

	return FALSE;
}

static void __bt_remove_push_request_id(int request_id)
{
	GSList *l;
	bt_sending_info_t *info;

	for (l = sending_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		if (info->request_id == request_id) {
			sending_list = g_slist_remove(sending_list, (void *)info);
			g_free(info);
			break;
		}
	}
}

static void __bt_remove_all_push_request_id(void)
{
	GSList *l;
	bt_sending_info_t *info;

	for (l = sending_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		g_free(info);
	}

	g_slist_free(sending_list);
	sending_list = NULL;
}

static void __bt_remove_all_server(void)
{
	GSList *l;
	bt_server_info_t *info;

	for (l = server_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		g_free(info);
	}

	g_slist_free(server_list);
	server_list = NULL;
}

static gboolean __bt_is_server_exist(int server_fd)
{
	GSList *l;
	bt_server_info_t *info;

	for (l = server_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		retv_if(info->server_fd == server_fd, TRUE);
	}

	return FALSE;
}

static void __bt_get_uuid_info(bluetooth_device_info_t *dev_info,
				char **uuids,
				int uuid_count)
{
	int i;
	char **parts;

	ret_if(dev_info == NULL);
	ret_if(uuids == NULL);
	ret_if(uuid_count <= 0);

	dev_info->service_index = uuid_count;

	for (i = 0; i < uuid_count && uuids[i] != NULL; i++) {
		g_strlcpy(dev_info->uuids[i], uuids[i], BLUETOOTH_UUID_STRING_MAX);

		parts = g_strsplit(uuids[i], "-", -1);

		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			continue;
		}

		dev_info->service_list_array[i] = g_ascii_strtoull(parts[0], NULL, 16);
		g_strfreev(parts);
	}
}

static bluetooth_device_info_t *__bt_get_device_info_in_message(DBusMessage *msg, int *ret)
{
	bluetooth_device_info_t *dev_info;
	char *address = NULL;
	char *name = NULL;
	char **uuids = NULL;
	unsigned int class = 0;
	int rssi = 0;
	gboolean paired = FALSE;
	gboolean connected = FALSE;
	gboolean trust = FALSE;
	int uuid_count = 0;
	int result = BLUETOOTH_ERROR_NONE;

	if (!dbus_message_get_args(msg, NULL,
		DBUS_TYPE_INT32, &result,
		DBUS_TYPE_STRING, &address,
		DBUS_TYPE_UINT32, &class,
		DBUS_TYPE_INT16, &rssi,
		DBUS_TYPE_STRING, &name,
		DBUS_TYPE_BOOLEAN, &paired,
		DBUS_TYPE_BOOLEAN, &connected,
		DBUS_TYPE_BOOLEAN, &trust,
		DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
		&uuids, &uuid_count,
		DBUS_TYPE_INVALID)) {
		BT_ERR("Unexpected parameters in signal");
		return NULL;
	}

	dev_info = g_malloc0(sizeof(bluetooth_device_info_t));

	dev_info->rssi = rssi;
	dev_info->paired = paired;
	dev_info->connected = connected;
	dev_info->paired = paired;
	dev_info->trust = trust;

	g_strlcpy(dev_info->device_name.name, name, BLUETOOTH_DEVICE_NAME_LENGTH_MAX + 1);

	_bt_divide_device_class(&dev_info->device_class, class);

	_bt_convert_addr_string_to_type(dev_info->device_address.addr,
					address);

	if (uuid_count > 0)
		__bt_get_uuid_info(dev_info, uuids, uuid_count);

	*ret = result;

	return dev_info;
}

static DBusHandlerResult __bt_adapter_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_ADAPTER_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;


	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_ENABLED) == 0) {
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (result == BLUETOOTH_ERROR_NONE) {
			if (vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 0) != 0)
				BT_ERR("Set vconf failed\n");
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_ENABLED,
				result, NULL,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DISABLED) == 0) {
		_bt_common_event_cb(BLUETOOTH_EVENT_DISABLED,
				BLUETOOTH_ERROR_NONE, NULL,
				event_info->cb, event_info->user_data);

		obex_server_id = BT_NO_SERVER;
		__bt_remove_all_server();
		__bt_remove_all_push_request_id();
	} else if (strcasecmp(member, BT_DISCOVERABLE_MODE_CHANGED) == 0) {
		int mode = 0;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &mode,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				result, &mode,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DISCOVERABLE_TIMEOUT_CHANGED) == 0) {
		int timeout = 0;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &timeout,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_CHANGED,
				result, &timeout,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_ADAPTER_NAME_CHANGED) == 0) {
		char *adapter_name = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &adapter_name,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_LOCAL_NAME_CHANGED,
				result, adapter_name,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DISCOVERY_STARTED) == 0) {
		_bt_common_event_cb(BLUETOOTH_EVENT_DISCOVERY_STARTED,
				BLUETOOTH_ERROR_NONE, NULL,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DISCOVERY_FINISHED) == 0) {
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_DISCOVERY_FINISHED,
				result, NULL,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DEVICE_FOUND) == 0) {
		int event;
		bluetooth_device_info_t *device_info;

		device_info = __bt_get_device_info_in_message(msg, &result);
		retv_if(device_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		if (strlen(device_info->device_name.name) > 0) {
			event = BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED;
		} else {
			event = BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND;
		}

		_bt_common_event_cb(event,
				result, device_info,
				event_info->cb, event_info->user_data);

		g_free(device_info);
	} else if (strcasecmp(member, BT_DEVICE_DISAPPEARED) == 0) {
		bluetooth_device_info_t *device_info;

		device_info = __bt_get_device_info_in_message(msg, &result);
		retv_if(device_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);


		_bt_common_event_cb(BLUETOOTH_EVENT_REMOTE_DEVICE_DISAPPEARED,
				result, device_info,
				event_info->cb, event_info->user_data);
		g_free(device_info);
	} else if (strcasecmp(member, BT_BOND_CREATED) == 0) {
		bluetooth_device_info_t *device_info;

		device_info = __bt_get_device_info_in_message(msg, &result);

		_bt_common_event_cb(BLUETOOTH_EVENT_BONDING_FINISHED,
				result, device_info,
				event_info->cb, event_info->user_data);

		g_free(device_info);
	} else if (strcasecmp(member, BT_BOND_DESTROYED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_SERVICE_SEARCHED) == 0) {
		bluetooth_device_info_t *device_info;
		bt_sdp_info_t sdp_info;

		device_info = __bt_get_device_info_in_message(msg, &result);

		memset(&sdp_info, 0x00, sizeof(bt_sdp_info_t));

		sdp_info.service_index = device_info->service_index;

		memcpy(&sdp_info.device_addr,
			&device_info->device_address,
			BLUETOOTH_ADDRESS_LENGTH);

		memcpy(sdp_info.service_list_array,
			device_info->service_list_array,
			BLUETOOTH_MAX_SERVICES_FOR_DEVICE);

		memcpy(sdp_info.uuids,
			device_info->uuids,
			BLUETOOTH_MAX_SERVICES_FOR_DEVICE * BLUETOOTH_UUID_STRING_MAX);

		_bt_common_event_cb(BLUETOOTH_EVENT_SERVICE_SEARCHED,
				result, &sdp_info,
				event_info->cb, event_info->user_data);

		g_free(device_info);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_device_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_DEVICE_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;


	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_DEVICE_CONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_DBG("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_DEVICE_CONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_DEVICE_DISCONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_DBG("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_DEVICE_DISCONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_hid_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_HID_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_INPUT_CONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_DBG("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_input_event_cb(BLUETOOTH_HID_CONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_INPUT_DISCONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_DBG("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		BT_DBG("address: %s", address);

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_input_event_cb(BLUETOOTH_HID_DISCONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_headset_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_HEADSET_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_HEADSET_CONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_CONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_HEADSET_DISCONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_DISCONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_STEREO_HEADSET_CONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_headset_event_cb(BLUETOOTH_EVENT_AV_CONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_STEREO_HEADSET_DISCONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_headset_event_cb(BLUETOOTH_EVENT_AV_DISCONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_SCO_CONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_AUDIO_CONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_SCO_DISCONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_AUDIO_DISCONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_SPEAKER_GAIN) == 0) {
		unsigned int gain;
		guint16 spkr_gain;
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_UINT16, &spkr_gain,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		gain = (unsigned int)spkr_gain;

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_SPEAKER_GAIN,
				result, &gain,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_MICROPHONE_GAIN) == 0) {
		unsigned int gain;
		guint16 mic_gain;
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_UINT16, &mic_gain,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		gain = (unsigned int)mic_gain;

		_bt_headset_event_cb(BLUETOOTH_EVENT_AG_MIC_GAIN,
				result, &gain,
				event_info->cb, event_info->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_network_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_NETWORK_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_NETWORK_CONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_NETWORK_CONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_NETWORK_DISCONNECTED) == 0) {
		char *address = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_NETWORK_DISCONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_NETWORK_SERVER_CONNECTED) == 0) {
		char *device = NULL;
		char *address = NULL;
		bluetooth_network_device_info_t network_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &device,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&network_info, 0x00, sizeof(bluetooth_network_device_info_t));

		_bt_convert_addr_string_to_type(network_info.device_address.addr,
						address);

		_bt_print_device_address_t(&network_info.device_address);
		g_strlcpy(network_info.interface_name, device, BLUETOOTH_INTERFACE_NAME_LENGTH);

		BT_DBG("name: %s", network_info.interface_name);

		_bt_common_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_CONNECTED,
				result, &network_info,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_NETWORK_SERVER_DISCONNECTED) == 0) {
		char *device = NULL;
		char *address = NULL;
		bluetooth_network_device_info_t network_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &device,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&network_info, 0x00, sizeof(bluetooth_network_device_info_t));

		_bt_convert_addr_string_to_type(network_info.device_address.addr,
						address);

		_bt_print_device_address_t(&network_info.device_address);

		_bt_common_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_DISCONNECTED,
				result, &network_info,
				event_info->cb, event_info->user_data);
	}


	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_avrcp_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_AVRCP_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_STEREO_HEADSET_CONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_CONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_STEREO_HEADSET_DISCONNECTED) == 0) {
		char *address = NULL;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_DISCONNECTED,
				result, address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_MEDIA_SHUFFLE_STATUS) == 0) {
		unsigned int status;
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_SETTING_SHUFFLE_STATUS,
				result, &status,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_MEDIA_EQUALIZER_STATUS) == 0) {
		unsigned int status;
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_SETTING_EQUALIZER_STATUS,
				result, &status,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_MEDIA_REPEAT_STATUS) == 0) {
		unsigned int status;
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_SETTING_REPEAT_STATUS,
				result, &status,
				event_info->cb, event_info->user_data);
	}  else if (strcasecmp(member, BT_MEDIA_SCAN_STATUS) == 0) {
		unsigned int status;
		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		_bt_avrcp_event_cb(BLUETOOTH_EVENT_AVRCP_SETTING_SCAN_STATUS,
				result, &status,
				event_info->cb, event_info->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_opp_client_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_OPP_CLIENT_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_OPP_CONNECTED) == 0) {
		char *address = NULL;
		int request_id = 0;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INT32, &request_id,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (__bt_is_request_id_exist(request_id) == FALSE) {
			BT_ERR("Different request id!");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_OPC_CONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);

		if (result != BLUETOOTH_ERROR_NONE) {
			__bt_remove_push_request_id(request_id);
		}
	} else if (strcasecmp(member, BT_OPP_DISCONNECTED) == 0) {
		char *address = NULL;
		int request_id = 0;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INT32, &request_id,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (__bt_is_request_id_exist(request_id) == FALSE) {
			BT_ERR("Different request id!");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_OPC_DISCONNECTED,
				result, &dev_address,
				event_info->cb, event_info->user_data);

		__bt_remove_push_request_id(request_id);
	} else if (strcasecmp(member, BT_TRANSFER_STARTED) == 0) {
		char *file_name = NULL;
		int request_id = 0;
		guint64 size = 0;
		bt_opc_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &request_id,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (__bt_is_request_id_exist(request_id) == FALSE) {
			BT_ERR("Different request id!");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&transfer_info, 0x00, sizeof(bt_opc_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.size = size;

		_bt_common_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_STARTED,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
	} else if (strcasecmp(member, BT_TRANSFER_PROGRESS) == 0) {
		char *file_name = NULL;
		int request_id = 0;
		guint64 size = 0;
		int progress = 0;
		bt_opc_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &progress,
			DBUS_TYPE_INT32, &request_id,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (__bt_is_request_id_exist(request_id) == FALSE) {
			BT_ERR("Different request id!");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&transfer_info, 0x00, sizeof(bt_opc_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.size = size;
		transfer_info.percentage = progress;

		_bt_common_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_PROGRESS,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
	} else if (strcasecmp(member, BT_TRANSFER_COMPLETED) == 0) {
		char *file_name = NULL;
		int request_id = 0;
		guint64 size = 0;
		bt_opc_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &request_id,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (__bt_is_request_id_exist(request_id) == FALSE) {
			BT_ERR("Different request id!");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&transfer_info, 0x00, sizeof(bt_opc_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.size = size;

		_bt_common_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_COMPLETE,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_opp_server_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_OPP_SERVER_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_TRANSFER_AUTHORIZED) == 0) {
		/* Native only event */
		char *file_name = NULL;
		guint64 size = 0;
		bt_obex_server_authorize_into_t auth_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* OSP server: Don't get this event */
		retv_if(obex_server_id == BT_CUSTOM_SERVER,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		memset(&auth_info, 0x00, sizeof(bt_obex_server_authorize_into_t));

		auth_info.filename = g_strdup(file_name);
		auth_info.length = size;

		_bt_common_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_AUTHORIZE,
				result, &auth_info,
				event_info->cb, event_info->user_data);

		g_free(auth_info.filename);
	} else if (strcasecmp(member, BT_CONNECTION_AUTHORIZED) == 0) {
		/* OSP only event */
		char *address = NULL;
		char *name = NULL;
		bluetooth_device_address_t dev_address = { {0} };

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* Native server: Don't get this event */
		retv_if(obex_server_id == BT_NATIVE_SERVER,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		_bt_convert_addr_string_to_type(dev_address.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_CONNECTION_AUTHORIZE,
				result, &dev_address,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_TRANSFER_STARTED) == 0) {
		char *file_name = NULL;
		char *type = NULL;
		int transfer_id = 0;
		int server_type = 0; /* bt_server_type_t */
		guint64 size = 0;
		bt_obex_server_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &transfer_id,
			DBUS_TYPE_INT32, &server_type,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* Other server's event */
		retv_if(obex_server_id != server_type &&
			server_type != BT_FTP_SERVER,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		memset(&transfer_info, 0x00, sizeof(bt_obex_server_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.type = g_strdup(type);
		transfer_info.file_size = size;
		transfer_info.transfer_id = transfer_id;

		_bt_common_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_STARTED,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
		g_free(transfer_info.type);
	} else if (strcasecmp(member, BT_TRANSFER_PROGRESS) == 0) {
		char *file_name = NULL;
		char *type = NULL;
		int transfer_id = 0;
		int progress = 0;
		int server_type = 0; /* bt_server_type_t */
		guint64 size = 0;
		bt_obex_server_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &transfer_id,
			DBUS_TYPE_INT32, &progress,
			DBUS_TYPE_INT32, &server_type,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* Other server's event */
		retv_if(obex_server_id != server_type &&
			server_type != BT_FTP_SERVER,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		memset(&transfer_info, 0x00, sizeof(bt_obex_server_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.type = g_strdup(type);
		transfer_info.file_size = size;
		transfer_info.transfer_id = transfer_id;
		transfer_info.percentage = progress;

		_bt_common_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_PROGRESS,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
		g_free(transfer_info.type);
	} else if (strcasecmp(member, BT_TRANSFER_COMPLETED) == 0) {
		char *file_name = NULL;
		char *device_name = NULL;
		char *type = NULL;
		int transfer_id = 0;
		int server_type = 0; /* bt_server_type_t */
		guint64 size = 0;
		bt_obex_server_transfer_info_t transfer_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &file_name,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_STRING, &device_name,
			DBUS_TYPE_UINT64, &size,
			DBUS_TYPE_INT32, &transfer_id,
			DBUS_TYPE_INT32, &server_type,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* Other server's event */
		retv_if(obex_server_id != server_type &&
			server_type != BT_FTP_SERVER,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		memset(&transfer_info, 0x00, sizeof(bt_obex_server_transfer_info_t));

		transfer_info.filename = g_strdup(file_name);
		transfer_info.type = g_strdup(type);
		transfer_info.device_name = g_strdup(device_name);
		transfer_info.file_size = size;
		transfer_info.transfer_id = transfer_id;

		_bt_common_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_COMPLETED,
				result, &transfer_info,
				event_info->cb, event_info->user_data);

		g_free(transfer_info.filename);
		g_free(transfer_info.type);
		g_free(transfer_info.device_name);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_rfcomm_client_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_RFCOMM_CLIENT_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_RFCOMM_CONNECTED) == 0) {
		char *address = NULL;
		char *uuid = NULL;
		int socket_fd = 0;
		bluetooth_rfcomm_connection_t conn_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&conn_info, 0x00, sizeof(bluetooth_rfcomm_connection_t));
		conn_info.device_role = RFCOMM_ROLE_CLIENT;
		g_strlcpy(conn_info.uuid, uuid, BLUETOOTH_UUID_STRING_MAX);
		conn_info.socket_fd = socket_fd;
		_bt_convert_addr_string_to_type(conn_info.device_addr.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
				result, &conn_info,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_RFCOMM_DISCONNECTED) == 0) {
		char *address = NULL;
		char *uuid = NULL;
		int socket_fd = 0;
		bluetooth_rfcomm_disconnection_t disconn_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&disconn_info, 0x00, sizeof(bluetooth_rfcomm_disconnection_t));
		disconn_info.device_role = RFCOMM_ROLE_CLIENT;
		g_strlcpy(disconn_info.uuid, uuid, BLUETOOTH_UUID_STRING_MAX);
		disconn_info.socket_fd = socket_fd;
		_bt_convert_addr_string_to_type(disconn_info.device_addr.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
				result, &disconn_info,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_RFCOMM_DATA_RECEIVED) == 0) {
		char *buffer = NULL;
		int buffer_len = 0;
		int socket_fd = 0;
		bluetooth_rfcomm_received_data_t data_r;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&buffer, &buffer_len,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		data_r.socket_fd = socket_fd;
		data_r.buffer_size = buffer_len;
		data_r.buffer = g_memdup(buffer, buffer_len);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED,
				result, &data_r,
				event_info->cb, event_info->user_data);

		g_free(data_r.buffer);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult __bt_rfcomm_server_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	bt_event_info_t *event_info;
	int result = BLUETOOTH_ERROR_NONE;
	const char *member = dbus_message_get_member(msg);

	event_info = (bt_event_info_t *)data;
	retv_if(event_info == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_interface(msg, BT_EVENT_SERVICE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_has_path(msg, BT_RFCOMM_SERVER_PATH))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	retv_if(member == NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (strcasecmp(member, BT_RFCOMM_CONNECTED) == 0) {
		char *address = NULL;
		char *uuid = NULL;
		int socket_fd = 0;
		bluetooth_rfcomm_connection_t conn_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&conn_info, 0x00, sizeof(bluetooth_rfcomm_connection_t));
		conn_info.device_role = RFCOMM_ROLE_SERVER;
		g_strlcpy(conn_info.uuid, uuid, BLUETOOTH_UUID_STRING_MAX);
		conn_info.socket_fd = socket_fd;
		_bt_convert_addr_string_to_type(conn_info.device_addr.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
				result, &conn_info,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_RFCOMM_DISCONNECTED) == 0) {
		char *address = NULL;
		char *uuid = NULL;
		int socket_fd = 0;
		bluetooth_rfcomm_disconnection_t disconn_info;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		memset(&disconn_info, 0x00, sizeof(bluetooth_rfcomm_disconnection_t));
		disconn_info.device_role = RFCOMM_ROLE_SERVER;
		g_strlcpy(disconn_info.uuid, uuid, BLUETOOTH_UUID_STRING_MAX);
		disconn_info.socket_fd = socket_fd;
		_bt_convert_addr_string_to_type(disconn_info.device_addr.addr,
						address);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
				result, &disconn_info,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_CONNECTION_AUTHORIZED) == 0) {
		/* OSP only event */
		bluetooth_rfcomm_connection_request_t req_ind;
		char *address = NULL;
		char *uuid = NULL;
		char *name = NULL;
		int socket_fd = 0;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		/* Don't send the authorized event to other server */
		retv_if(__bt_is_server_exist(socket_fd) == FALSE,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		memset(&req_ind, 0x00, sizeof(bluetooth_rfcomm_connection_request_t));
		_bt_convert_addr_string_to_type(req_ind.device_addr.addr,
						address);

		req_ind.socket_fd = socket_fd;

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_AUTHORIZE,
				result, &req_ind,
				event_info->cb, event_info->user_data);
	} else if (strcasecmp(member, BT_RFCOMM_SERVER_REMOVED) == 0) {
		/* OSP only event */
		int socket_fd = 0;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		retv_if(__bt_is_server_exist(socket_fd) == FALSE,
				DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

		_bt_remove_server(socket_fd);
	} else if (strcasecmp(member, BT_RFCOMM_DATA_RECEIVED) == 0) {
		char *buffer = NULL;
		int buffer_len = 0;
		int socket_fd = 0;
		bluetooth_rfcomm_received_data_t data_r;

		if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &socket_fd,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&buffer, &buffer_len,
			DBUS_TYPE_INVALID)) {
			BT_ERR("Unexpected parameters in signal");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		data_r.socket_fd = socket_fd;
		data_r.buffer_size = buffer_len;
		data_r.buffer = g_memdup(buffer, buffer_len);

		_bt_common_event_cb(BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED,
				result, &data_r,
				event_info->cb, event_info->user_data);

		g_free(data_r.buffer);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __bt_remove_all_events(void)
{
	GSList *l;
	bt_event_info_t *info;

	for (l = event_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;

		if (info)
			_bt_unregister_event(info->event_type);
	}

	g_slist_free(event_list);
	event_list = NULL;
}

static gboolean __bt_event_is_registered(int event_type)
{
	GSList *l;
	bt_event_info_t *info;

	for (l = event_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		retv_if(info->event_type == event_type, TRUE);
	}

	return FALSE;
}

bt_event_info_t* __bt_event_get_cb_data(int event_type)
{
	GSList *l;
	bt_event_info_t *info;

	for (l = event_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		if (info->event_type == event_type)
			return info;
	}

	return NULL;
}

void _bt_add_server(int server_fd)
{
	bt_server_info_t *info;

	info = g_new0(bt_server_info_t, 1);
	info->server_fd = server_fd;

	server_list = g_slist_append(server_list, info);
}

void _bt_remove_server(int server_fd)
{
	GSList *l;
	bt_server_info_t *info;

	for (l = server_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		if (info->server_fd == server_fd) {
			server_list = g_slist_remove(server_list, (void *)info);
		}

		g_free(info);
	}
}

void _bt_set_obex_server_id(int server_type)
{
	obex_server_id = server_type;
}

int _bt_get_obex_server_id(void)
{
	return obex_server_id;
}

int _bt_init_event_handler(void)
{
	if (is_initialized == TRUE) {
		BT_ERR("Connection already exist");
		return BLUETOOTH_ERROR_ALREADY_INITIALIZED;
	}

	__bt_remove_all_events();

	is_initialized = TRUE;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_deinit_event_handler(void)
{
	if (is_initialized == FALSE) {
		BT_ERR("Connection dose not exist");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__bt_remove_all_events();

	is_initialized = FALSE;

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_event_data_free(void *data)
{
	bt_event_info_t *cb_data = data;

	ret_if(cb_data == NULL);

	if (cb_data->conn)
		dbus_connection_unref(cb_data->conn);

	g_free(cb_data);
}

int _bt_register_event(int event_type, void *event_cb, void *user_data)
{
	DBusError dbus_error;
	char *match;
	DBusConnection *connection_type;
	DBusHandleMessageFunction event_func;
	bt_event_info_t *cb_data;

	if (is_initialized == FALSE)
		_bt_init_event_handler();

	if (__bt_event_is_registered(event_type) == TRUE) {
		BT_ERR("The event is already registed");
		return BLUETOOTH_ERROR_ALREADY_INITIALIZED;
	}

	switch (event_type) {
	case BT_ADAPTER_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_adapter_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_ADAPTER_PATH);
		break;
	case BT_DEVICE_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_device_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_DEVICE_PATH);
		break;
	case BT_HID_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_hid_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_HID_PATH);
		break;
	case BT_HEADSET_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_headset_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_HEADSET_PATH);
		break;
	case BT_NETWORK_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_network_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_NETWORK_PATH);
		break;
	case BT_AVRCP_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_avrcp_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_AVRCP_PATH);
		break;
	case BT_OPP_CLIENT_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_opp_client_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_OPP_CLIENT_PATH);
		break;
	case BT_OPP_SERVER_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_opp_server_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_OPP_SERVER_PATH);
		break;
	case BT_RFCOMM_CLIENT_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_rfcomm_client_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_RFCOMM_CLIENT_PATH);
		break;
	case BT_RFCOMM_SERVER_EVENT:
		connection_type = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);

		event_func = __bt_rfcomm_server_event_filter;
		match = g_strdup_printf(EVENT_MATCH_RULE, BT_EVENT_SERVICE,
					BT_RFCOMM_SERVER_PATH);
		break;
	default:
		BT_ERR("Unknown event");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	cb_data = g_new0(bt_event_info_t, 1);

	cb_data->event_type = event_type;
	cb_data->conn = connection_type;
	cb_data->func = event_func;
	cb_data->match_rule = match;
	cb_data->cb = event_cb;
	cb_data->user_data = user_data;

	if (!dbus_connection_add_filter(connection_type, event_func,
				(void *)cb_data, __bt_event_data_free)) {
		BT_ERR("Fail to add filter");
		goto fail;
	}

	dbus_error_init(&dbus_error);

	if (match)
		dbus_bus_add_match(connection_type, match, &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		goto fail;
	}

	event_list = g_slist_append(event_list, cb_data);

	return BLUETOOTH_ERROR_NONE;
fail:
	if (connection_type)
		dbus_connection_unref(connection_type);

	g_free(cb_data);
	g_free(match);
	return BLUETOOTH_ERROR_INTERNAL;
}

int _bt_unregister_event(int event_type)
{
	DBusConnection *connection_type;
	DBusHandleMessageFunction event_func;
	bt_event_info_t *cb_data;
	char *match;
	DBusError dbus_error;

	if (is_initialized == FALSE) {
		BT_ERR("Event is not registered");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (__bt_event_is_registered(event_type) == FALSE) {
		BT_ERR("Not registered event");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	cb_data = __bt_event_get_cb_data(event_type);

	if (cb_data == NULL) {
		BT_ERR("No matched event data");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	connection_type = cb_data->conn;
	event_func = cb_data->func;
	match = cb_data->match_rule;

	event_list = g_slist_remove(event_list, (void *)cb_data);

	retv_if(connection_type == NULL, BLUETOOTH_ERROR_INTERNAL);
	retv_if(event_func == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_error_init(&dbus_error);

	dbus_bus_remove_match (connection_type, match, &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to remove match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
	}

	dbus_connection_remove_filter(connection_type, event_func,
					(void *)cb_data);

	g_free(match);
	return BLUETOOTH_ERROR_NONE;
}

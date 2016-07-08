/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Kumar Rai <a.rai@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <string.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"
#include "bt-request-handler.h"
#include "bt-service-util.h"
#include "bt-service-event.h"
#include "bt-service-hidhost.h"
#include "bt-service-common.h"
#include "bt-service-event-receiver.h"
#include "oal-event.h"
#include "oal-device-mgr.h"
#include "oal-hid-host.h"

typedef struct {
	char address[BT_ADDRESS_STRING_SIZE];
	bt_remote_dev_info_t *dev_info;
} bt_connected_hid_dev_info_t;

enum {
	HID_DEV_INFO_NONE,
	HID_DEV_INFO_ADDED,
	HID_DEV_INFO_UPDATED
};

static GList *g_connected_list;

static invocation_info_t* __bt_get_request_info(int service_function, char *address)
{
	GSList *l;
	invocation_info_t *req_info = NULL;

	BT_DBG("+");

	retv_if(NULL == address, FALSE);

	/* Get method invocation context */
	for (l = _bt_get_invocation_list(); l != NULL; l = g_slist_next(l)) {
		req_info = l->data;
		if (req_info == NULL || req_info->service_function != service_function)
			continue;

		if (!strncasecmp((char *)req_info->user_data, address, BT_ADDRESS_STRING_SIZE))
			return req_info;
	}

	return NULL;
}

static gboolean __bt_is_hid_device_connected(const char *address)
{
	bt_connected_hid_dev_info_t *hid_dev_info;
	GList *node;

	BT_DBG("+");

	node = g_list_first(g_connected_list);
	while (node != NULL) {
		hid_dev_info = (bt_connected_hid_dev_info_t *)node->data;

		if (g_strcmp0(hid_dev_info->address, address) == 0) {
			BT_ERR("Device present in the list");
			return TRUE;
		}
		node = g_list_next(node);
	}

	return FALSE;
	BT_DBG("-");

}

static void __bt_add_hid_device_to_connected_list(const char *address)
{
	bt_connected_hid_dev_info_t *hid_dev_info;

	BT_DBG("+");

	if (TRUE == __bt_is_hid_device_connected(address)) {
		BT_ERR("Device already present in the list");
		return;
	}

	hid_dev_info = g_malloc0(sizeof(bt_connected_hid_dev_info_t));
	g_strlcpy(hid_dev_info->address, address, sizeof(hid_dev_info->address));
	hid_dev_info->dev_info = NULL;
	g_connected_list = g_list_append(g_connected_list, hid_dev_info);

	BT_DBG("-");
}

static void __bt_remove_hid_device_from_connected_list(const char *address)
{
	bt_connected_hid_dev_info_t *hid_dev_info;
	GList *node;

	BT_DBG("+");

	node = g_list_first(g_connected_list);
	while (node != NULL) {
		hid_dev_info = node->data;
		if (g_strcmp0(hid_dev_info->address, address) == 0) {
			BT_DBG("Address match \n");
			g_connected_list = g_list_remove(g_connected_list, hid_dev_info);
			if(hid_dev_info->dev_info)
				_bt_free_device_info(hid_dev_info->dev_info);
			g_free(hid_dev_info);
			break;
		}

		node = g_list_next(node);
	}

	BT_DBG("-");
}

static void __bt_clear_connected_device_list(void)
{
	bt_connected_hid_dev_info_t *hid_dev_info;
	GList *node;

	BT_DBG("+");

	node = g_list_first(g_connected_list);
	while (node != NULL) {
		hid_dev_info = node->data;
		g_connected_list = g_list_remove(g_connected_list, hid_dev_info);
		if(hid_dev_info->dev_info)
			_bt_free_device_info(hid_dev_info->dev_info);
		g_free(hid_dev_info);
		node = g_list_next(node);
	}

	g_connected_list = NULL;
	BT_DBG("-");
}

static int __bt_update_hid_device_info(bt_remote_dev_info_t *rem_info)
{
	int ret = HID_DEV_INFO_NONE;
	bt_connected_hid_dev_info_t *hid_dev_info;
	GList *node;

	BT_DBG("+");

	node = g_list_first(g_connected_list);
	while (node != NULL) {
		hid_dev_info = node->data;
		if (g_strcmp0(hid_dev_info->address, rem_info->address) != 0) {
			node = g_list_next(node);
			continue;
		}

		BT_DBG("Address match, Device present in the list");
		if(hid_dev_info->dev_info == NULL) {
			hid_dev_info->dev_info = rem_info;
			return HID_DEV_INFO_ADDED;
		}
		return ret;
	}

	return ret;
}

static void __bt_handle_hid_connection(char *address)
{
	bt_address_t bd_addr;

	BT_DBG("+");

	ret_if(NULL == address);

	memset(&bd_addr, 0x00, sizeof(bt_address_t));
	_bt_convert_addr_string_to_type(bd_addr.addr, address);

	device_query_attributes(&bd_addr);
	__bt_add_hid_device_to_connected_list(address);

	BT_DBG("-");
}

static void __bt_handle_hid_disconnection(char *address)
{
	int result = BLUETOOTH_ERROR_NONE;
	GVariant *param;

	BT_DBG("+");

	ret_if(NULL == address);

	/* Remove HID device from connected list */
	__bt_remove_hid_device_from_connected_list(address);

	/* Send HID disconnected event to Application */
	param = g_variant_new("(is)", result, address);
	_bt_send_event(BT_HID_EVENT, BLUETOOTH_HID_DISCONNECTED, param);

	BT_DBG("-");
}

static void __bt_handle_device_properties(bt_remote_dev_info_t *rem_info)
{
	int ret;
	int result = BLUETOOTH_ERROR_NONE;
	GVariant *param;

	BT_DBG("+");

	/* Update HID device info in connected list */
	ret = __bt_update_hid_device_info(rem_info);
	if (HID_DEV_INFO_ADDED == ret) {
		/* Send HID connected event to Application */
		param = g_variant_new("(is)", result, rem_info->address);
		_bt_send_event(BT_HID_EVENT, BLUETOOTH_HID_CONNECTED, param);
	} else {
		_bt_free_device_info(rem_info);
	}

	BT_DBG("-");
}

static void __bt_hid_event_handler(int event_type, gpointer event_data)
{
	bluetooth_device_address_t device_address;
	char address[BT_ADDRESS_STRING_SIZE];

	int result = BLUETOOTH_ERROR_NONE;

	invocation_info_t *req_info;
	GArray *out_param;

	BT_DBG("+");

	switch(event_type) {
	case OAL_EVENT_HID_CONNECTED: {
		event_hid_conn_t *event = event_data;

		memset(&device_address, 0x00, sizeof(bluetooth_device_address_t));
		memcpy(device_address.addr, event->address.addr, BLUETOOTH_ADDRESS_LENGTH);

		memset(address, 0x00, BT_ADDRESS_STRING_SIZE);
		_bt_convert_addr_type_to_string(address, event->address.addr);

		/* Reply to async request for HID connect, if any */
		req_info = __bt_get_request_info(BT_HID_CONNECT, address);
		if (NULL != req_info) {
			out_param = g_array_new(FALSE, FALSE, sizeof(gchar));
			g_array_append_vals(out_param, &device_address,
					sizeof(bluetooth_device_address_t));
			_bt_service_method_return(req_info->context,
					out_param, result);
			g_array_free(out_param, TRUE);
			g_free(req_info->user_data);
			_bt_free_info_from_invocation_list(req_info);
		}
		__bt_handle_hid_connection(address);
		break;
	}
	case OAL_EVENT_HID_DISCONNECTED: {
		event_hid_conn_t *event = event_data;

		memset(&device_address, 0x00, sizeof(bluetooth_device_address_t));
		memcpy(device_address.addr, event->address.addr, BLUETOOTH_ADDRESS_LENGTH);

		memset(address, 0x00, BT_ADDRESS_STRING_SIZE);
		_bt_convert_addr_type_to_string(address, event->address.addr);

		BT_INFO("HID device [%s] disconnected", address);
		req_info = __bt_get_request_info(BT_HID_DISCONNECT, address);
		if (NULL == req_info) {
			BT_DBG("BT_HID_DISCONNECT request not found");
			req_info = __bt_get_request_info(BT_HID_CONNECT, address);
			if (NULL == req_info) {
				BT_DBG("BT_HID_CONNECT request also not found");
				__bt_handle_hid_disconnection(address);
				return;
			} else {
				/*
				 * HID_DISCONNECTED event is received in response to hid_connect,
				 * Set result as BLUETOOTH_ERROR_INTERNAL
				 * */
				result = BLUETOOTH_ERROR_INTERNAL;
			}
		}

		if (OAL_STATUS_SUCCESS != event->status)
			result = BLUETOOTH_ERROR_INTERNAL;

		if (BLUETOOTH_ERROR_NONE == result)
			__bt_handle_hid_disconnection(address);

		if (NULL != req_info) {
			out_param = g_array_new(FALSE, FALSE, sizeof(gchar));
			g_array_append_vals(out_param, &device_address,
					sizeof(bluetooth_device_address_t));
			_bt_service_method_return(req_info->context,
					out_param, result);
			g_array_free(out_param, TRUE);
			g_free(req_info->user_data);
			_bt_free_info_from_invocation_list(req_info);
		}
		break;
	}
	case OAL_EVENT_DEVICE_PROPERTIES: {
		event_dev_properties_t *event_dev_prop = event_data;
		bt_remote_dev_info_t *rem_info;

		BT_INFO("OAL_EVENT_DEVICE_PROPERTIES");

		rem_info = g_malloc0(sizeof(bt_remote_dev_info_t));
		_bt_copy_remote_dev(rem_info, &event_dev_prop->device_info);
		__bt_handle_device_properties(rem_info);
		break;
	}
	default:
		BT_ERR("Unhandled event: %d", event_type);
	}

	BT_DBG("-");
}

int _bt_hidhost_initialize()
{
	BT_DBG("+");

	/* Enable HID Profile */
	if(OAL_STATUS_SUCCESS != hid_enable()) {
		BT_ERR("HID Enable failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* Register HID event handler */
	_bt_service_register_event_handler_callback(BT_HID_MODULE, __bt_hid_event_handler);
	return BLUETOOTH_ERROR_NONE;
}

void _bt_hidhost_deinitialize()
{
	BT_DBG("+");

	/* Unregister HID event handler */
	_bt_service_unregister_event_handler_callback(BT_HID_MODULE);

	/* Clear connected device list */
	__bt_clear_connected_device_list();

	/* Disable HID Profile */
	hid_disable();

	return;
}

int _bt_hid_connect(bluetooth_device_address_t *device_address)
{
	int result;
	char address[BT_ADDRESS_STRING_SIZE];
	bt_address_t bd_addr;

	BT_DBG("+");
	_bt_convert_addr_type_to_string(address, device_address->addr);
	BT_INFO("HID connect called for [%s]", address);

	if (TRUE == __bt_is_hid_device_connected(address)) {
		BT_ERR("HID device already connected");
		return BLUETOOTH_ERROR_ALREADY_CONNECT;
	}

	memset(&bd_addr, 0x00, sizeof(bt_address_t));
	memcpy(bd_addr.addr, device_address->addr, BT_ADDRESS_BYTES_NUM);

	result = hid_connect(&bd_addr);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("hid_connect error: [%d]", result);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	return BLUETOOTH_ERROR_NONE;
}

int _bt_hid_disconnect(bluetooth_device_address_t *device_address)
{
	int result;
	char address[BT_ADDRESS_STRING_SIZE];
	bt_address_t bd_addr;

	BT_DBG("+");
	_bt_convert_addr_type_to_string(address, device_address->addr);
	BT_INFO("HID disconnect called for [%s]", address);

	memset(&bd_addr, 0x00, sizeof(bt_address_t));
	memcpy(bd_addr.addr, device_address->addr, BT_ADDRESS_BYTES_NUM);

	result = hid_disconnect(&bd_addr);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("hid_disconnect error: [%d]", result);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	return BLUETOOTH_ERROR_NONE;
}

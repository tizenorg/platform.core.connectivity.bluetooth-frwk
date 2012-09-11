/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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

#include "bluetooth-api-common.h"
#include "bluetooth-api.h"
#include "bluetooth-hid-api.h"

#define BLUEZ_INPUT_NAME "org.bluez.Input"

#define DBUS_HID_MATCH_RULE \
	"type='signal',interface='" BLUEZ_INPUT_NAME"',member='PropertyChanged'"

typedef struct {
	hid_cb_func_ptr app_cb;
	DBusGConnection *conn;
	DBusConnection *sys_conn;
	DBusGProxy *hid_proxy;
	void *user_data;
} bt_hid_info_t;

static bt_hid_info_t bt_hid_info;

static void __hid_connection_changed_cb(gboolean connected,
					hid_device_address_t *device_addr)
{
	hid_event_param_t bt_event = { 0, };

	DBG("+");

	bt_event.event = connected ? BLUETOOTH_HID_CONNECTED : \
				BLUETOOTH_HID_DISCONNECTED;
	bt_event.result = BLUETOOTH_ERROR_NONE;
	bt_event.param_data = (void *)device_addr;

	if (bt_hid_info.app_cb)
		bt_hid_info.app_cb(bt_event.event, &bt_event, bt_hid_info.user_data);

	DBG("-");
}

static DBusHandlerResult __hid_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	char *property = NULL;
	gboolean property_flag = FALSE;
	DBusMessageIter item_iter;
	DBusMessageIter value_iter;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!dbus_message_is_signal(msg, BLUEZ_INPUT_NAME, "PropertyChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (path == NULL || strcmp(path, "/") == 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		DBG("This is bad format dbus\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);
	DBG("Property (%s)\n", property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!strcmp(property, "Connected")) {
		char address[BT_ADDRESS_STRING_SIZE] = { 0, };
		hid_device_address_t device_addr = { {0} };

		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &property_flag);

		_bluetooth_internal_device_path_to_address(path, address);
		_bluetooth_internal_convert_addr_string_to_addr_type(
					(bluetooth_device_address_t *)&device_addr,
					address);

		__hid_connection_changed_cb(property_flag, &device_addr);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __hid_connect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
				    gpointer user_data)
{
	GError *g_error = NULL;
	const char *dev_path = NULL;
	hid_event_param_t bt_event = { 0, };
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	hid_device_address_t device_address = { {0} };

	DBG("+");

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_INVALID);
	dev_path = dbus_g_proxy_get_path(proxy);

	if (g_error != NULL) {
		DBG("Hidh Connect Dbus Call Error: %s\n", g_error->message);

		g_error_free(g_error);

		_bluetooth_internal_device_path_to_address(dev_path, address);

		_bluetooth_internal_convert_addr_string_to_addr_type(
				(bluetooth_device_address_t *)&device_address,
				address);

		bt_event.event = BLUETOOTH_HID_CONNECTED;
		bt_event.result = BLUETOOTH_ERROR_CONNECTION_ERROR;
		bt_event.param_data = (void *)&device_address;

		if (bt_hid_info.app_cb)
			bt_hid_info.app_cb(bt_event.event, &bt_event, bt_hid_info.user_data);

	} else {
		DBG("Hidh Connect Dbus Call is done\n");
	}

	g_object_unref(proxy);
	bt_hid_info.hid_proxy = NULL;

	DBG("-");
}


static void __hid_disconnect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
				    gpointer user_data)
{
	GError *g_error = NULL;
	const char *dev_path = NULL;
	hid_event_param_t bt_event = { 0, };
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	hid_device_address_t device_address = { {0} };

	DBG("+");

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_INVALID);
	dev_path = dbus_g_proxy_get_path(proxy);

	if (g_error != NULL) {
		DBG("Hidh Connect Dbus Call Error: %s\n", g_error->message);

		g_error_free(g_error);

		_bluetooth_internal_device_path_to_address(dev_path, address);

		_bluetooth_internal_convert_addr_string_to_addr_type(
				(bluetooth_device_address_t *)&device_address,
				address);

		bt_event.event = BLUETOOTH_HID_DISCONNECTED;
		bt_event.result = BLUETOOTH_ERROR_CONNECTION_ERROR;
		bt_event.param_data = (void *)&device_address;

		if (bt_hid_info.app_cb)
			bt_hid_info.app_cb(bt_event.event, &bt_event, bt_hid_info.user_data);

	} else {
		DBG("Hidh Disconnect Dbus Call is done\n");
	}

	g_object_unref(proxy);
	bt_hid_info.hid_proxy = NULL;

	DBG("-");
}



/**********************************************************************
*                               HID APIs                              *
***********************************************************************/

BT_EXPORT_API int bluetooth_hid_init(hid_cb_func_ptr callback_ptr,
					void *user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	GError *err = NULL;
	DBusError dbus_error;
	DBusGConnection *conn = NULL;
	DBusConnection *sys_conn = NULL;

	DBG("+");

	g_type_init();

	if (bt_hid_info.conn) {
		DBG("HID is already initialized");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (err != NULL) {
		DBG("ERROR: Can't get on system bus [%s]", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	sys_conn = dbus_g_connection_get_connection(conn);

	dbus_connection_add_filter(sys_conn, __hid_event_filter, NULL, NULL);

	dbus_error_init(&dbus_error);

	dbus_bus_add_match(sys_conn, DBUS_HID_MATCH_RULE, &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		result = BLUETOOTH_ERROR_INTERNAL;
		goto failed;
	}

	bt_hid_info.conn = conn;
	bt_hid_info.sys_conn = sys_conn;
	bt_hid_info.app_cb = callback_ptr;
	bt_hid_info.user_data = user_data;

	DBG("-");

	return BLUETOOTH_ERROR_NONE;
failed:
	if (conn)
		dbus_g_connection_unref(conn);

	return result;
}

BT_EXPORT_API int bluetooth_hid_deinit(void)
{
	DBG("+\n");

	if (bt_hid_info.conn == NULL) {
		DBG("HID is not initialized");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (bt_hid_info.sys_conn) {
		dbus_connection_remove_filter(bt_hid_info.sys_conn,
						__hid_event_filter,
						NULL);

		dbus_bus_remove_match(bt_hid_info.sys_conn,
					DBUS_HID_MATCH_RULE, NULL);
	}

	if (bt_hid_info.hid_proxy)
		g_object_unref(bt_hid_info.hid_proxy);

	dbus_g_connection_unref(bt_hid_info.conn);

	bt_hid_info.conn = NULL;
	bt_hid_info.sys_conn = NULL;
	bt_hid_info.hid_proxy = NULL;
	bt_hid_info.app_cb = NULL;
	bt_hid_info.user_data = NULL;

	DBG("-\n");

	return HID_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hid_connect(hid_device_address_t *device_address)
{
	GError *g_error = NULL;
	DBusGProxy *hid_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	char adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	const char *hid_dev_path = NULL;

	DBG("+\n");

	if (device_address == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (bt_hid_info.conn == NULL) {
		DBG("HID is not initialized");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bluetooth_internal_get_adapter_path(bt_hid_info.conn, adapter_path) < 0) {
		DBG("Could not get adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(bt_hid_info.conn, BLUEZ_SERVICE_NAME,
					adapter_path, BLUEZ_ADAPTER_INTERFACE);

	if (adapter_proxy == NULL) {
		DBG("dbus_g_proxy_new_for_name() failed\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	_bluetooth_internal_addr_type_to_addr_string(address,
			(const bluetooth_device_address_t *)device_address);

	dbus_g_proxy_call(adapter_proxy, "FindDevice",
			  &g_error, G_TYPE_STRING, address,
			  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			  &hid_dev_path, G_TYPE_INVALID);

	if (g_error != NULL) {
		DBG("Failed to Find device: %s\n", g_error->message);
		g_error_free(g_error);
		g_object_unref(adapter_proxy);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	hid_proxy = dbus_g_proxy_new_for_name(bt_hid_info.conn, BLUEZ_SERVICE_NAME,
				      hid_dev_path, BLUEZ_INPUT_NAME);

	if (hid_proxy == NULL) {
		DBG("Failed to get hidh proxy\n");
		g_object_unref(adapter_proxy);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	bt_hid_info.hid_proxy = hid_proxy;

	if (!dbus_g_proxy_begin_call(hid_proxy, "Connect",
				(DBusGProxyCallNotify)__hid_connect_request_cb,
				NULL,
				NULL, G_TYPE_INVALID)) {
		DBG("Hidh connect Dbus Call Error");
		g_object_unref(hid_proxy);
		g_object_unref(adapter_proxy);
		bt_hid_info.hid_proxy = NULL;
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	g_object_unref(adapter_proxy);

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hid_disconnect(hid_device_address_t *device_address)
{
	GError *g_error = NULL;
	DBusGProxy *hid_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	char adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	const char *hid_dev_path = NULL;

	DBG("+\n");

	if (device_address == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (bt_hid_info.conn == NULL) {
		DBG("HID is not initialized");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bluetooth_internal_get_adapter_path(bt_hid_info.conn, adapter_path) < 0) {
		DBG("Could not get adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(bt_hid_info.conn, BLUEZ_SERVICE_NAME,
					adapter_path, BLUEZ_ADAPTER_INTERFACE);

	if (adapter_proxy == NULL) {
		DBG("dbus_g_proxy_new_for_name() failed\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	_bluetooth_internal_addr_type_to_addr_string(address,
			(const bluetooth_device_address_t *)device_address);

	dbus_g_proxy_call(adapter_proxy, "FindDevice",
			  &g_error, G_TYPE_STRING, address,
			  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			  &hid_dev_path, G_TYPE_INVALID);

	if (g_error != NULL) {
		DBG("Failed to Find device: %s\n", g_error->message);
		g_error_free(g_error);
		g_object_unref(adapter_proxy);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	hid_proxy = dbus_g_proxy_new_for_name(bt_hid_info.conn, BLUEZ_SERVICE_NAME,
				      hid_dev_path, BLUEZ_INPUT_NAME);

	if (hid_proxy == NULL) {
		DBG("Failed to get hidh proxy\n");
		g_object_unref(adapter_proxy);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	bt_hid_info.hid_proxy = hid_proxy;

	if (!dbus_g_proxy_begin_call(hid_proxy, "Disconnect",
				(DBusGProxyCallNotify)__hid_disconnect_request_cb,
				NULL,
				NULL, G_TYPE_INVALID)) {
		DBG("Hidh disconnect Dbus Call Error");
		g_object_unref(adapter_proxy);
		g_object_unref(hid_proxy);
		bt_hid_info.hid_proxy = NULL;
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	g_object_unref(adapter_proxy);

	DBG("-\n");

	return HID_ERROR_NONE;
}

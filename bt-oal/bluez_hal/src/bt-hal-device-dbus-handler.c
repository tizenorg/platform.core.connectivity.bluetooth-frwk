/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <vconf.h>

#include <syspopup_caller.h>
#include <bundle_internal.h>

/* BT HAL Headers */
#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-internal.h"
#include "bt-hal-event-receiver.h"
#include "bt-hal-dbus-common-utils.h"

#include "bt-hal-adapter-dbus-handler.h"
#include "bt-hal-device-dbus-handler.h"
#include "bt-hal-event-receiver.h"

/* Forward Delcaration */
static void __bt_bond_device_cb(GDBusProxy *proxy, GAsyncResult *res, gpointer user_data);

static void __bt_unbond_device_cb(GDBusProxy *proxy, GAsyncResult *res,
                                        gpointer user_data);

int _bt_hal_device_create_bond(const bt_bdaddr_t *bd_addr)
{
	GDBusProxy *proxy;
	char address[BT_HAL_ADDRESS_STRING_SIZE] = { 0 };
	int transport = 0;

	GDBusConnection *conn;
	char *device_path = NULL;
	GDBusProxy *adapter_proxy;
	GError *error = NULL;
	struct hal_ev_bond_state_changed ev;
	memset(&ev, 0, sizeof(ev));
	DBG("+");

	DBG("Transport [%d] Add[0x%x] [0x%x][0x%x][0x%x][0x%x][0x%x]", transport, bd_addr->address[0], bd_addr->address[1],
			bd_addr->address[2], bd_addr->address[3],
			bd_addr->address[4], bd_addr->address[5]);
	conn = _bt_get_system_gconn();
	if (!conn) {
		DBG("Could not get DBUS connection!");
		return BT_STATUS_FAIL;
	}

	_bt_convert_addr_type_to_string(address, bd_addr->address);
	device_path = _bt_get_device_object_path(address);

	if (device_path == NULL) {
		ERR("No searched device, attempt to create device");
		GVariant *ret = NULL;
		adapter_proxy = _bt_get_adapter_proxy();
		if (!adapter_proxy) {
			ERR("Could not get Adapter Proxy");
			return BT_STATUS_FAIL;
		}

		ret = g_dbus_proxy_call_sync(adapter_proxy, "CreateDevice",
				g_variant_new("(s)", address),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&error);

		if (error != NULL) {
			ERR("CreateDevice Fail: %s", error->message);
			g_clear_error(&error);
		}
		if (ret)
			g_variant_unref(ret);
		device_path = _bt_get_device_object_path(address);

		if (device_path == NULL) {
			ERR("Device path is still not created!!");
			return BT_STATUS_FAIL;
		} else {
			DBG("Device_path is created[%s]", device_path);
		}
	}
	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			device_path, BT_HAL_DEVICE_INTERFACE,  NULL, NULL);

	g_free(device_path);
	if (!proxy) {
		ERR("Could not get Device Proxy");
		return BT_STATUS_FAIL;
	}

	g_dbus_proxy_call(proxy, "Pair",
			g_variant_new("(y)", transport),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT,
			NULL,
			(GAsyncReadyCallback)__bt_bond_device_cb,
			NULL);

	/* Prepare to send Bonding event event to HAL bluetooth */
	ev.status = BT_STATUS_SUCCESS;
	ev.state = BT_BOND_STATE_BONDING;

	_bt_convert_addr_string_to_type(ev.bdaddr, address);

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending HAL_EV_BOND_STATE_CHANGED event");
		event_cb(HAL_EV_BOND_STATE_CHANGED, (void*)&ev, sizeof(ev));
	}

	DBG("-");
	return BT_STATUS_SUCCESS;
}

int _bt_hal_device_remove_bond(const bt_bdaddr_t *bd_addr)
{
	char *device_path = NULL;
	GDBusProxy *adapter_proxy = NULL;
	GDBusProxy *device_proxy = NULL;
	GDBusConnection *conn;
	GError *error = NULL;
	GVariant *ret = NULL;
	char address[BT_HAL_ADDRESS_STRING_SIZE] = { 0 };

	DBG("Add[0x%x] [0x%x][0x%x][0x%x][0x%x][0x%x]",
			bd_addr->address[0], bd_addr->address[1],
			bd_addr->address[2], bd_addr->address[3],
			bd_addr->address[4], bd_addr->address[5]);

	adapter_proxy = _bt_get_adapter_proxy();
	if (!adapter_proxy) {
		ERR("Could not get Adapter Proxy");
		return BT_STATUS_FAIL;
	}

	_bt_convert_addr_type_to_string(address, bd_addr->address);

	device_path = _bt_get_device_object_path(address);

	/* This is a special case, bluedroid always sends success to HAL even if device is already removed
	   whereas bluez sends BLUETOOTH_ERROR_NOT_PAIRED. However we will return Failure
	   in case of bluez*/
	if (device_path == NULL) {
		ERR("No paired device");
		return BT_STATUS_FAIL;
	}

	conn = _bt_get_system_gconn();
	if (conn == NULL) {
		ERR("conn is NULL");
		return BT_STATUS_FAIL;
	}


	device_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			device_path, BT_HAL_PROPERTIES_INTERFACE,  NULL, NULL);

	if (device_proxy != NULL) {

		ret = g_dbus_proxy_call_sync(device_proxy, "Get",
				g_variant_new("(ss)", BT_HAL_DEVICE_INTERFACE, "Paired"),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&error);
		if (error) {
			ERR("Getting property failed: [%s]\n", error->message);
			g_error_free(error);
			return BT_STATUS_FAIL;
		} else {
			if (!ret) {
				ERR("No paired device");
				g_object_unref(device_proxy);
				return BT_STATUS_FAIL;
			}
			g_variant_unref(ret);
		}
		g_object_unref(device_proxy);
	}

	g_dbus_proxy_call(adapter_proxy, "UnpairDevice",
			g_variant_new("(o)", device_path),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT,
			NULL,
			(GAsyncReadyCallback)__bt_unbond_device_cb,
			(gpointer)device_path);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

static void __bt_bond_device_cb(GDBusProxy *proxy, GAsyncResult *res,
                                        gpointer user_data)
{
	GError *err = NULL;
	const char *device_path;
	int result = BT_STATUS_SUCCESS;
	struct hal_ev_bond_state_changed ev;
	memset(&ev, 0, sizeof(ev));
	char dev_address[18];
	DBG("+");

#ifdef TIZEN_SYSPOPUP_SUPPORTED
	/* Terminate ALL system popup */
	syspopup_destroy_all();
#endif

	g_dbus_proxy_call_finish(proxy, res, &err);
	device_path = g_dbus_proxy_get_object_path(proxy);
	DBG("Device path: %s", device_path);
	_bt_convert_device_path_to_address(device_path, dev_address);
	DBG("Remote Device address [%s]", dev_address);

	if (err != NULL) {
		g_dbus_error_strip_remote_error(err);
		ERR("@@@Error occured in CreateBonding [%s]", err->message);
		if (g_strrstr(err->message, "Already Exists")) {
			DBG("Existing Bond, remove and retry");
		} else if (g_strrstr(err->message, "Authentication Rejected")) {
			DBG("REJECTED");
		} else if (g_strrstr(err->message, "In Progress")) {
			DBG("Bond in progress, cancel and retry");
		} else if (g_strrstr(err->message, "Authentication Failed")) {
			DBG("Authentication Failed");
			result = BT_STATUS_AUTH_FAILURE;
		} else if (g_strrstr(err->message, "Page Timeout")) {
			DBG("Page Timeout");
			result = BT_STATUS_RMT_DEV_DOWN;
		} else if (g_strrstr(err->message, BT_HAL_TIMEOUT_MESSAGE)) {
			DBG("Timeout");
		} else if (g_strrstr(err->message, "Connection Timeout")) {
		} else if (g_strrstr(err->message, "Authentication Timeout")) {
		} else {
			DBG("Default case: Pairing failed");
			result = BT_STATUS_AUTH_FAILURE;
		}
	}

	if (result == BT_STATUS_AUTH_FAILURE ||
			result == BT_STATUS_RMT_DEV_DOWN) {
		DBG("Bonding Failed!!");
	} else {
		DBG("Bonding Success!!");
	}

	/* Prepare to send event to HAL bluetooth */
	ev.status = result;
	if (result == BT_STATUS_SUCCESS)
		ev.state = BT_BOND_STATE_BONDED;
	else
		ev.state = BT_BOND_STATE_NONE;

	_bt_convert_addr_string_to_type(ev.bdaddr, dev_address);

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending HAL_EV_BOND_STATE_CHANGED event");
		event_cb(HAL_EV_BOND_STATE_CHANGED, (void*)&ev, sizeof(ev));
	}
	DBG("-");
}

static void __bt_unbond_device_cb(GDBusProxy *proxy, GAsyncResult *res,
                                        gpointer user_data)
{
	GError *err = NULL;
	char *device_path = NULL;
	char dev_address[18];
	int result = BT_STATUS_SUCCESS;
	struct hal_ev_bond_state_changed ev;
	memset(&ev, 0, sizeof(ev));
	DBG("+");

	g_dbus_proxy_call_finish(proxy, res, &err);

	if (err != NULL) {
		ERR("Error occured in RemoveBonding [%s]\n", err->message);
		result = BT_STATUS_FAIL;
	}

	g_error_free(err);

	/* Prepare to send event to HAL bluetooth */
	ev.status = result;
	ev.state = BT_BOND_STATE_NONE;

	device_path = (char *)user_data;
	_bt_convert_device_path_to_address(device_path, dev_address);
	_bt_convert_addr_string_to_type(ev.bdaddr, dev_address);

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending HAL_EV_BOND_STATE_CHANGED event");
		event_cb(HAL_EV_BOND_STATE_CHANGED, (void*)&ev, sizeof(ev));
	}
	g_free(device_path);
	DBG("-");
}

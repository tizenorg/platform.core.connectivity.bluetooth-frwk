/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Atul Kumar Rai <a.rai@samsung.com>
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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <vconf.h>

#include "bt-hal-hid-dbus-handler.h"
#include "bt-hal-dbus-common-utils.h"
#include "bt-hal-internal.h"

static handle_stack_msg event_cb = NULL;

/* To send stack event to hal-hidhost handler */
void _bt_hal_register_hid_dbus_handler_cb(handle_stack_msg cb)
{
	event_cb = cb;
}

/* To send stack event to hal-hidhost handler */
void _bt_hal_unregister_hid_dbus_handler_cb()
{
	event_cb = NULL;
}

static void __bt_hid_connect_cb(GDBusProxy *proxy, GAsyncResult *res,
		gpointer user_data)
{
	GError *g_error = NULL;
	struct hal_ev_hidhost_conn_state ev;
	GVariant *reply = NULL;
	char *address = user_data;
	int result = BT_STATUS_SUCCESS;

	DBG("+");

	reply = g_dbus_proxy_call_finish(proxy, res, &g_error);
	g_object_unref(proxy);
	if (reply == NULL) {
		ERR("Hid Connect Dbus Call Error");
		if (g_error) {
			ERR("Error: %s\n", g_error->message);
			g_clear_error(&g_error);
		}
		result = BT_STATUS_FAIL;
	}
	g_variant_unref(reply);

	DBG("Address: %s", address);
	/*
	 * If result is success, HID connected event will be triggered
	 * automatically from stack, so return from here.
	 */
	if (result == BT_STATUS_SUCCESS)
		goto done;

	/* Prepare to send HID connection state event */
	memset(&ev, 0, sizeof(ev));
	_bt_convert_addr_string_to_type(ev.bdaddr, address);
	ev.state = HAL_HIDHOST_STATE_DISCONNECTED;
	if (!event_cb)
		ERR("HID dbus handler callback not registered");
	else
		event_cb(HAL_EV_HIDHOST_CONN_STATE, (void *)&ev, sizeof(ev));

done:
	g_free(address);
}

bt_status_t _bt_hal_dbus_handler_hidhost_connect(bt_bdaddr_t *bd_addr)
{
	char *address;
	struct hal_ev_hidhost_conn_state ev;
	GDBusConnection *conn;

	int ret;
	char *uuid;

	if(!bd_addr) {
		ERR("bd_addr is NULL, return");
		return BT_STATUS_PARM_INVALID;
	}

	conn = _bt_get_system_gconn();
	if(!conn) {
		ERR("_bt_get_system_gconn returned NULL, return");
		return BT_STATUS_FAIL;
	}

	address = g_malloc0(BT_HAL_ADDRESS_STRING_SIZE * sizeof(char));
	if (!address) {
		ERR("Memory allocation failed");
		return BT_STATUS_NOMEM;
	}
	_bt_convert_addr_type_to_string(address, bd_addr->address);
	uuid = HID_UUID;

	ret = _bt_connect_profile(address, uuid,
			__bt_hid_connect_cb, address);

	if (ret != BT_HAL_ERROR_NONE) {
		ERR("_bt_connect_profile Error");
		return BT_STATUS_FAIL;
	}

	/* Prepare to send HID connecting event */
	memset(&ev, 0, sizeof(ev));
	ev.state = HAL_HIDHOST_STATE_CONNECTING;
	memcpy(ev.bdaddr, bd_addr, sizeof(bt_bdaddr_t));
	if (!event_cb)
		ERR("HID dbus handler callback not registered");
	else
		event_cb(HAL_EV_HIDHOST_CONN_STATE, (void *)&ev, sizeof(ev));

	return BT_STATUS_SUCCESS;
}

static void __bt_hid_disconnect_cb(GDBusProxy *proxy, GAsyncResult *res,
		gpointer user_data)
{
	GError *g_error = NULL;
	GVariant *reply = NULL;
	char *address = user_data;
	int result = BT_STATUS_SUCCESS;

	DBG("+");

	reply = g_dbus_proxy_call_finish(proxy, res, &g_error);
	g_object_unref(proxy);
	if (reply == NULL) {
		ERR("Hid Disconnect Dbus Call Error");
		if (g_error) {
			ERR("Error: %s\n", g_error->message);
			g_clear_error(&g_error);
		}
		result = BT_STATUS_FAIL;
	}
	g_variant_unref(reply);

	if (result != BT_STATUS_FAIL)
		DBG("HID Disconnect successful for Device: %s", address);
	else
		DBG("HID Disconnect un-successful for Device: %s", address);
	g_free(address);
	DBG("-");
}

bt_status_t _bt_hal_dbus_handler_hidhost_disconnect(bt_bdaddr_t *bd_addr)
{
	char *address;
	struct hal_ev_hidhost_conn_state ev;
	GDBusConnection *conn;

	int ret;
	char *uuid;

	if(!bd_addr) {
		ERR("bd_addr is NULL, return");
		return BT_STATUS_PARM_INVALID;
	}

	conn = _bt_get_system_gconn();
	if(!conn) {
		ERR("_bt_get_system_gconn returned NULL, return");
		return BT_STATUS_FAIL;
	}

	address = g_malloc0(BT_HAL_ADDRESS_STRING_SIZE * sizeof(char));
	if (!address) {
		ERR("Memory allocation failed");
		return BT_STATUS_NOMEM;
	}
	_bt_convert_addr_type_to_string(address, bd_addr->address);
	uuid = HID_UUID;

	ret = _bt_disconnect_profile(address, uuid,
			__bt_hid_disconnect_cb, address);
	if (ret != BT_HAL_ERROR_NONE) {
		ERR("_bt_connect_profile Error");
		return BT_STATUS_FAIL;
	}

	/* Prepare to send HID connecting event */
	memset(&ev, 0, sizeof(ev));
	ev.state = HAL_HIDHOST_STATE_DISCONNECTING;
	memcpy(ev.bdaddr, bd_addr, sizeof(bt_bdaddr_t));
	if (!event_cb)
		ERR("HID dbus handler callback not registered");
	else
		event_cb(HAL_EV_HIDHOST_CONN_STATE, (void *)&ev, sizeof(ev));

	return BT_STATUS_SUCCESS;
}

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

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"

#include <bt-hal-adapter-dbus-handler.h>
#include <bt-hal-dbus-common-utils.h>

#define BT_MAX_PROPERTY_BUF_SIZE 1024
#define BT_ENABLE_TIMEOUT 20000 /* 20 seconds */
#define BT_CORE_NAME "org.projectx.bt_core"
#define BT_CORE_PATH "/org/projectx/bt_core"
#define BT_CORE_INTERFACE "org.projectx.btcore"
#define BT_ADAPTER_INTERFACE "org.bluez.Adapter1"

static GDBusProxy *core_proxy = NULL;
static GDBusConnection *system_conn = NULL;
static handle_stack_msg event_cb = NULL;

handle_stack_msg _bt_get_adapter_event_cb(void)
{
	if (!event_cb)
		return event_cb;
	else
		return NULL;
}

GDBusConnection *__bt_get_system_gconn(void)
{
	DBG("+");
	if (system_conn == NULL)
		system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

	DBG("-");
	return system_conn;
}

GDBusProxy *_bt_init_core_proxy(void)
{	GDBusProxy *proxy;
	GDBusConnection *conn;

	DBG("+");
	conn = __bt_get_system_gconn();
	if (!conn)
		return NULL;

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL,
			BT_CORE_NAME,
			BT_CORE_PATH,
			BT_CORE_INTERFACE,
			NULL, NULL);

	if (!proxy)
		return NULL;

	core_proxy = proxy;

	DBG("-");
	return proxy;
}

static GDBusProxy *__bt_get_core_proxy(void)
{
	return (core_proxy) ? core_proxy : _bt_init_core_proxy();
}

/* To send stack event to hal-bluetooth handler */
void _bt_hal_dbus_store_stack_msg_cb(handle_stack_msg cb)
{
	event_cb = cb;
}

int _bt_hal_dbus_enable_adapter(void)
{
	GDBusProxy *proxy;
	GError *error = NULL;
	GVariant *result = NULL;

	DBG("+");
	proxy = __bt_get_core_proxy();

	if (!proxy) {
		DBG("_bt_hal_dbus_enable_adapter: Core proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy, "EnableAdapter",
			NULL,
			G_DBUS_CALL_FLAGS_NONE, BT_ENABLE_TIMEOUT,
			NULL, &error);
	if (error) {
		DBG("EnableAdapter failed: %s", error->message);
		g_clear_error(&error);
		error = NULL;
		result = g_dbus_proxy_call_sync(proxy,
				"DisableAdapter",
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&error);

		if (error != NULL) {
			DBG("Bt core call failed(Error: %s)", error->message);
			g_clear_error(&error);
		}
		g_variant_unref(result);
		//Terminate myself
		/* TODO: Terminate bluetooth service or not, need to check */
		//g_idle_add((GSourceFunc)_bt_terminate_service, NULL);
		return BT_STATUS_FAIL;
	}

	DBG("-");
	g_variant_unref(result);
	return BT_STATUS_SUCCESS;
}

int _bt_hal_dbus_disable_adapter(void)
{
	GDBusProxy *proxy;
	GError *error = NULL;
	GVariant *result = NULL;

	DBG("+");
	proxy = __bt_get_core_proxy();

	if (!proxy) {
		DBG("_bt_hal_dbus_enable_adapter: Core proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy, "DisableAdapter",
			NULL,
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	if (error) {
		DBG("DisableAdapter failed: %s", error->message);
		g_clear_error(&error);
		error = NULL;
		g_variant_unref(result);
		//Terminate myself
		/* TODO: Terminate bluetooth service or not, need to check */
		//g_idle_add((GSourceFunc)_bt_terminate_service, NULL);
		return BT_STATUS_FAIL;
	}

	DBG("-");
	g_variant_unref(result);
	return BT_STATUS_SUCCESS;
}

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

#include <malloc.h>
#include <vconf.h>
#include <vconf-keys.h>
#include <aul.h>
#include <stdlib.h>

#include "bluetooth-agent.h"
#include "sc_core_agent.h"


struct bt_agent_appdata *app_data = NULL;
static GMainLoop *main_loop = NULL;

static void __bt_agent_release_service(void);
static void __bt_agent_terminate(void);

bt_status_t _bt_agent_bt_status_get()
{
	return app_data->bt_status;
}

void _bt_agent_bt_status_set(bt_status_t status)
{
	app_data->bt_status = status;
}

int _bt_agent_destroy()
{
	DBG("_bt_agent_destroy");

	__bt_agent_release_service();

	__bt_agent_terminate();

	return BT_AGENT_ERROR_NONE;
}

static int __agent_check_bt_service(void *data)
{
	int bt_status = VCONFKEY_BT_STATUS_OFF;
	if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_status) < 0) {
		DBG("no bluetooth device info, so BT was disabled at previous session");
	}

	if (bt_status != VCONFKEY_BT_STATUS_OFF) {
		DBG("Previous session was enabled.");
		/* Enable the BT */
		_sc_core_agent_mode_change(BT_AGENT_CHANGED_MODE_ENABLE);
	} else {
		DBG("State: %d", _bt_agent_bt_status_get());

		if (_bt_agent_bt_status_get() != BT_ACTIVATING) {
			/* Destroy the agent */
			_sc_core_agent_remove();
			_bt_agent_destroy();
		}
	}

	return BT_AGENT_ERROR_NONE;
}

static void __agent_adapter_added_cb(DBusGProxy *manager_proxy, const char *adapter_path,
				   gpointer user_data)
{
	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)user_data;
	DBusGConnection *connection = (DBusGConnection *) ad->g_connection;
	DBusGProxy *adapter_proxy = NULL;

	DBG("Adapter added [%s]", adapter_path);

	adapter_proxy = dbus_g_proxy_new_for_name(connection, "org.bluez", adapter_path,
						"org.bluez.Adapter");
	if (adapter_proxy) {
		_bt_agent_register(adapter_proxy);
		g_object_unref(adapter_proxy);
	}

	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_ON) != 0)
		DBG("Set vconf failed\n");

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		DBG("Set vconf failed\n");

	_bt_agent_bt_status_set(BT_ACTIVATED);
}

static void __agent_adapter_removed_cb(DBusGProxy *manager_proxy, const char *adapter_path,
				     gpointer user_data)
{
	DBG("Adapter [%s] removed", adapter_path);
}

static void __bt_agent_flight_mode_cb(keynode_t *node, void *data)
{
	gboolean flight_mode = FALSE;

	DBG("key=%s\n", vconf_keynode_get_name(node));

	if (vconf_keynode_get_type(node) == VCONF_TYPE_BOOL) {
		flight_mode = vconf_keynode_get_bool(node);

		DBG("value=%d\n", flight_mode);

		if (flight_mode == TRUE) {
			DBG("Deactivate Bluetooth Service\n");
			_sc_core_agent_mode_change(BT_AGENT_CHANGED_MODE_DISABLE);
		}
	}
}
static gboolean __agent_init(gpointer data)
{
	struct bt_agent_appdata *ad = data;
	DBusGConnection *connection = NULL;
	DBusGProxy *manager_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	GError *error = NULL;
	const char *adapter_path = NULL;

	_bt_agent_bt_status_set(BT_DEACTIVATED);

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		ERR("ERROR: Can't get on system bus [%s]", error->message);
		g_error_free(error);
		return TRUE;
	}

	ad->g_connection = connection;

	manager_proxy = dbus_g_proxy_new_for_name(connection, "org.bluez", "/",
									"org.bluez.Manager");
	if (manager_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return TRUE;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &error,
			       G_TYPE_INVALID,
			       DBUS_TYPE_G_OBJECT_PATH, &adapter_path, G_TYPE_INVALID)) {
		if (error != NULL) {
			DBG("Getting DefaultAdapter failed: [%s]", error->message);
			g_error_free(error);
		}

		_bt_agent_register(NULL);

	} else {
		DBG("DefaultAdapter [%s]", adapter_path);
		adapter_proxy = dbus_g_proxy_new_for_name(connection, "org.bluez", adapter_path,
								"org.bluez.Adapter");
		if (adapter_proxy) {
			_bt_agent_bt_status_set(BT_ACTIVATED);
			_bt_agent_register(adapter_proxy);
			g_object_unref(adapter_proxy);
		}
	}

	dbus_g_proxy_add_signal(manager_proxy, "AdapterAdded",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(manager_proxy, "AdapterAdded",
				    G_CALLBACK(__agent_adapter_added_cb), ad, NULL);

	dbus_g_proxy_add_signal(manager_proxy, "AdapterRemoved",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(manager_proxy, "AdapterRemoved",
				    G_CALLBACK(__agent_adapter_removed_cb), ad, NULL);

	ad->manager_proxy = manager_proxy;

	vconf_notify_key_changed(VCONFKEY_SETAPPL_FLIGHT_MODE_BOOL, __bt_agent_flight_mode_cb, ad);

	g_idle_add((GSourceFunc) __agent_check_bt_service, ad);

	return FALSE;
}

static void __bt_agent_terminate(void)
{
	if (main_loop != NULL)
		g_main_loop_quit(main_loop);
	else
		exit(0);
}

static void __bt_agent_release_service(void)
{
	struct bt_agent_appdata *ad = app_data;

	if (ad->manager_proxy) {
		dbus_g_proxy_disconnect_signal(ad->manager_proxy, "AdapterAdded",
						G_CALLBACK(__agent_adapter_added_cb),
						NULL);

		dbus_g_proxy_disconnect_signal(ad->manager_proxy, "AdapterRemoved",
						G_CALLBACK(__agent_adapter_removed_cb),
						NULL);

		g_object_unref(ad->manager_proxy);
		ad->manager_proxy = NULL;
	}

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_FLIGHT_MODE_BOOL,
				__bt_agent_flight_mode_cb);
}

static int __bt_agent_create(void *data)
{
	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)data;

	DBG("__bt_agent_create() start.\n");

	__agent_init(ad);

	return BT_AGENT_ERROR_NONE;
}

int main(int argc, char *argv[])
{
	struct bt_agent_appdata ad = { 0 };
	app_data = &ad;

	g_type_init();

	__bt_agent_create((void *)&ad);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	if (main_loop != NULL)
		g_main_loop_unref(main_loop);

	return 0;
}

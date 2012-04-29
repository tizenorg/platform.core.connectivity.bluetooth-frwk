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

#include "bluetooth-agent.h"

struct bt_agent_appdata *app_data = NULL;

/* status - 0 : No operation, 1 : Activate , 2 : Deactivate, 3 : Search Test*/
/* run_type - No window change, 1 : Top window, 2 : Background*/
static void __agent_launch_bt_service(int status, int run_type)
{
	bundle *kb;
	char status_val[5] = { 0, };
	char run_type_val[5] = { 0, };

	snprintf(status_val, sizeof(status_val), "%d", status);
	snprintf(run_type_val, sizeof(run_type_val), "%d", run_type);

	DBG("status: %s, run_type: %s", status_val, run_type_val);

	kb = bundle_create();

	bundle_add(kb, "launch-type", "setstate");
	bundle_add(kb, "status", status_val);
	bundle_add(kb, "run-type", run_type_val);

	aul_launch_app("org.tizen.bluetooth", kb);

	bundle_free(kb);
}

static int __agent_check_bt_service(void *data)
{
	int bt_status = VCONFKEY_BT_STATUS_OFF;
	if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_status) < 0) {
		DBG("no bluetooth device info, so BT was disabled at previous session");
	}

	if (bt_status != VCONFKEY_BT_STATUS_OFF) {
		DBG("Previous session was enabled.");

		/*check BT service*/
		if (!aul_app_is_running("org.tizen.bluetooth")) {
			__agent_launch_bt_service(BT_AGENT_RUN_STATUS_ACTIVATE,
						BT_AGENT_ON_BACKGROUND);
		}
	}

	return 0;
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
	if (adapter_proxy)
		_bt_agent_register(adapter_proxy);

	/*check BT service*/
	if (!aul_app_is_running("org.tizen.bluetooth"))
		__agent_launch_bt_service(BT_AGENT_RUN_STATUS_NO_CHANGE,
					BT_AGENT_ON_CURRENTVIEW);

	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_ON) != 0)
		DBG("Set vconf failed\n");

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		DBG("Set vconf failed\n");
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

		if (flight_mode == TRUE && aul_app_is_running("org.tizen.bluetooth")) {
			DBG("Deactivate Bluetooth Service\n");
			__agent_launch_bt_service(BT_AGENT_RUN_STATUS_DEACTIVATE,
						BT_AGENT_ON_CURRENTVIEW);
		}
	}
}

static int __agent_init(void *data)
{
	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)data;
	static DBusGConnection *connection = NULL;
	static DBusGProxy *manager_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	GError *error = NULL;
	const char *adapter_path = NULL;

	if (connection == NULL)
		connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		ERR("ERROR: Can't get on system bus [%s]", error->message);
		g_error_free(error);
		return 1;
	}

	ad->g_connection = (void *)connection;

	if (manager_proxy == NULL)
		manager_proxy = dbus_g_proxy_new_for_name(connection, "org.bluez", "/",
									"org.bluez.Manager");

	if (manager_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return 1;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &error,
			       G_TYPE_INVALID,
			       DBUS_TYPE_G_OBJECT_PATH, &adapter_path, G_TYPE_INVALID)) {
		if (error != NULL) {
			DBG("Getting DefaultAdapter failed: [%s]", error->message);
			g_error_free(error);
		}

		_bt_agent_register(NULL);

		dbus_g_proxy_add_signal(manager_proxy, "AdapterAdded",
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(manager_proxy, "AdapterAdded",
					    G_CALLBACK(__agent_adapter_added_cb), ad, NULL);
	} else {
		DBG("DefaultAdapter [%s]", adapter_path);
		adapter_proxy = dbus_g_proxy_new_for_name(connection, "org.bluez", adapter_path,
								"org.bluez.Adapter");
		if (adapter_proxy)
			_bt_agent_register(adapter_proxy);
	}

	dbus_g_proxy_add_signal(manager_proxy, "AdapterRemoved",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(manager_proxy, "AdapterRemoved",
				    G_CALLBACK(__agent_adapter_removed_cb), NULL, NULL);

	g_idle_add((GSourceFunc) __agent_check_bt_service, NULL);

	return 0;
}

static int __bt_agent_create(void *data)
{
	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)data;

	DBG("__bt_agent_create() start.\n");

	g_idle_add((GSourceFunc) __agent_init, ad);

	vconf_notify_key_changed(VCONFKEY_SETAPPL_FLIGHT_MODE_BOOL, __bt_agent_flight_mode_cb, ad);

	return 0;
}

GMainLoop *main_loop = NULL;

int main(int argc, char *argv[])
{
	struct bt_agent_appdata ad = { 0 };
	app_data = &ad;

	g_type_init();

	__bt_agent_create((void *)&ad);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	if (main_loop != NULL) {
		g_main_loop_unref(main_loop);
	}

	return 0;
}

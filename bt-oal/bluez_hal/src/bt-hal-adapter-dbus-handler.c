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

static void ___bt_fill_le_supported_features(const char *item,
		const char *value, uint8_t *le_features)
{
	DBG("+");

	if (g_strcmp0(item, "adv_inst_max") == 0) {
		le_features[1] = atoi(value);
	} else if (g_strcmp0(item, "rpa_offloading") == 0) {
		le_features[2] = atoi(value);
	} else if (g_strcmp0(item, "max_filter") == 0) {
		le_features[4] = atoi(value);
	} else {
		DBG("No registered item");
	}

	/*
	 * TODO: Need to check these usages for Bluez Case. In Bluedroid case,
	 * these are used, so just setting all to 0
	 */
	le_features[3] = 0; /* Adapter MAX IRK List Size */
	/* lo byte */
	le_features[5] = 0; /* Adapter Scan result storage size */
	/* hi byte */
	le_features[6] = 0;
	le_features[7] = 0; /* Adapter Activity energy info supported */

	DBG("-");
}

static gboolean __bt_adapter_all_properties_cb(gpointer user_data)
{
	GVariant *result = user_data;
	GVariantIter *property_iter;
	const gchar *key;
	GVariant *value;

	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;
	size_t size = 0;
	gchar *address = NULL;
	gchar *name = NULL;
	unsigned int cod = 0;
	gboolean discoverable;
	gboolean connectable;
	unsigned int scan_mode = BT_SCAN_MODE_NONE;
	unsigned int disc_timeout;
	gchar *version;
	gboolean is_discovering;
	gboolean is_le_discovering;
	gboolean ipsp_initialized;
	gboolean powered;
	gboolean pairable;
	unsigned int pairable_timeout;
	gboolean scan_mode_property_update = FALSE;

	DBG("+");

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	DBG("@@Start parsing properties");
	g_variant_get(result, "(a{sv})", &property_iter);
	while (g_variant_iter_loop(property_iter, "{sv}", &key, &value)) {
		if(!g_strcmp0(key, "Address")) {
			uint8_t bdaddr[6];

			address = (gchar *) g_variant_get_string(value, NULL);
			DBG("Address [%s]", address);
			_bt_convert_addr_string_to_type(bdaddr, address);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_ADDR, sizeof(bdaddr), bdaddr);
			ev->num_props++;
			g_free(address);
		} else if (!g_strcmp0(key, "Alias")) {
			name = (gchar *) g_variant_get_string(value, NULL);
			DBG("Alias [%s]@@@", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_NAME, strlen(name) + 1, name);
			ev->num_props++;
			g_free(name);
		} else if (!g_strcmp0(key, "Class")) {
			cod = g_variant_get_uint32(value);
			DBG("Class [%d]", cod);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_CLASS, sizeof(unsigned int), &cod);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Discoverable")) {
			discoverable = g_variant_get_boolean(value);
			DBG("Discoverable [%d]", discoverable);
			if (discoverable)
				scan_mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
			scan_mode_property_update = TRUE;
		} else if (!g_strcmp0(key, "DiscoverableTimeout")) {
			disc_timeout = g_variant_get_uint32(value);
			DBG("Discoverable Timeout [%d]", disc_timeout);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_DISC_TIMEOUT, sizeof(unsigned int), &disc_timeout);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Connectable")) {
			connectable = g_variant_get_boolean(value);
			DBG("Connectable [%d]", connectable);
			if (scan_mode == BT_SCAN_MODE_NONE)
				scan_mode = BT_SCAN_MODE_CONNECTABLE;
			scan_mode_property_update = TRUE;
		} else if (!g_strcmp0(key, "Version")) {
			version = (gchar *) g_variant_get_string(value, NULL);
			DBG("Version [%s]", version);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_VERSION, strlen(version) + 1, version);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Name")) {
			name = (gchar *) g_variant_get_string(value, NULL);
			DBG("Name [%s]", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_NAME, strlen(name) + 1, name);
			ev->num_props++;
			g_free(name);
		} else if (!g_strcmp0(key, "Powered")) {
			powered = g_variant_get_boolean(value);
			DBG("Powered = [%d]", powered);
		} else if (!g_strcmp0(key, "Pairable")) {
			pairable = g_variant_get_boolean(value);
			DBG("Pairable [%d]", pairable);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_PAIRABLE, sizeof(gboolean), &pairable);
			ev->num_props++;
		} else if (!g_strcmp0(key, "PairableTimeout")) {
			pairable_timeout = g_variant_get_uint32(value);
			DBG("Pairable Timeout = [%d]", pairable_timeout);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_PAIRABLE_TIMEOUT, sizeof(unsigned int), &pairable_timeout);
			ev->num_props++;
		} else if (!g_strcmp0(key, "UUIDs")) {
			char **uuid_value;
			int uuid_count = 0;
			gsize size1 = 0;
			int i =0;
			size1 = g_variant_get_size(value);
			int num_props_tmp = ev->num_props;
			if (size1 > 0) {
				uuid_value = (char **)g_variant_get_strv(value, &size1);
				for (i = 0; uuid_value[i] != NULL; i++)
					uuid_count++;
				/* UUID collection */
				uint8_t uuids[HAL_UUID_LEN * uuid_count];
				for (i = 0; uuid_value[i] != NULL; i++) {
					char *uuid_str = NULL;
					uint8_t uuid[HAL_UUID_LEN];
					uuid_str = g_strdup(uuid_value[i]);
					DBG("UUID string [%s]\n", uuid_str);
					_bt_convert_uuid_string_to_type(uuid, uuid_str);
					memcpy(uuids + i * HAL_UUID_LEN, uuid, HAL_UUID_LEN);
				}
				size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_UUIDS,
						(HAL_UUID_LEN * uuid_count),
						uuids);
				ev->num_props = num_props_tmp + 1;
				g_free(uuid_value);
			}
		} else if (!g_strcmp0(key, "Discovering")) {
			is_discovering = g_variant_get_boolean(value);
			DBG("Discovering = [%d]", is_discovering);
		} else if (!g_strcmp0(key, "LEDiscovering")) {
			is_le_discovering = g_variant_get_boolean(value);
			DBG("LE Discovering = [%d]", is_le_discovering);
		} else if (!g_strcmp0(key, "Modalias")) {
			char *modalias = NULL;
			g_variant_get(value, "s", &modalias);
			DBG("Adapter ModAlias [%s]", modalias);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_MODALIAS, strlen(modalias) + 1, modalias);
			ev->num_props++;
			g_free(modalias);
		} else if (!g_strcmp0(key, "SupportedLEFeatures")) {
			DBG("LE Supported features");
			char *name = NULL;
			char *val = NULL;
			GVariantIter *iter = NULL;
			uint8_t le_features[8];
			gboolean le_features_present = FALSE;

			g_variant_get(value, "as", &iter);
			if (iter) {
				while (g_variant_iter_loop(iter, "s", &name)) {
					DBG("name = %s", name);
					g_variant_iter_loop(iter, "s", &val);
					DBG("Value = %s", val);
					___bt_fill_le_supported_features(name, val, le_features);
					le_features_present = TRUE;
				}
				g_variant_iter_free(iter);

				if (le_features_present) {
					size += __bt_insert_hal_properties(buf + size,
							HAL_PROP_ADAPTER_LOCAL_LE_FEAT, sizeof(le_features), le_features);
					ev->num_props++;
				} else {
					DBG("le supported features values are NOT provided by Stack");
				}
			}
		} else if (!g_strcmp0(key, "IpspInitStateChanged")) {
			g_variant_get(value, "b" ,&ipsp_initialized);
			DBG("IPSP Initialized = %d", ipsp_initialized);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_IPSP_INITIALIZED, sizeof(gboolean), &ipsp_initialized);
			ev->num_props++;
		} else {
			ERR("Unhandled Property:[%s]", key);
		}
	}

	if (scan_mode_property_update) {
		size += __bt_insert_hal_properties(buf + size,
				HAL_PROP_ADAPTER_SCAN_MODE, sizeof(int), &scan_mode);
		ev->num_props++;
	}

	if (size > 2) {
		DBG("Send Adapter properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]", ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_variant_unref(result);
	return FALSE;
}

static int __bt_hal_dbus_get_all_adapter_properties(void)
{
	GDBusProxy *proxy;
	GVariant *result;
	GError *error = NULL;

	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"GetAll",
			g_variant_new("(s)", BT_ADAPTER_INTERFACE),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get all adapter properties (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get all adapter properties");
		return BT_STATUS_FAIL;
	}

	DBG("Got All properties from Bluez Stack!!, time to start parsing");
	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_all_properties_cb, (gpointer)result);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

int _bt_hal_dbus_get_adapter_properties(void)
{
	DBG("+");

	return __bt_hal_dbus_get_all_adapter_properties();

	DBG("-");
}

/* Get Discoverable timeout API and callback */
static gboolean __bt_adapter_discovery_timeout_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;;
	size_t size = 0;
	unsigned int *timeout = user_data;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	DBG("Discovery timeout in callback: [%d]", *timeout);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_DISC_TIMEOUT,
			sizeof(unsigned int), timeout);

	ev->num_props++;
	DBG("Timeout value [%d] property Num [%d]", *timeout, ev->num_props);

	if (size > 2) {
		DBG("Send Adapter Properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_free(timeout);
	return FALSE;
}

int _bt_hal_dbus_get_discovery_timeout(void)
{
	GDBusProxy *proxy;
	GVariant *result;
	GVariant *temp;
	GError *error = NULL;
	unsigned int *timeout;
	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"DiscoverableTimeout"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get local version (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get local version");
		return BT_STATUS_FAIL;
	}

	timeout = g_malloc0(sizeof(int));
	if (!timeout) {
		ERR("Memory allocation failed");
		g_variant_unref(result);
		return BT_STATUS_FAIL;
	}

	g_variant_get(result, "(v)", &temp);
	*timeout = g_variant_get_uint32(temp);
	DBG("Timeout value: [%d]", *timeout);

	g_variant_unref(result);
	g_variant_unref(temp);

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_discovery_timeout_cb, (gpointer) timeout);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

/* Get Discoverable Mode API and callback */
static gboolean __bt_adapter_scan_mode_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;;
	size_t size = 0;
	int *mode = user_data;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	DBG("Scan mode callback: [%d]", *mode);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_SCAN_MODE,
			sizeof(int), mode);

	ev->num_props++;
	DBG("Scan mode [%d] property Num [%d]", *mode, ev->num_props);

	if (size > 2) {
		DBG("Send Adapter Properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_free(mode);
	return FALSE;
}

int _bt_hal_dbus_get_scan_mode(void)
{
	GDBusProxy *proxy;
	gboolean discoverable;
	gboolean connectable;
	GVariant *result;
	GVariant *temp;
	GError *error = NULL;
	int *scan_mode;
		;
	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"Discoverable"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get discoverable mode (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get discoverable mode");
		return BT_STATUS_FAIL;
	}

	g_variant_get(result, "(v)", &temp);
	discoverable = g_variant_get_boolean(temp);
	DBG("discoverable:%d", discoverable);

	g_variant_unref(result);
	g_variant_unref(temp);

	if (!discoverable) {
		result = g_dbus_proxy_call_sync(proxy,
				"Get",
				g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
					"Connectable"),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&error);
		if (!result) {
			if (error != NULL) {
				ERR("Failed to get connectable mode (Error: %s)", error->message);
				g_clear_error(&error);
			} else
				ERR("Failed to get connectable mode");
			return BT_STATUS_FAIL;
		}

		g_variant_get(result, "(v)", &temp);
		connectable = g_variant_get_boolean(temp);
		DBG("connectable:%d", connectable);

		g_variant_unref(result);
		g_variant_unref(temp);
	}

	scan_mode = g_malloc0(sizeof(int));
	if (!scan_mode) {
		ERR("Memory allocation failed");
		return BT_STATUS_FAIL;
	}

	if (discoverable)
		*scan_mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
	else if (connectable)
		*scan_mode = BT_SCAN_MODE_CONNECTABLE;
	else
		*scan_mode = BT_SCAN_MODE_NONE;

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_scan_mode_cb, (gpointer) scan_mode);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

/* Get Local Version API and callback */
static gboolean __bt_adapter_local_version_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;;
	size_t size = 0;
	char *version = NULL;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	version = (char*) user_data;
	DBG("Local Version in callback: [%s]", version);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_VERSION,
			(strlen(version) + 1), version);

	ev->num_props++;
	DBG("Device version [%s] property Num [%d]", version, ev->num_props);

	if (size > 2) {
		DBG("Send Adapter Properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_free(version);
	return FALSE;
}

int _bt_hal_dbus_get_local_version(void)
{
	GDBusProxy *proxy;
	const char *version = NULL;
	GVariant *result;
	GVariant *temp;
	GError *error = NULL;
	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"Version"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get local version (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get local version");
		return BT_STATUS_FAIL;
	}

	g_variant_get(result, "(v)", &temp);
	version = g_variant_dup_string(temp, NULL);
	DBG("Local Version: [%s]", version);

	g_variant_unref(result);
	g_variant_unref(temp);

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_local_version_cb, (gpointer) version);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

/* Get Local Name API and callback */
static gboolean __bt_adapter_local_name_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;;
	size_t size = 0;
	char *name = NULL;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	name = (char*) user_data;
	DBG("Local Name in callback: [%s]", name);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_NAME,
			strlen(name) + 1, name);

	ev->num_props++;
	DBG("Device name [%s] property Num [%d]",name, ev->num_props);

	if (size > 2) {
		DBG("Send Adapter Properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_free(name);
	return FALSE;
}

int _bt_hal_dbus_get_local_name(void)
{
	GDBusProxy *proxy;
	const char *name = NULL;
	GVariant *result;
	GVariant *temp;
	GError *error = NULL;
	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("_bt_hal_dbus_get_local_name: Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"Alias"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get local name (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get local name");
		return BT_STATUS_FAIL;
	}

	g_variant_get(result, "(v)", &temp);
	name = g_variant_dup_string(temp, NULL);
	DBG("Local Name: [%s]", name);

	g_variant_unref(result);
	g_variant_unref(temp);

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_local_name_cb, (gpointer) name);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

/* Get Local Address API and callback */
static gboolean __bt_adapter_local_address_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;
	size_t size = 0;
	char * address = NULL;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	address = (char*) user_data;

	uint8_t bdaddr[6];
	_bt_convert_addr_string_to_type(bdaddr, address);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_ADDR,
			sizeof(bdaddr), bdaddr);

	ev->num_props++;
	DBG("Device address [%s] property Num [%d]",address, ev->num_props);

	size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_ADDR,
			sizeof(bdaddr), bdaddr);

	if (size > 1) {
		DBG("Send Device found event to HAL user,"
			" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_free(address);
	return FALSE;
}

int _bt_hal_dbus_get_local_address(void)
{
	GDBusProxy *proxy;
	GError *error = NULL;
	const char *address;
	GVariant *result;
	GVariant *temp;

	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();
	if (!proxy) {
		DBG("_bt_hal_dbus_get_local_address: Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"Address"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		ERR("Failed to get local address");
		if (error != NULL) {
			ERR("Failed to get local address (Error: %s)", error->message);
			g_clear_error(&error);
		}
		return BT_STATUS_FAIL;
	}

	g_variant_get(result, "(v)", &temp);
	address = g_variant_dup_string(temp, NULL);

	if (address) {
		DBG("Address:%s", address);
	} else {
		return BT_STATUS_FAIL;
	}

	g_variant_unref(result);
	g_variant_unref(temp);

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_local_address_cb, (gpointer) address);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

/* Get Local services API and callback */
static gboolean __bt_adapter_service_uuids_cb(gpointer user_data)
{
	GVariant *result = user_data;
	GVariant *temp;
	GVariantIter *iter = NULL;
	gchar *uuid_str;

	/* Buffer and propety count management */
	uint8_t buf[BT_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;
	size_t size = 0;

	/* UUID collection */
	uint8_t uuids[HAL_UUID_LEN * MAX_UUID_COUNT];
	int uuid_count = 0;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	g_variant_get(result, "(v)", &temp);
	g_variant_get(temp, "as", &iter);
	if (iter == NULL) {
		ERR("Failed to get UUIDs");
		goto fail;
	}

	while (g_variant_iter_loop(iter, "s", &uuid_str)) {
		uint8_t uuid[HAL_UUID_LEN];

		DBG("UUID string [%s]\n", uuid_str);
		_bt_convert_uuid_string_to_type(uuid, uuid_str);
		memcpy(uuids + uuid_count * HAL_UUID_LEN, uuid, HAL_UUID_LEN);
		uuid_count++;
	}

	size += __bt_insert_hal_properties(buf + size,
			HAL_PROP_ADAPTER_UUIDS,
			(HAL_UUID_LEN * uuid_count),
			uuids);
	ev->num_props++;

	if (size > 2) {
		DBG("Send Adapter properties changed event to HAL user,"
				" Num Prop [%d] total size [%d]", ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);
	}

	g_variant_iter_free(iter);
	g_variant_unref(result);
	g_variant_unref(temp);
	return FALSE;

fail:
	ev->status = BT_STATUS_FAIL;
	ev->num_props = 0;
	DBG("Send Adapter properties changed event to HAL user,"
			" Num Prop [%d] total size [%d]", ev->num_props, size);
	event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, (void*) buf, size);

	g_variant_unref(result);
	return FALSE;
}

int _bt_hal_dbus_get_adapter_supported_uuids(void)
{
	GDBusProxy *proxy;
	GError *error = NULL;
	GVariant *result;

	DBG("+");

	proxy = _bt_get_adapter_properties_proxy();

	if (!proxy) {
		DBG("_bt_hal_dbus_get_local_name: Adapter Properties proxy get failed!!!");
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(proxy,
			"Get",
			g_variant_new("(ss)", BT_ADAPTER_INTERFACE,
				"UUIDs"),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		if (error != NULL) {
			ERR("Failed to get UUIDs (Error: %s)", error->message);
			g_clear_error(&error);
		} else
			ERR("Failed to get UUIDs");
		return BT_STATUS_FAIL;
	}


	DBG("Got All Adaptr service UUID's from Bluez Stack!!, time to start parsing");

	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_adapter_service_uuids_cb, (gpointer)result);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

int _bt_hal_dbus_get_adapter_property(bt_property_type_t property_type)
{
	DBG("+");

	INFO("property_type: %d", property_type);

	switch (property_type) {
	case BT_PROPERTY_BDADDR:
		return _bt_hal_dbus_get_local_address();
	case BT_PROPERTY_BDNAME:
		return _bt_hal_dbus_get_local_name();
	case BT_PROPERTY_VERSION:
		return _bt_hal_dbus_get_local_version();
	case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		return _bt_hal_dbus_get_discovery_timeout();
	case BT_PROPERTY_ADAPTER_SCAN_MODE:
		return _bt_hal_dbus_get_scan_mode();
	case BT_PROPERTY_CLASS_OF_DEVICE:
		return BT_STATUS_UNSUPPORTED;
	case BT_PROPERTY_UUIDS:
		return _bt_hal_dbus_get_adapter_supported_uuids();
	case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
		return BT_STATUS_UNSUPPORTED;
	default:
		return BT_STATUS_UNSUPPORTED;
	}

	DBG("-");
}

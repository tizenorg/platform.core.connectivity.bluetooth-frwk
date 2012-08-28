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

/*:Associate with "Bluetooth" */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "bluetooth-api-common.h"
#include "bluetooth-gap-api.h"
#include "bluetooth-network-api.h"

#include "marshal.h"

static void __bluetooth_internal_mode_changed_cb(DBusGProxy *object, const char *changed_mode,
						gpointer user_data);

/* Global session information*/
static bt_info_t bt_info = { 0, };

bt_info_t *_bluetooth_internal_get_information(void)
{
	bt_info_t *bt_internal_info = &bt_info;
	return bt_internal_info;
}

void _bluetooth_internal_event_cb(int event, int result, void *param_data)
{
	DBG("+");
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param_data;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_cb_ptr)
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event,
					bt_internal_info->user_data);

	DBG("-");
}

bool _bluetooth_internal_is_adapter_enabled(void)
{
	GError *err = NULL;
	const char *adapter_path = NULL;
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->manager_proxy == NULL) {
		DBG("manager_proxy is NULL");
		return FALSE;
	}

	if (!dbus_g_proxy_call(bt_internal_info->manager_proxy, "DefaultAdapter", &err,
				G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			DBG("DefaultAdapter err:[%s]", err->message);
			g_error_free(err);
		}
		return FALSE;
	}

	if (adapter_path == NULL) {
		DBG("adapter_path is NULL");
		return FALSE;
	}

	DBG("adapter_path is %s", adapter_path);

	return TRUE;
}

void bluetooth_internal_convert_uuid_num_to_string(const bluetooth_service_uuid_list_t uuid_num,
							char *uuid, int size)
{
	DBG("+");

	if (!uuid)
		return;

	snprintf(uuid, size, "0000%x-%s", uuid_num, BLUETOOTH_UUID_POSTFIX);

	DBG("uuid string is %s", uuid);

	DBG("-");
}

int _bluetooth_internal_get_adapter_path(DBusGConnection *conn, char *path)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	char *adapter_path = NULL;

	DBG("+\n");

	if (conn == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	manager_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
				BLUEZ_MANAGER_OBJ_PATH, BLUEZ_MANAGER_INTERFACE);

	if (manager_proxy == NULL) {
		DBG("Could not create a dbus proxy\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
			       G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			DBG("Getting DefaultAdapter failed: [%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(manager_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (adapter_path == NULL || strlen(adapter_path) >= BT_ADAPTER_OBJECT_PATH_MAX) {
		DBG("Adapter path is inproper\n");
		g_object_unref(manager_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	strncpy(path, adapter_path, BT_ADAPTER_OBJECT_PATH_MAX);
	DBG("path = %s\n", adapter_path);

	g_object_unref(manager_proxy);

	return BLUETOOTH_ERROR_NONE;
}

DBusGProxy *_bluetooth_internal_get_adapter_proxy(DBusGConnection *conn)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	char *adapter_path = NULL;

	DBG("+\n");

	if (conn == NULL)
		return NULL;

	manager_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
				BLUEZ_MANAGER_OBJ_PATH, BLUEZ_MANAGER_INTERFACE);

	if (manager_proxy == NULL) {
		DBG("Could not create a dbus proxy\n");
		return NULL;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
			       G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			DBG("Getting DefaultAdapter failed: [%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(manager_proxy);
		return NULL;
	}

	if (adapter_path == NULL || strlen(adapter_path) >= BT_ADAPTER_OBJECT_PATH_MAX) {
		DBG("Adapter path is inproper\n");
		g_object_unref(manager_proxy);
		return NULL;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(conn,
					BLUEZ_SERVICE_NAME,
					adapter_path,
					BLUEZ_ADAPTER_INTERFACE);

	g_object_unref(manager_proxy);

	return adapter_proxy;
}


void _bluetooth_internal_convert_addr_string_to_addr_type(bluetooth_device_address_t *addr,
									const char *address)
{
	char *ptr1, *ptr2, *ptr3, *ptr4, *ptr5;

	if (!address || !addr)
		return;

	addr->addr[0] = strtol(address, &ptr5, 16);
	addr->addr[1] = strtol(ptr5 + 1, &ptr4, 16);
	addr->addr[2] = strtol(ptr4 + 1, &ptr3, 16);
	addr->addr[3] = strtol(ptr3 + 1, &ptr2, 16);
	addr->addr[4] = strtol(ptr2 + 1, &ptr1, 16);
	addr->addr[5] = strtol(ptr1 + 1, NULL, 16);
}

void _bluetooth_internal_print_bluetooth_device_address_t(const bluetooth_device_address_t *addr)
{
	DBG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", addr->addr[0], addr->addr[1], addr->addr[2],
				addr->addr[3], addr->addr[4], addr->addr[5]);
}

void _bluetooth_internal_addr_type_to_addr_string(char *address,
						const bluetooth_device_address_t *addr)
{
	if (!address || !addr)
		return;

	snprintf(address, BT_ADDRESS_STRING_SIZE,
		"%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", addr->addr[0], addr->addr[1],
				addr->addr[2], addr->addr[3], addr->addr[4], addr->addr[5]);
}

void _bluetooth_internal_divide_device_class(bluetooth_device_class_t *device_class,
									unsigned int cod)
{
	if (!device_class)
		return;

	device_class->major_class = (unsigned short)(cod & 0x00001F00) >> 8;
	device_class->minor_class = (unsigned short)((cod & 0x000000FC));
	device_class->service_class = (unsigned int)((cod & 0x00FF0000));

	if (cod & 0x002000) {
		device_class->service_class |=
					BLUETOOTH_DEVICE_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE;
	}
}

static int __bluetooth_internal_store_get_value(const char *key,
				bt_store_type_t store_type,
				unsigned int size, void *value)
{
	int ret = 0;
	int int_value = 0;
	int *intval = NULL;
	gboolean *bool_value = FALSE;
	char *str = NULL;
	char *ptr = NULL;

	if (value == NULL) {
		return -1;
	}

	switch (store_type) {
	case BT_STORE_BOOLEAN:
		bool_value = (gboolean *) value;
		ret = vconf_get_bool(key, &int_value);
		if (ret < 0) {
			DBG("Get gboolean is failed");
			*bool_value = FALSE;
			return -1;
		}
		*bool_value = (int_value != FALSE);
		break;
	case BT_STORE_INT:
		intval = (int *)value;
		ret = vconf_get_int(key, intval);
		if (ret < 0) {
			DBG("Get int is failed");
			*intval = 0;
			return -1;
		}
		break;
	case BT_STORE_STRING:
		str = vconf_get_str(key);
		if (str == NULL || strlen(str) == 0) {
			DBG("Get string is failed");
			return -1;
		}
		if (size > 1) {
			if (!g_utf8_validate(str, -1, (const char **)&ptr))
				*ptr = '\0';

			g_strlcpy((char *)value, str, size - 1);
		}

		free(str);
		break;
	default:
		DBG("Unknown Store Type");
		return -1;
	}

	return ret;
}

DBusGProxy *_bluetooth_internal_find_device_by_path(const char *dev_path)
{
	GList *list = bt_info.device_proxy_list;
	DBusGProxy *device_proxy = NULL;
	const char *proxy_path = NULL;
	int list_length, i;

	if (list == NULL || dev_path == NULL) {
		return NULL;
	}

	list_length = g_list_length(list);

	for (i = 0; i < list_length; i++) {
		device_proxy = (DBusGProxy *) g_list_nth_data(list, i);

		if (device_proxy != NULL) {
			proxy_path = dbus_g_proxy_get_path(device_proxy);

			if (strcmp(proxy_path, dev_path) == 0) {
				return device_proxy;
			}
		}
	}

	return NULL;
}

void _bluetooth_change_uuids_to_sdp_info(GValue *value, bt_sdp_info_t *sdp_data)
{
	char **uuids;
	int i;
	char **parts;

	if (value == NULL || sdp_data == NULL)
		return;

	uuids = g_value_get_boxed(value);
	if (uuids == NULL)
		return;

	sdp_data->service_index = 0;

	for (i = 0; uuids[i] != NULL && i < BLUETOOTH_MAX_SERVICES_FOR_DEVICE; i++) {
		g_strlcpy(sdp_data->uuids[i], uuids[i], BLUETOOTH_UUID_STRING_MAX);

		parts = g_strsplit(uuids[i], "-", -1);

		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			return;
		}

		sdp_data->service_list_array[i] = g_ascii_strtoull(parts[0], NULL, 16);
		g_strfreev(parts);

		DBG("UUIDs %d UUID %x ", i, sdp_data->service_list_array[i]);

		sdp_data->service_index++;
	}
}

static void __bluetooth_internal_device_property_changed(DBusGProxy *device_proxy,
							const char *property,
						       GValue *value,
							gpointer user_data)
{
	const char *dev_path = dbus_g_proxy_get_path(device_proxy);
	GHashTable *hash = NULL;
	GValue *property_value;

	DBG("+ remote device[%s] property[%s]\n", dev_path, property);

	if (g_strcmp0(property, "Paired") == 0) {
		bt_info_t *bt_internal_info = NULL;
		gboolean paired = g_value_get_boolean(value);
		char address[BT_ADDRESS_STRING_SIZE] = { 0 };

		bt_internal_info = _bluetooth_internal_get_information();

		if (bt_internal_info->is_bonding_req == TRUE) {
			DBG("Will recieve the async result");
			return;
		}

		_bluetooth_internal_device_path_to_address(dev_path, address);

		if (paired == TRUE) {
			_bluetooth_internal_bonding_created_cb(address,
							(gpointer)device_proxy);
		}
	} else if (g_strcmp0(property, "Trusted") == 0) {
		char address[BT_ADDRESS_STRING_SIZE] = { 0 };
		bluetooth_device_address_t device_addr = { {0} };
		gboolean trusted = g_value_get_boolean(value);

		DBG("Remote Device [%s] Trusted Changed [%d]\n", dev_path,
								trusted);

		_bluetooth_internal_device_path_to_address(dev_path, address);
		_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr, address);
		_bluetooth_internal_event_cb(trusted ? BLUETOOTH_EVENT_DEVICE_AUTHORIZED :
						BLUETOOTH_EVENT_DEVICE_UNAUTHORIZED,
						BLUETOOTH_ERROR_NONE, &device_addr);

	} else if (g_strcmp0(property, "Connected") == 0) {
		char address[BT_ADDRESS_STRING_SIZE] = { 0 };
		bluetooth_device_address_t device_addr = { {0} };
		gboolean connected = g_value_get_boolean(value);

		_bluetooth_internal_device_path_to_address(dev_path, address);
		_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr,
									address);
		_bluetooth_internal_event_cb(connected ? BLUETOOTH_EVENT_DEVICE_CONNECTED :
						BLUETOOTH_EVENT_DEVICE_DISCONNECTED,
						BLUETOOTH_ERROR_NONE, &device_addr);

	} else if (g_strcmp0(property, "Name") == 0) {
		const gchar *name = g_value_get_string(value);
		const char *address = NULL;
		guint remote_class;
		gboolean paired = FALSE;

		dbus_g_proxy_call(device_proxy, "GetProperties", NULL,
				  G_TYPE_INVALID,
				  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

		if (hash != NULL) {
			property_value = g_hash_table_lookup(hash, "Address");
			address = (char *)property_value ? g_value_get_string(property_value) : NULL;

			property_value = g_hash_table_lookup(hash, "Class");
			remote_class = property_value ? g_value_get_uint(property_value) : 0;

			property_value = g_hash_table_lookup(hash, "Paired");
			paired = property_value ? g_value_get_boolean(property_value) : FALSE;

			_bluetooth_internal_remote_device_name_updated_cb(address,
						name, 0, remote_class, paired);
		}
	} else if (g_strcmp0(property, "UUIDs") == 0) {
		bt_sdp_info_t sdp_data;
		char address[BT_ADDRESS_STRING_SIZE] = { 0 };
		int err = BLUETOOTH_ERROR_NONE;
		bt_info_t *bt_internal_info = NULL;
		bt_internal_info = _bluetooth_internal_get_information();

		DBG("Device Property Changed (UUIDs )");

		_bluetooth_internal_device_path_to_address(dev_path, address);

		_bluetooth_internal_convert_addr_string_to_addr_type(&sdp_data.device_addr, address);

		_bluetooth_internal_print_bluetooth_device_address_t(&sdp_data.device_addr);

		_bluetooth_change_uuids_to_sdp_info(value, &sdp_data);

		bt_internal_info->is_service_req = FALSE;

		/* Report UUID list as xml_parsed_sdp_data to the upper layer. */
		if (sdp_data.service_index <= 0 ||
			sdp_data.service_index >= BLUETOOTH_MAX_SERVICES_FOR_DEVICE) {
			sdp_data.service_index = 0;
			err = BLUETOOTH_ERROR_SERVICE_SEARCH_ERROR;
		}

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_SERVICE_SEARCHED,
							err, &sdp_data);
	}

	DBG("-\n");

}

static void __bluetooth_internal_add_device_signal(DBusGProxy *device_proxy)
{
	if (device_proxy == NULL) {
		return;
	}

	dbus_g_proxy_add_signal(device_proxy, "PropertyChanged", G_TYPE_STRING,
						G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(device_proxy, "PropertyChanged",
				    G_CALLBACK(__bluetooth_internal_device_property_changed),
					NULL, NULL);
}

static void __bluetooth_internal_remove_device_signal(DBusGProxy *device_proxy)
{
	if (device_proxy == NULL) {
		return;
	}

	dbus_g_proxy_disconnect_signal(device_proxy, "PropertyChanged",
				       	G_CALLBACK(__bluetooth_internal_device_property_changed),
					NULL);
}

DBusGProxy *_bluetooth_internal_add_device(const char *path)
{
	DBusGProxy *device_proxy = NULL;

	device_proxy = dbus_g_proxy_new_for_name(bt_info.conn, BLUEZ_SERVICE_NAME,
						path, BLUEZ_DEVICE_INTERFACE);
	if (device_proxy) {
		bt_info.device_proxy_list = g_list_append(bt_info.device_proxy_list,
								device_proxy);
		__bluetooth_internal_add_device_signal(device_proxy);
	}

	return device_proxy;
}

static void __bluetooth_internal_device_created(DBusGProxy *adapter,
					const char *path, gpointer user_data)
{
	DBG("+ device[%s]", path);

	if (path != NULL) {
		DBusGProxy *device_proxy = _bluetooth_internal_find_device_by_path(path);
		if (device_proxy == NULL) {
			device_proxy = _bluetooth_internal_add_device(path);

			if (device_proxy) {
				DBG("Newly added device [%s]", path);
				bt_info.is_headset_bonding = _bluetooth_is_headset_device(device_proxy);
			}
		} else {
			DBG("Newly added device, but it is stored in list");
		}
	}

	DBG("-");
}

void _bluetooth_internal_device_path_to_address(const char *device_path,
						char *device_address)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr = NULL;

	if (!device_path || !device_address)
		return;

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		char *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL) {
			*pos = ':';
		}

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}

static void __bluetooth_internal_device_removed(DBusGProxy *adapter,
					const char *path, gpointer user_data)
{
	DBG("+ device[%s]", path);

	if (path != NULL) {
		DBusGProxy *device_proxy = _bluetooth_internal_find_device_by_path(path);
		char address[BT_ADDRESS_STRING_SIZE] = { 0 };

		if (device_proxy == NULL) {
			return;
		}

		_bluetooth_internal_device_path_to_address(path, address);

		_bluetooth_internal_bonding_removed_cb(address, (gpointer) device_proxy);

		__bluetooth_internal_remove_device_signal(device_proxy);
		bt_info.device_proxy_list = g_list_remove(bt_info.device_proxy_list,
							device_proxy);
		g_object_unref(device_proxy);
		device_proxy = NULL;
	}

	DBG("-");
}

static int __bluetooth_get_timeout_value(DBusGProxy *adapter)
{
	DBG("+");

	int timeout = 0;
	GHashTable *hash = NULL;
	GValue *value = NULL;

	if (adapter == NULL)
		return timeout;

	dbus_g_proxy_call(adapter, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			  &hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "DiscoverableTimeout");
		timeout = g_value_get_uint(value);
	}

	DBG("-");
	return timeout;
}

static bool __bluetooth_get_discoverable_value(DBusGProxy *adapter)
{
	DBG("+");

	bool discoverable = FALSE;
	GHashTable *hash = NULL;
	GValue *value = NULL;

	if (adapter == NULL)
		return discoverable;

	dbus_g_proxy_call(adapter, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			  &hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Discoverable");
		discoverable = g_value_get_boolean(value);
	}

	DBG("-");
	return discoverable;
}

static void __bluetooth_internal_adapter_property_changed(DBusGProxy *adapter,
							const char *property,
							GValue *value,
							gpointer user_data)
{
	DBG("+ property[%s]", property);

	if (g_strcmp0(property, "Name") == 0) {
		const gchar *name = g_value_get_string(value);
		if (name && strlen(name)) {
			DBG("Changed Name [%s]", name);
			g_strlcpy(bt_info.bt_local_name.name, name,
					BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);

			_bluetooth_internal_adapter_name_changed_cb();
		}
	} else if (g_strcmp0(property, "Discovering") == 0) {
		gboolean discovering = g_value_get_boolean(value);

		if (discovering == FALSE) {
			dbus_g_proxy_call(adapter, "StopDiscovery", NULL,
					G_TYPE_INVALID, G_TYPE_INVALID);
			bt_info.is_discovering = FALSE;
			_bluetooth_internal_discovery_completed_cb();
		} else {
			bt_info.is_discovering = TRUE;
			_bluetooth_internal_discovery_started_cb();
		}
	} else if (g_strcmp0(property, "Discoverable") == 0) {
		gboolean discoverable = g_value_get_boolean(value);
		if (discoverable == FALSE) {
			GValue timeout = { 0 };
			g_value_init(&timeout, G_TYPE_UINT);
			g_value_set_uint(&timeout, 0);

			dbus_g_proxy_call_no_reply(adapter, "SetProperty",
						   G_TYPE_STRING, "DiscoverableTimeout",
						   G_TYPE_VALUE, &timeout,
						   G_TYPE_INVALID);

			g_value_unset(&timeout);

			__bluetooth_internal_mode_changed_cb(adapter,
						"connectable", user_data);
		} else {
			if (__bluetooth_get_timeout_value(adapter) == 0)
				__bluetooth_internal_mode_changed_cb(adapter,
							"discoverable",
							user_data);
		}
	} else if (g_strcmp0(property, "DiscoverableTimeout") == 0) {
		guint timeout = g_value_get_uint(value);
		if (timeout == 0) {
			if (__bluetooth_get_discoverable_value(adapter) == TRUE)
				__bluetooth_internal_mode_changed_cb(adapter,
							"discoverable",
							user_data);
			else
				__bluetooth_internal_mode_changed_cb(adapter,
							"connectable",
							user_data);
		} else {
			__bluetooth_internal_mode_changed_cb(adapter,
						"limited_discoverable",
						user_data);
		}
	}

	DBG("-");
}

static void __bluetooth_internal_remote_device_found(DBusGProxy *adapter,
							const char *address,
							GHashTable *hash,
							gpointer user_data)
{
	GValue *value;
	const gchar *name;
	guint remote_class;
	gint rssi;
	gboolean is_name_include = FALSE;
	gboolean paired = FALSE;

	DBG("+ address[%s]", address);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		is_name_include = value ? TRUE : FALSE;
		name = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Class");
		remote_class = value ? g_value_get_uint(value) : 0;

		value = g_hash_table_lookup(hash, "RSSI");
		rssi = value ? g_value_get_int(value) : 0;

		value = g_hash_table_lookup(hash, "Paired");
		paired = value ? g_value_get_boolean(value) : FALSE;

		if (is_name_include) {
			_bluetooth_internal_remote_device_name_updated_cb(address,
									name,
									rssi,
									remote_class,
									paired);
		} else {
			_bluetooth_internal_remote_device_found_cb(address,
								rssi,
								remote_class,
								paired);
		}
	}

	DBG("-");
}

static int __bluetooth_internal_add_signal()
{
	GPtrArray *gp_array = NULL;
	GError *error = NULL;

	if (bt_info.adapter_proxy == NULL) {
		ERR("Add Signal Failed!!!");
		return -1;
	}

	dbus_g_object_register_marshaller(marshal_VOID__STRING, G_TYPE_NONE,
						G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_object_register_marshaller(marshal_VOID__STRING_UINT_INT,
					  	G_TYPE_NONE, G_TYPE_STRING,
						G_TYPE_UINT, G_TYPE_INT,
						G_TYPE_INVALID);
	dbus_g_object_register_marshaller(marshal_VOID__STRING_STRING,
					  	G_TYPE_NONE, G_TYPE_STRING,
						G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_object_register_marshaller(marshal_VOID__UINT, G_TYPE_NONE,
						G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_object_register_marshaller(marshal_VOID__STRING_STRING_INT,
					  	G_TYPE_NONE, G_TYPE_STRING,
						G_TYPE_STRING, G_TYPE_INT,
						G_TYPE_INVALID);
	dbus_g_object_register_marshaller(marshal_VOID__STRING_STRING_INT_UINT,
					  	G_TYPE_NONE, G_TYPE_STRING,
						G_TYPE_STRING, G_TYPE_INT, G_TYPE_UINT,
					  	G_TYPE_INVALID);

	dbus_g_object_register_marshaller(marshal_VOID__STRING_BOXED,
					  G_TYPE_NONE, G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);

	dbus_g_proxy_add_signal(bt_info.adapter_proxy, "PropertyChanged",
				G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_info.adapter_proxy, "PropertyChanged",
				    G_CALLBACK(__bluetooth_internal_adapter_property_changed),
					NULL, NULL);

	dbus_g_proxy_add_signal(bt_info.adapter_proxy, "DeviceFound",
				G_TYPE_STRING, dbus_g_type_get_map("GHashTable",
						G_TYPE_STRING, G_TYPE_VALUE),
				G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_info.adapter_proxy, "DeviceFound",
				    G_CALLBACK(__bluetooth_internal_remote_device_found),
					NULL, NULL);

	dbus_g_proxy_add_signal(bt_info.adapter_proxy, "DeviceCreated",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_info.adapter_proxy, "DeviceCreated",
				    G_CALLBACK(__bluetooth_internal_device_created),
					NULL, NULL);

	dbus_g_proxy_add_signal(bt_info.adapter_proxy, "DeviceRemoved",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_info.adapter_proxy, "DeviceRemoved",
				    G_CALLBACK(__bluetooth_internal_device_removed),
					NULL, NULL);

	_bluetooth_network_server_add_signal();

	_bluetooth_network_client_add_filter();

	dbus_g_proxy_call(bt_info.adapter_proxy, "ListDevices", &error,
			  G_TYPE_INVALID,
			  dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
			  &gp_array, G_TYPE_INVALID);

	if (error == NULL) {
		if (gp_array != NULL) {
			int i;
			for (i = 0; i < gp_array->len; i++) {
				gchar *gp_path = g_ptr_array_index(gp_array, i);

				if (gp_path != NULL) {
					if (_bluetooth_internal_add_device(gp_path))
						DBG("Newly added device [%s]", gp_path);
				}
				g_free(gp_path);
			}
			g_ptr_array_free(gp_array, TRUE);
		}
	} else {
		DBG("ListDevices error: [%s]", error->message);
		g_error_free(error);
		return -2;
	}

	return 0;
}

static int __bluetooth_internal_remove_signal(void)
{
	if (bt_info.adapter_proxy == NULL) {
		DBG("Removed Signal Failed!!!");
		return -1;
	}

	dbus_g_proxy_disconnect_signal(bt_info.adapter_proxy, "PropertyChanged",
				       G_CALLBACK(__bluetooth_internal_adapter_property_changed),
					NULL);

	dbus_g_proxy_disconnect_signal(bt_info.adapter_proxy, "DeviceFound",
				       G_CALLBACK(__bluetooth_internal_remote_device_found), NULL);

	dbus_g_proxy_disconnect_signal(bt_info.adapter_proxy, "DeviceCreated",
				       G_CALLBACK(__bluetooth_internal_device_created), NULL);

	dbus_g_proxy_disconnect_signal(bt_info.adapter_proxy, "DeviceRemoved",
				       G_CALLBACK(__bluetooth_internal_device_removed), NULL);

	_bluetooth_network_server_remove_signal();

	_bluetooth_network_client_remove_filter();

	if (bt_info.device_proxy_list != NULL) {
		int i, list_length = 0;
		DBusGProxy *device_proxy = NULL;

		list_length = g_list_length(bt_info.device_proxy_list);

		for (i = 0; i < list_length; i++) {
			device_proxy = g_list_nth_data(bt_info.device_proxy_list, i);
			__bluetooth_internal_remove_device_signal(device_proxy);
			g_object_unref(device_proxy);
			device_proxy = NULL;
		}
		g_list_free(bt_info.device_proxy_list);
		bt_info.device_proxy_list = NULL;
	}

	g_object_unref(bt_info.adapter_proxy);
	bt_info.adapter_proxy = NULL;

	return 0;
}

int bluetooth_internal_set_adapter_path(const char *adapter_path)
{
	DBG("+\n");

	GHashTable *hash = NULL;
	GValue *value = NULL;
	char *name = NULL;
	gboolean discovering = FALSE;

	if (adapter_path == NULL) {
		DBG("Invalid param");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Get default adapter : [%s]", adapter_path);

	g_strlcpy(bt_info.adapter_path, adapter_path, BT_ADAPTER_OBJECT_PATH_MAX);

	bt_info.adapter_proxy =
	    dbus_g_proxy_new_for_name(bt_info.conn, BLUEZ_SERVICE_NAME, bt_info.adapter_path,
					BLUEZ_ADAPTER_INTERFACE);
	if (!bt_info.adapter_proxy) {
		AST("Could not create a dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/*Implementing the Adpater.GetProperties Synchronous.   This change is
	   required because, before giving the BLUETOOTH_EVENT_ENABLED event cb we
	   have to make sure that device add is filled. Otherwise if application calls
	   bluetooth_get_local_address(), from the event cb, we will return 00:00:00:00:00.
	 */

	DBG("GetProperties Synchronous Implementation\n");

	dbus_g_proxy_call(bt_info.adapter_proxy, "GetProperties", NULL,
			  	G_TYPE_INVALID,
			  	dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		name = (char *)(value ? g_value_get_string(value) : NULL);

		value = g_hash_table_lookup(hash, "Discovering");
		discovering = value ? g_value_get_boolean(value) : 0;
	}

	bt_info.is_discovering = discovering;

	if (name && strlen(bt_info.bt_local_name.name) > 0 &&
			strcmp(name, bt_info.bt_local_name.name) != 0) {
		DBG("store name : [%s] , bluez name [%s]", bt_info.bt_local_name.name, name);
	}
	/*Signal register*/
	if (__bluetooth_internal_add_signal() < 0) {
		AST("Can not add DM signal");
	}
	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
}

static void __bluetooth_internal_adapter_added_cb(DBusGProxy *manager_proxy,
						  const char *adapter_path, gpointer user_data)
{
	DBG("<<<<<<< SIGNAL AdapterAdded >>>>>>>>>");
	DBG("Adapter added [%s]", adapter_path);

	if (strstr(adapter_path, "hci0")) {
		if (bluetooth_internal_set_adapter_path(adapter_path) == BLUETOOTH_ERROR_NONE) {
			bt_info.bt_adapter_state = BLUETOOTH_ADAPTER_ENABLED;
			DBG("Send event to application");
			_bluetooth_internal_enabled_cb();
		}
	} else {
		DBG("path is not include hci0");
	}
}

static void __bluetooth_internal_adapter_removed_cb(DBusGProxy *manager_proxy,
						const char *adapter_path,
						 gpointer user_data)
{
	DBG("<<<<<<< SIGNAL AdapterRemoved >>>>>>>>>");
	DBG("Adapter removed [%s]", adapter_path);

	if (strstr(adapter_path, "hci0")) {
		__bluetooth_internal_remove_signal();
	} else {
		DBG("path is not include hci0");
	}
}

static void __bluetooth_internal_name_owner_changed(DBusGProxy *dbus_proxy, const char *name,
						  const char *prev, const char *new,
							gpointer user_data)
{
	DBG("<<<<<<< SIGNAL NameOwnerChanged >>>>>>>>>\n");

	DBG("Name str = %s", name);

	if (g_strcmp0(name, BLUEZ_SERVICE_NAME) == 0 && *new == '\0') {
		DBG("BlueZ is terminated");
		bt_info.bt_adapter_state = BLUETOOTH_ADAPTER_DISABLED;

		DBG("Send event to application");
		_bluetooth_internal_disabled_cb();
	} else if (g_strcmp0(name, "org.bluez.frwk_agent") == 0) {
		bt_info.agent_proxy = NULL;
		bt_info.agent_proxy = dbus_g_proxy_new_for_name(bt_info.conn,
								"org.bluez.frwk_agent",
								"/org/bluez/agent/frwk_agent",
								"org.bluez.Agent");
		if (!bt_info.agent_proxy) {
			AST("Could not create a agent dbus proxy");
		}
	}
}

static void __bluetooth_internal_mode_changed_cb(DBusGProxy *object, const char *changed_mode,
						gpointer user_data)
{

	int result = BLUETOOTH_ERROR_NONE;
	void *param_data = NULL;
	int scanEnable = 0;

	if (changed_mode == NULL) {
		ERR("changed_mode is NULL");
		return;
	}

	DBG("Mode changed [%s]\n", changed_mode);

	if (strlen(changed_mode) == 0) {
		DBG("ModeChanged get mode failed\n");
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		if (strcmp(changed_mode, "connectable") == 0)
			scanEnable = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		else if (strcmp(changed_mode, "discoverable") == 0)
			scanEnable = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
		else if (strcmp(changed_mode, "limited_discoverable") == 0)
			scanEnable = BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
		else
			scanEnable = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;

		param_data = &scanEnable;
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
					result, param_data);

	DBG("-\n");
}

static int __bluetooth_get_default_name(char *default_dev_name, int size)
{
	/* Getting Phone name starts */
	int ret = 0;

	if (default_dev_name == NULL) {
		DBG("Invalid parameter");
		return -1;
	}
	ret = __bluetooth_internal_store_get_value(BT_SETTING_DEVICE_NAME,
				 BT_STORE_STRING, size,
				 (void *)default_dev_name);

	if (ret < 0) {
		DBG("get value fail: %d", ret);
		return -1;
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bluetooth_get_default_adapter_name(bluetooth_device_name_t *dev_name, int size) {
	int ret = 0;

	DBG("+");

	if (dev_name == NULL)
		return -1;

	ret = __bluetooth_get_default_name(dev_name->name, size);

	if (ret < 0) {
		DBG("Fail to get default name: %d", ret);
		return -1;
	}

	DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

void _bluetooth_internal_session_init(void)
{
	GError *err = NULL;
	const char *adapter_path = NULL;

	DBG("+\n");
	if (bt_info.application_pid == 0) {
		DBG("Not yet session initialized, so init session");
		g_type_init();
		bt_info.application_pid = getpid();

		bt_info.conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);
		if (!bt_info.conn) {
			AST("ERROR: Can't get on system bus [%s]", err->message);
			g_error_free(err);
			return;
		}

		bt_info.dbus_proxy = dbus_g_proxy_new_for_name(bt_info.conn,
							       DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
								DBUS_INTERFACE_DBUS);
		if (!bt_info.dbus_proxy) {
			AST("Could not create a dbus proxy");
		} else {
			dbus_g_proxy_add_signal(bt_info.dbus_proxy, "NameOwnerChanged",
						G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
						G_TYPE_INVALID);

			dbus_g_proxy_connect_signal(bt_info.dbus_proxy, "NameOwnerChanged",
						  G_CALLBACK(__bluetooth_internal_name_owner_changed),
							NULL, NULL);
		}

		bt_info.manager_proxy = dbus_g_proxy_new_for_name(bt_info.conn, BLUEZ_SERVICE_NAME,
							BLUEZ_MANAGER_OBJ_PATH, BLUEZ_MANAGER_INTERFACE);
		if (!bt_info.manager_proxy) {
			AST("Could not create a dbus proxy");
			return;
		}

		bt_info.agent_proxy = dbus_g_proxy_new_for_name(bt_info.conn,
								"org.bluez.frwk_agent",
								"/org/bluez/agent/frwk_agent",
								"org.bluez.Agent");
		if (!bt_info.agent_proxy) {
			AST("Could not create a agent dbus proxy");
		}

		dbus_g_proxy_add_signal(bt_info.manager_proxy, "AdapterAdded",
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(bt_info.manager_proxy, "AdapterAdded",
					    G_CALLBACK(__bluetooth_internal_adapter_added_cb), NULL,
						NULL);

		dbus_g_proxy_add_signal(bt_info.manager_proxy, "AdapterRemoved",
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(bt_info.manager_proxy, "AdapterRemoved",
					    G_CALLBACK(__bluetooth_internal_adapter_removed_cb),
						NULL, NULL);

		if (!dbus_g_proxy_call(bt_info.manager_proxy, "DefaultAdapter", &err,
				       G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
					G_TYPE_INVALID)) {
			if (err != NULL) {
				DBG("DefaultAdapter err:[%s]", err->message);
				g_error_free(err);
			}
			bt_info.bt_adapter_state = BLUETOOTH_ADAPTER_DISABLED;
		} else {
			if (adapter_path && strlen(adapter_path) < 50) {
				bt_info.bt_adapter_state = BLUETOOTH_ADAPTER_ENABLED;
				bluetooth_internal_set_adapter_path(adapter_path);
			} else {
				AST("Get default adapter, but there is error");
				return;
			}

		}

		DBG("Session inited : pid (%d)", bt_info.application_pid);
	}

	DBG("-\n");

}

void bluetooth_internal_session_deinit(void)
{
	DBG("+\n");

	if (bt_info.dbus_proxy != NULL) {
		dbus_g_proxy_disconnect_signal(bt_info.dbus_proxy, "NameOwnerChanged",
					       G_CALLBACK(__bluetooth_internal_name_owner_changed),
						NULL);

		g_object_unref(bt_info.dbus_proxy);
	} else {
		DBG("bt_info.dbus_proxy is NULL\n");
	}

	if (bt_info.manager_proxy != NULL) {
		dbus_g_proxy_disconnect_signal(bt_info.manager_proxy, "AdapterAdded",
					       G_CALLBACK(__bluetooth_internal_adapter_added_cb),
						NULL);

		dbus_g_proxy_disconnect_signal(bt_info.manager_proxy, "AdapterRemoved",
					       G_CALLBACK(__bluetooth_internal_adapter_removed_cb),
						NULL);

		g_object_unref(bt_info.manager_proxy);
	} else {
		DBG("bt_info.manager_proxy is NULL\n");
	}

	if (bt_info.agent_proxy) {
		g_object_unref(bt_info.agent_proxy);
	}

	if (bt_info.bt_change_state_timer) {
		g_source_remove(bt_info.bt_change_state_timer);
		bt_info.bt_change_state_timer = 0;
	}

	if (bt_info.bt_discovery_req_timer) {
		g_source_remove(bt_info.bt_discovery_req_timer);
		bt_info.bt_discovery_req_timer = 0;
	}

	if (bt_info.bt_bonding_req_timer) {
		g_source_remove(bt_info.bt_bonding_req_timer);
		bt_info.bt_bonding_req_timer = 0;
	}

	__bluetooth_internal_remove_signal();

	if (bt_info.conn) {
		dbus_g_connection_unref(bt_info.conn);
		bt_info.conn = NULL;
	}

	bt_info.application_pid = 0;

	DBG("-\n");
}

BT_EXPORT_API int bluetooth_is_supported(void)
{
	int is_supported = 0;
	int len = 0;
	int fd = -1;
	rfkill_event event;

	DBG("+\n");

        fd = open(RFKILL_NODE, O_RDONLY);
        if (fd < 0) {
		DBG("Fail to open RFKILL node");
		return BLUETOOTH_ERROR_INTERNAL;
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		DBG("Fail to set RFKILL node to non-blocking");
		close(fd);
		return BLUETOOTH_ERROR_INTERNAL;
        }

        while (1) {
                len = read(fd, &event, sizeof(event));
                if (len < 0) {
                        DBG("Fail to read events");
                        break;
                }

                if (len != RFKILL_EVENT_SIZE) {
                        DBG("The size is wrong\n");
                        continue;
                }

		if (event.type == RFKILL_TYPE_BLUETOOTH) {
			is_supported = 1;
			break;
		}
        }

        close(fd);

	DBG("supported: %d\n", is_supported);

	DBG("-\n");

	return is_supported;
}

BT_EXPORT_API int bluetooth_register_callback(bluetooth_cb_func_ptr callback_ptr, void *user_data)
{
	_bluetooth_internal_session_init();

	bt_info.bt_cb_ptr = callback_ptr;
	bt_info.user_data = user_data;

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_unregister_callback(void)
{
	bluetooth_internal_session_deinit();

	bt_info.bt_cb_ptr = NULL;

	return BLUETOOTH_ERROR_NONE;
}

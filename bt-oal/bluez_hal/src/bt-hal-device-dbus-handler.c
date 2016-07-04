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

static handle_stack_msg event_cb = NULL;

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

	DBG("Transport [%d] Add[0x%x] [0x%x][0x%x][0x%x][0x%x][0x%x]",
			transport, bd_addr->address[0], bd_addr->address[1],
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

	if (!event_cb)
		event_cb = _bt_hal_get_stack_message_handler();
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

	if (!event_cb)
		event_cb = _bt_hal_get_stack_message_handler();
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

	if (!event_cb)
		event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending HAL_EV_BOND_STATE_CHANGED event");
		event_cb(HAL_EV_BOND_STATE_CHANGED, (void*)&ev, sizeof(ev));
	}
	g_free(device_path);
	DBG("-");
}

static gboolean __bt_device_bonded_device_info_cb(gpointer user_data)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_HAL_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_remote_device_props *ev = (void*) buf;;
	size_t size = 0;

	GVariant *result = user_data;
	GVariantIter *property_iter;
	GVariantIter *char_value_iter;

	const gchar *address = NULL;
	const gchar *name = NULL;
	unsigned int cod = 0;
	gint rssi = 0;
	gboolean trust = FALSE;
	gboolean paired = FALSE;
	int connected = 0;
	GByteArray *manufacturer_data = NULL;
	const gchar *key;
	GVariant *value;
	guint8 char_value;
	unsigned int data_len = 0;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	g_variant_get(result, "(a{sv})", &property_iter);
	while (g_variant_iter_loop(property_iter, "{sv}", &key, &value)) {
		if(!g_strcmp0(key, "Address")) {
			address = g_variant_get_string(value, NULL);
			DBG("Address [%s]", address);
			_bt_convert_addr_string_to_type(ev->bdaddr, address);
		} else if (!g_strcmp0(key, "Alias")) {
			name = g_variant_get_string(value, NULL);
			DBG("Alias [%s]", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_FRIENDLY_NAME, strlen(name) + 1, name);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Class")) {
			cod = g_variant_get_uint32(value);
			DBG("Class [%d]", cod);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_CLASS, sizeof(unsigned int), &cod);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Connected")) {
			connected = g_variant_get_byte(value);
			DBG("Connected [%d]", connected);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_CONNECTED,
					sizeof(unsigned int), &connected);
			ev->num_props++;
		} else if (!g_strcmp0(key,"Paired")) {
			paired = g_variant_get_boolean(value);
			DBG("Paired [%d]", paired);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_PAIRED, sizeof(unsigned int), &paired);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Trusted")) {
			trust = g_variant_get_boolean(value);
			DBG("Trusted [%d]", trust);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_TRUSTED, sizeof(unsigned int), &trust);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Name")) {
			name = g_variant_get_string(value, NULL);
			DBG("Name [%s]", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_NAME, strlen(name) + 1, name);
			ev->num_props++;
		} else if (!g_strcmp0(key, "RSSI")) {
			rssi = g_variant_get_int16(value);
			DBG("RSSI [%d]", rssi);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_DEVICE_RSSI, sizeof(unsigned int), &rssi);
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
				uint8_t uuids[BT_HAL_STACK_UUID_SIZE * uuid_count];
				for (i = 0; uuid_value[i] != NULL; i++) {
					char *uuid_str = NULL;
					uint8_t uuid[BT_HAL_STACK_UUID_SIZE];
					memset(uuid, 0x00, BT_HAL_STACK_UUID_SIZE);
					uuid_str = g_strdup(uuid_value[i]);
					DBG("UUID string [%s]\n", uuid_str);
					_bt_convert_uuid_string_to_type(uuid, uuid_str);
					memcpy(uuids + i * BT_HAL_STACK_UUID_SIZE, uuid, BT_HAL_STACK_UUID_SIZE);
				}
				size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_UUIDS,
						(BT_HAL_STACK_UUID_SIZE * uuid_count), uuids);
				ev->num_props = num_props_tmp + 1;
				g_free(uuid_value);
			}
		} else if (!g_strcmp0(key, "ManufacturerDataLen")) {
			data_len = g_variant_get_uint16(value);
			DBG("ManufacturerDataLen [%d]", data_len);
		} else if (!g_strcmp0(key, "ManufacturerData")) {
			manufacturer_data = g_byte_array_new();
			g_variant_get(value, "ay", &char_value_iter);
			while(g_variant_iter_loop(char_value_iter, "y",  &char_value)) {
				g_byte_array_append(manufacturer_data, &char_value, 1);
			}

			if (manufacturer_data) {
				if (manufacturer_data->len > 0) {
					size += __bt_insert_hal_properties(
							buf + size, HAL_PROP_DEVICE_BLE_ADV_DATA,
							manufacturer_data->len, manufacturer_data->data);
					ev->num_props++;
				}
			}
			g_byte_array_free(manufacturer_data, FALSE);
		} else {
			ERR("Unhandled Property:[%s]", key);
		}
	}

	DBG("trust: %d, paired: %d", trust, paired);
	if (!event_cb)
		event_cb = _bt_hal_get_stack_message_handler();
	if (!event_cb) {
		ERR("event_cb is NULL");
		goto done;
	}

	if ((paired == FALSE) && (trust == FALSE)) {
		ev->status = BT_STATUS_FAIL;
		ev->num_props = 0;
		size = sizeof(*ev);
		DBG("Send Remote Device properties event to HAL,"
				" Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_REMOTE_DEVICE_PROPS, (void*) buf, size);
	} else {
		if (size > 2) {
			DBG("Send Remote Device properties event to HAL,"
				" Num Prop [%d] total size [%d]",ev->num_props, size);
			event_cb(HAL_EV_REMOTE_DEVICE_PROPS, (void*) buf, size);
		}
	}

done:
	g_variant_unref(result);
	return FALSE;
}

int _bt_hal_dbus_get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
	char *device_path = NULL;
	char address[BT_HAL_ADDRESS_STRING_SIZE] = { 0 };
	GError *error = NULL;
	GDBusProxy *device_proxy;
	GDBusConnection *conn;
	GVariant *result;

	if(!remote_addr) {
		ERR("Invalid device address ptr received");
		return BT_STATUS_PARM_INVALID;
	}

	_bt_convert_addr_type_to_string(address, remote_addr->address);
	device_path = _bt_get_device_object_path(address);
	if (!device_path) {
		ERR("Device not paired");
		return BT_STATUS_FAIL;
	}

	conn = _bt_get_system_gconn();
	if (!conn) {
		ERR("_bt_get_system_gconn failed");
		return BT_STATUS_FAIL;
	}

	device_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL,
			BT_HAL_BLUEZ_NAME,
			device_path,
			BT_HAL_PROPERTIES_INTERFACE,
			NULL, NULL);

	if (!device_proxy) {
		ERR("Error creating device_proxy");
		g_free(device_path);
		return BT_STATUS_FAIL;
	}

	result = g_dbus_proxy_call_sync(device_proxy,
			"GetAll",
			g_variant_new("(s)", BT_HAL_DEVICE_INTERFACE),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&error);

	if (!result) {
		ERR("Error occured in Proxy call");
		if (error != NULL) {
			ERR("Error occured in Proxy call (Error: %s)", error->message);
			g_clear_error(&error);
		}
		g_object_unref(device_proxy);
		g_free(device_path);
		return BT_STATUS_FAIL;
	}

	g_object_unref(device_proxy);
	g_free(device_path);
	/*
	 * As we need to provide async callback to user from HAL, simply schedule a
	 * callback method which will carry actual result
	 */
	g_idle_add(__bt_device_bonded_device_info_cb, (gpointer)result);

	DBG("-");
	return BT_STATUS_SUCCESS;
}

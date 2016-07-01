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

#include <glib.h>
#include <string.h>
#include <dlog.h>
#include <vconf.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <vconf.h>

/* BT HAL Headers */
#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-internal.h"
#include "bt-hal-event-receiver.h"
#include "bt-hal-dbus-common-utils.h"

#define BASELEN_PROP_CHANGED (sizeof(struct hal_ev_adapter_props_changed) \
		+ sizeof(struct hal_property))

/*TODO: Basic filters are currently added,
  Need to add different event filters like HID,
  Device etc in subsequent patches */

/* Global variables and structures */
static GDBusConnection *manager_conn;
static handle_stack_msg event_cb = NULL;
static guint event_id;

/* Forward declarations */
int __bt_hal_register_service_event(GDBusConnection *g_conn, int event_type);
static int __bt_hal_register_manager_subscribe_signal(GDBusConnection *conn, int subscribe);
static int __bt_hal_parse_event(GVariant *msg);
static int __bt_hal_get_owner_info(GVariant *msg, char **name, char **previous, char **current);
static void __bt_hal_adapter_property_changed_event(GVariant *msg);
void __bt_hal_handle_property_changed_event(GVariant *msg, const char *object_path);
static  void __bt_hal_manager_event_filter(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data);
static int __bt_hal_register_manager_subscribe_signal(GDBusConnection *conn, int subscribe);
int __bt_hal_register_service_event(GDBusConnection *g_conn, int event_type);
static int __bt_hal_initialize_manager_receiver(void);
static gboolean __bt_hal_parse_interface(GVariant *msg);
static void __bt_hal_handle_device_event(GVariant *value, GVariant *parameters);
static gboolean __bt_hal_parse_device_properties(GVariant *item);
static gboolean __bt_hal_discovery_finished_cb(gpointer user_data);
static void __bt_hal_device_property_changed_event(GVariant *msg, const char *path);
static void __bt_hal_dbus_device_found_properties(const char *device_path);
static void __bt_hal_device_properties_lookup(GVariant *result, char *address);

static gboolean __bt_hal_discovery_finished_cb(gpointer user_data)
{
	event_id = 0;
	DBG("+");
	struct hal_ev_discovery_state_changed ev;
	ev.state = HAL_DISCOVERY_STATE_STOPPED;
	event_cb(HAL_EV_DISCOVERY_STATE_CHANGED, &ev, sizeof(ev));
	DBG("-");

	return FALSE;
}

static int __bt_hal_parse_event(GVariant *msg)
{
	GVariantIter iter;
	GVariant *child;
	char *interface_name= NULL;
	GVariant *inner_iter = NULL;

	g_variant_iter_init(&iter, msg);

	while ((child = g_variant_iter_next_value(&iter))) {
		g_variant_get(child,"{&s@a{sv}}", &interface_name, &inner_iter);
		if (g_strcmp0(interface_name,
					BT_HAL_DEVICE_INTERFACE) == 0) {
			DBG("__bt_hal_parse_event: Interface: BT_HAL_DEVICE_INTERFACE");
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_HAL_DEVICE_EVENT;
		} else if (g_strcmp0(interface_name,
					BT_HAL_MEDIATRANSPORT_INTERFACE) == 0) {
			DBG("__bt_hal_parse_event: Interface: BT_HAL_MEDIATRANSPORT_INTERFACE");
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_HAL_MEDIA_TRANSFER_EVENT;
		} else if (g_strcmp0(interface_name,
					BT_HAL_PLAYER_CONTROL_INTERFACE) == 0) {
			DBG("__bt_hal_parse_event: Interface: BT_HAL_PLAYER_CONTROL_INTERFACE");
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_HAL_AVRCP_CONTROL_EVENT;
		}
		g_variant_unref(inner_iter);
		g_variant_unref(child);
	}

	return 0;
}

static int __bt_hal_get_owner_info(GVariant *msg, char **name, char **previous, char **current)
{
	g_variant_get(msg, "(sss)", name, previous, current);
	return BT_HAL_ERROR_NONE;
}

int __bt_insert_hal_properties(void *buf, uint8_t type, uint16_t len, const void *val)
{	struct hal_property *prop = buf;

	prop->type = type;
	prop->len = len;

	if (len)
		memcpy(prop->val, val, len);

	return sizeof(*prop) + len;
}

handle_stack_msg _bt_hal_get_stack_message_handler(void)
{
	return event_cb;
}

static void __bt_hal_adapter_property_changed_event(GVariant *msg)
{
	GVariantIter value_iter;
	GVariant *value = NULL;
	GDBusProxy *adapter_proxy;
	GError *err = NULL;
	char *key = NULL;
	g_variant_iter_init (&value_iter, msg);

	/* Buffer and propety count management */
	uint8_t buf[BT_HAL_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_adapter_props_changed *ev = (void*) buf;
	size_t size = 0;
	const gchar *address = NULL;
	gchar *name = NULL;
	unsigned int cod = 0;
	gboolean discoverable;
	gboolean connectable;
	unsigned int scan_mode = BT_SCAN_MODE_NONE;
	unsigned int disc_timeout;
	const gchar *version;
	const gboolean ipsp_initialized;
	gboolean powered;
	gboolean pairable;
	unsigned int pairable_timeout;
	gboolean scan_mode_property_update = FALSE;
	gboolean is_discovering;
        gboolean is_le_discovering;

	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;
	ev->status = BT_STATUS_SUCCESS;

	DBG("+");

	while (g_variant_iter_loop(&value_iter, "{sv}", &key, &value)) {
		if(!g_strcmp0(key, "Address")) {
			uint8_t bdaddr[6];

			address = g_variant_get_string(value, NULL);
			DBG("##Address [%s]", address);
			_bt_convert_addr_string_to_type(bdaddr, address);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_ADDR, sizeof(bdaddr), bdaddr);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Alias")) {
			g_variant_get(value, "s", &name);
			DBG("##Alias [%s] ", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_NAME, strlen(name) + 1, name);
			ev->num_props++;
			g_free(name);
		} else if (!g_strcmp0(key, "Class")) {
			cod = g_variant_get_uint32(value);
			DBG("##Class [%d]", cod);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_CLASS, sizeof(unsigned int), &cod);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Discoverable")) {
			discoverable = g_variant_get_boolean(value);
			DBG("##Discoverable [%d]", discoverable);
			if (discoverable)
				scan_mode = BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
			scan_mode_property_update = TRUE;
		} else if (!g_strcmp0(key, "DiscoverableTimeout")) {
			disc_timeout = g_variant_get_uint32(value);
			DBG("##Discoverable Timeout [%d]", disc_timeout);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_DISC_TIMEOUT, sizeof(unsigned int), &disc_timeout);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Connectable")) {
			connectable = g_variant_get_boolean(value);
			DBG("##Connectable [%d]", connectable);
			if (scan_mode == BT_SCAN_MODE_NONE)
				scan_mode = BT_SCAN_MODE_CONNECTABLE;
			scan_mode_property_update = TRUE;
		} else if (!g_strcmp0(key, "Version")) {
			version = g_variant_get_string(value, NULL);
			DBG("##Version [%s]", version);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_VERSION, strlen(version) + 1, version);
			ev->num_props++;
		} else if (!g_strcmp0(key, "Name")) {
			g_variant_get(value, "s", &name);
			DBG("##Name [%s]", name);
			size += __bt_insert_hal_properties(buf + size,
					HAL_PROP_ADAPTER_NAME, strlen(name) + 1, name);
			ev->num_props++;
			g_free(name);
		} else if (!g_strcmp0(key, "Powered")) {
			powered = g_variant_get_boolean(value);
			DBG("##Powered = %d", powered);
			/* TODO: Need to check this operation!! */
			if (powered == FALSE) {
				DBG("###### Adapter Powered Down ######");
				struct hal_ev_adapter_state_changed ev;
				ev.state = HAL_POWER_OFF;
				event_cb(HAL_EV_ADAPTER_STATE_CHANGED, &ev, sizeof(ev));
				/* Destroy Agent */
			} else {
				DBG("###### Adapter Powered Up ######");
				struct hal_ev_adapter_state_changed ev;
				ev.state = HAL_POWER_ON;
				event_cb(HAL_EV_ADAPTER_STATE_CHANGED, &ev, sizeof(ev));
				/* Create Agent */
			}

		} else if (!g_strcmp0(key, "Pairable")) {
			pairable = g_variant_get_boolean(value);
			DBG("##Pairable [%d]", pairable);
		} else if (!g_strcmp0(key, "PairableTimeout")) {
			pairable_timeout = g_variant_get_uint32(value);
			DBG("##Pairable Timeout = %d", pairable_timeout);
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
					uuid_str = g_strdup(uuid_value[i]);
					DBG("##UUID string [%s]\n", uuid_str);
					_bt_convert_uuid_string_to_type(uuid, uuid_str);
					memcpy(uuids+i*BT_HAL_STACK_UUID_SIZE, uuid, BT_HAL_STACK_UUID_SIZE);
				}
				size += __bt_insert_hal_properties(buf + size, HAL_PROP_ADAPTER_UUIDS,
						(BT_HAL_STACK_UUID_SIZE * uuid_count),
						uuids);
				ev->num_props = num_props_tmp + 1;
				g_free(uuid_value);
			}
		} else if (!g_strcmp0(key, "Discovering")) {
			is_discovering = g_variant_get_boolean(value);
			DBG("##Discovering = [%d]", is_discovering);

			if (is_discovering == FALSE) {
				DBG("###### Adapter Has stopped Discovering ######");
				/* In Tizen Bluez, this actually does not mean Discovery is stopped
				   in Bluez. Tizen Bluez sends this event after a certain timeout,
				   Therefore, we must forecefully call StopDiscovery to stop discovery in BlueZ */
				if (event_id > 0)
					continue;

				adapter_proxy = _bt_get_adapter_proxy();

				if (adapter_proxy == NULL)
					continue;

				/* Need to stop searching */
				DBG("Event though Bluez reported DIscovering stopped, we force stop Discovery ");
				g_dbus_proxy_call_sync(adapter_proxy, "StopDiscovery",
						NULL,
						G_DBUS_CALL_FLAGS_NONE,
						DBUS_TIMEOUT, NULL,
						&err);
				if (err) {
					ERR("Dbus Error : %s", err->message);

					/* This error is thrown by Bluez, as Discovery is already stopped.
					   Discovery is stopped if user cancels on going discovery.
					   In order to maintain correct state of Bluetooth Discovery state,
					   simply send Discovery stopped event to HAL user */
					struct hal_ev_discovery_state_changed ev;
					ev.state = HAL_DISCOVERY_STATE_STOPPED;
					event_cb(HAL_EV_DISCOVERY_STATE_CHANGED, &ev, sizeof(ev));
					g_clear_error(&err);
					continue;

				} else {
					event_id = g_timeout_add(BT_HAL_DISCOVERY_FINISHED_DELAY,
							(GSourceFunc)__bt_hal_discovery_finished_cb, NULL);
				}

			} else {
				DBG("###### Adapter Has started Discovering ######");
				struct hal_ev_discovery_state_changed ev;
				ev.state = HAL_DISCOVERY_STATE_STARTED;
				event_cb(HAL_EV_DISCOVERY_STATE_CHANGED, &ev, sizeof(ev));
			}

		} else if (!g_strcmp0(key, "LEDiscovering")) {
			is_le_discovering = g_variant_get_boolean(value);
			DBG("##LE Discovering = [%d]", is_le_discovering);
		} else if (!g_strcmp0(key, "Modalias")) {
			char *modalias = NULL;
			g_variant_get(value, "s", &modalias);
			DBG("##Adapter ModAlias [%s]", modalias);
		} else if (!g_strcmp0(key, "SupportedLEFeatures")) {
			DBG("##LE Supported features");
		} else if (!g_strcmp0(key, "IpspInitStateChanged")) {
			g_variant_get(value, "b" ,&ipsp_initialized);
			DBG("##IPSP Initialized = %d", ipsp_initialized);
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
		DBG("Send Adapter properties changed event to HAL user, Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_ADAPTER_PROPS_CHANGED, buf, size);
	}
	g_variant_unref(value);
	DBG("-");
}

static gboolean __bt_hal_parse_device_properties(GVariant *item)
{
	GVariantIter iter;
	gchar *key;
	GVariant *val;
	gsize len = 0;
	if (!item)
		return FALSE;
	DBG("+");

	/* Buffer and propety count management */
	uint8_t buf[BT_HAL_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_device_found *ev = (void *) buf;
	size_t size = 0;
	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;

	g_variant_iter_init(&iter, item);
	while (g_variant_iter_loop(&iter, "{sv}", &key, &val)) {

		if (strcasecmp(key, "Address") == 0)  {

			char * address = NULL;
			address = g_variant_dup_string(val, &len);
			uint8_t bdaddr[6];
			_bt_convert_addr_string_to_type(bdaddr, address);

			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_ADDR,
					sizeof(bdaddr), bdaddr);

			ev->num_props++;
			DBG("Device address [%s] property Num [%d]",address, ev->num_props);

		} else if (strcasecmp(key, "Class") == 0) {
			unsigned int class = g_variant_get_uint32(val);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_CLASS,
					sizeof(unsigned int), &class);
			ev->num_props++;
			DBG("Device class [%d] Property num [%d]", class, ev->num_props);
		} else if (strcasecmp(key, "name") == 0) {
			char *name = g_variant_dup_string(val, &len);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_NAME,
					strlen(name) + 1, name);
			ev->num_props++;
			DBG("Device Name [%s] Property num [%d]", name, ev->num_props);
		} else if (strcasecmp(key, "Connected") == 0) {
			unsigned int connected = g_variant_get_uint32(val);

			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_CONNECTED,
					sizeof(unsigned int), &connected);
			ev->num_props++;
			DBG("Device connected [%u] Property num [%d]", connected,  ev->num_props);
		} else if (strcasecmp(key, "paired") == 0) {
			gboolean paired = g_variant_get_boolean(val);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_PAIRED,
					sizeof(gboolean), &paired);
			ev->num_props++;
			DBG("Device Paired [%d] Property num [%d]", paired, ev->num_props);
		} else if (strcasecmp(key, "Trusted") == 0) {
			gboolean trust = g_variant_get_boolean(val);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_TRUSTED,
					sizeof(gboolean), &trust);
			ev->num_props++;
			DBG("Device trusted [%d] Property num [%d]", trust, ev->num_props);
		} else if (strcasecmp(key, "RSSI") == 0) {
			int rssi = g_variant_get_int16(val);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_RSSI,
					sizeof(int), &rssi);
			ev->num_props++;
			DBG("Device RSSI [%d] Property num [%d]", rssi, ev->num_props);
		} else if (strcasecmp(key, "LastAddrType") == 0) {
			/* TODO: To be handled later*/
		} else if (strcasecmp(key, "UUIDs") == 0) {
			char **uuid_value;
			int uuid_count = 0;
			gsize size1 = 0;
			int i =0;
			int z;
			size1 = g_variant_get_size(val);
			DBG("UUID count from size  [%d]\n", size1);
			int num_props_tmp = ev->num_props;

			if (size1 > 0) {
				uuid_value = (char **)g_variant_get_strv(val, &size1);
				for (i = 0; uuid_value[i] != NULL; i++)
					uuid_count++;
				DBG("UUID count [%d]\n", uuid_count);
				/* UUID collection */
				uint8_t uuids[BT_HAL_STACK_UUID_SIZE * uuid_count];

				for (i = 0; uuid_value[i] != NULL; i++) {

					char *uuid_str = NULL;
					uint8_t uuid[BT_HAL_STACK_UUID_SIZE];
					memset(uuid, 0x00, BT_HAL_STACK_UUID_SIZE);

					DBG("UUID string from Bluez [%s]\n", uuid_value[i]);
					uuid_str = g_strdup(uuid_value[i]);
					DBG("UUID string [%s]\n", uuid_str);
					_bt_convert_uuid_string_to_type(uuid, uuid_str);
					for(z=0; z < 16; z++)
						DBG("[0x%x]", uuid[z]);

					memcpy(uuids+i*BT_HAL_STACK_UUID_SIZE, uuid, BT_HAL_STACK_UUID_SIZE);
					g_free(uuid_str);
				}

				size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_UUIDS,
						(BT_HAL_STACK_UUID_SIZE * uuid_count),
						uuids);
				ev->num_props = num_props_tmp + 1;
				g_free(uuid_value);
			}

		} else if (strcasecmp(key, "ManufacturerDataLen") == 0) {
			/* TODO: To be handled later*/
		} else if (strcasecmp(key, "ManufacturerData") == 0) {

			/* TODO: To be handled later*/
		}
	}
	DBG("-");

	if (size > 1) {
		DBG("Send Device found event to HAL user, Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_DEVICE_FOUND, (void*) buf, size);
	}

	return TRUE;
}

void __bt_hal_handle_property_changed_event(GVariant *msg, const char *object_path)
{
	char *interface_name = NULL;
	GVariant *val = NULL;

	DBG("+");

	g_variant_get(msg, "(&s@a{sv}@as)", &interface_name, &val,NULL);

	if (strcasecmp(interface_name, BT_HAL_ADAPTER_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_ADAPTER_INTERFACE");
		__bt_hal_adapter_property_changed_event(val);
	} else if (strcasecmp(interface_name, BT_HAL_DEVICE_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_DEVICE_INTERFACE");
		__bt_hal_device_property_changed_event(val, object_path);
	} else if (strcasecmp(interface_name, BT_HAL_OBEX_TRANSFER_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_OBEX_TRANSFER_INTERFACE");
		/* TODO: Handle event */
	} else if (strcasecmp(interface_name, BT_HAL_MEDIA_CONTROL_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_MEDIA_CONTROL_INTERFACE");
		/* TODO: Handle event */
	} else if (strcasecmp(interface_name, BT_HAL_PLAYER_CONTROL_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_PLAYER_CONTROL_INTERFACE");
		/* TODO: Handle event */
	} else if (strcasecmp(interface_name, BT_HAL_NETWORK_CLIENT_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_NETWORK_CLIENT_INTERFACE");
		/* TODO: Handle event */
	} else if (strcasecmp(interface_name, BT_HAL_GATT_CHAR_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_GATT_CHAR_INTERFACE");
		/* TODO: Handle event */
	} else if (strcasecmp(interface_name, BT_HAL_INPUT_INTERFACE) == 0) {
		DBG("Event: Property Changed: Interface: BT_HAL_INPUT_INTERFACE");
	}
	g_variant_unref(val);

	DBG("-");
}

static void __bt_hal_handle_device_event(GVariant *value, GVariant *parameters)
{
	DBG("+");

	if (__bt_hal_parse_interface(parameters) == FALSE) {
		ERR("Fail to parse the properies");
		g_variant_unref(value);
		return;
	}

	DBG("-");
}

static gboolean __bt_hal_parse_interface(GVariant *msg)
{
	char *path = NULL;
	GVariant *optional_param;
	GVariantIter iter;
	GVariant *child;
	char *interface_name= NULL;
	GVariant *inner_iter = NULL;
	g_variant_get(msg, "(&o@a{sa{sv}})",
			&path, &optional_param);
	g_variant_iter_init(&iter, optional_param);

	while ((child = g_variant_iter_next_value(&iter))) {
		g_variant_get(child,"{&s@a{sv}}", &interface_name, &inner_iter);
		if (g_strcmp0(interface_name, BT_HAL_DEVICE_INTERFACE) == 0) {
			DBG("Found a device: %s", path);
			if (__bt_hal_parse_device_properties(inner_iter) == FALSE) {
				g_variant_unref(inner_iter);
				g_variant_unref(child);
				g_variant_unref(optional_param);
				ERR("Fail to parse the properies");
				return FALSE;
			} else {
				g_variant_unref(inner_iter);
				g_variant_unref(child);
				g_variant_unref(optional_param);
				return TRUE;
			}
		}
		g_variant_unref(inner_iter);
		g_variant_unref(child);
	}

	g_variant_unref(optional_param);

	return FALSE;
}

static  void __bt_hal_manager_event_filter(GDBusConnection *connection,
		const gchar *sender_name,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *signal_name,
		GVariant *parameters,
		gpointer user_data)
{
	bt_hal_event_type_t bt_event = 0x00;
	GVariant *value;
	char *obj_path = NULL;

	DBG("+");

	if (signal_name == NULL)
		return;

	if (strcasecmp(signal_name, "InterfacesAdded") == 0) {

		/*TODO: Handle Interfaces Added Signal from stack */
		DBG("Manager Event: Signal Name: InterfacesAdded");

		g_variant_get(parameters, "(&o@a{sa{sv}})", &obj_path, &value);

		if (strcasecmp(obj_path, BT_HAL_BLUEZ_HCI_PATH) == 0) {
			/* TODO: Handle adapter added */
			DBG("Manager Event: Signal Name: InterfiacesAdded: Adapter added in bluetoothd: path [hci0]");
		} else {
			bt_event = __bt_hal_parse_event(value);
			if (bt_event == BT_HAL_DEVICE_EVENT) {
				DBG("Device path : %s ", obj_path);
				__bt_hal_handle_device_event(value, parameters);
			} else if (bt_event == BT_HAL_AVRCP_CONTROL_EVENT) {
				/*TODO: Handle AVRCP control events from BlueZ */
			}
		}
		g_variant_unref(value);

	} else if (strcasecmp(signal_name, "InterfacesRemoved") == 0) {
		/*TODO: Handle Interfaces Removed Signal from stack */
		DBG("Manager Event: Signal Name: InterfacesRemoved");
	} else if (strcasecmp(signal_name, "NameOwnerChanged") == 0) {
		char *name = NULL;
		char *previous = NULL;
		char *current = NULL;

		/* TODO: Handle Name Owener changed Signal */
		DBG("Manager Event: Signal Name: NameOwnerChanged");

		if (__bt_hal_get_owner_info(parameters, &name, &previous, &current)) {
			DBG("Fail to get the owner info");
			return;
		}
		if (current && *current != '\0') {
			g_free(name);
			g_free(previous);
			g_free(current);
			return;
		}
		if (strcasecmp(name, BT_HAL_BLUEZ_NAME) == 0) {
			DBG("Bluetoothd is terminated");

			/* TODO: Handle Bluetoothd terminating scenario */
		}

		g_free(name);
		g_free(previous);
		g_free(current);

	} else if (g_strcmp0(interface_name, BT_HAL_PROPERTIES_INTERFACE) == 0) {
		DBG("Manager Event: Interface Name: BT_HAL_PROPERTIES_INTERFACE");
		__bt_hal_handle_property_changed_event(parameters, object_path);
	} else if (g_strcmp0(interface_name, BT_HAL_ADAPTER_INTERFACE) == 0) {
		/* TODO: Handle Adapter events from stack */
		DBG("Manager Event: Interface Name: BT_HAL_ADAPTER_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_INPUT_INTERFACE) == 0) {
		DBG("Manager Event: Interface Name: BT_HAL_INPUT_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_NETWORK_SERVER_INTERFACE) == 0) {
		/* TODO: Handle Network Server events from stack */
		DBG("Manager Event: Interface Name: BT_HAL_NETWORK_SERVER_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_HEADSET_INTERFACE) == 0) {
		DBG("Manager Event: Interface Name: BT_HAL_HEADSET_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_SINK_INTERFACE) == 0) {
		/* TODO: Handle Sink interface events from stack */
		DBG("Manager Event: Interface Name:BT_HAL_SINK_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_AGENT_INTERFACE) == 0) {
		/* TODO: Handle Agent events from stack */
		DBG("Manager Event: Interface Name:BT_HAL_AGENT_INTERFACE");
	} else if (g_strcmp0(interface_name, BT_HAL_DEVICE_INTERFACE) == 0) {
		DBG("Manager Event: Interface Name:BT_HAL_DEVICE_INTERFACE");
	}

	DBG("-");
	return;
}

static int __bt_hal_register_manager_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_interface_added_id = -1;
	static int subs_interface_removed_id = -1;
	static int subs_name_owner_id = -1;
	static int subs_property_id = -1;
	static int subs_adapter_id = -1;

	INFO_C("+");

	if (subscribe) {
		if (subs_interface_added_id == -1) {
			subs_interface_added_id = g_dbus_connection_signal_subscribe(conn,
					NULL, BT_HAL_MANAGER_INTERFACE,
					BT_HAL_INTERFACES_ADDED, NULL, NULL, 0,
					__bt_hal_manager_event_filter,
					NULL, NULL);
		}
		if (subs_interface_removed_id == -1) {
			subs_interface_removed_id = g_dbus_connection_signal_subscribe(conn,
					NULL, BT_HAL_MANAGER_INTERFACE,
					BT_HAL_INTERFACES_REMOVED, NULL, NULL, 0,
					__bt_hal_manager_event_filter,
					NULL, NULL);
		}
		if (subs_name_owner_id == -1) {
			subs_name_owner_id = g_dbus_connection_signal_subscribe(conn,
					NULL, BT_HAL_FREEDESKTOP_INTERFACE,
					BT_HAL_NAME_OWNER_CHANGED, NULL, NULL, 0,
					__bt_hal_manager_event_filter,
					NULL, NULL);
		}
		if (subs_property_id == -1) {
			subs_property_id = g_dbus_connection_signal_subscribe(conn,
					NULL, BT_HAL_PROPERTIES_INTERFACE,
					BT_HAL_PROPERTIES_CHANGED, NULL, NULL, 0,
					__bt_hal_manager_event_filter,
					NULL, NULL);
		}
		if (subs_adapter_id == -1) {
			subs_adapter_id = g_dbus_connection_signal_subscribe(conn,
					NULL, BT_HAL_ADAPTER_INTERFACE,
					NULL, NULL, NULL, 0,
					__bt_hal_manager_event_filter,
					NULL, NULL);
		}
	} else {
		if (subs_interface_added_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_interface_added_id);
			subs_interface_added_id = -1;
		}
		if (subs_interface_removed_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_interface_removed_id);
			subs_interface_removed_id = -1;
		}
		if (subs_name_owner_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_name_owner_id);
			subs_name_owner_id = -1;
		}
		if (subs_property_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_property_id);
			subs_property_id = -1;
		}
		if (subs_adapter_id == -1) {
			g_dbus_connection_signal_unsubscribe(conn, subs_adapter_id);
			subs_adapter_id = -1;
		}
	}

	INFO_C("-");
	return 0;
}

int __bt_hal_register_service_event(GDBusConnection *g_conn, int event_type)
{
	DBG("+");

	if (g_conn == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	/* TODO: Add more events in subsequent patches */
	switch (event_type) {
		case BT_HAL_MANAGER_EVENT:
			__bt_hal_register_manager_subscribe_signal(g_conn, TRUE);
			break;
		default:
			INFO_C("Register Event: event_type [%d]", event_type);
			return BT_HAL_ERROR_NOT_SUPPORT;
	}

	return BT_HAL_ERROR_NONE;
}

static int __bt_hal_initialize_manager_receiver(void)
{
	DBG("+");

	GError *error = NULL;

	if (manager_conn == NULL) {
		manager_conn =  g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error != NULL) {
			ERR_C("ERROR: Can't get on system bus [%s]", error->message);
			g_clear_error(&error);
		}
		if (manager_conn == NULL)
			goto fail;
	}

	if (__bt_hal_register_service_event(manager_conn,
				BT_HAL_MANAGER_EVENT) != BT_HAL_ERROR_NONE)
		goto fail;

	return BT_HAL_ERROR_NONE;
fail:
	if (manager_conn) {
		g_object_unref(manager_conn);
		manager_conn = NULL;
	}

	DBG("-");

	return BT_HAL_ERROR_INTERNAL;
}

/* To receive the event from bluez */
int _bt_hal_initialize_event_receiver(handle_stack_msg cb)
{
	int result;
	DBG("+");

	if (!cb)
		return BT_HAL_ERROR_INVALID_PARAM;

	result = __bt_hal_initialize_manager_receiver();

	DBG("Manager event receiver initialization result [%d]", result);
	if (result != BT_HAL_ERROR_NONE)
		return result;

	/*TODO: Initialize Obexd Event receiver */

	event_cb = cb;
	DBG("-");

	return BT_HAL_ERROR_NONE;
}

static void __bt_hal_device_property_changed_event(GVariant *msg, const char *path)
{
       GVariantIter value_iter;
       GVariant *value = NULL;
       char *key = NULL;
       g_variant_iter_init (&value_iter, msg);
       DBG("+");

       while (g_variant_iter_loop(&value_iter, "{sv}", &key, &value)) {
               if(!g_strcmp0(key, "Connected")) {
                       guint connected = 0;
                       g_variant_get(value, "i", &connected);
                       DBG("Device property changed : Connected [%d]", connected);
               } else if (!g_strcmp0(key, "RSSI")) {
                       DBG("Device property changed : RSSI");
                       __bt_hal_dbus_device_found_properties(path);
               } else if (!g_strcmp0(key, "GattConnected")) {
                       DBG("Device property changed : GattConnected");
               } else if (!g_strcmp0(key, "Paired")) {
                       DBG("Device property changed : Paired");
               } else if (!g_strcmp0(key, "LegacyPaired")) {
                       DBG("Device property changed : LegacyPaired");
               } else if (!g_strcmp0(key, "Trusted")) {
                       DBG("Device property changed : Trusted");
               } else if (!g_strcmp0(key, "IpspConnected")) {
                       DBG("Device property changed : IpspConnected");
               } else if (!g_strcmp0(key, "IpspInitStateChanged")) {
                       DBG("Device property changed : IpspInitStateChanged");
               } else {
                       ERR("Unhandled Property:[%s]", key);
               }
       }
       DBG("-");
}

static void __bt_hal_dbus_device_found_properties(const char *device_path)
{
       char *address;
       GError *error = NULL;
       GDBusProxy *device_proxy;
       GDBusConnection *conn;
       GVariant *result;
       DBG("+");

       if(!device_path) {
               ERR("Invalid device path");
               return;
       }

       conn = _bt_get_system_gconn();
       if (!conn) {
               ERR("_bt_get_system_gconn failed");
               return;
       }

       device_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
                       NULL,
                       BT_HAL_BLUEZ_NAME,
                       device_path,
                       BT_HAL_PROPERTIES_INTERFACE,
                       NULL, NULL);

       if (!device_proxy) {
               ERR("Error creating device_proxy");
               return;
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
               return;
       }

       address = g_malloc0(BT_HAL_ADDRESS_STRING_SIZE);
       _bt_convert_device_path_to_address(device_path, address);

       __bt_hal_device_properties_lookup(result, address);

       g_object_unref(device_proxy);
       g_free(address);

       DBG("-");
}

static void __bt_hal_device_properties_lookup(GVariant *result, char *address)
{
	/* Buffer and propety count management */
	uint8_t buf[BT_HAL_MAX_PROPERTY_BUF_SIZE];
	struct hal_ev_device_found *ev = (void *) buf;
	size_t size = 0;
	memset(buf, 0, sizeof(buf));
	size = sizeof(*ev);
	ev->num_props = 0;

	GVariant *tmp_value;
	GVariant *value;
	gchar *name;
	gchar *manufacturer_data = NULL;
	DBG("+");

	if (result != NULL) {
		g_variant_get(result , "(@a{sv})", &value);
		g_variant_unref(result);

		/* Alias */
		tmp_value = g_variant_lookup_value (value, "Alias", G_VARIANT_TYPE_STRING);

		g_variant_get(tmp_value, "s", &name);

		g_variant_unref(tmp_value);
		if (name != NULL) {
			DBG_SECURE("Alias Name [%s]", name);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_NAME,
					strlen(name) + 1, name);
			ev->num_props++;
			DBG("Device Name [%s] Property num [%d]", name, ev->num_props);
		} else {
			/* Name */
			tmp_value = g_variant_lookup_value(value, "Name", G_VARIANT_TYPE_STRING);
			g_variant_unref(tmp_value);
			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_NAME,
					strlen(name) + 1, name);
			ev->num_props++;
			DBG("Device Name [%s] Property num [%d]", name, ev->num_props);
			g_variant_get(tmp_value, "s", &name);
		}

		/* Class */
		tmp_value = g_variant_lookup_value(value, "Class", G_VARIANT_TYPE_UINT32);
		unsigned int class = tmp_value ? g_variant_get_uint32(tmp_value) : 0;
		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_CLASS,
				sizeof(unsigned int), &class);
		ev->num_props++;
		g_variant_unref(tmp_value);


		/* Connected */
		tmp_value = g_variant_lookup_value(value, "Connected",  G_VARIANT_TYPE_BOOLEAN);
		unsigned int connected = tmp_value ? g_variant_get_boolean(tmp_value) : 0;
		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_CONNECTED,
				sizeof(unsigned int), &connected);
		ev->num_props++;
		DBG("Device connected [%u] Property num [%d]", connected,  ev->num_props);
		g_variant_unref(tmp_value);

		/* Trust */
		tmp_value = g_variant_lookup_value(value, "Trusted",  G_VARIANT_TYPE_BOOLEAN);
		gboolean trust = tmp_value ? g_variant_get_boolean(tmp_value) : FALSE;
		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_TRUSTED,
				sizeof(gboolean), &trust);
		ev->num_props++;
		DBG("Device trusted [%d] Property num [%d]", trust, ev->num_props);
		g_variant_unref(tmp_value);

		/* Paired */
		tmp_value = g_variant_lookup_value(value, "Paired",  G_VARIANT_TYPE_BOOLEAN);
		gboolean paired = tmp_value ? g_variant_get_boolean(tmp_value) : FALSE;

		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_PAIRED,
				sizeof(gboolean), &paired);
		ev->num_props++;
		DBG("Device Paired [%d] Property num [%d]", paired, ev->num_props);
		g_variant_unref(tmp_value);

		/* RSSI*/
		tmp_value = g_variant_lookup_value(value, "RSSI", G_VARIANT_TYPE_INT32);
		int rssi = tmp_value ? g_variant_get_int32(tmp_value) : 0;
		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_RSSI,
				sizeof(int), &rssi);
		ev->num_props++;
		DBG("Device RSSI [%d] Property num [%d]", rssi, ev->num_props);
		g_variant_unref(tmp_value);

		/* Last Addr Type */
		tmp_value = g_variant_lookup_value(value, "LastAddrType", G_VARIANT_TYPE_UINT32);
		unsigned int addr_type = tmp_value ? g_variant_get_uint32(tmp_value) : 0;
		g_variant_unref(tmp_value);
		DBG("Device Last Address Type [0x%x]", addr_type);

		/* UUID's */
		tmp_value = g_variant_lookup_value(value, "UUIDs", G_VARIANT_TYPE_STRING_ARRAY);
		gsize uuid_count = g_variant_get_size(tmp_value);
		char **uuid_value = g_variant_dup_strv(tmp_value, &uuid_count);
		{
			/* UUID collection */
			int i;
			int z;
			int num_props_tmp = ev->num_props;

			uint8_t uuids[BT_HAL_STACK_UUID_SIZE * uuid_count];

			for (i = 0; uuid_value[i] != NULL; i++) {

				char *uuid_str = NULL;
				uint8_t uuid[BT_HAL_STACK_UUID_SIZE];
				memset(uuid, 0x00, BT_HAL_STACK_UUID_SIZE);

				DBG("UUID string from Bluez [%s]\n", uuid_value[i]);
				uuid_str = g_strdup(uuid_value[i]);
				DBG("UUID string [%s]\n", uuid_str);

				_bt_convert_uuid_string_to_type(uuid, uuid_str);

				for(z=0; z < 16; z++)
					DBG("[0x%x]", uuid[z]);

				memcpy(uuids+i*BT_HAL_STACK_UUID_SIZE, uuid, BT_HAL_STACK_UUID_SIZE);
				g_free(uuid_str);
			}

			size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_UUIDS,
					(BT_HAL_STACK_UUID_SIZE * uuid_count),
					uuids);
			ev->num_props = num_props_tmp + 1;
			g_free(uuid_value);
		}
		g_variant_unref(tmp_value);

		/* ManufacturerDataLen */
		tmp_value = g_variant_lookup_value(value, "ManufacturerDataLen", G_VARIANT_TYPE_UINT32);
		unsigned int manufacturer_data_len = tmp_value ? g_variant_get_uint32(tmp_value) : 0;
		if (manufacturer_data_len > BT_HAL_MANUFACTURER_DATA_LENGTH_MAX) {
			ERR("manufacturer_data_len is too long(len = %d)", manufacturer_data_len);
			manufacturer_data_len = BT_HAL_MANUFACTURER_DATA_LENGTH_MAX;
		}
		g_variant_unref(tmp_value);
		/*size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_MANUFACTURER_DATA_LEN,
		  sizeof(unsigned int), &manufacturer_data_len);
		  ev->num_props++;*/
		DBG("Device Manufacturer data length [%u]", manufacturer_data_len);

		/* ManufacturerData */
		tmp_value = g_variant_lookup_value(value, "ManufacturerData", G_VARIANT_TYPE_BYTESTRING);
		manufacturer_data = value ? (gchar *)g_variant_get_bytestring(tmp_value) : NULL;
		if (manufacturer_data) {
			if (manufacturer_data_len > 0) {
				//size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_MANUFACTURER_DATA,
				size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_BLE_ADV_DATA,
						manufacturer_data_len, manufacturer_data);
				ev->num_props++;
			}
		}
		g_variant_unref(tmp_value);

		/* Address */
		uint8_t bdaddr[6];
		_bt_convert_addr_string_to_type(bdaddr, address);
		size += __bt_insert_hal_properties(buf + size, HAL_PROP_DEVICE_ADDR,
				sizeof(bdaddr), bdaddr);
		ev->num_props++;
		DBG("Device address [%s] property Num [%d]",address, ev->num_props);

		g_free(name);
		g_variant_unref(value);
	} else {
		ERR("result  is NULL\n");
	}
	if (size > 1) {
		DBG("Send Device found event to HAL user, Num Prop [%d] total size [%d]",ev->num_props, size);
		event_cb(HAL_EV_DEVICE_FOUND, (void*) buf, size);
	}
	DBG("-");
}

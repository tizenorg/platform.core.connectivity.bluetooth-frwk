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
		} else if (!g_strcmp0(key, "LEDiscovering")) {
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
				/*TODO: Handle device events from BlueZ */
				DBG("Device path : %s ", obj_path);
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

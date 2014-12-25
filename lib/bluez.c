/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
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

#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>
#include "common.h"
#include "bluez.h"

#define BLUEZ_NAME "org.bluez"
#define OBJECT_MANAGE_PATH "/"
#define ADAPTER_INTERFACE "org.bluez.Adapter1"
#define MEDIA_INTERFACE "org.bluez.Media1"
#define MEDIATRANSPORT_INTERFACE "org.bluez.MediaTransport1"
#define MEDIACONTROL_INTERFACE "org.bluez.MediaControl1"
#define DEVICE_INTERFACE "org.bluez.Device1"
#define NETWORK_INTERFACE "org.bluez.Network1"
#define NETWORKSERVER_INTERFACES "org.bluez.NetworkServer1"
#define INPUT_INTERFACE "org.bluez.Input1"
#define AGENT_INTERFACE "org.bluez.AgentManager1"
#define PROFILE_INTERFACE "org.bluez.ProfileManager1"
#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"
#define GATT_SERVICE_IFACE "org.bluez.GattService1"
#define GATT_CHR_IFACE "org.bluez.GattCharacteristic1"
#define GATT_DESCRIPTOR_IFACE "org.bluez.GattDescriptor1"

#define CONNMAN_DBUS_NAME "net.connman"
#define CONNMAN_BLUETOOTH_TECHNOLOGY_PATH "/net/connman/technology/bluetooth"
#define CONNMAN_BLUETOTOH_TECHNOLOGY_INTERFACE "net.connman.Technology"

#define BT_MEDIA_OBJECT_PATH "/Musicplayer"
#define MEDIA_PLAYER_INTERFACE  "org.mpris.MediaPlayer2.Player"

GDBusObjectManager *object_manager = NULL;

struct player_settinngs_t {
	int key;
	const char *property;
};

static struct player_settinngs_t loopstatus_settings[] = {
	{ REPEAT_INVALID, "" },
	{ REPEAT_MODE_OFF, "None" },
	{ REPEAT_SINGLE_TRACK, "Track" },
	{ REPEAT_ALL_TRACK, "Playlist" },
	{ REPEAT_INVALID, "" }
};

static struct player_settinngs_t playback_status[] = {
	{ STATUS_STOPPED, "Stopped" },
	{ STATUS_PLAYING, "Playing" },
	{ STATUS_PAUSED, "Paused" },
	{ STATUS_INVALID, "" }
};

static struct player_settinngs_t shuffle_settings[] = {
	{ SHUFFLE_INVALID, "" },
	{ SHUFFLE_MODE_OFF, "off" },
	{ SHUFFLE_ALL_TRACK, "alltracks" },
	{ SHUFFLE_INVALID, "" }
};

struct _bluez_object {
	char *path_name;
	enum audio_profile_type media_type;
	GDBusObject *obj;
	GList *interfaces;
	GDBusProxy *properties_proxy;
};

struct _bluez_adpater;

struct _device_head {
	char *adapter_path;
	struct _bluez_adapter *adapter;
	GHashTable *device_hash;
};

struct _gatt_service_head {
	char *device_path;
	struct _bluez_device *device;
	GHashTable *gatt_service_hash;
};

struct _gatt_char_head {
	char *gatt_service_path;
	struct _bluez_gatt_service *service;
	GHashTable *gatt_char_hash;
};

struct _gatt_desc_head {
	char *gatt_char_path;
	struct _bluez_gatt_char *characteristic;
	GHashTable *gatt_desc_hash;
};

struct _bluez_adapter {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusInterface *media_interface;
	GDBusInterface *netserver_interface;
	guint avrcp_registration_id;
	GDBusProxy *proxy;
	GDBusProxy *media_proxy;
	GDBusProxy *netserver_proxy;
	GDBusProxy *property_proxy;
	struct _bluez_object *parent;
	struct _device_head *device_head;
	bluez_adapter_powered_cb_t powered_cb;
	gpointer powered_cb_data;
	bluez_adapter_device_cb_t device_created_cb;
	gpointer device_created_data;
	bluez_adapter_device_cb_t device_removed_cb;
	gpointer device_removed_data;
	bluez_adapter_alias_cb_t alias_cb;
	gpointer alias_cb_data;
	bluez_adapter_discovering_cb_t discovering_cb;
	gpointer discovering_cb_data;
	bluez_adapter_discoverable_cb_t discoverable_cb;
	gpointer discoverable_cb_data;
	bluez_adapter_discoverable_tm_cb_t discoverable_timeout_cb;
	gpointer discoverable_timeout_cb_data;
};

struct _bluez_agent {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _bluez_object *parent;
};

struct _bluez_profile {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _bluez_object *parent;
};

struct _bluez_device {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusInterface *control_interface;
	GDBusInterface *network_interface;
	GDBusInterface *input_interface;
	GDBusInterface *hdp_interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
	GDBusProxy *control_proxy;
	GDBusProxy *network_proxy;
	GDBusProxy *input_proxy;
	GDBusProxy *hdp_proxy;
	struct _bluez_object *parent;
	struct _device_head *head;
	struct _gatt_service_head *service_head;

	bluez_device_paired_cb_t device_paired_cb;
	gpointer device_paired_cb_data;
	bluez_device_connected_cb_t device_connected_cb;
	gpointer device_connected_cb_data;
	bluez_device_trusted_cb_t device_trusted_cb;
	gpointer device_trusted_cb_data;
	bluez_device_network_connected_cb_t network_connected_cb;
	gpointer network_connected_cb_data;
	bluez_hdp_state_changed_t hdp_state_changed_cb;
	gpointer hdp_state_changed_cb_data;
	bluez_set_data_received_changed_t data_received_changed_cb;
	gpointer data_received_changed_data;
	bluez_device_input_connected_cb_t input_connected_cb;
	gpointer input_connected_cb_data;

	adapter_device_discovery_info_t *device_discovery_info;
};

struct _bluez_gatt_service {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
	struct _bluez_object *parent;
	struct _gatt_service_head *head;
	struct _gatt_char_head *char_head;
};

struct _bluez_gatt_char {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
	struct _bluez_object *parent;
	struct _gatt_char_head *head;
	struct _gatt_desc_head *desc_head;
	bluez_gatt_char_value_changed_cb_t value_changed_cb;
	gpointer value_changed_cb_data;
};

struct _bluez_gatt_desc {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
	struct _bluez_object *parent;
	struct _gatt_desc_head *head;
};

static GHashTable *bluez_object_hash;

static GList *bluez_adapter_list;

static GHashTable *bluez_adapter_hash;

static GHashTable *bluez_device_hash;

static GHashTable *bluez_gatt_service_hash;

static GHashTable *bluez_gatt_char_hash;

static GHashTable *bluez_gatt_desc_hash;

static bluez_adapter_added_cb_t adapter_added_cb;
static gpointer adapter_added_cb_data;
static bluez_agent_added_cb_t agent_added_cb;
static gpointer agent_added_cb_data;
static bluez_avrcp_target_cb_t avrcp_target_cb;
static gpointer avrcp_target_cb_data;
static bluez_avrcp_shuffle_cb_t avrcp_shuffle_cb;
static gpointer avrcp_shuffle_cb_data;
static bluez_avrcp_repeat_cb_t avrcp_repeat_cb;
static gpointer avrcp_repeat_cb_data;
static bluez_audio_state_cb_t audio_state_cb;
static gpointer audio_state_cb_data;
static bluez_nap_connection_state_cb_t nap_connnection_state_cb;
static gpointer nap_connnection_state_cb_data;
static device_connect_cb_t dev_connect_cb;
static gpointer dev_connect_data;
static device_disconnect_cb_t dev_disconnect_cb;
static gpointer dev_disconnect_data;
static char_read_value_cb_t char_read_calue_cb;
static gpointer char_read_data;
static char_write_value_cb_t char_write_calue_cb;
static gpointer char_write_data;
static bluez_paired_cb_t device_paired_cb;
static gpointer device_paired_cb_data;

struct gatt_char_read_notify {
	struct _bluez_gatt_char *characteristic;
	char_read_value_cb_t cb;
};

struct gatt_char_write_notify {
	struct _bluez_gatt_char *characteristic;
	char_write_value_cb_t cb;
};
static void free_discovery_device_info(
		adapter_device_discovery_info_t *discovery_device_info)
{
	int i;

	if (discovery_device_info == NULL)
		return;

	if (discovery_device_info->remote_address)
		g_free(discovery_device_info->remote_address);

	if (discovery_device_info->remote_name)
		g_free(discovery_device_info->remote_name);

	for (i = 0; i < discovery_device_info->service_count; ++i)
		g_free(discovery_device_info->service_uuid[i]);

	if (discovery_device_info->service_uuid)
		g_free(discovery_device_info->service_uuid);

	g_free(discovery_device_info);
}

static void update_device_discovery_info(GVariant *changed_properties,
		adapter_device_discovery_info_t *device_info)
{
	gchar *remote_address, *remote_name;
	gint16 rssi;
	gboolean paired;
	guint32 class;
	char **uuids;

	if (device_info == NULL)
		return;

	DBG("+");

	if (g_variant_lookup(changed_properties, "Address",
					"s", &remote_address)) {
		if (device_info->remote_address)
			g_free(device_info->remote_address);
		device_info->remote_address = remote_address;
	}

	if (g_variant_lookup(changed_properties, "Alias",
					"s", &remote_name)) {
		if (device_info->remote_name)
			g_free(device_info->remote_name);
		device_info->remote_name = remote_name;
	}

	if (g_variant_lookup(changed_properties, "RSSI",
					"n", &rssi))
		device_info->rssi = rssi;

	if (g_variant_lookup(changed_properties, "Paired",
						"b", &paired))
		device_info->is_bonded = paired;

	if (g_variant_lookup(changed_properties, "UUIDs",
						"ss", &uuids)) {
		int i;

		for (i = 0; i < device_info->service_count; i++)
			g_free(device_info->service_uuid[i]);

		g_free(device_info->service_uuid);

		device_info->service_uuid = uuids;
		device_info->service_count = g_strv_length(uuids);
	}

	if (g_variant_lookup(changed_properties, "Class",
						"u", &class))
		device_info->bt_class = class;

	DBG("-");
}

static adapter_device_discovery_info_t *get_discovery_device_info(
						bluez_device_t *device)
{
	guint len;
	signed short rssi;
	int paired;
	char *alias, *address;
	char **uuids;
	unsigned int class;
	guint16 appearance = 0x00;
	adapter_device_discovery_info_t *device_info;

	DBG("");

	if (device == NULL)
		return NULL;

	device_info = g_new0(adapter_device_discovery_info_t, 1);
	if (device_info == NULL) {
		ERROR("no memory.");
		return NULL;
	}

	address = bluez_device_get_property_address(device);
	alias = bluez_device_get_property_alias(device);
	uuids = bluez_device_get_property_uuids(device);
	bluez_device_get_property_class(device, &class);
	bluez_device_get_property_rssi(device, &rssi);
	bluez_device_get_property_paired(device, &paired);
	bluez_device_get_property_appearance(device, &appearance);

	len = g_strv_length(uuids);

	device_info->service_count = len;
	device_info->remote_address = address;
	device_info->remote_name = alias;
	device_info->rssi = rssi;
	device_info->is_bonded = paired;
	device_info->service_uuid = uuids;
	device_info->appearance = convert_appearance_to_type(appearance);

	device_info->bt_class = class;

	return device_info;
}

adapter_device_discovery_info_t *bluez_get_discovery_device_info(
					bluez_device_t *device)
{
	if (device)
		return device->device_discovery_info;

	return NULL;
}

static struct _bluez_object *get_object_from_path(const char *path)
{
	return g_hash_table_lookup(bluez_object_hash, (gpointer) path);
}

static struct _bluez_object *create_object(GDBusObject *obj)
{
	GDBusProxy *properties_proxy;
	struct _bluez_object *object;
	const char *path = g_dbus_object_get_object_path(obj);

	DBG("object 0x%p, object path %s", obj, path);

	object = g_try_new0(struct _bluez_object, 1);
	if (object == NULL) {
		ERROR("no memeory");
		return NULL;
	}

	object->obj = g_object_ref(obj);

	properties_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);
	if (properties_proxy == NULL) {
		g_free(object);
		ERROR("create properties proxy error");
		return NULL;
	}

	object->properties_proxy = properties_proxy;
	object->path_name = g_strdup(path);

	return object;
}

static void handle_adapter_powered_changed(GVariant *changed_properties,
						struct _bluez_adapter *adapter)
{
	gboolean powered, variant_found;

	variant_found = g_variant_lookup(changed_properties,
					"Powered",
					"b",
					&powered);
	if (!variant_found)
		return;

	adapter->powered_cb(adapter,
				powered,
				adapter->powered_cb_data);
}

static void handle_adapter_alias_changed(GVariant *changed_properties,
						struct _bluez_adapter *adapter)
{
	gchar *alias = NULL;
	gboolean variant_found = g_variant_lookup(changed_properties,
							"Alias", "s", &alias);
	if (!variant_found)
		return;

	adapter->alias_cb(adapter,
			alias,
			adapter->alias_cb_data);

	g_free(alias);
}

static void handle_adapter_discovering_changed(GVariant *changed_properties,
						struct _bluez_adapter *adapter)
{
	gboolean discovering;
	gboolean variant_found = g_variant_lookup(changed_properties,
					"Discovering", "b", &discovering);
	if (!variant_found)
		return;

	adapter->discovering_cb(adapter,
			discovering,
			adapter->discovering_cb_data);
}

static void handle_adapter_discoverable_changed(GVariant *changed_properties,
						struct _bluez_adapter *adapter)
{
	gboolean discoverable;
	gboolean variant_found = g_variant_lookup(changed_properties,
					"Discoverable", "b", &discoverable);
	if (!variant_found)
		return;

	adapter->discoverable_cb(adapter,
			discoverable,
			adapter->discoverable_cb_data);
}

static void handle_adapter_discoverable_timeout_changed(
					GVariant *changed_properties,
					struct _bluez_adapter *adapter)
{
	guint32 timeout;
	gboolean variant_found;

	variant_found = g_variant_lookup(changed_properties,
					"DiscoverableTimeout", "u", &timeout);
	if (!variant_found)
		return;

	adapter->discoverable_timeout_cb(adapter, timeout,
				adapter->discoverable_timeout_cb_data);
}

static void networkserver_on_signal(GDBusProxy *proxy,
					gchar *sender_name,
					gchar *signal_name,
					GVariant *param,
					gpointer user_data)
{
	gboolean connected;
	gchar *device = NULL, *address =  NULL;

	DBG("sender_name = %s, signal_name = %s",
				sender_name, signal_name);
	if (strcasecmp(signal_name, "PeerConnected"))
		connected = TRUE;
	else if (strcasecmp(signal_name, "PeerDisconnected"))
		connected = FALSE;
	else
		return;

	g_variant_get(param, "(ss)", &device, &address);

	if (nap_connnection_state_cb)
		nap_connnection_state_cb(connected,
			address, device,
			nap_connnection_state_cb_data);

	g_free(device);
	g_free(address);
}

static void adapter_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	struct _bluez_adapter *adapter = user_data;
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);
	if (adapter->powered_cb)
		handle_adapter_powered_changed(changed_properties, user_data);

	if (adapter->alias_cb)
		handle_adapter_alias_changed(changed_properties, user_data);

	if (adapter->discovering_cb)
		handle_adapter_discovering_changed(changed_properties,
								user_data);

	if (adapter->discoverable_cb)
		handle_adapter_discoverable_changed(changed_properties,
								user_data);

	if (adapter->discoverable_timeout_cb)
		handle_adapter_discoverable_timeout_changed(
					changed_properties, user_data);

	g_free(properties);
}

static struct _bluez_adapter *create_adapter(struct _bluez_object *object)
{
	struct _bluez_adapter *adapter;

	DBG("");

	adapter = g_try_new0(struct _bluez_adapter, 1);
	if (!adapter) {
		ERROR("no memory");
		return NULL;
	}

	adapter->object_path = g_strdup(object->path_name);

	adapter->parent = object;

	adapter->interface_name = g_strdup(ADAPTER_INTERFACE);

	return adapter;
}

static void parse_bluez_adapter_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_adapter *adapter = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *signal_proxy, *property_proxy;
	const gchar *iface_name, *adapter_path;

	if (!adapter) {
		WARN("no adapter");
		return;
	}

	adapter_path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, ADAPTER_INTERFACE) == 0) {
		property_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						adapter_path,
						PROPERTIES_INTERFACE,
						NULL, NULL);

		DBG("adapter->proxy = proxy");
		adapter->interface = interface;
		adapter->proxy = proxy;
		adapter->property_proxy = property_proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(adapter_properties_changed), adapter);
	} else if (g_strcmp0(iface_name, MEDIA_INTERFACE) == 0) {
		DBG("adapter->media_proxy = proxy");
		adapter->media_interface = interface;
		adapter->media_proxy = proxy;
	} else if (g_strcmp0(iface_name,
				NETWORKSERVER_INTERFACES) == 0) {
		signal_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						adapter_path,
						iface_name,
						NULL, NULL);

		DBG("adapter->netserver_proxy = proxy");

		adapter->netserver_interface = interface;
		adapter->netserver_proxy = signal_proxy;

		g_signal_connect(signal_proxy, "g-signal",
					G_CALLBACK(networkserver_on_signal),
							NULL);
	}

}

static GList *bluez_object_list;

static GList *device_head_list;

static GList *gatt_service_head_list;

static GList *gatt_char_head_list;

static GList *gatt_desc_head_list;

static void free_device_head(struct _device_head *head)
{
	DBG("%s", head->adapter_path);

	g_free(head->adapter_path);
	g_hash_table_destroy(head->device_hash);
	g_free(head);
}

static void detach_device_head(struct _bluez_adapter *adapter)
{
	struct _device_head *head = NULL;
	GList *list, *next;

	for (list = g_list_first(device_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		if (head->adapter_path == NULL)
			continue;

		if (!g_strcmp0(head->adapter_path, adapter->object_path)) {
			adapter->device_head = NULL;
			head->adapter = NULL;
			break;
		}
	}

	if (head == NULL)
		return;

	if (g_hash_table_size(head->device_hash) == 0) {
		device_head_list = g_list_remove(device_head_list,
							(gpointer) head);
		free_device_head(head);
	}

	return;
}

static void unregister_bluez_adapter(struct _bluez_adapter *adapter)
{
	DBG("adapter path %s", adapter->object_path);

	g_hash_table_steal(bluez_adapter_hash,
				(gpointer) adapter->object_path);

	detach_device_head(adapter);
}

static void register_bluez_object(struct _bluez_object *object)
{
	DBG("%p", object);

	bluez_object_list = g_list_prepend(bluez_object_list,
						(gpointer) object);
	g_hash_table_insert(bluez_object_hash,
				(gpointer) object->path_name,
				(gpointer) object);
}

static GList *bluez_adapter_list;
static GHashTable *bluez_adapter_hash;

static void attach_device_head(struct _bluez_adapter *adapter)
{
	GList *list, *next;

	for (list = g_list_first(device_head_list); list; list = next) {
		struct _device_head *head = list->data;

		next = g_list_next(list);

		if (head->adapter_path == NULL)
			continue;

		if (!g_strcmp0(head->adapter_path, adapter->object_path)) {
			adapter->device_head = head;
			head->adapter = adapter;
			return;
		}
	}
}

static void register_bluez_adapter(struct _bluez_adapter *adapter)
{
	GList **interface_list = &adapter->parent->interfaces;

	DBG("adapter path %s", adapter->object_path);

	bluez_adapter_list = g_list_prepend(bluez_adapter_list,
						(gpointer) adapter);
	g_hash_table_insert(bluez_adapter_hash,
				(gpointer) adapter->object_path,
				(gpointer) adapter);

	*interface_list = g_list_prepend(*interface_list,
					(gpointer) adapter);

	attach_device_head(adapter);

	if (adapter_added_cb)
		adapter_added_cb(adapter, adapter_added_cb_data);
}

static void bluez_adapter_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_adapter *adapter;

	DBG("");

	adapter = create_adapter(object);

	g_list_foreach(ifaces, parse_bluez_adapter_interfaces, adapter);

	register_bluez_adapter(adapter);
}

void bluez_adapter_set_adapter_added(bluez_adapter_added_cb_t cb,
							void *user_data)
{
	adapter_added_cb = cb;
	adapter_added_cb_data = user_data;
}

void bluez_adapter_unset_adapter_added(void)
{
	adapter_added_cb = NULL;
	adapter_added_cb_data = NULL;
}

static inline void handle_device_paired(GVariant *changed_properties,
						struct _bluez_device *device)
{
	gboolean paired;

	if (g_variant_lookup(changed_properties, "Paired", "b", &paired))
		device->device_paired_cb(device, paired,
					device->device_paired_cb_data);
}

static inline void handle_device_connected(GVariant *changed_properties,
						struct _bluez_device *device)
{
	gboolean connected;

	if (g_variant_lookup(changed_properties, "Connected", "b", &connected))
		device->device_connected_cb(device, connected,
					device->device_connected_cb_data);
}

static inline void handle_device_trusted(GVariant *changed_properties,
						struct _bluez_device *device)
{
	gboolean trusted;

	if (g_variant_lookup(changed_properties, "Trusted", "b", &trusted))
		device->device_trusted_cb(device, trusted,
					device->device_trusted_cb_data);
}

static void device_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	struct _bluez_device *device = user_data;
	gchar *properties = g_variant_print(changed_properties, TRUE);
	gboolean paired;

	DBG("properties %s", properties);

	update_device_discovery_info(changed_properties,
					device->device_discovery_info);

	if (g_variant_lookup(changed_properties, "Paired", "b", &paired))
		if (device_paired_cb)
			device_paired_cb(
				device->device_discovery_info->remote_address,
				paired,
				device_paired_cb_data);

	if (device->device_paired_cb)
		handle_device_paired(changed_properties, user_data);

	if (device->device_connected_cb)
		handle_device_connected(changed_properties, user_data);

	if (device->device_trusted_cb)
		handle_device_trusted(changed_properties, user_data);

	g_free(properties);
}

static void gatt_service_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	g_free(properties);
}

static void handle_gatt_char_value_changed(GVariant *changed_properties,
				struct _bluez_gatt_char *charateristic)
{
	GVariant *variant_found;
	GByteArray *gb_array = NULL;
	GVariantIter *iter;
	guchar g_value;
	unsigned char *value_array;
	int value_length;

	DBG("");

	variant_found = g_variant_lookup_value(changed_properties,
						"Value",
						G_VARIANT_TYPE_BYTESTRING);
	if (!variant_found)
		return;

	g_variant_get(variant_found, "ay", &iter);

	gb_array = g_byte_array_new();

	while (g_variant_iter_loop(iter, "y", &g_value)) {
		g_byte_array_append(gb_array, &g_value,
					sizeof(unsigned char));
	}

	value_array = g_malloc0(gb_array->len * sizeof(unsigned char));

	memcpy(value_array, gb_array->data, gb_array->len);
	value_length = gb_array->len;

	charateristic->value_changed_cb(charateristic,
				value_array, value_length,
				charateristic->value_changed_cb_data);

	g_byte_array_unref(gb_array);
}

static void gatt_char_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	struct _bluez_gatt_char *charateristic = user_data;
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	if (charateristic->value_changed_cb)
		handle_gatt_char_value_changed(changed_properties, user_data);

	g_free(properties);
}

static void gatt_desc_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	g_free(properties);
}

static struct _bluez_device *create_device(struct _bluez_object *object)
{
	struct _bluez_device *device;

	DBG("");

	device = g_try_new0(struct _bluez_device, 1);
	if (!device) {
		ERROR("no memory");
		return NULL;
	}

	device->object_path = g_strdup(object->path_name);

	device->parent = object;

	device->interface_name = g_strdup(DEVICE_INTERFACE);

	return device;
}

static struct _bluez_gatt_service *create_service(struct _bluez_object *object)
{
	struct _bluez_gatt_service *service;

	DBG("");

	service = g_try_new0(struct _bluez_gatt_service, 1);
	if (!service) {
		ERROR("no memory");
		return NULL;
	}

	service->object_path = g_strdup(object->path_name);

	service->parent = object;

	service->interface_name = g_strdup(GATT_SERVICE_IFACE);

	return service;
}

static struct _bluez_gatt_char *create_char(struct _bluez_object *object)
{
	struct _bluez_gatt_char *characteristic;

	DBG("");

	characteristic = g_try_new0(struct _bluez_gatt_char, 1);
	if (!characteristic) {
		ERROR("no memory");
		return NULL;
	}

	characteristic->object_path = g_strdup(object->path_name);

	characteristic->parent = object;

	characteristic->interface_name = g_strdup(GATT_CHR_IFACE);

	return characteristic;
}

static struct _bluez_gatt_desc *create_desc(struct _bluez_object *object)
{
	struct _bluez_gatt_desc *descriptor;

	DBG("");

	descriptor = g_try_new0(struct _bluez_gatt_desc, 1);
	if (!descriptor) {
		ERROR("no memory");
		return NULL;
	}

	descriptor->object_path = g_strdup(object->path_name);

	descriptor->parent = object;

	descriptor->interface_name = g_strdup(GATT_DESCRIPTOR_IFACE);

	return descriptor;
}

static void control_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	g_free(properties);
}

static inline void handle_device_network_connected(
					GVariant *changed_properties,
					struct _bluez_device *device)
{
	gboolean connected;

	if (g_variant_lookup(changed_properties, "Connected", "b", &connected))
		device->network_connected_cb(device, connected,
					device->network_connected_cb_data);
}

static void network_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);
	struct _bluez_device *device = user_data;

	DBG("properties %s", properties);

	if (device->network_connected_cb)
		handle_device_network_connected(changed_properties, user_data);

	g_free(properties);
}

static void hdp_properties_changed(GDBusProxy *proxy,
					GVariant *changed,
					GStrv *invalidated,
					gpointer user_data)
{
	char *path = NULL;

	g_variant_lookup(changed,
				"MainChannel", "o", &path);

	if (path == NULL)
		return;

	DBG("object_path = %s", path);
}

static void hdp_signal_changed(GDBusProxy *proxy,
					gchar *sender_name,
					gchar *signal_name,
					GVariant *param,
					gpointer user_data)
{
	if (g_strcmp0(signal_name, "ChannelConnected") == 0) {
		hdp_internal_handle_connect(user_data, param);
	} else if (g_strcmp0(signal_name, "ChannelDeleted")
							== 0) {
		hdp_internal_handle_disconnect(user_data, param);
	}
}

static inline void handle_device_input_connected(GVariant *changed_properties,
					struct _bluez_device *device)
{
	gboolean connected;

	if (g_variant_lookup(changed_properties, "Connected", "b", &connected))
		device->input_connected_cb(device, connected,
					device->input_connected_cb_data);
}

static void input_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);
	struct _bluez_device *device = user_data;

	DBG("properties %s", properties);

	if (device->input_connected_cb)
		handle_device_input_connected(changed_properties, user_data);

	g_free(properties);
}

static void parse_bluez_device_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_device *device = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *signal_proxy, *property_proxy;
	const gchar *iface_name, *path;

	if (!device) {
		WARN("no device");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, DEVICE_INTERFACE) == 0) {
		property_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM, 0,
					NULL,
					BLUEZ_NAME,
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

		device->interface = interface;
		device->proxy = proxy;
		device->property_proxy = property_proxy;
		device->device_discovery_info =
			get_discovery_device_info(device);
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(device_properties_changed), device);
	} else if (g_strcmp0(iface_name, MEDIACONTROL_INTERFACE) == 0) {
		device->control_interface = interface;
		device->control_proxy = proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(control_properties_changed), device);
	} else if (g_strcmp0(iface_name, NETWORK_INTERFACE) == 0) {
		device->network_interface = interface;
		device->network_proxy = proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(network_properties_changed), device);
	} else if (g_strcmp0(iface_name, HDP_DEVICE_INTERFACE) == 0) {
		DBG("hdp path = %s", path);

		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(hdp_properties_changed), device);

		signal_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						path,
						iface_name,
						NULL, NULL);

		g_signal_connect(signal_proxy, "g-signal",
			G_CALLBACK(hdp_signal_changed), device);
		device->hdp_proxy = signal_proxy;
		device->hdp_interface = interface;
	} else if (g_strcmp0(iface_name, INPUT_INTERFACE) == 0) {
		device->input_interface = interface;
		device->input_proxy = proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(input_properties_changed), device);
	}

}

static void parse_bluez_control_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_object *object = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *property_proxy;
	const gchar *iface_name, *path;

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, MEDIATRANSPORT_INTERFACE) == 0) {
		gchar *uuid, *device_address;
		gchar *device_path;
		enum audio_profile_type type;

		path = g_dbus_proxy_get_object_path(proxy);

		property_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);

		device_address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		if (device_address == NULL)
			return;

		device_path = property_get_string(property_proxy,
				MEDIATRANSPORT_INTERFACE, "Device");
		if (device_path == NULL) {
			DBG("device_path == NULL");
			g_free(device_address);
			return;
		}

		convert_device_path_to_address((const gchar *)device_path,
							device_address);

		uuid = property_get_string(property_proxy,
				MEDIATRANSPORT_INTERFACE, "UUID");
		if (uuid == NULL) {
			g_free(device_address);
			g_free(device_path);
		}

		DBG("uuid = %s", uuid);

		if (g_strcmp0(uuid, BT_A2DP_SINK_UUID) == 0) {
			type = AUDIO_TYPE_A2DP;
			object->media_type = type;
		}

		if (audio_state_cb) {
				audio_state_cb(0, TRUE, device_address,
					type, audio_state_cb_data);
		}

		if (avrcp_target_cb)
				avrcp_target_cb(device_address, TRUE,
					avrcp_target_cb_data);

		g_free(device_path);
		g_free(uuid);
	}
}

static void parse_bluez_gatt_service_interfaces(gpointer data,
						gpointer user_data)
{
	struct _bluez_gatt_service *service = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *property_proxy;
	const gchar *iface_name, *path;

	if (!service) {
		WARN("no service");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, GATT_SERVICE_IFACE) == 0) {
		property_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM, 0,
					NULL,
					BLUEZ_NAME,
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

		service->interface = interface;
		service->proxy = proxy;
		service->property_proxy = property_proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(gatt_service_properties_changed), service);
	}

}

static void parse_bluez_gatt_char_interfaces(gpointer data,
						gpointer user_data)
{
	struct _bluez_gatt_char *characteristic = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *property_proxy;
	const gchar *iface_name, *path;

	if (!characteristic) {
		WARN("no characteristic");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, GATT_CHR_IFACE) == 0) {
		property_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM, 0,
					NULL,
					BLUEZ_NAME,
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

		characteristic->interface = interface;
		characteristic->proxy = proxy;
		characteristic->property_proxy = property_proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(gatt_char_properties_changed),
			characteristic);
	}

}

static void parse_bluez_gatt_desc_interfaces(gpointer data,
						gpointer user_data)
{
	struct _bluez_gatt_desc *descriptor = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *property_proxy;
	const gchar *iface_name, *path;

	if (!descriptor) {
		WARN("no descriptor");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, GATT_DESCRIPTOR_IFACE) == 0) {
		property_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SYSTEM, 0,
					NULL,
					BLUEZ_NAME,
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

		descriptor->interface = interface;
		descriptor->proxy = proxy;
		descriptor->property_proxy = property_proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(gatt_desc_properties_changed), descriptor);
	}

}

char *bluez_device_property_get_adapter(struct _bluez_device *device)
{
	return property_get_string(device->property_proxy,
					DEVICE_INTERFACE, "Adapter");
}

char *bluez_gatt_service_property_get_device(
				struct _bluez_gatt_service *service)
{
	return property_get_string(service->property_proxy,
					GATT_SERVICE_IFACE, "Device");
}

int bluez_gatt_service_get_property_primary(
				struct _bluez_gatt_service *service,
					gboolean *primary)
{
	return property_get_boolean(service->property_proxy,
					GATT_SERVICE_IFACE,
					"Primary", primary);
}

char **bluez_gatt_service_get_property_includes(
				struct _bluez_gatt_service *service)
{
	return property_get_object_list(service->property_proxy,
					GATT_SERVICE_IFACE, "Includes");
}

char *bluez_gatt_service_get_property_uuid(
				struct _bluez_gatt_service *service)
{
	return property_get_string(service->property_proxy,
					GATT_SERVICE_IFACE, "UUID");
}

char *bluez_gatt_char_get_property_uuid(
				struct _bluez_gatt_char *characteristic)
{
	return property_get_string(characteristic->property_proxy,
					GATT_CHR_IFACE, "UUID");
}

int bluez_gatt_char_get_property_notifying(
				struct _bluez_gatt_char *characteristic,
				gboolean *notifying)
{
	return property_get_boolean(characteristic->property_proxy,
					GATT_CHR_IFACE,
					"Notifying", notifying);
}

GByteArray *bluez_gatt_char_get_property_value(
				struct _bluez_gatt_char *characteristic)
{
	return property_get_bytestring(characteristic->property_proxy,
					GATT_CHR_IFACE, "Value");
}

char *bluez_gatt_char_property_get_service(
				struct _bluez_gatt_char *characteristic)
{
	return property_get_string(characteristic->property_proxy,
					GATT_CHR_IFACE, "Service");
}

char **bluez_gatt_char_property_get_flags(
				struct _bluez_gatt_char *characteristic)
{
	return property_get_string_list(characteristic->property_proxy,
					GATT_CHR_IFACE, "Flags");
}

char *bluez_gatt_desc_property_get_char(
				struct _bluez_gatt_desc *descriptor)
{
	return property_get_string(descriptor->property_proxy,
				GATT_DESCRIPTOR_IFACE, "Characteristic");
}

char *bluez_gatt_service_get_object_path(
				struct _bluez_gatt_service *service)
{
	return service->object_path;
}

char *bluez_gatt_char_get_object_path(
				struct _bluez_gatt_char *characteristic)
{
	return characteristic->object_path;
}

struct _bluez_gatt_service *bluez_gatt_get_service_by_path(
				const char *service_path)
{
	struct _gatt_service_head *head = NULL;
	struct _bluez_gatt_service *service = NULL;
	GList *list, *next;

	for (list = g_list_first(gatt_service_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		service = g_hash_table_lookup(head->gatt_service_hash,
					(gconstpointer) service_path);

		if (service != NULL)
			break;
	}

	return service;
}

GList *bluez_gatt_service_get_char_paths(struct _bluez_gatt_service *service)
{
	struct _gatt_char_head *char_head = service->char_head;
	GList *characteristics = NULL;

	characteristics = g_hash_table_get_keys(char_head->gatt_char_hash);

	return characteristics;
}

GList *bluez_gatt_service_get_chars(struct _bluez_gatt_service *service)
{
	struct _gatt_char_head *char_head = service->char_head;
	GList *characteristics = NULL;

	characteristics = g_hash_table_get_values(char_head->gatt_char_hash);

	return characteristics;
}

struct _bluez_gatt_char *bluez_gatt_get_char_by_path(
				const char *gatt_char_path)
{
	struct _gatt_char_head *head = NULL;
	struct _bluez_gatt_char *characteristic = NULL;
	GList *list, *next;

	for (list = g_list_first(gatt_char_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		characteristic = g_hash_table_lookup(head->gatt_char_hash,
					(gconstpointer) gatt_char_path);

		if (characteristic != NULL)
			break;
	}

	return characteristic;
}

static void char_read_value_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	struct gatt_char_read_notify *notify = user_data;
	struct _bluez_gatt_char *characteristic;
	GVariant *ret;
	GByteArray *gb_array = NULL;
	GError *error = NULL;
	GVariantIter *iter;
	guchar g_value;
	unsigned char *value_array;
	int value_length;

	DBG("");

	characteristic = notify->characteristic;

	ret = g_dbus_proxy_call_finish(characteristic->proxy,
					res, &error);

	if (ret == NULL)
		DBG("error: %s", error->message);
	else {
		g_variant_get(ret, "(ay)", &iter);

		gb_array = g_byte_array_new();

		while (g_variant_iter_loop(iter, "y", &g_value)) {
			g_byte_array_append(gb_array, &g_value,
						sizeof(unsigned char));
		}

		value_array = g_malloc0(gb_array->len * sizeof(unsigned char));

		memcpy(value_array, gb_array->data, gb_array->len);
		value_length = gb_array->len;

		notify->cb(characteristic, value_array,
				value_length, char_read_data);

		g_byte_array_unref(gb_array);
		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_gatt_read_char_value(struct _bluez_gatt_char *characteristic)
{
	struct gatt_char_read_notify *notify;

	notify = g_try_new0(struct gatt_char_read_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->characteristic = characteristic;
	notify->cb = char_read_calue_cb;

	g_dbus_proxy_call(characteristic->proxy,
			"ReadValue", NULL,
			0, -1, NULL,
			char_read_value_callback, notify);
}

static void char_write_value_callback(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	struct gatt_char_write_notify *notify = user_data;
	struct _bluez_gatt_char *characteristic;
	GVariant *ret;
	GError *error = NULL;

	DBG("");

	characteristic = notify->characteristic;

	ret = g_dbus_proxy_call_finish(characteristic->proxy,
					res, &error);

	if (ret == NULL)
		DBG("error: %s", error->message);
	else {
		notify->cb(characteristic, char_write_data);

		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_gatt_write_char_value(struct _bluez_gatt_char *characteristic,
				const unsigned char *value,
				int value_length,
				unsigned char request)
{
	GVariantBuilder *builder;
	GVariant *parameters;
	GError *error = NULL;
	int i;

	DBG("");

	builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));

	for (i = 0; i < value_length; i++)
		g_variant_builder_add(builder, "y", value[i]);

	parameters = g_variant_new("(ay)", builder);

	if (request) {
		struct gatt_char_write_notify *notify;

		notify = g_try_new0(struct gatt_char_write_notify, 1);
		if (notify == NULL) {
			ERROR("no memory");
			return;
		}

		notify->characteristic = characteristic;
		notify->cb = char_write_calue_cb;

		g_dbus_proxy_call(characteristic->proxy,
				"WriteValue", parameters,
				0, -1, NULL,
				char_write_value_callback, notify);

	} else {
		g_dbus_proxy_call_sync(characteristic->proxy,
				"WriteValue", parameters,
				0, -1, NULL, &error);
	}

	g_variant_builder_unref(builder);
}

static void destruct_bluez_device(gpointer data)
{
	struct _bluez_device *device = data;
	GList **interface_list = &device->parent->interfaces;

	DBG("%s", device->object_path);

	*interface_list = g_list_remove(*interface_list, data);

	g_free(device->interface_name);
	g_free(device->object_path);
	g_object_unref(device->interface);

	if (device->device_discovery_info)
		free_discovery_device_info(
			device->device_discovery_info);
	if (device->control_interface)
		g_object_unref(device->control_interface);
	if (device->input_interface)
		g_object_unref(device->input_interface);
	if (device->hdp_interface)
		g_object_unref(device->hdp_interface);
	if (device->network_interface)
		g_object_unref(device->network_interface);

	g_free(device);
}

static void destruct_interfaces_bluez_device(gpointer data)
{
	struct _bluez_device *device = data;

	DBG("%s", device->object_path);

	g_free(device->interface_name);
	g_free(device->object_path);
	g_object_unref(device->interface);

	if (device->device_discovery_info)
		free_discovery_device_info(
			device->device_discovery_info);
	if (device->control_interface)
		g_object_unref(device->control_interface);
	if (device->input_interface)
		g_object_unref(device->input_interface);
	if (device->hdp_interface)
		g_object_unref(device->hdp_interface);
	if (device->network_interface)
		g_object_unref(device->network_interface);

	g_free(device);
}

static void destruct_bluez_gatt_service(gpointer data)
{
	struct _bluez_gatt_service *service = data;
	GList **interface_list = &service->parent->interfaces;

	DBG("%s", service->object_path);

	*interface_list = g_list_remove(*interface_list, data);

	g_free(service->interface_name);
	g_free(service->object_path);
	g_object_unref(service->interface);
	g_object_unref(service->property_proxy);

	g_free(service);
}

static void destruct_interfaces_bluez_gatt_service(gpointer data)
{
	struct _bluez_gatt_service *service = data;

	DBG("%s", service->object_path);

	g_free(service->interface_name);
	g_free(service->object_path);
	g_object_unref(service->interface);
	g_object_unref(service->property_proxy);

	g_free(service);
}

static void destruct_bluez_gatt_char(gpointer data)
{
	struct _bluez_gatt_char *characteristic = data;
	GList **interface_list = &characteristic->parent->interfaces;

	DBG("%s", characteristic->object_path);

	*interface_list = g_list_remove(*interface_list, data);

	g_free(characteristic->interface_name);
	g_free(characteristic->object_path);
	g_object_unref(characteristic->interface);
	g_object_unref(characteristic->property_proxy);

	g_free(characteristic);
}

static void destruct_interfaces_bluez_gatt_char(gpointer data)
{
	struct _bluez_gatt_char *characteristic = data;

	DBG("%s", characteristic->object_path);

	g_free(characteristic->interface_name);
	g_free(characteristic->object_path);
	g_object_unref(characteristic->interface);
	g_object_unref(characteristic->property_proxy);

	g_free(characteristic);
}

static void destruct_bluez_gatt_desc(gpointer data)
{
	struct _bluez_gatt_desc *descriptor = data;
	GList **interface_list = &descriptor->parent->interfaces;

	DBG("%s", descriptor->object_path);

	*interface_list = g_list_remove(*interface_list, data);

	g_free(descriptor->interface_name);
	g_free(descriptor->object_path);
	g_object_unref(descriptor->interface);
	g_object_unref(descriptor->property_proxy);

	g_free(descriptor);
}

static void destruct_interfaces_bluez_gatt_desc(gpointer data)
{
	struct _bluez_gatt_desc *descriptor = data;

	DBG("%s", descriptor->object_path);

	g_free(descriptor->interface_name);
	g_free(descriptor->object_path);
	g_object_unref(descriptor->interface);
	g_object_unref(descriptor->property_proxy);

	g_free(descriptor);
}

static void attach_adapter(struct _device_head *new_head)
{
	struct _bluez_adapter *adapter;

	adapter = g_hash_table_lookup(bluez_adapter_hash,
				(gconstpointer) new_head->adapter_path);
	if (adapter == NULL)
		return;

	adapter->device_head = new_head;
	new_head->adapter = adapter;
}

static void attach_device(struct _gatt_service_head *new_head)
{
	struct _bluez_device *device;

	device = g_hash_table_lookup(bluez_device_hash,
			(gconstpointer) new_head->device_path);
	if (device == NULL)
		return;

	device->service_head = new_head;
	new_head->device = device;
}

static void attach_gatt_service(struct _gatt_char_head *new_head)
{
	struct _bluez_gatt_service *service;

	service = g_hash_table_lookup(bluez_gatt_service_hash,
			(gconstpointer) new_head->gatt_service_path);
	if (service == NULL)
		return;

	service->char_head = new_head;
	new_head->service = service;
}

static void attach_gatt_char(struct _gatt_desc_head *new_head)
{
	struct _bluez_gatt_char *characteristic;

	characteristic = g_hash_table_lookup(bluez_gatt_char_hash,
				(gconstpointer) new_head->gatt_char_path);
	if (characteristic == NULL)
		return;

	characteristic->desc_head = new_head;
	new_head->characteristic = characteristic;
}

static void add_to_device_head_list(struct _bluez_device *device,
					const char *adapter_path)
{
	struct _device_head *new_head;
	GList *list, *next = NULL;

	for (list = g_list_first(device_head_list); list; list = next) {
		struct _device_head *head = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(head->adapter_path, adapter_path)) {

			DBG("insert %s into %s", device->object_path,
							adapter_path);
			g_hash_table_insert(head->device_hash,
						(gpointer) device->object_path,
						(gpointer) device);
			device->head = head;
			return;
		} else
			continue;
	}

	new_head = g_try_new0(struct _device_head, 1);
	if (new_head == NULL) {
		ERROR("no mem");
		return;
	}

	new_head->adapter_path = g_strdup(adapter_path);

	DBG("add new device head %s", adapter_path);

	new_head->device_hash = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						NULL,
						destruct_bluez_device);

	DBG("insert %s into %s", device->object_path, adapter_path);
	g_hash_table_insert(new_head->device_hash,
					(gpointer) device->object_path,
					(gpointer) device);
	device->head = new_head;

	attach_adapter(new_head);

	device_head_list = g_list_append(device_head_list,
					(gpointer) new_head);
}

static void add_to_gatt_service_head_list(struct _bluez_gatt_service *service,
					const char *device_path)
{
	struct _gatt_service_head *new_head;
	GList *list, *next = NULL;

	for (list = g_list_first(gatt_service_head_list); list; list = next) {
		struct _gatt_service_head *head = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(head->device_path, device_path)) {

			DBG("insert %s into %s", service->object_path,
							device_path);
			g_hash_table_insert(head->gatt_service_hash,
						(gpointer) service->object_path,
						(gpointer) service);
			service->head = head;
			return;
		} else
			continue;
	}

	new_head = g_try_new0(struct _gatt_service_head, 1);
	if (new_head == NULL) {
		ERROR("no mem");
		return;
	}

	new_head->device_path = g_strdup(device_path);

	DBG("add new service head %s", device_path);

	new_head->gatt_service_hash = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						NULL,
						destruct_bluez_gatt_service);

	DBG("insert %s into %s", service->object_path, device_path);
	g_hash_table_insert(new_head->gatt_service_hash,
					(gpointer) service->object_path,
					(gpointer) service);
	service->head = new_head;

	attach_device(new_head);

	gatt_service_head_list = g_list_append(gatt_service_head_list,
					(gpointer) new_head);
}

static void add_to_gatt_char_head_list(struct _bluez_gatt_char *characteristic,
					const char *gatt_service_path)
{
	struct _gatt_char_head *new_head;
	GList *list, *next = NULL;

	for (list = g_list_first(gatt_char_head_list); list; list = next) {
		struct _gatt_char_head *head = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(head->gatt_service_path, gatt_service_path)) {

			DBG("insert %s into %s", characteristic->object_path,
							gatt_service_path);
			g_hash_table_insert(head->gatt_char_hash,
					(gpointer) characteristic->object_path,
					(gpointer) characteristic);
			characteristic->head = head;
			return;
		} else
			continue;
	}

	new_head = g_try_new0(struct _gatt_char_head, 1);
	if (new_head == NULL) {
		ERROR("no mem");
		return;
	}

	new_head->gatt_service_path = g_strdup(gatt_service_path);

	DBG("add new characteristic head %s", gatt_service_path);

	new_head->gatt_char_hash = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						NULL,
						destruct_bluez_gatt_char);

	DBG("insert %s into %s", characteristic->object_path,
					gatt_service_path);

	g_hash_table_insert(new_head->gatt_char_hash,
					(gpointer) characteristic->object_path,
					(gpointer) characteristic);
	characteristic->head = new_head;

	attach_gatt_service(new_head);

	gatt_char_head_list = g_list_append(gatt_char_head_list,
					(gpointer) new_head);
}

static void add_to_gatt_desc_head_list(struct _bluez_gatt_desc *descriptor,
					const char *gatt_char_path)
{
	struct _gatt_desc_head *new_head;
	GList *list, *next = NULL;

	for (list = g_list_first(gatt_desc_head_list); list; list = next) {
		struct _gatt_desc_head *head = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(head->gatt_char_path, gatt_char_path)) {

			DBG("insert %s into %s", descriptor->object_path,
							gatt_char_path);

			g_hash_table_insert(head->gatt_desc_hash,
					(gpointer) descriptor->object_path,
					(gpointer) descriptor);
			descriptor->head = head;
			return;
		} else
			continue;
	}

	new_head = g_try_new0(struct _gatt_desc_head, 1);
	if (new_head == NULL) {
		ERROR("no mem");
		return;
	}

	new_head->gatt_char_path = g_strdup(gatt_char_path);

	DBG("add new descriptor head %s", gatt_char_path);

	new_head->gatt_desc_hash = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						NULL,
						destruct_bluez_gatt_desc);

	DBG("insert %s into %s", descriptor->object_path, gatt_char_path);
	g_hash_table_insert(new_head->gatt_desc_hash,
					(gpointer) descriptor->object_path,
					(gpointer) descriptor);
	descriptor->head = new_head;

	attach_gatt_char(new_head);

	gatt_desc_head_list = g_list_append(gatt_desc_head_list,
					(gpointer) new_head);
}

static void register_bluez_device(struct _bluez_device *device)
{
	char *adapter_path;
	struct _bluez_adapter *adapter;

	GList **interface_list = &device->parent->interfaces;

	adapter_path = bluez_device_property_get_adapter(device);
	if (adapter_path == NULL)
		return;

	add_to_device_head_list(device, adapter_path);

	g_free(adapter_path);

	g_hash_table_insert(bluez_device_hash,
				(gpointer) device->object_path,
				(gpointer) device);

	*interface_list = g_list_prepend(*interface_list,
					(gpointer) device);

	if (!device->head)
		return;

	adapter = device->head->adapter;

	if (!adapter)
		return;

	if (adapter->device_created_cb)
		adapter->device_created_cb(device,
				adapter->device_created_data);
}

static void register_bluez_gatt_service(struct _bluez_gatt_service *service)
{
	char *device_path;

	GList **interface_list = &service->parent->interfaces;

	device_path = bluez_gatt_service_property_get_device(service);
	if (device_path == NULL)
		return;

	add_to_gatt_service_head_list(service, device_path);

	g_free(device_path);

	g_hash_table_insert(bluez_gatt_service_hash,
				(gpointer) service->object_path,
				(gpointer) service);

	*interface_list = g_list_prepend(*interface_list,
					(gpointer) service);
}

static void register_bluez_gatt_char(struct _bluez_gatt_char *characteristic)
{
	char *gatt_service_path;

	GList **interface_list = &characteristic->parent->interfaces;

	gatt_service_path =
		bluez_gatt_char_property_get_service(characteristic);

	if (gatt_service_path == NULL)
		return;

	add_to_gatt_char_head_list(characteristic, gatt_service_path);

	g_free(gatt_service_path);

	g_hash_table_insert(bluez_gatt_char_hash,
				(gpointer) characteristic->object_path,
				(gpointer) characteristic);

	*interface_list = g_list_prepend(*interface_list,
				(gpointer) characteristic);
}

static void register_bluez_gatt_desc(struct _bluez_gatt_desc *descriptor)
{
	char *gatt_char_path;

	GList **interface_list = &descriptor->parent->interfaces;

	gatt_char_path = bluez_gatt_desc_property_get_char(descriptor);
	if (gatt_char_path == NULL)
		return;

	add_to_gatt_desc_head_list(descriptor, gatt_char_path);

	g_free(gatt_char_path);

	g_hash_table_insert(bluez_gatt_desc_hash,
				(gpointer) descriptor->object_path,
				(gpointer) descriptor);

	*interface_list = g_list_prepend(*interface_list,
					(gpointer) descriptor);
}

static void bluez_device_interface_added(GDBusObject *object,
					GDBusInterface *interface,
					gpointer user_data)
{
	parse_bluez_device_interfaces(interface, user_data);
}

static void bluez_device_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_device *device;

	DBG("");

	device = create_device(object);

	g_signal_connect(object->obj, "interface-added",
			G_CALLBACK(bluez_device_interface_added), device);

	g_list_foreach(ifaces, parse_bluez_device_interfaces, device);

	register_bluez_device(device);
}

static void bluez_control_added(struct _bluez_object *object,
					GList *ifaces)
{
	DBG("");
	g_list_foreach(ifaces, parse_bluez_control_interfaces, object);
}

static void bluez_gatt_service_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_gatt_service *service;

	DBG("");

	service = create_service(object);

	g_list_foreach(ifaces, parse_bluez_gatt_service_interfaces, service);

	register_bluez_gatt_service(service);
}

static void bluez_gatt_char_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_gatt_char *characteristic;

	DBG("");

	characteristic = create_char(object);

	g_list_foreach(ifaces, parse_bluez_gatt_char_interfaces,
						characteristic);

	register_bluez_gatt_char(characteristic);
}

static void bluez_gatt_desc_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_gatt_desc *descriptor;

	DBG("");

	descriptor = create_desc(object);

	g_list_foreach(ifaces, parse_bluez_gatt_desc_interfaces, descriptor);

	register_bluez_gatt_desc(descriptor);
}

static struct _bluez_agent *create_agent(struct _bluez_object *object)
{
	struct _bluez_agent *agent;

	DBG("");

	agent = g_try_new0(struct _bluez_agent, 1);
	if (!agent) {
		ERROR("no memory");
		return NULL;
	}

	agent->object_path = g_strdup(object->path_name);

	agent->parent = object;

	agent->interface_name = g_strdup(AGENT_INTERFACE);

	return agent;
}

static void free_agent(struct _bluez_agent *agent)
{
	if (agent == NULL)
		return;

	g_free(agent->object_path);
	g_free(agent->interface_name);

	g_object_unref(agent->proxy);

	g_free(agent);
}

static void parse_bluez_agent_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_agent *agent = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	const gchar *iface_name;

	if (!agent) {
		WARN("no adapter");
		return;
	}

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, AGENT_INTERFACE))
		return;

	agent->interface = interface;
	agent->proxy = proxy;
}

static struct _bluez_profile *create_profile(struct _bluez_object *object)
{
	struct _bluez_profile *profile;

	DBG("");

	profile = g_try_new0(struct _bluez_profile, 1);
	if (!profile) {
		ERROR("no memory");
		return NULL;
	}

	profile->object_path = g_strdup(object->path_name);

	profile->parent = object;

	profile->interface_name = g_strdup(PROFILE_INTERFACE);

	return profile;
}

static void free_profile(struct _bluez_profile *profile)
{
	if (profile == NULL)
		return;

	g_free(profile->object_path);
	g_free(profile->interface_name);

	g_object_unref(profile->proxy);

	g_free(profile);
}

static void parse_bluez_profile_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_profile *profile = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	const gchar *iface_name;

	if (!profile) {
		WARN("no profile");
		return;
	}

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, PROFILE_INTERFACE))
		return;

	profile->interface = interface;
	profile->proxy = proxy;
}

static struct _bluez_agent *this_agent;
static struct _bluez_profile *this_profile;

struct _bluez_agent *bluez_agent_get_agent(void)
{
	return this_agent;
}

void bluez_set_device_connect_changed_cb(device_connect_cb_t cb,
					gpointer user_data)
{
	dev_connect_cb = cb;
	dev_connect_data = user_data;
}

void bluez_set_device_disconnect_changed_cb(device_disconnect_cb_t cb,
					gpointer user_data)
{
	dev_disconnect_cb = cb;
	dev_disconnect_data = user_data;
}

void bluez_set_char_read_value_cb(char_read_value_cb_t cb,
					gpointer user_data)
{
	char_read_calue_cb = cb;
	char_read_data = user_data;
}

void bluez_set_char_write_value_cb(char_write_value_cb_t cb,
					gpointer user_data)
{
	char_write_calue_cb = cb;
	char_write_data = user_data;
}

void bluez_set_char_value_changed_cb(
				struct _bluez_gatt_char *characteristic,
				bluez_gatt_char_value_changed_cb_t cb,
				gpointer user_data)
{
	DBG("");

	characteristic->value_changed_cb = cb;
	characteristic->value_changed_cb_data = user_data;
}

void bluez_unset_char_value_changed_cb(
				struct _bluez_gatt_char *characteristic)
{
	DBG("");

	characteristic->value_changed_cb = NULL;
	characteristic->value_changed_cb_data = NULL;
}

void bluez_set_avrcp_target_cb(bluez_avrcp_target_cb_t cb,
						gpointer user_data)
{
	avrcp_target_cb = cb;
	avrcp_target_cb_data = user_data;
}

void bluez_unset_avrcp_target_cb(void)
{
	avrcp_target_cb = NULL;
	avrcp_target_cb_data = NULL;
}

void bluez_set_avrcp_shuffle_cb(bluez_avrcp_shuffle_cb_t cb,
						gpointer user_data)
{
	avrcp_shuffle_cb = cb;
	avrcp_shuffle_cb_data = user_data;
}

void bluez_unset_avrcp_shuffle_cb(void)
{
	avrcp_shuffle_cb = NULL;
	avrcp_shuffle_cb_data = NULL;
}

void bluez_set_avrcp_repeat_cb(bluez_avrcp_repeat_cb_t cb,
						gpointer user_data)
{
	avrcp_repeat_cb = cb;
	avrcp_repeat_cb_data = user_data;
}

void bluez_unset_avrcp_repeat_cb(void)
{
	avrcp_repeat_cb = NULL;
	avrcp_repeat_cb_data = NULL;
}

void bluez_set_nap_connection_state_cb(
				bluez_nap_connection_state_cb_t cb,
				gpointer user_data)
{
	nap_connnection_state_cb = cb;
	nap_connnection_state_cb_data = user_data;
}

void bluez_unset_nap_connection_state_cb(void)
{
	nap_connnection_state_cb = NULL;
	nap_connnection_state_cb_data = NULL;
}

void bluez_set_audio_state_cb(bluez_audio_state_cb_t cb,
					gpointer user_data)
{
	audio_state_cb = cb;
	audio_state_cb_data = user_data;
}

void bluez_unset_audio_state_cb()
{
	audio_state_cb = NULL;
	audio_state_cb_data = NULL;
}

void bluez_agent_set_agent_added(bluez_agent_added_cb_t cb,
							void *user_data)
{
	agent_added_cb = cb;
	agent_added_cb_data = user_data;
}

void bluez_agent_unset_agent_added(void)
{
	agent_added_cb = NULL;
	agent_added_cb_data = NULL;
}
static void register_bluez_agent(struct _bluez_agent *agent)
{
	DBG("");

	if (this_agent)
		WARN("agent %p not unregister", this_agent);

	this_agent = agent;

	if (agent_added_cb)
		agent_added_cb(agent, agent_added_cb_data);
}

static void bluez_agent_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_agent *agent;

	DBG("");

	agent = create_agent(object);

	g_list_foreach(ifaces, parse_bluez_agent_interfaces, agent);

	register_bluez_agent(agent);
}

static void register_bluez_profile(struct _bluez_profile *profile)
{
	DBG("");

	if (this_profile)
		WARN("profile %p not unregister", this_profile);

	this_profile = profile;
}

static void bluez_profile_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_profile *profile;

	DBG("");

	profile = create_profile(object);

	g_list_foreach(ifaces, parse_bluez_profile_interfaces, profile);

	register_bluez_profile(profile);
}

static void parse_root_object(struct _bluez_object *object, GList *ifaces)
{
	if (g_dbus_object_get_interface(object->obj, AGENT_INTERFACE))
		bluez_agent_added(object, ifaces);

	if (g_dbus_object_get_interface(object->obj, PROFILE_INTERFACE))
		bluez_profile_added(object, ifaces);
}

static void parse_object(gpointer data, gpointer user_data)
{
	GDBusObject *obj = data;
	struct _bluez_object *object;
	const char *path = g_dbus_object_get_object_path(obj);
	GList *ifaces;

	object = get_object_from_path(path);
	if (!object) {
		object = create_object(obj);
		register_bluez_object(object);
	}

	ifaces = g_dbus_object_get_interfaces(obj);

	if (g_dbus_object_get_interface(obj, ADAPTER_INTERFACE))
		bluez_adapter_added(object, ifaces);
	else if (g_dbus_object_get_interface(obj, DEVICE_INTERFACE))
		bluez_device_added(object, ifaces);
	else if (g_dbus_object_get_interface(obj, MEDIATRANSPORT_INTERFACE))
		bluez_control_added(object, ifaces);
	else if (g_dbus_object_get_interface(obj, GATT_SERVICE_IFACE))
		bluez_gatt_service_added(object, ifaces);
	else if (g_dbus_object_get_interface(obj, GATT_CHR_IFACE))
		bluez_gatt_char_added(object, ifaces);
	else if (g_dbus_object_get_interface(obj, GATT_DESCRIPTOR_IFACE))
		bluez_gatt_desc_added(object, ifaces);
	else
		parse_root_object(object, ifaces);

	return;
}

struct _bluez_adapter *bluez_adapter_get_adapter(const char *name)
{
	struct _bluez_adapter *adapter;
	char *adapter_path;
	int size;

	if (name == NULL) {
		ERROR("name is NULL");
		return NULL;
	}

	size = 12 + strlen(name);
	adapter_path = malloc(size);

	sprintf(adapter_path, "/org/bluez/%s", name);

	adapter = g_hash_table_lookup(bluez_adapter_hash,
				(gconstpointer) adapter_path);

	free(adapter_path);

	return adapter;
}

static void destruct_bluez_adapter(gpointer data)
{
	struct _bluez_adapter *adapter = data;
	GList **interface_list = &adapter->parent->interfaces;

	DBG("%s", adapter->object_path);

	*interface_list = g_list_remove(*interface_list, data);

	bluez_adapter_list = g_list_remove(bluez_adapter_list,
						(gpointer) adapter);
	g_free(adapter->interface_name);
	g_free(adapter->object_path);
	g_object_unref(adapter->interface);

	if (adapter->media_interface)
		g_object_unref(adapter->media_interface);

	if (adapter->netserver_interface)
		g_object_unref(adapter->netserver_interface);

	g_free(adapter);
}

static void destruct_interfaces_bluez_adapter(gpointer data)
{
	struct _bluez_adapter *adapter = data;

	DBG("%s", adapter->object_path);

	bluez_adapter_list = g_list_remove(bluez_adapter_list,
						(gpointer) adapter);
	g_free(adapter->interface_name);
	g_free(adapter->object_path);
	g_object_unref(adapter->interface);

	if (adapter->media_interface)
		g_object_unref(adapter->media_interface);

	if (adapter->netserver_interface)
		g_object_unref(adapter->netserver_interface);

	g_free(adapter);
}

static void remove_device_from_head(struct _bluez_device *device)
{
	struct _device_head *head;

	head = device->head;

	if (head == NULL)
		return;

	g_hash_table_steal(head->device_hash, (gpointer) device->object_path);

	device->head = NULL;

	DBG("");
	if (head->adapter != NULL) {
		struct _bluez_adapter *adapter = head->adapter;

		if (adapter->device_removed_cb)
			adapter->device_removed_cb(device,
					adapter->device_removed_data);
	}

	/*
	 * Free head when adapter was destructed and
	 * no device attached in the head
	 */
	if (g_hash_table_size(head->device_hash) != 0)
		return;

	if (head->adapter != NULL)
		return;

	device_head_list = g_list_remove(device_head_list,
					(gpointer) head);

	free_device_head(head);
}

static void free_gatt_service_head(struct _gatt_service_head *head)
{
	DBG("%s", head->device_path);

	g_free(head->device_path);
	g_hash_table_destroy(head->gatt_service_hash);
	g_free(head);
}

static void detach_gatt_service_head(struct _bluez_device *device)
{
	struct _gatt_service_head *head = NULL;
	GList *list, *next;

	for (list = g_list_first(gatt_service_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		if (head->device_path == NULL)
			continue;

		if (!g_strcmp0(head->device_path, device->object_path)) {
			device->service_head = NULL;
			head->device = NULL;
			break;
		}
	}

	if (head == NULL)
		return;

	if (g_hash_table_size(head->gatt_service_hash) == 0) {
		gatt_service_head_list = g_list_remove(gatt_service_head_list,
							(gpointer) head);
		free_gatt_service_head(head);
	}

	return;
}

static void unregister_bluez_device(struct _bluez_device *device)
{
	DBG("device path %s", device->object_path);

	g_hash_table_steal(bluez_device_hash, device->object_path);

	remove_device_from_head(device);

	detach_gatt_service_head(device);
}

static void remove_service_from_head(struct _bluez_gatt_service *service)
{
	struct _gatt_service_head *head;

	head = service->head;

	if (head == NULL)
		return;

	g_hash_table_steal(head->gatt_service_hash,
				(gpointer) service->object_path);

	service->head = NULL;

	DBG("");

	if (g_hash_table_size(head->gatt_service_hash) != 0)
		return;

	if (head->device != NULL)
		return;

	gatt_service_head_list = g_list_remove(gatt_service_head_list,
					(gpointer) head);

	free_gatt_service_head(head);
}

static void free_gatt_char_head(struct _gatt_char_head *head)
{
	DBG("%s", head->gatt_service_path);

	g_free(head->gatt_service_path);
	g_hash_table_destroy(head->gatt_char_hash);
	g_free(head);
}

static void detach_gatt_char_head(struct _bluez_gatt_service *service)
{
	struct _gatt_char_head *head = NULL;
	GList *list, *next;

	for (list = g_list_first(gatt_char_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		if (head->gatt_service_path == NULL)
			continue;

		if (!g_strcmp0(head->gatt_service_path, service->object_path)) {
			service->char_head = NULL;
			head->service = NULL;
			break;
		}
	}

	if (head == NULL)
		return;

	if (g_hash_table_size(head->gatt_char_hash) == 0) {
		gatt_char_head_list = g_list_remove(gatt_char_head_list,
							(gpointer) head);
		free_gatt_char_head(head);
	}

	return;
}

static void unregister_bluez_gatt_service(struct _bluez_gatt_service *service)
{
	DBG("service path %s", service->object_path);

	g_hash_table_steal(bluez_gatt_service_hash, service->object_path);

	remove_service_from_head(service);

	detach_gatt_char_head(service);

}

static void remove_char_from_head(struct _bluez_gatt_char *characteristic)
{
	struct _gatt_char_head *head;

	head = characteristic->head;

	if (head == NULL)
		return;

	g_hash_table_steal(head->gatt_char_hash,
			(gpointer) characteristic->object_path);

	characteristic->head = NULL;

	DBG("");

	if (g_hash_table_size(head->gatt_char_hash) != 0)
		return;

	if (head->service != NULL)
		return;

	gatt_char_head_list = g_list_remove(gatt_char_head_list,
					(gpointer) head);

	free_gatt_char_head(head);
}

static void free_gatt_desc_head(struct _gatt_desc_head *head)
{
	DBG("%s", head->gatt_char_path);

	g_free(head->gatt_char_path);
	g_hash_table_destroy(head->gatt_desc_hash);
	g_free(head);
}

static void detach_gatt_desc_head(struct _bluez_gatt_char *characteristic)
{
	struct _gatt_desc_head *head = NULL;
	GList *list, *next;

	for (list = g_list_first(gatt_desc_head_list); list; list = next) {
		head = list->data;

		next = g_list_next(list);

		if (head->gatt_char_path == NULL)
			continue;

		if (!g_strcmp0(head->gatt_char_path,
			characteristic->object_path)) {
			characteristic->desc_head = NULL;
			head->characteristic = NULL;
			break;
		}
	}

	if (head == NULL)
		return;

	if (g_hash_table_size(head->gatt_desc_hash) == 0) {
		gatt_desc_head_list = g_list_remove(gatt_desc_head_list,
							(gpointer) head);
		free_gatt_desc_head(head);
	}

	return;
}

static void unregister_bluez_gatt_char(struct _bluez_gatt_char *characteristic)
{
	DBG("characteristic path %s", characteristic->object_path);

	g_hash_table_steal(bluez_gatt_char_hash, characteristic->object_path);

	remove_char_from_head(characteristic);

	detach_gatt_desc_head(characteristic);
}

static void remove_desc_from_head(struct _bluez_gatt_desc *descriptor)
{
	struct _gatt_desc_head *head;

	head = descriptor->head;

	if (head == NULL)
		return;

	g_hash_table_steal(head->gatt_desc_hash,
			(gpointer) descriptor->object_path);

	descriptor->head = NULL;

	DBG("");

	if (g_hash_table_size(head->gatt_desc_hash) != 0)
		return;

	if (head->characteristic != NULL)
		return;

	gatt_desc_head_list = g_list_remove(gatt_desc_head_list,
					(gpointer) head);

	free_gatt_desc_head(head);
}

static void unregister_bluez_gatt_desc(struct _bluez_gatt_desc *descriptor)
{
	DBG("descriptor path %s", descriptor->object_path);

	g_hash_table_steal(bluez_gatt_desc_hash, descriptor->object_path);

	remove_desc_from_head(descriptor);
}

static void destruct_bluez_object_interfaces(struct _bluez_object *object)
{
	GList *list, *next;

	DBG("interfaces %p", object->interfaces);

	for (list = g_list_first(object->interfaces); list; list = next) {
		const char **interface_name = list->data;
		next = g_list_next(list);

		if (!g_strcmp0(*interface_name, ADAPTER_INTERFACE)) {
			struct _bluez_adapter *adapter = list->data;
			unregister_bluez_adapter(adapter);
			destruct_interfaces_bluez_adapter(adapter);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, DEVICE_INTERFACE)) {
			struct _bluez_device *device = list->data;
			unregister_bluez_device(device);
			destruct_interfaces_bluez_device(device);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, GATT_SERVICE_IFACE)) {
			struct _bluez_gatt_service *service = list->data;
			unregister_bluez_gatt_service(service);
			destruct_interfaces_bluez_gatt_service(service);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, GATT_CHR_IFACE)) {
			struct _bluez_gatt_char *characteristic = list->data;
			unregister_bluez_gatt_char(characteristic);
			destruct_interfaces_bluez_gatt_char(characteristic);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, GATT_DESCRIPTOR_IFACE)) {
			struct _bluez_gatt_desc *descriptor = list->data;
			unregister_bluez_gatt_desc(descriptor);
			destruct_interfaces_bluez_gatt_desc(descriptor);
			list->data = NULL;
			continue;
		}

		WARN("unknown interface name %s", *interface_name);
	}

	g_list_free(object->interfaces);

	object->interfaces = NULL;
}

static void destruct_bluez_object(gpointer data)
{
	struct _bluez_object *object = data;

	DBG("");

	bluez_object_list = g_list_remove(bluez_object_list, object);

	destruct_bluez_object_interfaces(object);

	g_free(object->path_name);
	g_object_unref(object->obj);
	g_object_unref(object->properties_proxy);

	g_free(object);
}

static void object_added(GDBusObjectManager *manger, GDBusObject *object,
							gpointer user_data)
{
	DBG("");

	parse_object(object, user_data);
}

static void parse_bluez_object_removed(gpointer data, gpointer user_data)
{
	struct _bluez_object *bluez_object = user_data;
	GDBusInterface *interfaces = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interfaces);
	const gchar *iface_name;

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s, %s", iface_name, bluez_object->path_name);

	if (g_strcmp0(iface_name, MEDIATRANSPORT_INTERFACE) == 0) {
		gchar *device_address;
		device_address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		if (device_address == NULL)
			return;

		convert_device_path_to_address(bluez_object->path_name,
							device_address);

		if (audio_state_cb) {
			audio_state_cb(0, FALSE, device_address,
				bluez_object->media_type, audio_state_cb_data);
		}

		if (avrcp_target_cb)
			avrcp_target_cb(device_address, FALSE,
							avrcp_target_cb_data);
	}
}

static void object_removed(GDBusObjectManager *manger, GDBusObject *object,
				gpointer user_data)
{
	struct _bluez_object *bluez_object;
	const gchar *object_path;
	GList *ifaces;

	object_path = g_dbus_object_get_object_path(object);
	DBG("object path: %s", object_path);

	bluez_object = get_object_from_path(object_path);
	if (object == NULL)
		return;

	ifaces = g_dbus_object_get_interfaces(object);

	g_list_foreach(ifaces, parse_bluez_object_removed, bluez_object);

	g_hash_table_remove(bluez_object_hash,
				(gconstpointer) bluez_object->path_name);
}

int bluez_lib_init(void)
{
	GList *obj_list;

	DBG("");

	if (object_manager != NULL)
		return 0;

	object_manager = g_dbus_object_manager_client_new_for_bus_sync(
							G_BUS_TYPE_SYSTEM,
							0,
							BLUEZ_NAME,
							OBJECT_MANAGE_PATH,
							NULL, NULL, NULL,
							NULL, NULL);
	if (object_manager == NULL) {
		ERROR("create object manager error");
		/* TODO: define error type */
		return -1;
	}

	DBG("object manager %p is created", object_manager);

	g_signal_connect(object_manager, "object-added",
				G_CALLBACK(object_added), NULL);
	g_signal_connect(object_manager, "object-removed",
				G_CALLBACK(object_removed), NULL);

	bluez_object_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_object);

	bluez_adapter_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_adapter);

	bluez_device_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_device);

	bluez_gatt_service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
					NULL, destruct_bluez_gatt_service);

	bluez_gatt_char_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_gatt_char);

	bluez_gatt_desc_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_gatt_desc);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	DBG("Objects count: %d", g_list_length(obj_list));

	g_list_foreach(obj_list, parse_object, NULL);

	return 0;
}

static void destruct_bluez_objects(void)
{
	DBG("");

	g_hash_table_destroy(bluez_object_hash);

	bluez_object_hash = NULL;

	if (this_agent) {
		free_agent(this_agent);
		this_agent = NULL;
	}

	if (this_profile) {
		free_profile(this_profile);
		this_profile = NULL;
	}
}

static void destruct_bluez_object_manager(void)
{
	g_object_unref(object_manager);

	object_manager = NULL;
}

void bluez_lib_deinit(void)
{
	destruct_bluez_objects();
	destruct_bluez_object_manager();
}

void bluez_adapter_set_alias(struct _bluez_adapter *adapter,
				const gchar *alias)
{

	GVariant *val = g_variant_new("s", alias);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "Alias", val);

	DBG("Alias %s", alias);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL,
					simple_reply_callback, NULL);
}

int bluez_adapter_set_powered(struct _bluez_adapter *adapter,
				gboolean powered)
{
	GError *error = NULL;
	GDBusConnection *connection;
	GVariant *val = g_variant_new("b", powered);
	GVariant *parameters = g_variant_new("(sv)",
					"Powered", val);

	DBG("powered %d", powered);

	connection = get_system_lib_dbus_connect();

	if (connection == NULL)
		return BLUEZ_ERROR_OPERATION_FAILED;

	g_dbus_connection_call_sync(connection, CONNMAN_DBUS_NAME,
				CONNMAN_BLUETOOTH_TECHNOLOGY_PATH,
				CONNMAN_BLUETOTOH_TECHNOLOGY_INTERFACE,
				"SetProperty",
				parameters,
				NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		return BLUEZ_ERROR_OPERATION_FAILED;
	}

	return BLUEZ_ERROR_NONE;
}

void bluez_adapter_set_discoverable(struct _bluez_adapter *adapter,
				gboolean discoverable)
{

	GVariant *val = g_variant_new("b", discoverable);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "Discoverable", val);

	DBG("discoverable %d", discoverable);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL,
					simple_reply_callback, NULL);
}

void bluez_adapter_set_discoverable_timeout(struct _bluez_adapter *adapter,
							guint32 timeout)
{
	GVariant *val = g_variant_new("u", timeout);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "DiscoverableTimeout", val);

	DBG("discoverable timeout %d", timeout);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL,
					simple_reply_callback, NULL);
}

void bluez_adapter_start_discovery(struct _bluez_adapter *adapter)
{
	DBG("proxy 0x%p", adapter->proxy);

	g_dbus_proxy_call(adapter->proxy,
			"StartDiscovery", NULL,
			0, -1, NULL,
			simple_reply_callback, NULL);

}

void bluez_adapter_stop_discovery(struct _bluez_adapter *adapter)
{
	g_dbus_proxy_call(adapter->proxy,
			"StopDiscovery", NULL,
			0, -1, NULL,
			simple_reply_callback, NULL);
}

int bluez_adapter_get_property_powered(struct _bluez_adapter *adapter,
						gboolean *powered)
{
	return property_get_boolean(adapter->property_proxy, ADAPTER_INTERFACE,
					"Powered", powered);
}

void bluez_adapter_set_powered_changed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_powered_cb_t cb,
					gpointer user_data)
{
	adapter->powered_cb = cb;
	adapter->powered_cb_data = user_data;
}

void bluez_adapter_unset_powered_changed_cb(struct _bluez_adapter *adapter)
{
	adapter->powered_cb = NULL;
	adapter->powered_cb_data = NULL;
}

void bluez_adapter_set_discoverable_changed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_discoverable_cb_t cb,
					gpointer user_data)
{
	adapter->discoverable_cb = cb;
	adapter->discoverable_cb_data = user_data;
}

void bluez_adapter_unset_discoverable_changed_cb(
					struct _bluez_adapter *adapter)
{
	adapter->discoverable_cb = NULL;
	adapter->discoverable_cb_data = NULL;
}

void bluez_adapter_set_discoverable_timeout_changed_cb(
					struct _bluez_adapter *adapter,
					bluez_adapter_discoverable_tm_cb_t cb,
					gpointer user_data)
{
	adapter->discoverable_timeout_cb = cb;
	adapter->discoverable_timeout_cb_data = user_data;
}

void bluez_adapter_unset_discoverable_timeout_changed_cb(
					struct _bluez_adapter *adapter)
{
	adapter->discoverable_timeout_cb = NULL;
	adapter->discoverable_timeout_cb_data = NULL;
}

static void new_devices(gpointer key, gpointer value, gpointer user_data)
{
	struct _bluez_device *device = value;
	struct _bluez_adapter *adapter = user_data;

	if (adapter->device_created_cb)
		adapter->device_created_cb(device,
				adapter->device_created_data);
}

void bluez_adapter_set_device_created_cb(struct _bluez_adapter *adapter,
					bluez_adapter_device_cb_t cb,
					gpointer user_data)
{
	adapter->device_created_cb = cb;
	adapter->device_created_data = user_data;

	if (!adapter->device_head)
		return;

	/* Go through the existing devices */
	g_hash_table_foreach(adapter->device_head->device_hash,
					new_devices, (gpointer) adapter);
}

void bluez_adapter_unset_device_created_cb(struct _bluez_adapter *adapter)
{
	adapter->device_created_cb = NULL;
	adapter->device_created_data = NULL;
}

void bluez_adapter_set_device_removed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_device_cb_t cb,
					gpointer user_data)
{
	adapter->device_removed_cb = cb;
	adapter->device_removed_data = user_data;
}

void bluez_adapter_unset_device_removed_cb(struct _bluez_adapter *adapter)
{
	adapter->device_removed_cb = NULL;
	adapter->device_removed_data = NULL;
}

void bluez_adapter_set_device_discovering_cb(struct _bluez_adapter *adapter,
					bluez_adapter_discovering_cb_t cb,
					gpointer user_data)
{
	adapter->discovering_cb = cb;
	adapter->discovering_cb_data = user_data;
}

void bluez_adapter_unset_device_discovering_cb(struct _bluez_adapter *adapter)
{
	adapter->discovering_cb = NULL;
	adapter->discovering_cb_data = NULL;
}

char *bluez_adapter_get_property_alias(struct _bluez_adapter *adapter)
{
	return property_get_string(adapter->property_proxy,
					ADAPTER_INTERFACE, "Alias");
}

void bluez_adapter_set_alias_changed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_alias_cb_t cb,
					gpointer user_data)
{
	adapter->alias_cb = cb;
	adapter->alias_cb_data = user_data;
}

void bluez_adapter_unset_alias_changed_cb(struct _bluez_adapter *adapter)
{
	adapter->alias_cb = NULL;
	adapter->alias_cb_data = NULL;
}

char *bluez_adapter_get_property_address(struct _bluez_adapter *adapter)
{
	return property_get_string(adapter->property_proxy,
					ADAPTER_INTERFACE, "Address");
}

int bluez_adapter_get_property_discoverable(struct _bluez_adapter *adapter,
						gboolean *discoverable)
{
	return property_get_boolean(adapter->property_proxy, ADAPTER_INTERFACE,
				"Discoverable", discoverable);
}

int bluez_adapter_get_property_discoverable_timeout(
				struct _bluez_adapter *adapter,
				guint32 *time)
{
	return property_get_uint32(adapter->property_proxy, ADAPTER_INTERFACE,
				"DiscoverableTimeout", time);
}

int bluez_adapter_get_property_discovering(struct _bluez_adapter *adapter,
						gboolean *discovering)
{
	return property_get_boolean(adapter->property_proxy, ADAPTER_INTERFACE,
					"Discovering", discovering);
}

char **bluez_adapter_get_property_uuids(struct _bluez_adapter *adapter)
{
	return property_get_string_list(adapter->property_proxy,
						ADAPTER_INTERFACE, "UUIDs");
}

static gchar *address_to_path(const gchar *prefix, const gchar *address)
{
	gchar *path, *p;

	path = g_new0(gchar, 255);
	if (path == NULL)
		return NULL;

	sprintf(path, "%s/dev_%s", prefix, address);

	p = path;
	while (*p != 0) {
		if (*p == ':')
			*p = '_';

		++p;
	}

	return path;
}

struct _bluez_device *bluez_adapter_get_device_by_path(
				struct _bluez_adapter *adapter,
				const char *path)
{
	struct _bluez_device *device = NULL;

	if (adapter == NULL || path == NULL)
		return NULL;

	if (adapter->device_head)
		device = g_hash_table_lookup(
				adapter->device_head->device_hash,
					(gconstpointer) path);

	return device;
}

struct _bluez_device *bluez_adapter_get_device_by_address(
				struct _bluez_adapter *adapter,
				const char *address)
{
	gchar *device_path;
	struct _bluez_device *device = NULL;

	if (adapter == NULL || address == NULL)
		return NULL;

	device_path = address_to_path(adapter->object_path, address);
	if (device_path == NULL)
		return NULL;

	if (adapter->device_head)
		device = g_hash_table_lookup(
				adapter->device_head->device_hash,
					(gconstpointer) device_path);

	g_free(device_path);

	return device;
}

void bluez_adapter_remove_device(struct _bluez_adapter *adapter,
					struct _bluez_device *device)
{
	g_dbus_proxy_call(adapter->proxy, "RemoveDevice",
			g_variant_new("(o)", device->object_path),
 			0, -1, NULL,
			simple_reply_callback, NULL);
}

const GList *bluez_adapter_get_devices_path(struct _bluez_adapter *adapter)
{
	if (adapter->device_head == NULL)
		return NULL;

	return g_hash_table_get_keys(adapter->device_head->device_hash);
}

GList *bluez_adapter_get_devices(struct _bluez_adapter *adapter)
{
	if (adapter->device_head == NULL)
		return NULL;

	return g_hash_table_get_values(adapter->device_head->device_hash);
}

/* Device Functions */

int bluez_device_network_connect(struct _bluez_device *device,
						const gchar *role)
{
	struct simple_reply_data *reply_data;

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return -1;
	}

	reply_data->proxy = device->network_proxy;

	DBG("%p", device->network_proxy);
	if (!device->network_proxy)
		return -1;

	g_dbus_proxy_call(device->network_proxy, "Connect",
				g_variant_new("(s)", role),
				0, -1, NULL,
				simple_reply_callback, reply_data);

	return 0;
}

int bluez_device_network_disconnect(struct _bluez_device *device)
{
	struct simple_reply_data *reply_data;

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return -1;
	}

	reply_data->proxy = device->network_proxy;

	DBG("%p", device->network_proxy);
	if (!device->network_proxy)
		return -1;

	g_dbus_proxy_call(device->network_proxy, "Disconnect",
				NULL, 0, -1, NULL,
				simple_reply_callback, reply_data);

	return 0;
}

GList *bluez_device_get_primary_services(struct _bluez_device *device)
{
	struct _gatt_service_head *service_head = device->service_head;
	struct _bluez_gatt_service *service;
	GList *primary_services = NULL;
	GList *services, *list, *next;
	int primary;

	services = g_hash_table_get_values(service_head->gatt_service_hash);

	for (list = g_list_first(services); list; list = next) {
		service = list->data;

		next = g_list_next(list);

		bluez_gatt_service_get_property_primary(service, &primary);
		if (primary)
			primary_services = g_list_append(primary_services,
							service->object_path);
	}

	return primary_services;
}

void bluez_device_network_set_connected_changed_cb(
					struct _bluez_device *device,
					bluez_device_network_connected_cb_t cb,
					gpointer user_data)
{
	device->network_connected_cb = cb;
	device->network_connected_cb_data = user_data;
}

void bluez_device_network_unset_connected_changed_cb(
					struct _bluez_device *device)
{
	device->network_connected_cb = NULL;
	device->network_connected_cb_data = NULL;
}

int bluez_device_network_get_property_connected(struct _bluez_device *device,
						gboolean *connected)
{
	return property_get_boolean(device->property_proxy, NETWORK_INTERFACE,
					"Connected", connected);
}

void bluez_device_input_set_connected_changed_cb(
					struct _bluez_device *device,
					bluez_device_input_connected_cb_t cb,
					gpointer user_data)
{
	DBG("");
	device->input_connected_cb = cb;
	device->input_connected_cb_data = user_data;
}

void bluez_device_input_unset_connected_changed_cb(
					struct _bluez_device *device)
{
	DBG("");
	device->input_connected_cb = NULL;
	device->input_connected_cb_data = NULL;
}

int bluez_device_input_get_property_connected(struct _bluez_device *device,
						gboolean *connected)
{
	return property_get_boolean(device->property_proxy,
			INPUT_INTERFACE, "Connected", connected);
}

void bluez_device_set_paired_changed_cb(struct _bluez_device *device,
					bluez_device_paired_cb_t cb,
					gpointer user_data)
{
	device->device_paired_cb = cb;
	device->device_paired_cb_data = user_data;
}

void bluez_set_paired_changed_cb(bluez_paired_cb_t cb,
					gpointer user_data)
{
	device_paired_cb = cb;
	device_paired_cb_data = user_data;
}

void bluez_device_set_connected_changed_cb(struct _bluez_device *device,
					bluez_device_connected_cb_t cb,
					gpointer user_data)
{
	device->device_connected_cb = cb;
	device->device_connected_cb_data = user_data;
}

void bluez_device_set_trusted_changed_cb(struct _bluez_device *device,
					bluez_device_trusted_cb_t cb,
					gpointer user_data)
{
	device->device_trusted_cb = cb;
	device->device_trusted_cb_data = user_data;
}

void bluez_device_unset_paired_changed_cb(struct _bluez_device *device)
{
	device->device_paired_cb = NULL;
	device->device_paired_cb_data = NULL;
}

void bluez_unset_paired_changed_cb(void)
{
	device_paired_cb = NULL;
	device_paired_cb_data = NULL;
}

void bluez_device_unset_connected_changed_cb(struct _bluez_device *device)
{
	device->device_connected_cb = NULL;
	device->device_connected_cb_data = NULL;
}

void bluez_device_unset_trusted_changed_cb(struct _bluez_device *device)
{
	device->device_trusted_cb = NULL;
	device->device_trusted_cb_data = NULL;
}

void bluez_device_set_trusted(struct _bluez_device *device,
					gboolean trusted)
{
	GVariant *val = g_variant_new("b", trusted);
	GVariant *parameter = g_variant_new("(ssv)",
				DEVICE_INTERFACE, "Trusted", val);

	g_dbus_proxy_call(device->parent->properties_proxy,
					"Set", parameter, 0,
					-1, NULL,
					simple_reply_callback, NULL);
}

int bluez_device_set_blocked(struct _bluez_device *device,
					gboolean blocked)
{
	GError *error = NULL;
	GVariant *ret;
	GVariant *val = g_variant_new("b", blocked);
	GVariant *parameter = g_variant_new("(ssv)",
				DEVICE_INTERFACE, "Blocked", val);

	DBG("");

	ret = g_dbus_proxy_call_sync(device->parent->properties_proxy,
					"Set", parameter, 0,
					-1, NULL, &error);

	if (ret == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_unref(ret);

	return 0;
}

void bluez_device_set_alias(struct _bluez_device *device,
					const gchar *alias)
{
	GVariant *val = g_variant_new("s", alias);
	GVariant *parameter = g_variant_new("(ssv)",
				DEVICE_INTERFACE, "Alias", val);

	g_dbus_proxy_call(device->parent->properties_proxy,
					"Set", parameter, 0,
					-1, NULL,
					simple_reply_callback, NULL);
}

char **bluez_device_get_property_uuids(struct _bluez_device *device)
{
	return property_get_string_list(device->property_proxy,
					DEVICE_INTERFACE, "UUIDs");
}

char *bluez_device_get_property_address(struct _bluez_device *device)
{
	return property_get_string(device->property_proxy,
					DEVICE_INTERFACE, "Address");
}

char *bluez_device_get_property_alias(struct _bluez_device *device)
{
	return property_get_string(device->property_proxy,
					DEVICE_INTERFACE, "Alias");
}

int bluez_device_get_property_class(struct _bluez_device *device,
					guint32 *class)
{
	return property_get_uint32(device->property_proxy,
				DEVICE_INTERFACE, "Class", class);
}

int bluez_device_get_property_appearance(struct _bluez_device *device,
					guint16 *appearance)
{
	return property_get_uint16(device->property_proxy,
				DEVICE_INTERFACE,
				"Appearance", appearance);
}

int bluez_device_get_property_paired(struct _bluez_device *device,
					gboolean *paired)
{
	return property_get_boolean(device->property_proxy, DEVICE_INTERFACE,
						"Paired", paired);
}

int bluez_device_get_property_trusted(struct _bluez_device *device,
					gboolean *trusted)
{
	return property_get_boolean(device->property_proxy, DEVICE_INTERFACE,
						"Trusted", trusted);
}

int bluez_device_get_property_connected(struct _bluez_device *device,
					gboolean *connected)
{
	return property_get_boolean(device->property_proxy, DEVICE_INTERFACE,
						"Connected", connected);
}

int bluez_device_get_property_rssi(struct _bluez_device *device,
					gint16 *rssi)
{
	return property_get_int16(device->property_proxy, DEVICE_INTERFACE,
					"RSSI", rssi);
}

char *bluez_device_get_property_icon(struct _bluez_device *device)
{
	return property_get_string(device->property_proxy, DEVICE_INTERFACE,
					"Icon");
}

struct profile_connect_state_notify {
	struct _bluez_device *device;
	profile_connect_cb_t cb;
};

struct profile_disconnect_state_notify {
	struct _bluez_device *device;
	profile_disconnect_cb_t cb;
};

struct device_connect_state_notify {
	struct _bluez_device *device;
	device_connect_cb_t cb;
};

struct device_disconnect_state_notify {
	struct _bluez_device *device;
	device_disconnect_cb_t cb;
};

static inline enum device_pair_state get_pairing_error_state(GError *error)
{
	if (g_strrstr(error->message,
			"org.bluez.Error.AuthenticationFailed"))
		return AUTHENTICATION_FAILED;
	else if (g_strrstr(error->message,
			"org.bluez.Error.AuthenticationCanceled"))
		return AUTHENTICATION_CANCELED;
	else if (g_strrstr(error->message,
			"org.bluez.Error.AuthenticationRejected"))
		return AUTHENTICATION_REJECTED;
	else if (g_strrstr(error->message,
			"org.bluez.Error.AuthenticationTimeout"))
		return AUTHENTICATION_TIMEOUT;
	else if (g_strrstr(error->message,
			"org.bluez.Error.ConnectionAttemptFailed"))
		return CONNECTION_ATTEMP_FAILED;
	else
		WARN("Unknown error state");

	return UNKNOWN_PAIRING_ERROR;
}

void bluez_device_pair(struct _bluez_device *device,
				simple_reply_cb_t pair_cb,
				void *user_data)
{
	struct simple_reply_data *reply_data;

	DBG("");

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = device->proxy;
	reply_data->reply_cb = pair_cb;
	reply_data->user_data = user_data;

	g_dbus_proxy_call(device->proxy,
			"Pair", NULL,
			0, -1, NULL,
			simple_reply_callback,
			reply_data);
}

void bluez_device_cancel_pair(struct _bluez_device *device,
				simple_reply_cb_t cancel_pair_cb,
				void *user_data)
{
	struct simple_reply_data *reply_data;

	DBG("");

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = device->proxy;
	reply_data->reply_cb = cancel_pair_cb;
	reply_data->user_data = user_data;

	g_dbus_proxy_call(device->proxy,
			"CancelPairing", NULL,
			0, -1, NULL,
			simple_reply_callback,
			reply_data);
}

static void device_profile_connect_cb(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	GVariant *ret;
	struct _bluez_device *device;
	profile_connect_cb_t profile_connect_cb;
	struct profile_connect_state_notify *notify = user_data;
	GError *error = NULL;

	DBG("");

	device = notify->device;
	profile_connect_cb = notify->cb;

	if (profile_connect_cb == NULL)
		return;

	ret = g_dbus_proxy_call_finish(device->proxy,
					res, &error);

	if (ret == NULL) {
		if (g_strrstr(error->message,
				"org.bluez.Error.DoesNotExist"))
			profile_connect_cb(device, PROFILE_NOT_EXIST);
		else if (g_strrstr(error->message,
				"org.bluez.Error.AlreadyConnected"))
			profile_connect_cb(device, PROFILE_ALREADY_CONNECTED);
		else if (g_strrstr(error->message,
				"org.bluez.Error.ConnectFailed"))
			profile_connect_cb(device, PROFILE_CONNECT_FAILED);
		else
			DBG("error: %s", error->message);
	} else {
		profile_connect_cb(device, PROFILE_CONNECT_SUCCESS);

		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_device_connect_profile(struct _bluez_device *device,
				const char *uuid,
				profile_connect_cb_t pf_connect_cb)
{
	struct profile_connect_state_notify *notify;

	if (!uuid) {
		DBG("uuid is null");
		return;
	}

	DBG("uuid = %s", uuid);

	notify = g_try_new0(struct profile_connect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = pf_connect_cb;

	g_dbus_proxy_call(device->proxy,
			"ConnectProfile", g_variant_new("(s)", uuid),
			0, -1, NULL,
			device_profile_connect_cb, notify);
}

void bluez_device_connect_all(struct _bluez_device *device,
				profile_connect_cb_t pf_connect_cb)
{
	struct profile_connect_state_notify *notify;

	DBG("");

	notify = g_try_new0(struct profile_connect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = pf_connect_cb;

	g_dbus_proxy_call(device->proxy,
			"Connect", NULL, 0, -1, NULL,
			device_profile_connect_cb, notify);
}

static void device_profile_disconnect_cb(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	GVariant *ret;
	struct _bluez_device *device;
	profile_disconnect_cb_t profile_disconnect_cb;
	struct profile_disconnect_state_notify *notify = user_data;
	GError *error = NULL;

	DBG("");

	device = notify->device;
	profile_disconnect_cb = notify->cb;

	if (profile_disconnect_cb == NULL)
		return;

	ret = g_dbus_proxy_call_finish(device->proxy,
					res, &error);

	if (ret == NULL) {
		if (g_strrstr(error->message,
				"org.bluez.Error.DoesNotExist"))
			profile_disconnect_cb(device, PROFILE_NOT_EXIST);
		else if (g_strrstr(error->message,
				"org.bluez.Error.NotConnected"))
			profile_disconnect_cb(device, PROFILE_NOT_CONNECTED);
		else if (g_strrstr(error->message,
				"org.bluez.Error.NotSupported"))
			profile_disconnect_cb(device, PROFILE_NOT_SUPPORTED);
		else if (g_strrstr(error->message,
				"org.bluez.Error.Failed"))
			profile_disconnect_cb(device, PROFILE_DISCONNECT_FAILED);
		else
			DBG("error: %s", error->message);
	} else {
		profile_disconnect_cb(device, PROFILE_DISCONNECT_SUCCESS);

		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_device_disconnect_all(struct _bluez_device *device,
				profile_disconnect_cb_t pf_disconnect_cb)
{
	struct profile_disconnect_state_notify *notify;

	DBG("");

	notify = g_try_new0(struct profile_disconnect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = pf_disconnect_cb;

	g_dbus_proxy_call(device->proxy,
			"Disconnect", NULL, 0, -1, NULL,
			device_profile_disconnect_cb, notify);
}

void bluez_device_disconnect_profile(struct _bluez_device *device,
				const char *uuid,
				profile_disconnect_cb_t pf_disconnect_cb)
{
	struct profile_disconnect_state_notify *notify;

	if (!uuid) {
		DBG("uuid is null");
		return;
	}

	DBG("uuid = %s", uuid);

	notify = g_try_new0(struct profile_disconnect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = pf_disconnect_cb;

	g_dbus_proxy_call(device->proxy,
			"DisconnectProfile", g_variant_new("(s)", uuid),
			0, -1, NULL,
			device_profile_disconnect_cb, notify);
}

/* Agent Functions */

static const gchar *get_capability_string(enum bluez_agent_cap capability)
{
	switch (capability) {
	case DISPLAY_ONLY:
		return "DisplayOnly";
	case DISPLAY_YES_NO:
		return "DisplayYesNo";
	case KEYBOAR_DONLY:
		return "KeyboardOnly";
	case NO_INPUT_NO_OUTPUT:
		return "NoInputNoOutput";
	case KEYBOARD_DISPLAY:
		return "KeyboardDisplay";
	default:
		return NULL;
	}
}

void bluez_agent_register_agent(const gchar *path,
				enum bluez_agent_cap capability,
				simple_reply_cb_t register_agent_cb,
				void *user_data)
{
	struct simple_reply_data *reply_data;
	const gchar *cap_string;

	DBG("");

	cap_string = get_capability_string(capability);
	if (cap_string == NULL) {
		ERROR("parameter capability error");
		return;
	}

	reply_data = g_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = this_agent->proxy;
	reply_data->reply_cb = register_agent_cb;
	reply_data->user_data = user_data;

	DBG("%s %s", path, cap_string);
	g_dbus_proxy_call(this_agent->proxy,
				"RegisterAgent",
				g_variant_new("(os)",
					path, cap_string),
				0, -1, NULL,
				simple_reply_callback, reply_data);
}

void bluez_agent_unregister_agent(const gchar *path,
				simple_reply_cb_t unregister_agent_cb,
				void *user_data)
{
	struct simple_reply_data *reply_data;

	DBG("path %s", path);

	reply_data = g_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = this_agent->proxy;
	reply_data->reply_cb = unregister_agent_cb;
	reply_data->user_data = user_data;

	g_dbus_proxy_call(this_agent->proxy,
				"UnregisterAgent",
				g_variant_new("(o)", path),
				0, -1, NULL,
				simple_reply_callback,
				reply_data);
}

void bluez_agent_request_default_agent(const gchar *path)
{
	DBG("path %s", path);

	g_dbus_proxy_call(this_agent->proxy,
				"RequestDefaultAgent",
				g_variant_new("(o)", path),
				0, -1, NULL,
				simple_reply_callback, NULL);
}

void bluez_profile_register_profile(const gchar *path, const gchar *uuid,
				GVariantBuilder *opts,
				simple_reply_cb_t callback,
				void *user_data)
{
	struct simple_reply_data *reply_data;

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = this_profile->proxy;
	reply_data->reply_cb = callback;
	reply_data->user_data = user_data;

	g_dbus_proxy_call(this_profile->proxy, "RegisterProfile",
				g_variant_new("(osa{sv})", path,
						uuid, opts),
				0, -1, NULL,
				simple_reply_callback, reply_data);
}

enum bluez_error_type bluez_profile_register_profile_sync(const gchar *path,
				const gchar *uuid, GVariantBuilder *opts)
{
	enum bluez_error_type err_type = ERROR_NONE;
	GError *error = NULL;

	g_dbus_proxy_call_sync(this_profile->proxy, "RegisterProfile",
				g_variant_new("(osa{sv})", path, uuid, opts),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error != NULL) {
		err_type = get_error_type(error);

		g_error_free(error);
	}

	return err_type;
}

void bluez_profile_unregister_profile(const gchar *path,
				simple_reply_cb_t callback, void *user_data)
{
	struct simple_reply_data *reply_data;

	reply_data = g_try_new0(struct simple_reply_data, 1);
	if (reply_data == NULL) {
		ERROR("no memory");
		return;
	}

	reply_data->proxy = this_profile->proxy;
	reply_data->reply_cb = callback;
	reply_data->user_data = user_data;

	g_dbus_proxy_call(this_profile->proxy, "UnregisterProfile",
				g_variant_new("(o)", path),
				0, -1, NULL,
				simple_reply_callback, reply_data);
}

enum bluez_error_type  bluez_profile_unregister_profile_sync(const gchar *path)
{
	enum bluez_error_type err_type = ERROR_NONE;
	GError *error = NULL;

	g_dbus_proxy_call_sync(this_profile->proxy, "UnregisterProfile",
				g_variant_new("(o)", path),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error != NULL) {
		err_type = get_error_type(error);

		g_error_free(error);
	}

	return err_type;
}

static gboolean bluez_set_property(struct _bluez_adapter *adapter,
				const char *key, GVariant *val)
{
	GDBusConnection  *conn;
	GError *error;
	GVariantBuilder *builder =
			g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

	DBG("");

	error = NULL;

	DBG("key = %s", key);

	g_variant_builder_add(builder, "{sv}", key, val);
	conn = g_dbus_proxy_get_connection(adapter->media_proxy);

	g_dbus_connection_emit_signal(conn, NULL,
			BT_MEDIA_OBJECT_PATH, PROPERTIES_INTERFACE,
			"PropertiesChanged",
			g_variant_new("(sa{sv})",
			MEDIA_PLAYER_INTERFACE, builder),
			&error);

	return error == NULL;
}

static gboolean bluez_set_metadata(struct _bluez_adapter *adapter,
				const char *key, GVariant *val)
{
	GDBusConnection  *conn;
	GError *error;
	GVariant *val_metadata;
	GVariantBuilder *builder =
				g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	GVariantBuilder *builder_array =
				g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

	DBG("");

	error = NULL;

	g_variant_builder_add(builder_array, "{sv}", key, val);

	val_metadata = g_variant_new("a{sv}", builder_array);
	g_variant_builder_add(builder, "{sv}", "Metadata", val_metadata);

	conn = g_dbus_proxy_get_connection(adapter->media_proxy);

	g_dbus_connection_emit_signal(conn, NULL,
			BT_MEDIA_OBJECT_PATH, PROPERTIES_INTERFACE,
			"PropertiesChanged",
			g_variant_new("(sa{sv})",
			MEDIA_PLAYER_INTERFACE, builder),
			&error);

	return error == NULL;
}

static int bluez_avrcp_set_interal_property(struct _bluez_adapter *adapter,
				int type, media_player_settings_t *properties)
{
	int value;
	gboolean shuffle;
	GVariant *val;

	DBG("");

	switch (type) {
	case LOOPSTATUS:
		value = properties->loopstatus;
		DBG("LOOPSTATUS loop = %s",
					loopstatus_settings[value].property);
		val = g_variant_new("s", loopstatus_settings[value].property);
		if (!bluez_set_property(adapter, "LoopStatus", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
		break;
	case SHUFFLE:
		value = properties->shuffle;
		if (g_strcmp0(shuffle_settings[value].property, "off") == 0)
			shuffle = FALSE;
		else
			shuffle = TRUE;
		val = g_variant_new("b", shuffle);
		if (!bluez_set_property(adapter, "Shuffle", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
		break;
	case PLAYBACKSTATUS:
		value = properties->playbackstatus;
		val = g_variant_new("s", playback_status[value].property);
		if (!bluez_set_property(adapter, "PlaybackStatus", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
		break;
	case POSITION:
		value = properties->position;
		val = g_variant_new("x", value);
		if (!bluez_set_property(adapter, "Position", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
		break;
	default:
		DBG("Invalid Type\n");
		return -1;
	}

	return 0;
}

int bluez_media_player_set_track_info(struct _bluez_adapter *adapter,
			media_metadata_attributes_t *meta_data)
{
	GVariant *val;
	GVariant *str_array[1];
	GVariant *val_array;

	DBG("");

	if (meta_data->title) {
		val = g_variant_new("s", meta_data->title);
		if (!bluez_set_metadata(adapter, "xesam:title", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	if (meta_data->artist) {
		const char *artist = meta_data->artist[0];
		val = g_variant_new_string(artist);
		str_array[0] = val;
		val_array = g_variant_new_array(G_VARIANT_TYPE_STRING,
							str_array, 1);
		if (!bluez_set_metadata(adapter, "xesam:artist",
							val_array)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	if (meta_data->album) {
		val = g_variant_new("s", meta_data->album);
		if (!bluez_set_metadata(adapter, "xesam:album", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	if (meta_data->genre) {
		const char *genre = meta_data->genre[0];
		val = g_variant_new_string(genre);
		str_array[0] = val;
		val_array = g_variant_new_array(G_VARIANT_TYPE_STRING,
							str_array, 1);
		if (!bluez_set_metadata(adapter, "xesam:genre",
							val_array)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	if (0 != meta_data->tracknumber) {
		val = g_variant_new("i", meta_data->tracknumber);
		if (!bluez_set_metadata(adapter, "xesam:trackNumber",
								val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	if (0 != meta_data->duration) {
		val = g_variant_new("x", meta_data->duration);
		if (!bluez_set_metadata(adapter, "mpris:length", val)) {
			DBG("Error sending the PropertyChanged signal\n");
			return -1;
		}
	}

	return 0;
}

int bluez_media_player_change_property(struct _bluez_adapter *adapter,
				media_player_property_type type,
				unsigned int value)
{
	media_player_settings_t properties;
	int ret;

	DBG("+");

	switch (type) {
	case LOOPSTATUS:
		properties.loopstatus = value;
		break;
	case SHUFFLE:
		properties.shuffle = value;
		break;
	case PLAYBACKSTATUS:
		properties.playbackstatus = value;
		break;
	case POSITION:
		properties.position = value;
		break;
	default:
		DBG("Invalid Type\n");
		return -1;
	}

	ret = bluez_avrcp_set_interal_property(adapter,
						type, &properties);

	DBG("-");
	return ret;
}

int bluez_media_player_set_properties(struct _bluez_adapter *adapter,
				media_player_settings_t *properties)
{

	if (bluez_avrcp_set_interal_property(adapter,
				LOOPSTATUS, properties) != 0)
		return -1;

	if (bluez_avrcp_set_interal_property(adapter,
				SHUFFLE, properties) != 0)
		return -1;

	if (bluez_avrcp_set_interal_property(adapter,
				PLAYBACKSTATUS, properties) != 0)
		return -1;

	if (bluez_avrcp_set_interal_property(adapter,
				POSITION, properties) != 0)
		return -1;

	return 0;
}

static gboolean handle_set_property(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *property_name,
				GVariant *value,
				GError **error,
				gpointer user_data)
{
	if (g_strcmp0(property_name, "LoopStatus") == 0) {
		const gchar *loopstatus =
				g_variant_get_string(value, NULL);
		DBG("loopstatus = %s", loopstatus);

		if (avrcp_repeat_cb)
			avrcp_repeat_cb(loopstatus, avrcp_repeat_cb_data);
	} else if (g_strcmp0(property_name, "Shuffle") == 0) {
		gboolean shuffle_mode = g_variant_get_boolean(value);
		if (shuffle_mode == TRUE)
			DBG("shuffle_mode TRUE");
		else
			DBG("shuffle_mode FALSE");

		if (avrcp_shuffle_cb)
			avrcp_shuffle_cb(shuffle_mode, avrcp_shuffle_cb_data);
	}

	return *error == NULL;
}

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.mpris.MediaPlayer2.Player'>"
	"    <property type='b' name='Shuffle' access='readwrite'/>"
	"    <property type='s' name='LoopStatus' access='readwrite'/>"
	"  </interface>"
	"</node>";

static const GDBusInterfaceVTable interface_vtable = {
	NULL,
	NULL,
	handle_set_property
};

static GDBusNodeInfo *introspection_data;

static guint _bluez_register_avrcp_property(struct _bluez_adapter *adapter)
{
	guint rid;
	GDBusConnection  *conn;

	conn = g_dbus_proxy_get_connection(adapter->media_proxy);

	introspection_data = g_dbus_node_info_new_for_xml(introspection_xml,
								NULL);

	rid = g_dbus_connection_register_object(conn, BT_MEDIA_OBJECT_PATH,
					introspection_data->interfaces[0],
					&interface_vtable,
					NULL,
					NULL,
					NULL);

	return rid;
}

static void _bluez_unregister_avrcp_property(
					struct _bluez_adapter *adapter,
					int avrcp_registration_id)
{
	GDBusConnection  *conn;

	conn = g_dbus_proxy_get_connection(adapter->media_proxy);

	g_dbus_connection_unregister_object(conn,
					avrcp_registration_id);
}

int bluez_media_register_player(struct _bluez_adapter *adapter)
{
	GError *error = NULL;
	GVariant *str_array[1];
	GVariant *val_array;
	GVariant *val_metadata;

	GVariantBuilder *builder;
	GVariantBuilder *builder_array;

	DBG("+");

	if (adapter == NULL) {
		ERROR("adapter is NULL");
		return -1;
	}

	if (adapter->media_proxy == NULL) {
		ERROR("adapter->mediaprooxy is NULL");
		return -1;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	builder_array = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

	GVariant *val = g_variant_new("s", "None");
	g_variant_builder_add(builder, "{sv}", "LoopStatus", val);

	val = g_variant_new("b", FALSE);
	g_variant_builder_add(builder, "{sv}", "Shuffle", val);

	val = g_variant_new("s", "Stopped");
	g_variant_builder_add(builder, "{sv}", "PlaybackStatus", val);

	val = g_variant_new("x", 0);
	g_variant_builder_add(builder, "{sv}", "Position", val);

	val = g_variant_new_string("\0");
	str_array[0] = val;
	val_array = g_variant_new_array(G_VARIANT_TYPE_STRING, str_array, 1);
	g_variant_builder_add(builder_array, "{sv}", "xesam:artist", val_array);

	val = g_variant_new_string("\0");
	str_array[0] = val;
	val_array = g_variant_new_array(G_VARIANT_TYPE_STRING, str_array, 1);
	g_variant_builder_add(builder_array, "{sv}", "xesam:genre", val_array);

	val = g_variant_new("s", "\0");
	g_variant_builder_add(builder_array, "{sv}", "xesam:title", val);

	val = g_variant_new("i", 0);
	g_variant_builder_add(builder_array, "{sv}", "xesam:trackNumber", val);

	val = g_variant_new("s", "\0");
	g_variant_builder_add(builder_array, "{sv}", "xesam:album", val);

	val = g_variant_new("x", 0);
	g_variant_builder_add(builder_array, "{sv}", "mpris:length", val);

	val_metadata = g_variant_new("a{sv}", builder_array);
	g_variant_builder_add(builder, "{sv}", "Metadata", val_metadata);

	if (adapter->avrcp_registration_id == 0)
		adapter->avrcp_registration_id =
			_bluez_register_avrcp_property(adapter);

	g_dbus_proxy_call_sync(adapter->media_proxy,
			"RegisterPlayer",
			g_variant_new("(oa{sv})",
				BT_MEDIA_OBJECT_PATH, builder),
			0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);

		if (adapter->avrcp_registration_id)
			_bluez_unregister_avrcp_property(adapter,
					adapter->avrcp_registration_id);

		adapter->avrcp_registration_id = 0;
		return -1;
	}

	DBG("-");
	return 0;
}

void bluez_media_unregister_player(struct _bluez_adapter *adapter)
{
	DBG("+");

	if (adapter == NULL) {
		ERROR("adapter is NULL");
		return;
	}

	if (adapter->media_proxy == NULL) {
		ERROR("adapter->mediaprooxy is NULL");
		return;
	}

	g_dbus_proxy_call_sync(adapter->media_proxy,
			"UnregisterPlayer",
			g_variant_new("(o)", BT_MEDIA_OBJECT_PATH),
			0, -1, NULL, NULL);

	if (adapter->avrcp_registration_id)
		_bluez_unregister_avrcp_property(adapter,
				adapter->avrcp_registration_id);

	adapter->avrcp_registration_id = 0;

	DBG("-");
	return;
}

static void bluez_device_connect_cb(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	GVariant *ret;
	struct _bluez_device *device;
	device_connect_cb_t device_connect_cb;
	struct device_connect_state_notify *notify = user_data;
	GError *error = NULL;

	DBG("");

	device = notify->device;
	device_connect_cb = notify->cb;

	if (device_connect_cb == NULL)
		return;

	ret = g_dbus_proxy_call_finish(device->proxy,
					res, &error);

	if (ret == NULL) {
		if (g_strrstr(error->message,
				"org.bluez.Error.NotReady"))
			device_connect_cb(device, DEVICE_NOT_READY,
					dev_connect_data);
		else if (g_strrstr(error->message,
				"org.bluez.Error.AlreadyConnected"))
			device_connect_cb(device, DEVICE_ALREADY_CONNECTED,
					dev_connect_data);
		else if (g_strrstr(error->message,
				"org.bluez.Error.Failed"))
			device_connect_cb(device, DEVICE_CONNECT_FAILED,
					dev_connect_data);
		else if (g_strrstr(error->message,
				"org.bluez.Error.InProgress"))
			device_connect_cb(device, DEVICE_CONNECT_INPROGRESS,
					dev_connect_data);
		else
			DBG("error: %s", error->message);
	} else {
		device_connect_cb(device, DEVICE_CONNECT_SUCCESS,
				dev_connect_data);

		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_device_connect_le(struct _bluez_device *device)
{
	struct device_connect_state_notify *notify;

	notify = g_try_new0(struct device_connect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = dev_connect_cb;

	g_dbus_proxy_call(device->proxy,
			"Connect", NULL,
			0, -1, NULL,
			bluez_device_connect_cb, notify);

}

static void bluez_device_disconnect_cb(GObject *source_object,
						GAsyncResult *res,
						gpointer user_data)
{
	GVariant *ret;
	struct _bluez_device *device;
	device_disconnect_cb_t device_disconnect_cb;
	struct device_disconnect_state_notify *notify = user_data;
	GError *error = NULL;

	DBG("");

	device = notify->device;
	device_disconnect_cb = notify->cb;

	if (device_disconnect_cb == NULL)
		return;

	ret = g_dbus_proxy_call_finish(device->proxy,
					res, &error);

	if (ret == NULL) {
		if (g_strrstr(error->message,
				"org.bluez.Error.NotConnected"))
			device_disconnect_cb(device, DEVICE_NOT_CONNECTED,
					dev_disconnect_data);
	} else {
		device_disconnect_cb(device, DEVICE_DISCONNECT_SUCCESS,
				dev_disconnect_data);

		g_variant_unref(ret);
	}

	g_free(notify);
}

void bluez_device_disconnect_le(struct _bluez_device *device)
{
	struct device_disconnect_state_notify *notify;

	notify = g_try_new0(struct device_disconnect_state_notify, 1);
	if (notify == NULL) {
		ERROR("no memory");
		return;
	}

	notify->device = device;
	notify->cb = dev_disconnect_cb;

	g_dbus_proxy_call(device->proxy,
			"Disconnect", NULL,
			0, -1, NULL,
			bluez_device_disconnect_cb, notify);
}

gboolean bluez_get_media_type(const char *remote_address)
{
	struct _bluez_object *object;
	GList *list, *next;
	int length;
	gboolean is_type = FALSE;
	gchar device_address[BT_ADDRESS_STRING_SIZE];

	DBG("");

	length = g_list_length(bluez_object_list);

	if (length == 0)
		return FALSE;

	for (list = g_list_first(bluez_object_list); list; list = next) {
		next = g_list_next(list);
		object = list->data;

		convert_device_path_to_address(object->path_name,
						(gchar *)device_address);

		if (!g_strcmp0(remote_address, device_address) &&
			object->media_type == AUDIO_TYPE_A2DP) {
			is_type = TRUE;
			break;
		}
	}

	return is_type;
}

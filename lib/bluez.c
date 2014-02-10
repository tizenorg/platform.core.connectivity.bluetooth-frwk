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
#define MEDIACONTROL_INTERFACE "org.bluez.MediaControl1"
#define DEVICE_INTERFACE "org.bluez.Device1"
#define AGENT_INTERFACE "org.bluez.AgentManager1"
#define PROFILE_INTERFACE "org.bluez.ProfileManager1"
#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

GDBusObjectManager *object_manager = NULL;

struct _bluez_object {
	char *path_name;
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

struct _bluez_adapter {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusInterface *media_interface;
	guint avrcp_registration_id;
	GDBusProxy *proxy;
	GDBusProxy *media_proxy;
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
};

struct _bluez_device {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusInterface *control_interface;
	GDBusProxy *proxy;
	GDBusProxy *control_proxy;
	struct _bluez_object *parent;
	struct _device_head *head;

	bluez_device_paired_cb_t device_paired_cb;
	gpointer device_paired_cb_data;
	bluez_device_connected_cb_t device_connected_cb;
	gpointer device_connected_cb_data;
	bluez_device_trusted_cb_t device_trusted_cb;
	gpointer device_trusted_cb_data;
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

static GHashTable *bluez_object_hash;

static GList *bluez_adapter_list;

static GHashTable *bluez_adapter_hash;

static GHashTable *bluez_device_hash;

static bluez_adapter_added_cb_t adapter_added_cb;
static gpointer adapter_added_cb_data;
static bluez_agent_added_cb_t agent_added_cb;
static gpointer agent_added_cb_data;

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
	const gchar *alias = NULL;
	gboolean variant_found = g_variant_lookup(changed_properties,
							"Alias", "s", alias);
	if (!variant_found)
		return;

	adapter->alias_cb(adapter,
			alias,
			adapter->alias_cb_data);
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
	const gchar *iface_name;

	if (!adapter) {
		WARN("no adapter");
		return;
	}

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, ADAPTER_INTERFACE) == 0) {
		DBG("adapter->proxy = proxy");
		adapter->interface = interface;
		adapter->proxy = proxy;

		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(adapter_properties_changed), adapter);
	} else if (g_strcmp0(iface_name, MEDIA_INTERFACE) == 0) {
		DBG("adapter->media_proxy = proxy");
		adapter->media_interface = interface;
		adapter->media_proxy = proxy;
	}
}

static GList *bluez_object_list;

GList *device_head_list;

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
	bluez_adapter_list = g_list_remove(bluez_adapter_list,
						(gpointer) adapter);
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

	DBG("properties %s", properties);

	if (device->device_paired_cb)
		handle_device_paired(changed_properties, user_data);
	else if (device->device_connected_cb)
		handle_device_connected(changed_properties, user_data);
	else if (device->device_trusted_cb)
		handle_device_trusted(changed_properties, user_data);

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

static void control_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	g_free(properties);
}

static void parse_bluez_device_interfaces(gpointer data, gpointer user_data)
{
	struct _bluez_device *device = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	const gchar *iface_name;

	if (!device) {
		WARN("no adapter");
		return;
	}

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, DEVICE_INTERFACE) == 0) {
		device->interface = interface;
		device->proxy = proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(device_properties_changed), device);
	} else if (g_strcmp0(iface_name, MEDIACONTROL_INTERFACE) == 0) {
		device->control_interface = interface;
		device->control_proxy = proxy;
		g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(control_properties_changed), device);
	}
}

char *bluez_device_property_get_adapter(struct _bluez_device *device)
{
	return property_get_string(device->proxy, "Adapter");
}

static void free_bluez_device(gpointer data)
{
	struct _bluez_device *device = data;

	DBG("%s", device->object_path);

	g_free(device->interface_name);
	g_free(device->object_path);
	g_object_unref(device->interface);
	g_object_unref(device->proxy);
	g_free(device);
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
						free_bluez_device);

	DBG("insert %s into %s", device->object_path, adapter_path);
	g_hash_table_insert(new_head->device_hash,
					(gpointer) device->object_path,
					(gpointer) device);
	device->head = new_head;

	attach_adapter(new_head);

	device_head_list = g_list_append(device_head_list,
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

static void bluez_device_added(struct _bluez_object *object,
					GList *ifaces)
{
	struct _bluez_device *device;

	DBG("");

	device = create_device(object);

	g_list_foreach(ifaces, parse_bluez_device_interfaces, device);

	register_bluez_device(device);
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
	g_object_unref(adapter->media_proxy);
	g_object_unref(adapter->proxy);

	g_free(adapter);
}

static void free_bluez_adapter(struct _bluez_adapter *adapter)
{
	DBG("%s", adapter->object_path);

	g_free(adapter->interface_name);
	g_free(adapter->object_path);
	g_object_unref(adapter->interface);
	g_object_unref(adapter->proxy);
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

		g_hash_table_steal(bluez_device_hash, device->object_path);
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

static void unregister_bluez_device(struct _bluez_device *device)
{
	DBG("%p", device);

	remove_device_from_head(device);
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
			free_bluez_adapter(adapter);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, DEVICE_INTERFACE)) {
			struct _bluez_device *device = list->data;
			unregister_bluez_device(device);
			free_bluez_device(device);
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
	object->interfaces = NULL;

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

static void object_removed(GDBusObjectManager *manger, GDBusObject *object,
				gpointer user_data)
{
	struct _bluez_object *bluez_object;
	const gchar *object_path;

	object_path = g_dbus_object_get_object_path(object);
	DBG("object path: %s", object_path);

	bluez_object = get_object_from_path(object_path);
	if (object == NULL)
		return;

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
						NULL, free_bluez_device);

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
					-1, NULL, NULL, NULL);
}

void bluez_adapter_set_powered(struct _bluez_adapter *adapter,
				gboolean powered)
{

	GVariant *val = g_variant_new("b", powered);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "Powered", val);

	DBG("powered %d", powered);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL, NULL, NULL);
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
					-1, NULL, NULL, NULL);
}

void bluez_adapter_start_discovery(struct _bluez_adapter *adapter)
{
	DBG("proxy 0x%p", adapter->proxy);

	g_dbus_proxy_call(adapter->proxy,
			"StartDiscovery", NULL,
			0, -1, NULL, NULL, NULL);

}

void bluez_adapter_stop_discovery(struct _bluez_adapter *adapter)
{
	g_dbus_proxy_call(adapter->proxy,
			"StopDiscovery", NULL,
			0, -1, NULL, NULL, NULL);
}

int bluez_adapter_get_property_powered(struct _bluez_adapter *adapter,
						gboolean *powered)
{
	return property_get_boolean(adapter->proxy, "Powered", powered);
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
	return property_get_string(adapter->proxy, "Alias");
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
	return property_get_string(adapter->proxy, "Address");
}

int bluez_adapter_get_property_discoverable(struct _bluez_adapter *adapter,
						gboolean *discoverable)
{
	return property_get_boolean(adapter->proxy, "Discoverable", discoverable);
}

int bluez_adapter_get_property_discoverable_timeout(
				struct _bluez_adapter *adapter,
				guint32 *time)
{
	return property_get_uint32(adapter->proxy,
				"DiscoverableTimeout", time);
}

int bluez_adapter_get_property_discovering(struct _bluez_adapter *adapter,
						gboolean *discovering)
{
	return property_get_boolean(adapter->proxy,
					"Discovering", discovering);
}

char **bluez_adapter_get_property_uuids(struct _bluez_adapter *adapter)
{
	return property_get_string_list(adapter->proxy, "UUIDs");
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

	device = g_hash_table_lookup(adapter->device_head->device_hash,
						(gconstpointer) path);

	return device;
}

struct _bluez_device *bluez_adapter_get_device_by_address(
				struct _bluez_adapter *adapter,
				const char *address)
{
	gchar *device_path;
	struct _bluez_device *device;

	if (adapter == NULL || address == NULL)
		return NULL;

	device_path = address_to_path(adapter->object_path, address);
	if (device_path == NULL)
		return NULL;

	device = g_hash_table_lookup(adapter->device_head->device_hash,
						(gconstpointer) device_path);

	g_free(device_path);

	return device;
}

void bluez_adapter_remove_device(struct _bluez_adapter *adapter,
					struct _bluez_device *device)
{
	g_dbus_proxy_call(adapter->proxy, "RemoveDevice",
			g_variant_new("(o)", device->object_path),
 			0, -1, NULL, NULL, NULL);
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

void bluez_device_set_paired_changed_cb(struct _bluez_device *device,
					bluez_device_paired_cb_t cb,
					gpointer user_data)
{
	device->device_paired_cb = cb;
	device->device_paired_cb_data = user_data;
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
					-1, NULL, NULL, NULL);
}

void bluez_device_set_alias(struct _bluez_device *device,
					const gchar *alias)
{
	GVariant *val = g_variant_new("s", alias);
	GVariant *parameter = g_variant_new("(ssv)",
				DEVICE_INTERFACE, "Alias", val);

	g_dbus_proxy_call(device->parent->properties_proxy,
					"Set", parameter, 0,
					-1, NULL, NULL, NULL);
}

char **bluez_device_get_property_uuids(struct _bluez_device *device)
{
	return property_get_string_list(device->proxy, "UUIDs");
}

char *bluez_device_get_property_address(struct _bluez_device *device)
{
	return property_get_string(device->proxy, "Address");
}

char *bluez_device_get_property_alias(struct _bluez_device *device)
{
	return property_get_string(device->proxy, "Alias");
}

int bluez_device_get_property_class(struct _bluez_device *device,
					guint32 *class)
{
	return property_get_uint32(device->proxy, "Class", class);
}

int bluez_device_get_property_paired(struct _bluez_device *device,
					gboolean *paired)
{
	return property_get_boolean(device->proxy, "Paired", paired);
}

int bluez_device_get_property_trusted(struct _bluez_device *device,
					gboolean *trusted)
{
	return property_get_boolean(device->proxy, "Trusted", trusted);
}

int bluez_device_get_property_connected(struct _bluez_device *device,
					gboolean *connected)
{
	return property_get_boolean(device->proxy, "Connected", connected);
}

int bluez_device_get_property_rssi(struct _bluez_device *device,
					gint16 *rssi)
{
	return property_get_int16(device->proxy, "RSSI", rssi);
}

char *bluez_device_get_property_icon(struct _bluez_device *device)
{
	return property_get_string(device->proxy, "Icon");
}

struct simple_reply_data {
	GDBusProxy *proxy;
	simple_reply_cb_t reply_cb;
	void *user_data;
};

struct profile_connect_state_notify {
	struct _bluez_device *device;
	profile_connect_cb_t cb;
};

struct profile_disconnect_state_notify {
	struct _bluez_device *device;
	profile_disconnect_cb_t cb;
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

static void simple_reply_callback(GObject *source_object, GAsyncResult *res,
							gpointer user_data)
{
	struct simple_reply_data *reply_data = user_data;
	enum bluez_error_type error_type = ERROR_NONE;
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish(reply_data->proxy, res, &error);
	if (ret == NULL) {
		DBG("%s", error->message);
		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	if (!reply_data)
		return;

	if (reply_data->reply_cb)
		reply_data->reply_cb(error_type, reply_data->user_data);

	g_free(reply_data);
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

void bluez_device_disconnect_profile(struct _bluez_device *device,
				const char *uuid,
				profile_disconnect_cb_t pf_disconnect_cb)
{
	struct profile_disconnect_state_notify *notify;

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
				0, -1, NULL, NULL, NULL);
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

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
#include <errno.h>
#include <gio/gio.h>
#include "common.h"

#include "bluetooth.h"
#include "bluetooth-service.h"

#define COMMS_SERVICE_NAME "org.tizen.comms"
#define OBJECT_MANAGER_OBJ_PATH "/org/tizen/comms"
#define COMMS_MANAGER_OBJ_PATH "/org/tizen/comms/manager"
#define COMMS_BLUETOOTH_OBJ_PATH "/org/tizen/comms/bluetooth"
#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"
#define COMMS_MANAGER_INTERFACE "org.tizen.comms.manager"
#define COMMS_BLUETOOTH_PARING_INTERFACE "org.tizen.comms.pairing"
#define COMMS_BLUETOOTH_OPP_INTERFACE "org.tizen.comms.opp"
#define COMMS_BLUETOOTH_MEDIAPLAYER_INTERFACE "org.tizen.comms.mediaplayer"

#define OPP_SEND_IN_PROG "GDBus.Error:org.tizen.comms.Error.InProgress: In Progress"

static GDBusObjectManager *object_manager;

struct _comms_object {
	char *service_name;
	char *path_name;
	GDBusObject *obj;
	GList *interfaces;
	GDBusProxy *properties_proxy;
};

struct _comms_manager {
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
	struct _comms_object *parent;
};

struct _proxy {
	char *interface_name;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	GDBusProxy *property_proxy;
};

struct _comms_bluetooth {
	char *object_path;
	struct _comms_object *parent;
	struct _proxy pairing;
	struct _proxy opp;
	struct _proxy mediaplayer;
};

static GHashTable *comms_object_hash;

comms_manager_bt_in_service_watch_t manager_bt_in_service_watch;
void *manager_bt_in_service_watch_data;

static adapter_connectable_watch_t adapter_connectable_changed_watch;
static void *adapter_connectable_changed_watch_data;

opp_manager_service_watch_t manager_opp_service_watch;
void *manager_opp_service_watch_data;

static struct _comms_object *get_object_from_path(const char *path)
{
	return g_hash_table_lookup(comms_object_hash, (gpointer) path);
}

static struct _comms_object *create_object(GDBusObject *obj)
{
	GDBusProxy *properties_proxy;
	struct _comms_object *object;
	const char *path = g_dbus_object_get_object_path(obj);

	DBG("object 0x%p, object path %s", obj, path);

	object = g_try_new0(struct _comms_object, 1);
	if (object == NULL) {
		ERROR("no memeory");
		return NULL;
	}

	object->service_name = g_strdup(COMMS_SERVICE_NAME);

	object->obj = g_object_ref(obj);

	properties_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						COMMS_SERVICE_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);
	if (properties_proxy == NULL)
		WARN("create properties proxy error");

	object->properties_proxy = g_object_ref(properties_proxy);
	object->path_name = g_strdup(path);

	return object;
}

static GList *comms_object_list;

static void register_comms_object(struct _comms_object *object)
{
	DBG("%p", object);

	comms_object_list = g_list_prepend(comms_object_list,
						(gpointer) object);
	g_hash_table_insert(comms_object_hash,
				(gpointer) object->path_name,
				(gpointer) object);
}

static void free_comms_manager(struct _comms_manager *manager)
{
	g_free(manager->object_path);
	g_object_unref(manager->interface);
	g_object_unref(manager->proxy);
	g_object_unref(manager->property_proxy);
	g_free(manager);
}

static void handle_manager_bt_in_service_watch(GVariant *changed_properties,
							void *user_data)
{
	gboolean in_service;
	gboolean variant_found = g_variant_lookup(changed_properties,
				"BluetoothInService", "b", &in_service);
	if (!variant_found)
		return;

	manager_bt_in_service_watch(in_service, manager_bt_in_service_watch_data);
}

static void handle_manager_adapter_connectable_watch(GVariant *properties,
							void *user_data)
{
	gboolean connectable;
	gboolean variant_found = g_variant_lookup(properties,
				"AdapterConnectable", "b", &connectable);
	if (!variant_found)
		return;

	adapter_connectable_changed_watch(0, connectable,
				adapter_connectable_changed_watch_data);
}

static void manager_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	if (manager_bt_in_service_watch)
		handle_manager_bt_in_service_watch(
					changed_properties, user_data);

	if (adapter_connectable_changed_watch)
		handle_manager_adapter_connectable_watch(
					changed_properties, user_data);
}

static void opp_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	DBG("");

	if (changed_properties != NULL) {
		gchar *address, *name;
		guint64 size;
		guint transfer_id, state;
		double percent;
		guint32 pid = 0, cur_pid;
		gboolean variant_found;

		if (!manager_opp_service_watch)
			return;

		cur_pid = getpid();

		variant_found = g_variant_lookup(changed_properties,
							"pid", "u", &pid);

		if (!variant_found) {
			DBG("can not find pid");
			return;
		}

		if (cur_pid != pid) {
			DBG("pid and cur_pid do not match");
			return;
		}

		variant_found = g_variant_lookup(changed_properties,
						"address", "s", &address);

		if (!variant_found)
			address = NULL;

		variant_found = g_variant_lookup(changed_properties,
						"name", "s", &name);

		if (!variant_found)
			name = NULL;

		variant_found = g_variant_lookup(changed_properties,
						"size", "t", &size);

		if (!variant_found)
			size = 0;

		variant_found = g_variant_lookup(changed_properties,
					"transfer_id", "i", &transfer_id);

		if (!variant_found)
			transfer_id = 0;

		variant_found = g_variant_lookup(changed_properties,
					"state", "i", &state);

		if (!variant_found)
			state = 0;

		variant_found = g_variant_lookup(changed_properties,
					"percent", "d", &percent);

		if (!variant_found)
			percent = 0;

		manager_opp_service_watch(address, name, size,
				transfer_id, state, percent,
				manager_opp_service_watch_data);
	}
}

static struct _comms_manager *this_manager;

static void register_comms_manager(struct _comms_manager *manager)
{

	DBG("manager %p", manager);

	if (this_manager)
		WARN("manager %p not unregister", this_manager);

	this_manager = manager;
}

static void unregister_comms_manager(struct _comms_manager *manager)
{

	if (this_manager != manager)
		return;

	DBG("%p", manager);

	this_manager = NULL;
}

static inline int get_proxy(struct _proxy *proxy,
				struct _comms_object *object,
				gboolean is_system,
				const char *interface_name)
{
	if (interface_name == NULL) {
		proxy->proxy = NULL;
		return -1;
	}

	proxy->interface = g_dbus_object_get_interface(object->obj,
							interface_name);

	proxy->interface_name = g_strdup(interface_name);

	proxy->proxy = g_dbus_proxy_new_for_bus_sync((is_system ?
							G_BUS_TYPE_SYSTEM :
							G_BUS_TYPE_SESSION),
							0,
							NULL,
							object->service_name,
							object->path_name,
							interface_name,
							NULL, NULL);
	if (proxy->proxy == NULL) {
		g_object_unref(proxy->interface);
		proxy->interface = NULL;
		g_free(proxy->interface_name);
		proxy->interface_name = NULL;
		return -1;
	}

	DBG("proxy %p", proxy->proxy);

	proxy->property_proxy = g_dbus_proxy_new_for_bus_sync((is_system ?
							G_BUS_TYPE_SYSTEM :
							G_BUS_TYPE_SESSION),
							0,
							NULL,
							object->service_name,
							object->path_name,
							PROPERTIES_INTERFACE,
							NULL, NULL);
	if (proxy->proxy == NULL) {
		g_object_unref(proxy->interface);
		proxy->interface = NULL;
		g_free(proxy->interface_name);
		proxy->interface_name = NULL;
		return -1;
	}

	DBG("property proxy %p", proxy->property_proxy);

	return 0;
}

static void free_proxy(struct _proxy *proxy)
{
	g_free(proxy->interface_name);
	if (proxy->interface)
		g_object_unref(proxy->interface);
	if (proxy->proxy)
		g_object_unref(proxy->proxy);
	if (proxy->property_proxy)
		g_object_unref(proxy->property_proxy);
}

void free_comms_bluetooth(struct _comms_bluetooth *bluetooth)
{
	g_free(bluetooth->object_path);

	bluetooth->parent = NULL;

	free_proxy(&bluetooth->pairing);

	free_proxy(&bluetooth->opp);

	free_proxy(&bluetooth->mediaplayer);
};

static struct _comms_bluetooth *this_bluetooth;

static void register_comms_bluetooth(struct _comms_bluetooth *bluetooth)
{

	DBG("bluetooth %p", bluetooth);

	if (this_bluetooth)
		WARN("manager %p not unregister", this_manager);

	this_bluetooth = bluetooth;
}

static void unregister_comms_bluetooth(struct _comms_bluetooth *bluetooth)
{

	if (bluetooth != this_bluetooth)
		return;

	DBG("%p", bluetooth);

	this_bluetooth = NULL;
}

static void destruct_comms_manager(void)
{

	struct _comms_manager *manager = this_manager;

	unregister_comms_manager(manager);

	free_comms_manager(manager);
}

static void destruct_comms_bluetooth(void)
{
	struct _comms_bluetooth *bluetooth = this_bluetooth;

	unregister_comms_bluetooth(bluetooth);

	free_comms_bluetooth(bluetooth);
}

static void destruct_comms_object(gpointer data)
{
	struct _comms_object *object = data;

	DBG("");

	if (!g_strcmp0(object->path_name, COMMS_MANAGER_OBJ_PATH))
		destruct_comms_manager();
	else if (!g_strcmp0(object->path_name, COMMS_BLUETOOTH_OBJ_PATH))
		destruct_comms_bluetooth();

	g_free(object->service_name);

	g_free(object->path_name);

	g_object_unref(object->obj);

	if (object->properties_proxy)
		g_object_unref(object->properties_proxy);

	g_free(object);
}

GDBusProxy *manager_proxy;

static struct _comms_bluetooth *create_comms_bluetooth(const gchar *path)
{
	struct _comms_bluetooth *bluetooth;

	bluetooth = g_try_new0(struct _comms_bluetooth, 1);
	if (bluetooth == NULL) {
		ERROR("no memroy");
		return NULL;
	}

	bluetooth->object_path = g_strdup(path);

	return bluetooth;
}

static struct _comms_manager *create_manager(const gchar *path)
{
	struct _comms_manager *manager;

	manager = g_try_new0(struct _comms_manager, 1);
	if (manager == NULL) {
		ERROR("no memroy");
		return NULL;
	}

	manager->object_path = g_strdup(path);

	return manager;
}

static void parse_comms_bluetooth(gpointer data, gpointer user_data)
{
	struct _comms_bluetooth *bluetooth = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	struct _proxy *proxy_node;
	gchar *iface_name;
	const gchar *path;

	if (!bluetooth) {
		WARN("no bluetooth");
		return;
	}

	iface_name = g_strdup(g_dbus_proxy_get_interface_name(proxy));
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, COMMS_BLUETOOTH_PARING_INTERFACE) == 0)
		proxy_node = &bluetooth->pairing;
	else if (g_strcmp0(iface_name, COMMS_BLUETOOTH_OPP_INTERFACE) == 0) {
		proxy_node = &bluetooth->opp;
		path = g_dbus_proxy_get_object_path(proxy);

		proxy_node->property_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						COMMS_SERVICE_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);

		g_signal_connect(proxy, "g-properties-changed",
				G_CALLBACK(opp_properties_changed), NULL);
	} else if (!g_strcmp0(
			iface_name, COMMS_BLUETOOTH_MEDIAPLAYER_INTERFACE))
		proxy_node = &bluetooth->mediaplayer;
	else
		return;

	proxy_node->interface_name = iface_name;
	proxy_node->interface = g_object_ref(interface);
	proxy_node->proxy = g_object_ref(proxy);
}

static void comms_service_bluetooth_added(struct _comms_object *object,
							GList *ifaces)
{
	struct _comms_bluetooth *bluetooth;

	DBG("");

	bluetooth = create_comms_bluetooth(object->path_name);

	g_list_foreach(ifaces, parse_comms_bluetooth, bluetooth);

	register_comms_bluetooth(bluetooth);
}

static void parse_comms_manager(gpointer data, gpointer user_data)
{
	struct _comms_manager *manager = user_data;
	GDBusInterface *interface = data;
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	GDBusProxy *properties_proxy;
	const gchar *iface_name, *path;

	if (!manager) {
		WARN("no manager");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);

	iface_name = g_strdup(g_dbus_proxy_get_interface_name(proxy));
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, COMMS_MANAGER_INTERFACE))
		return;

	properties_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						COMMS_SERVICE_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);
	if (properties_proxy == NULL)
		WARN("create properties proxy error");

	manager->interface = g_object_ref(interface);
	manager->proxy = g_object_ref(proxy);
	manager->property_proxy = properties_proxy;

	g_signal_connect(proxy, "g-properties-changed",
			G_CALLBACK(manager_properties_changed), NULL);
}

static void comms_service_manager_added(struct _comms_object *object,
							GList *ifaces)
{
	struct _comms_manager *manager;

	DBG("");

	manager = create_manager(object->path_name);

	g_list_foreach(ifaces, parse_comms_manager, manager);

	register_comms_manager(manager);
}

static void interface_added(GDBusObject *object, GDBusInterface *interface,
							gpointer user_data)
{
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	const gchar *iface_name;
	const gchar *object_path;

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	object_path = g_dbus_object_get_object_path(object);
	DBG("%s %s", object_path, iface_name);

	if (g_strcmp0(object_path, COMMS_MANAGER_OBJ_PATH) == 0)
		parse_comms_manager(interface, this_manager);
	else if (g_strcmp0(object_path, COMMS_BLUETOOTH_OBJ_PATH) == 0)
		parse_comms_bluetooth(interface, this_bluetooth);
	else
		WARN("Unknown path: %s", object_path);
}

static void interface_removed(GDBusObject *object, GDBusInterface *interface,
							gpointer user_data)
{
	GDBusProxy *proxy = G_DBUS_PROXY(interface);
	const gchar *iface_name;
	const gchar *object_path;

	iface_name = g_dbus_proxy_get_interface_name(proxy);
	object_path = g_dbus_object_get_object_path(object);
	DBG("%s %s", object_path, iface_name);
}

static void parse_object(gpointer data, gpointer user_data)
{
	struct _comms_object *comms_object;
	GDBusObject *object = data;
	const gchar *object_path;
	GList *ifaces;

	object_path = g_dbus_object_get_object_path(object);
	DBG("object path: %s", object_path);

	g_signal_connect(object, "interface-added",
				G_CALLBACK(interface_added), NULL);

	g_signal_connect(object, "interface-removed",
				G_CALLBACK(interface_removed), NULL);

	comms_object = get_object_from_path(object_path);
	if (!comms_object) {
		comms_object = create_object(object);
		register_comms_object(comms_object);
	}

	ifaces = g_dbus_object_get_interfaces(object);

	if (g_strcmp0(object_path, OBJECT_MANAGER_OBJ_PATH) == 0)
		DBG("");
	else if (g_strcmp0(object_path, COMMS_MANAGER_OBJ_PATH) == 0)
		comms_service_manager_added(comms_object, ifaces);
	else if (g_strcmp0(object_path, COMMS_BLUETOOTH_OBJ_PATH) == 0)
		comms_service_bluetooth_added(comms_object, ifaces);
	else {
		WARN("Unkonw object type");
		return;
	}
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
	struct _comms_object *comms_object;
	const gchar *object_path;

	object_path = g_dbus_object_get_object_path(object);
	DBG("object path: %s", object_path);

	comms_object = get_object_from_path(object_path);
	if (!comms_object)
		return;

	g_hash_table_remove(comms_object_hash,
				(gconstpointer) comms_object->path_name);
}

int comms_lib_init(void)
{
	GDBusObjectManager *manager;
	GList *obj_list;

	DBG("");

	if (object_manager != NULL)
		return 0;

	manager = g_dbus_object_manager_client_new_for_bus_sync(
							G_BUS_TYPE_SYSTEM,
							0, COMMS_SERVICE_NAME,
							OBJECT_MANAGER_OBJ_PATH,
							NULL, NULL, NULL,
							NULL, NULL);
	if (manager == NULL) {
		ERROR("create object manager error");
		/* TODO: define error type */
		return -1;
	}

	object_manager = g_object_ref(manager);

	g_signal_connect(object_manager, "object-added",
				G_CALLBACK(object_added), NULL);
	g_signal_connect(object_manager, "object-removed",
				G_CALLBACK(object_removed), NULL);

	comms_object_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_comms_object);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);

	g_list_free(obj_list);

	return 0;
}

static void destruct_comms_objects(void)
{
	DBG("");

	g_hash_table_destroy(comms_object_hash);

	comms_object_hash = NULL;
}

static void destruct_comms_object_manager(void)
{
	g_object_unref(object_manager);

	object_manager = NULL;
}

void comms_lib_deinit(void)
{
	if (manager_proxy)
		g_object_unref(manager_proxy);

	destruct_comms_objects();
	destruct_comms_object_manager();
}

struct _bluetooth_simple_async_result {
	bluetooth_simple_callback callback;
	void *user_data;
};

static void bluetooth_simple_async_cb(GObject *object, GAsyncResult *res,
						gpointer user_data)
{
	struct _bluetooth_simple_async_result *async_result_node = user_data;
	enum bluez_error_type error_type = ERROR_NONE;
	GDBusProxy *proxy = G_DBUS_PROXY(object);
	GError *error = NULL;
	GVariant *ret;

	ret = g_dbus_proxy_call_finish(proxy, res, &error);
	if (ret == NULL) {
		DBG("%s", error->message);

		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	if (async_result_node && async_result_node->callback)
		async_result_node->callback(error_type,
					async_result_node->user_data);

	g_free(async_result_node);
}

void comms_manager_enable_bluetooth(void)
{
	if (this_manager == NULL) {
		ERROR("manager not register");
		return;
	}

	g_dbus_proxy_call(this_manager->proxy, "EnableBluetoothService",
					NULL, 0, -1, NULL,
					bluetooth_simple_async_cb, NULL);
}

void comms_manager_disable_bluetooth(void)
{
	if (this_manager == NULL) {
		ERROR("manager not register");
		return;
	}

	g_dbus_proxy_call(this_manager->proxy, "DisableBluetoothService",
					NULL, 0, -1, NULL,
					bluetooth_simple_async_cb, NULL);
}

int comms_manager_set_connectable(gboolean connectable)
{
	GError *error = NULL;
	GVariant *ret;

	if (this_manager == NULL) {
		ERROR("manager not reigster");
		return -1;
	}

	ret = g_dbus_proxy_call_sync(this_manager->proxy,
					"SetAdapterConnectable",
					g_variant_new("(b)", connectable),
					0, -1, NULL, &error);
	if (ret == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_unref(ret);

	return 0;
}

int comms_manager_get_connectable(gboolean *connectable)
{
	GError *error = NULL;
	gboolean val;
	GVariant *ret;

	if (connectable == NULL)
		return -1;

	if (this_manager == NULL) {
		ERROR("manager not reigster");
		return -1;
	}

	ret = g_dbus_proxy_call_sync(this_manager->proxy,
					"GetAdapterConnectable",
					NULL, 0, -1, NULL, &error);
	if (ret == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_get(ret, "(b)", &val);
	g_variant_unref(ret);
	*connectable = val;

	return 0;
}

int comms_manager_get_bt_adapter_visibale_time(void)
{
	GError *error = NULL;
	unsigned int val;
	GVariant *ret;

	if (this_manager == NULL) {
		ERROR("manager not reigster");
		return -1;
	}

	ret = g_dbus_proxy_call_sync(this_manager->proxy,
					"GetAdapterVisibleTime",
					NULL, 0, -1, NULL, &error);
	if (ret == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);

		return -1;
	}

	g_variant_get(ret, "(u)", &val);
	g_variant_unref(ret);

	return val;
}

void opp_manager_set_service_watch(
				opp_manager_service_watch_t cb,
				void *user_data)
{
	manager_opp_service_watch = cb;
	manager_opp_service_watch_data = user_data;
}

void opp_manager_remove_service_watch(void)
{
	manager_opp_service_watch = NULL;
	manager_opp_service_watch_data = NULL;
}

void adapter_connectable_set_service_watch(
				adapter_connectable_watch_t cb,
				void *user_data)
{
	adapter_connectable_changed_watch = cb;
	adapter_connectable_changed_watch_data = user_data;
}

void adapter_connectable_remove_service_watch(void)
{
	adapter_connectable_changed_watch = NULL;
	adapter_connectable_changed_watch_data = NULL;
}

void comms_manager_set_bt_in_service_watch(
				comms_manager_bt_in_service_watch_t cb,
				void *user_data)
{
	manager_bt_in_service_watch = cb;
	manager_bt_in_service_watch_data = user_data;
}

void comms_manager_remove_bt_in_service_watch(void)
{
	manager_bt_in_service_watch = NULL;
	manager_bt_in_service_watch_data = NULL;
}

int comms_manager_get_property_bt_in_service(gboolean *in_service)
{
	if (this_manager == NULL)
		return -1;

	return property_get_boolean(this_manager->property_proxy,
		COMMS_MANAGER_INTERFACE, "BluetoothInService", in_service);
}

void comms_bluetooth_device_pair(const char *address,
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->pairing.proxy, "Pair",
					g_variant_new("(s)", address),
					0, -1, NULL,
					bluetooth_simple_async_cb,
					async_result_node);
}

enum bluez_error_type comms_bluetooth_device_cancel_pairing_sync()
{
	enum bluez_error_type error_type = ERROR_NONE;
	GError *error = NULL;
	GVariant *ret;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return ERROR_FAILED;
	}

	ret = g_dbus_proxy_call_sync(this_bluetooth->pairing.proxy,
					"CancelPairing", NULL,
					0, -1, NULL, &error);
	if (ret == NULL) {
		DBG("%s", error->message);

		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	return error_type;
}

void comms_bluetooth_register_pairing_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->pairing.proxy, "RegisterPairingAgent",
					g_variant_new("(o)", agent_path),
					0, -1, NULL,
					bluetooth_simple_async_cb,
					async_result_node);
}

int comms_bluetooth_register_pairing_agent_sync(const char *agent_path,
						 void *user_data)
{
	GError *error = NULL;
	GVariant *result;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_OPERATION_FAILED;
	}

	result = g_dbus_proxy_call_sync(this_bluetooth->pairing.proxy,
					"RegisterPairingAgent",
					g_variant_new("(o)", agent_path),
					0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

int comms_bluetooth_get_user_privileges_sync(const char *address)
{
	GError *error = NULL;
	GVariant *result;
	guint privileges = 0;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return 0;
	}

	result = g_dbus_proxy_call_sync(this_bluetooth->pairing.proxy,
				"GetUserPrivileges",
				g_variant_new("(s)", address),
				0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	g_variant_get(result, "(i)", &privileges);
	g_variant_unref(result);

	return privileges;
}

int comms_bluetooth_remove_user_privileges_sync(const char *address)
{
	GError *error = NULL;
	GVariant *result;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_INVALID_PARAMETER;
	}

	result = g_dbus_proxy_call_sync(this_bluetooth->pairing.proxy,
				"RemoveUserPrivileges",
				g_variant_new("(s)", address),
				0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

void comms_bluetooth_unregister_pairing_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->pairing.proxy,
				"UnregisterPairingAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

void comms_bluetooth_register_media_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->mediaplayer.proxy,
				"RegisterMediaAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

int comms_bluetooth_register_media_agent_sync(const char *agent_path,
						void *user_data)
{
	GError *error = NULL;
	GVariant *result;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_OPERATION_FAILED;
	}

	result = g_dbus_proxy_call_sync(this_bluetooth->mediaplayer.proxy,
					"RegisterMediaAgent",
					g_variant_new("(o)", agent_path),
					0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

void comms_bluetooth_unregister_media_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->mediaplayer.proxy,
				"UnregisterMediaAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

void comms_bluetooth_register_opp_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"RegisterObexAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

int comms_bluetooth_register_opp_agent_sync(const char *agent_path,
						void *user_data)
{
	GError *error = NULL;
	GVariant *result;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_OPERATION_FAILED;
	}

	result = g_dbus_proxy_call_sync(this_bluetooth->opp.proxy,
					"RegisterObexAgent",
					g_variant_new("(o)", agent_path),
					0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

void comms_bluetooth_unregister_opp_agent(const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"UnregisterObexAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

int comms_bluetooth_opp_send_file(const char *address,
					const char *agent_path,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;
	GError *error = NULL;
	GVariant *result;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return -1;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return -1;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	result = g_dbus_proxy_call_sync(this_bluetooth->opp.proxy,
				"SendFile",
				g_variant_new("(so)",
				address, agent_path),
				0, -1, NULL, &error);

	if (error) {
		int ret = -1;
		if (!g_strcmp0(error->message, OPP_SEND_IN_PROG))
			ret = 1;

		g_error_free(error);
		return ret;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

void comms_bluetooth_opp_cancel_transfer(int transfer_id,
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"CancelTransfer",
				g_variant_new("(i)", transfer_id),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

int comms_bluetooth_opp_add_file(const char *filename,
				const char *agent_path,
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;
	GError *error = NULL;
	GVariant *result;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return -1;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return -1;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	result = g_dbus_proxy_call_sync(this_bluetooth->opp.proxy,
				"AddFile",
				g_variant_new("(so)",
				filename, agent_path),
				0, -1, NULL, &error);

	if (error) {
		ERROR("%s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_unref(result);

	return BT_SUCCESS;
}

void comms_bluetooth_opp_remove_Files(
				const char *agent_path,
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"RemoveFiles",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

void comms_bluetooth_opp_add_notify(char *path,
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"AddNotify",
				g_variant_new("(s)", path),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

void comms_bluetooth_opp_cancel_transfers(
				bluetooth_simple_callback cb,
				void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return;
	}

	async_result_node = g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->opp.proxy,
				"CancelAllTransfer",
				NULL, 0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}

int comms_bluetooth_avrcp_change_property(
					unsigned int type,
					unsigned int value,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_NOT_ENABLED;
	}

	async_result_node =
		g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->mediaplayer.proxy,
				"MediaPlayerChangeProperty",
				g_variant_new("(uu)", type, value),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);

	return BT_SUCCESS;
}

int comms_bluetooth_avrcp_change_properties(void *properties_data,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;
	GVariantBuilder *builder = (GVariantBuilder *)properties_data;

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_NOT_ENABLED;
	}

	async_result_node =
		g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->mediaplayer.proxy,
				"MediaPlayerChangeProperties",
				g_variant_new("(a{sv})", builder),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
	return BT_SUCCESS;
}

int comms_bluetooth_avrcp_change_track(void *track_data,
					bluetooth_simple_callback cb,
					void *user_data)
{
	struct _bluetooth_simple_async_result *async_result_node;
	GVariantBuilder *builder = (GVariantBuilder *)track_data;

	DBG("");

	if (this_bluetooth == NULL) {
		ERROR("bluetooth not register");
		return BT_ERROR_NOT_ENABLED;
	}

	async_result_node =
		g_new0(struct _bluetooth_simple_async_result, 1);
	if (async_result_node == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	async_result_node->callback = cb;
	async_result_node->user_data = user_data;

	g_dbus_proxy_call(this_bluetooth->mediaplayer.proxy,
				"MediaPlayerChangeTrack",
				g_variant_new("(a{sv})", builder),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
	return BT_SUCCESS;
}

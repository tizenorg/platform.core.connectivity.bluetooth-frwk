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
	struct _comms_object *parent;
};

struct _proxy {
	char *interface_name;
	GDBusInterface *interface;
	GDBusProxy *proxy;
};

struct _comms_bluetooth {
	char *object_path;
	struct _comms_object *parent;
	struct _proxy pairing;
	struct _proxy opp;
};

static GHashTable *comms_object_hash;

comms_manager_bt_in_service_watch_t manager_bt_in_service_watch;
void *manager_bt_in_service_watch_data;

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

	object->properties_proxy = properties_proxy;
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

static void manager_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	if (manager_bt_in_service_watch)
		handle_manager_bt_in_service_watch(
					changed_properties, user_data);
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

	return 0;
}

static void free_proxy(struct _proxy *proxy)
{
	g_free(proxy->interface_name);
	if (proxy->interface)
		g_object_unref(proxy->interface);
	if (proxy->proxy)
		g_object_unref(proxy->proxy);
}

void free_comms_bluetooth(struct _comms_bluetooth *bluetooth)
{
	g_free(bluetooth->object_path);

	bluetooth->parent = NULL;

	free_proxy(&bluetooth->pairing);

	free_proxy(&bluetooth->opp);
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

	if (!bluetooth) {
		WARN("no bluetooth");
		return;
	}

	iface_name = g_strdup(g_dbus_proxy_get_interface_name(proxy));
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, COMMS_BLUETOOTH_PARING_INTERFACE) == 0)
		proxy_node = &bluetooth->pairing;
	else if (g_strcmp0(iface_name, COMMS_BLUETOOTH_OPP_INTERFACE) == 0)
		proxy_node = &bluetooth->opp;
	else
		return;

	proxy_node->interface_name = iface_name;
	proxy_node->interface = interface;
	proxy_node->proxy = proxy;
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
	gchar *iface_name;

	if (!manager) {
		WARN("no manager");
		return;
	}

	iface_name = g_strdup(g_dbus_proxy_get_interface_name(proxy));
	DBG("%s", iface_name);

	if (g_strcmp0(iface_name, COMMS_MANAGER_INTERFACE))
		return;

	manager->interface = interface;
	manager->proxy = proxy;

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

	g_object_unref(object);
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
	GList *obj_list;

	DBG("");

	if (object_manager != NULL)
		return 0;

	object_manager = g_dbus_object_manager_client_new_for_bus_sync(
							G_BUS_TYPE_SYSTEM,
							0, COMMS_SERVICE_NAME,
							OBJECT_MANAGER_OBJ_PATH,
							NULL, NULL, NULL,
							NULL, NULL);
	if (object_manager == NULL) {
		ERROR("create object manager error");
		/* TODO: define error type */
		return -1;
	}

	g_signal_connect(object_manager, "object-added",
				G_CALLBACK(object_added), NULL);
	g_signal_connect(object_manager, "object-removed",
				G_CALLBACK(object_removed), NULL);

	comms_object_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_comms_object);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);

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

void comms_manager_enable_bluetooth(void)
{
	if (this_manager == NULL) {
		ERROR("manager not register");
		return;
	}

	g_dbus_proxy_call(this_manager->proxy, "EnableBluetoothService",
					NULL, 0, -1, NULL, NULL, NULL);
}

void comms_manager_disable_bluetooth(void)
{
	if (this_manager == NULL) {
		ERROR("manager not register");
		return;
	}

	g_dbus_proxy_call(this_manager->proxy, "DisableBluetoothService",
					NULL, 0, -1, NULL, NULL, NULL);
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

	return property_get_boolean(this_manager->proxy,
				"BluetoothInService", in_service);
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

	if (async_result_node->callback)
		async_result_node->callback(error_type,
					async_result_node->user_data);

	g_free(async_result_node);
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

void comms_bluetooth_opp_send_file(const char *address,
					const char *file_name,
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
				"SendFile",
				g_variant_new("(ss)", address, file_name),
				0, -1, NULL,
				bluetooth_simple_async_cb,
				async_result_node);
}
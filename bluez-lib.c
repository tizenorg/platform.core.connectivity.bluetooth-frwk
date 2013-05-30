#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>
#include "common.h"
#include "bluez.h"

#define BLUEZ_NAME "org.bluez"
#define OBJECT_MANAGE_PATH "/"
#define ADAPTER_INTERFACE "org.bluez.Adapter1"
#define DEVICE_INTERFACE "org.bluez.Device1"
#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

GDBusObjectManager *object_manager;

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
	GDBusProxy *proxy;
	struct _bluez_object *parent;
	struct _device_head *device_head;
	bluez_adapter_powered_cb_t powered_cb;
	gpointer powered_cb_data;
	bluez_adapter_alias_cb_t alias_cb;
	gpointer alias_cb_data;
};

struct _bluez_device {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _bluez_object *parent;
};

static GList *bluez_adapter_list;
static GList *bluez_device_list;

static GHashTable *bluez_adapter_hash;
static GHashTable *bluez_device_hash;

static struct _bluez_object *create_object(GDBusObject *obj)
{
	GDBusProxy *properties_proxy;
	struct _bluez_object *object;
	const char *path = g_dbus_object_get_object_path(obj);

	DBG("obj 0x%p, object path %s", obj, path);

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
	const gchar *alias;
	gboolean variant_found = g_variant_lookup(changed_properties,
							"Alias", "s", alias);
	if (!variant_found)
		return;

	adapter->alias_cb(adapter,
			&alias,
			adapter->alias_cb_data);
}

static void adapter_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);
	struct _bluez_adapter *adapter = user_data;

	DBG("properties %s", properties);
	if (adapter->powered_cb)
		handle_adapter_powered_changed(changed_properties, user_data);

	if (adapter->alias_cb)
		handle_adapter_alias_changed(changed_properties, user_data);
}

static struct _bluez_adapter *create_adapter(struct _bluez_object *object)
{
	struct _bluez_adapter *adapter;
	GDBusInterface *interface;
	GDBusInterfaceInfo *interface_info;

	interface = g_dbus_object_get_interface(object->obj,
						ADAPTER_INTERFACE);
	if (interface == NULL)
		return NULL;

	adapter = g_try_new0(struct _bluez_adapter, 1);
	if (adapter == NULL) {
		g_object_unref(interface);
		ERROR("no memory");
		return NULL;
	}

	adapter->interface = interface;

	interface_info = g_dbus_interface_get_info(interface);

	adapter->proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						interface_info,
						BLUEZ_NAME,
						object->path_name,
						ADAPTER_INTERFACE,
						NULL, NULL);
	if (adapter->proxy == NULL) {
		ERROR("adapter create proxy error");
		g_object_unref(adapter->interface);
		g_free(adapter);
		return NULL;
	}

	g_signal_connect(adapter->proxy,
			"g-properties-changed",
			G_CALLBACK(adapter_properties_changed),
			adapter);

	adapter->interface_name = g_strdup(ADAPTER_INTERFACE);

	adapter->object_path = g_strdup(object->path_name);

	adapter->parent = object;

	return adapter;
}

static GList *bluez_object_list;
static GHashTable *bluez_object_hash;

static void register_bluez_object(struct _bluez_object *object)
{

	bluez_object_list = g_list_prepend(bluez_object_list,
						(gpointer) object);
	g_hash_table_insert(bluez_object_hash,
				(gpointer) object->path_name,
				(gpointer) object);
}

static GList *bluez_adapter_list;
static GHashTable *bluez_adapter_hash;

GList *device_head_list;

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
	GList *interface_list = adapter->parent->interfaces;

	bluez_adapter_list = g_list_prepend(bluez_adapter_list,
						(gpointer) adapter);
	g_hash_table_insert(bluez_adapter_hash,
				(gpointer) adapter->object_path,
				(gpointer) adapter);

	interface_list = g_list_prepend(interface_list,
					(gpointer) adapter);

	attach_device_head(adapter);
}

static void device_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);
	struct _bluez_device *device = user_data;

	DBG("properties %s", properties);
}

static struct _bluez_device *create_device(struct _bluez_object *object)
{
	struct _bluez_device *device;
	GDBusInterface *interface;
	GDBusInterfaceInfo *interface_info;

	interface = g_dbus_object_get_interface(object->obj,
						DEVICE_INTERFACE);
	if (interface == NULL)
		return NULL;

	device = g_try_new0(struct _bluez_device, 1);
	if (device == NULL) {
		g_object_unref(interface);
		ERROR("no memory");
		return NULL;
	}

	device->interface = interface;

	interface_info = g_dbus_interface_get_info(interface);

	device->proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						interface_info,
						BLUEZ_NAME,
						object->path_name,
						DEVICE_INTERFACE,
						NULL, NULL);
	if (device->proxy == NULL) {
		ERROR("adapter create proxy error");
		g_object_unref(device->interface);
		g_free(device);
		return NULL;
	}

	g_signal_connect(device->proxy,
			"g-properties-changed",
			G_CALLBACK(device_properties_changed),
			device);

	device->interface_name = g_strdup(DEVICE_INTERFACE);

	device->object_path = g_strdup(object->path_name);

	device->parent = object;

	return device;
}

int bluez_device_property_get_adapter(struct _bluez_device *device,
					const char **adapter_path)
{
	GVariant *adapter_path_v;

	DBG("");

	adapter_path_v = g_dbus_proxy_get_cached_property(
					device->proxy,
					"Adapter");
	if (adapter_path_v == NULL) {
		ERROR("no cached property");
		return -1;
	}

	*adapter_path = g_variant_get_string(adapter_path_v, 0);

	DBG("adpater path %s", *adapter_path);

	g_variant_unref(adapter_path_v);

	return 0;
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
	GList *list, *next;

	DBG("");

	for (list = g_list_first(device_head_list); list; list = next) {
		struct _device_head *head = list->data;

		if (!g_strcmp0(head->adapter_path, adapter_path)) {

			DBG("insert %s into %s", device->object_path,
							adapter_path);
			g_hash_table_insert(head->device_hash,
						(gpointer) device->object_path,
						(gpointer) device);
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
	attach_adapter(new_head);
	device_head_list = g_list_append(device_head_list,
					(gpointer) new_head);
}

static void register_bluez_device(struct _bluez_device *device)
{

	const char *adapter_path;
	int err;

	err = bluez_device_property_get_adapter(device, &adapter_path);
	if (err) {
		ERROR("get adapter path error");
		return;
	}

	add_to_device_head_list(device, adapter_path);
}

static void parse_object(gpointer data, gpointer user_data)
{
	GDBusObject *obj = data;
	GDBusInterface *interface;
	struct _bluez_object *object;
	struct _bluez_adapter *adapter;
	struct _bluez_device *device;

	object = create_object(obj);
	if (object == NULL)
		return;

	register_bluez_object(object);

	adapter = create_adapter(object);
	if (adapter) {
		register_bluez_adapter(adapter);
		return;
	}

	device = create_device(object);
	if (device) {
		register_bluez_device(device);
		return;
	}
}

static int check_adapter(struct _bluez_adapter *adapter)
{
	if (adapter == NULL)
		return -1;

	return 0;
	/* TODO: check adapter hash */
}

static int check_device(struct _bluez_device *device)
{
	if (device == NULL)
		return -1;

	return 0;
	/* TODO: check deivce hash */
}
struct _bluez_adapter *bluez_adapter_get_adapter(const char *name)
{
	struct _bluez_adapter *adapter;
	char *adapter_path;
	int size = 12 + strlen(name);

	adapter_path = malloc(size);

	sprintf(adapter_path, "/org/bluez/%s", name);

	adapter = g_hash_table_lookup(bluez_adapter_hash,
				(gconstpointer) adapter_path);

	free(adapter_path);

	return adapter;
}

#if 0
static void unregister_free_bluez_adapter(struct _bluez_adapter *adapter)
{
	DBG("");
	g_hash_table_remove(bluez_adapter_hash,
				(gconstpoint) adapter->object_path);
}
#endif

static void destruct_bluez_adapter(gpointer data)
{
	struct _bluez_adapter *adapter = data;
	GList *interface_list = adapter->parent->interfaces;

	DBG("0x%p", adapter);

	interface_list = g_list_remove(interface_list, data);

	bluez_adapter_list = g_list_remove(bluez_adapter_list,
						(gpointer) adapter);
	g_free(adapter->interface_name);

	g_free(adapter->object_path);

	g_object_unref(adapter->interface);

	g_object_unref(adapter->proxy);

	g_free(adapter);
}

#if 0
static void unregister_free_bluez_object(struct _bluez_object *object)
{
	DBG("");
	g_hash_table_remove(bluez_object_hash,
				(gconstpoint) object->path_name);
}
#endif

static void destruct_bluez_object(gpointer data)
{
	struct _bluez_object *object = data;

	DBG("0x%p", object);

	bluez_object_list = g_list_remove(bluez_object_list, data);

	g_free(object->path_name);

	g_object_unref(object->obj);

	g_object_unref(object->properties_proxy);

	g_free(object);
}

#if 0
static void unregister_free_bluez_device(struct _bluez_device *device)
{
	DBG("");
	g_hash_table_remove(bluez_device_hash,
				(gconstpoint) device->object_path);
}
#endif



GDBusProxy *manager_proxy;

static void interfaces_removed(GVariant *parameters)
{
	gchar *object_path;
	GVariant *interfaces;
	GVariantIter *iter;

	g_variant_get(parameters, "(oa{sa{sv}})", &object_path, &iter);

	DBG("object %s", object_path);
}

static void interfaces_added(GVariant *parameters)
{
	gchar *object_path;
	GVariant *interfaces;
	GVariantIter *iter;
	GDBusObject *obj;

	g_variant_get(parameters, "(oa{sa{sv}})", &object_path, &iter);

	DBG("object %s", object_path);

	obj = g_dbus_object_manager_get_object(object_manager, object_path);

	parse_object(obj, NULL);
}

static void interfaces_changed(GDBusProxy *proxy,
				gchar *sender_name,
				gchar *signal_name,
				GVariant *parameters,
				gpointer user_data)
{
	if (!g_strcmp0(signal_name, "InterfacesAdded"))
		interfaces_added(parameters);
	if (!g_strcmp0(signal_name, "InterfacesRemoved"))
		interfaces_removed(parameters);
}

int bluez_lib_init(void)
{
	GList *obj_list;
	GDBusObject *test_obj;

	DBG("");

	if (object_manager != NULL)
		return;

	object_manager = g_dbus_object_manager_client_new_for_bus_sync(
							G_BUS_TYPE_SYSTEM,
							0,
							BLUEZ_NAME,
							OBJECT_MANAGE_PATH,
							NULL, NULL, NULL,
							NULL, NULL);
	if (object_manager == NULL) {
		ERROR("create object manager error");
		/* TODO: define proper error type */
		return -1;
	}

	DBG("object manager 0x%p is created", object_manager);

	bluez_object_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_object);
	bluez_adapter_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_adapter);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);

	manager_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						NULL,
						BLUEZ_NAME,
						"/",
						MANAGER_INTERFACE,
						NULL, NULL);

	if (manager_proxy == NULL)
		ERROR("create manager_proxy error");
	else {
		DBG("manager proxy 0x%p created", manager_proxy);
		g_signal_connect(manager_proxy,
				"g-signal",
				G_CALLBACK(interfaces_changed),
				NULL);
	}
}

static void destruct_bluez_objects(void)
{
	DBG("");
	g_hash_table_destroy(bluez_object_hash);

	bluez_object_hash = NULL;
}

static void destroy_device_head(gpointer data)
{
	struct _device_head *head = data;

	g_free(head->adapter_path);
	head->adapter = NULL;

	if (head->adapter) {
		head->adapter->device_head = NULL;
		head->adapter = NULL;
	}

	g_hash_table_destroy(head->device_hash);
	head->device_hash = NULL;

	g_free(head);
}

static void destruct_bluez_devices(void)
{
	g_list_free_full(device_head_list, destroy_device_head);
	device_head_list = NULL;
}

static void destruct_bluez_adapters(void)
{
	DBG("");

	g_hash_table_destroy(bluez_adapter_hash);

	bluez_adapter_hash = NULL;
}

static void destruct_bluez_object_manager(void)
{
	g_object_unref(object_manager);

	object_manager = NULL;
}

void bluez_lib_deinit(void)
{
	if (manager_proxy)
		g_object_unref(manager_proxy);

	destruct_bluez_devices();
	destruct_bluez_adapters();
	destruct_bluez_objects();
	destruct_bluez_object_manager();
}

void bluez_adapter_set_alias(struct _bluez_adapter *adapter,
				const gchar *alias)
{

	GVariant *val = g_variant_new("s", alias);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "Alias", val);

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return;
	}

	DBG("Alias %s", alias);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL, NULL, NULL);
}

void bluez_adapter_set_powered(struct _bluez_adapter *adapter, gboolean power)
{

	GVariant *val = g_variant_new("b", power);
	GVariant *parameters = g_variant_new("(ssv)",
			ADAPTER_INTERFACE, "Powered", val);

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return;
	}

	DBG("powered %d", power);

	g_dbus_proxy_call(adapter->parent->properties_proxy,
					"Set", parameters, 0,
					-1, NULL, NULL, NULL);
}

void bluez_adapter_start_discovery(struct _bluez_adapter *adapter)
{

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return;
	}

	DBG("proxy 0x%p", adapter->proxy);

	g_dbus_proxy_call(adapter->proxy,
			"StartDiscovery", NULL,
			0, -1, NULL, NULL, NULL);

}

void bluez_adapter_stop_discovery(struct _bluez_adapter *adapter)
{

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return;
	}

	g_dbus_proxy_call(adapter->proxy,
			"StopDiscovery", NULL,
			0, -1, NULL, NULL, NULL);
}

void bluez_adapter_remove_device(struct _bluez_adapter *adapter,
					struct _bluez_device *device)
{

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return;
	}

	if (check_device(device)) {
		DBG("device does not exist");
		return;
	}


	g_dbus_proxy_call(adapter->proxy,
			"RemoveDevice", NULL,
			0, -1, NULL, NULL, NULL);
}

int bluez_adapter_get_property_powered(struct _bluez_adapter *adapter,
						gboolean *powered)
{
	GVariant *powered_v;
	gchar **names;
	int i;

	DBG("");

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return -1;
	}

	powered_v = g_dbus_proxy_get_cached_property(
					adapter->proxy,
					"Powered");
	if (powered_v == NULL) {
		ERROR("no cached property");
		return -1;
	}

	*powered = g_variant_get_boolean(powered_v);

	g_variant_unref(powered_v);

	return 0;
}

void bluez_adapter_set_powered_changed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_powered_cb_t cb,
					gpointer user_data)
{
	adapter->powered_cb = cb;
	adapter->powered_cb_data = user_data;
}

int bluez_adapter_get_property_alias(struct _bluez_adapter *adapter,
					const gchar **alias)
{
	GVariant *alias_v;

	DBG("");

	if (check_adapter(adapter)) {
		ERROR("adapter does not exist");
		return -1;
	}

	alias_v = g_dbus_proxy_get_cached_property(
					adapter->proxy,
					"Alias");
	if (alias_v == NULL) {
		ERROR("no cached property");
		return -1;
	}

	*alias = g_variant_get_string(alias_v, 0);
	DBG("alias %s", *alias);
	g_variant_unref(alias_v);

	return 0;
}

void bluez_adapter_set_alias_changed_cb(struct _bluez_adapter *adapter,
					bluez_adapter_alias_cb_t cb,
					gpointer user_data)
{
	adapter->alias_cb = cb;
	adapter->alias_cb_data = user_data;
}

struct _bluez_device *bluez_adapter_get_device(
				struct _bluez_adapter *adapter,
				const char *addr)
{
	char *device_path;
	struct _bluez_device *device;
	int size = strlen(adapter->object_path) + strlen(addr);

	device_path = malloc(size);

	sprintf(device_path, "%s/dev_%s", adapter->object_path, addr);

	DBG("device_path");

	device = g_hash_table_lookup(adapter->device_head->device_hash,
				(gconstpointer) device_path);

	free(device_path);

	return device;
}

/* Device Functions */


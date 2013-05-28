#include <gio/gio.h>
#include "common.h"
#include "bluez.h"

#define BLUEZ_NAME "org.bluez"
#define OBJECT_MANAGE_PATH "/"
#define ADAPTER_INTERFACE "org.bluez.Adapter1"
#define DEVICE_INTERFACE "org.bluez.Device1"
#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

GDBusObjectManager *object_manager;

struct _bluez_object {
	char *path_name;
	GDBusObject *obj;
	GList *interfaces;
	GDBusProxy *properties_proxy;
};

struct _bluez_adapter {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _bluez_object *parent;
	bluez_adapter_powered_cb_t powered_cb;
	gpointer powered_cb_data;
};

struct _bluez_device {
	char *interface_name;
	char *object_path;
	GDBusProxy *proxy;
	struct _bluez_object *parent;
};

struct _bluez_adapter *tmp_adapter;

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

	if (adapter->powered_cb)
		adapter->powered_cb(adapter,
					powered,
					adapter->powered_cb_data);
}

static void adapter_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);

	handle_adapter_powered_changed(changed_properties, user_data);
}

static struct _bluez_adapter *create_adapter(struct _bluez_object *object)
{
	struct _bluez_adapter *adapter;
	GDBusInterface *interface;
	GDBusInterfaceInfo *interface_info;

	adapter = g_try_new0(struct _bluez_adapter, 1);
	if (adapter == NULL) {
		ERROR("no memory");
		return NULL;
	}

	interface = g_dbus_object_get_interface(object->obj,
						ADAPTER_INTERFACE);
	if (interface == NULL)
		return NULL;

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

	tmp_adapter = adapter;

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

static void register_bluez_adapter(struct _bluez_adapter *adapter)
{
	GList *interface_list = adapter->parent->interfaces;

	bluez_adapter_list = g_list_prepend(bluez_adapter_list,
						(gpointer) adapter);
	g_hash_table_insert(bluez_adapter_hash,
				(gpointer) adapter->object_path,
				(gpointer) adapter);

	interface_list = g_list_prepend(interface_list, (gpointer) adapter);
}

static struct _bluez_device *create_device(struct _bluez_object *object)
{
	DBG("");

	return NULL;
#if 0

	struct _bluez_device *device;
	GDBusInterfaceInfo *interface_info =
				g_dbus_interface_get_info(interface);

	device = g_try_new0(struct _bluez_device, 1);
	if (device == NULL) {
		ERROR("no memory");
		return NULL;
	}

	device->proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SYSTEM, 0,
						interface_info,
						BLUEZ_NAME,
						path,
						DEVICE_INTERFACE,
						NULL, NULL);
	if (device->proxy == NULL) {
		ERROR("adapter create proxy error");
		g_free(device);
		device = NULL;
		return NULL;
	}

	device->path = g_strdup(path);

	return device;
#endif
}

static GList *bluez_device_list;
static GHashTable *bluez_device_hash;

static void register_bluez_device(struct _bluez_device *device)
{

	DBG("");

#if 0
	bluez_device_list = g_list_prepend(bluez_device_list,
						(gpointer) device);
	g_hash_table_insert(bluez_device_hash,
				(gpointer) device->object_path,
				(gpointer) device);
	return 0;
#endif
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
	if (adapter)
		register_bluez_adapter(adapter);

	device = create_device(object);
	if (device)
		register_bluez_device(device);
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
	/* TODO: Check bluez_adapter hash table */
	return tmp_adapter;
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

static void destruct_bluez_device(gpointer data)
{
	struct _bluez_device *device = data;

	DBG("");
#if 0
	bluez_device_list = g_list_remove(bluez_device_list, data);
#endif
}

int bluez_lib_init(void)
{
	GList *obj_list;

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
	bluez_device_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_bluez_device);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);
}

static void destruct_bluez_objects(void)
{
	DBG("");
	g_hash_table_destroy(bluez_object_hash);

	bluez_object_hash = NULL;
}

static void destruct_bluez_devices(void)
{
	DBG("");
	g_hash_table_destroy(bluez_device_hash);

	bluez_device_hash = NULL;
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
	destruct_bluez_devices();
	destruct_bluez_adapters();
	destruct_bluez_objects();
	destruct_bluez_object_manager();
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

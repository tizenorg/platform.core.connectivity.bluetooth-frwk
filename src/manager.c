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

#include "manager.h"
#include "vertical.h"
#include "comms_error.h"

#include "pairing.h"
#include "opp.h"
#ifdef TIZEN_2_MOBILE
#include "map_agent.h"
#endif
#include "bluez.h"
#include "gdbus.h"

#define DEFAULT_ADAPTER "hci0"

#define BLUETOOTH_PATH "/org/tizen/comms/bluetooth"

extern void opp_set_adapter_connectable(gboolean connectable);

static GDBusObjectManagerServer *manager_server;
GDBusObjectSkeleton *bt_object;

static gboolean bt_activate_timeout(gpointer user_data);

G_DEFINE_TYPE(CommsManagerSkeleton, comms_manager_skeleton,
				G_TYPE_DBUS_INTERFACE_SKELETON);

struct _CommsManagerSkeletonPrivate
{
	GValue *properties;
	GList *changed_properties;
	guint changed_properties_idle;
};

static inline gboolean _g_variant_equal0(GVariant *a, GVariant *b)
{
	if (a == NULL && b == NULL)
		return TRUE;

	if (a == NULL || b == NULL)
		return FALSE;

  	return g_variant_equal(a, b);
}

static gboolean _g_value_equal(const GValue *a, const GValue *b)
{
	g_assert(G_VALUE_TYPE(a) == G_VALUE_TYPE(b));

	switch (G_VALUE_TYPE(a)) {
	case G_TYPE_BOOLEAN:
		return (g_value_get_boolean(a) == g_value_get_boolean(b));
	case G_TYPE_UCHAR:
		return (g_value_get_uchar(a) == g_value_get_uchar(b));
	case G_TYPE_INT:
		return (g_value_get_int(a) == g_value_get_int(b));
	case G_TYPE_UINT:
		return (g_value_get_uint(a) == g_value_get_uint(b));
	case G_TYPE_INT64:
		return (g_value_get_int64(a) == g_value_get_int64(b));
	case G_TYPE_UINT64:
		return (g_value_get_uint64(a) == g_value_get_uint64(b));
	case G_TYPE_STRING:
		return (g_strcmp0(g_value_get_string(a),
				g_value_get_string(b)) == 0);
	case G_TYPE_VARIANT:
		return _g_variant_equal0(g_value_get_variant(a),
						g_value_get_variant(b));
	default:
		g_critical("_g_value_equal() does not handle type %s",
					g_type_name(G_VALUE_TYPE (a)));
	}

	return FALSE;
}

static void comms_manager_skeleton_init(CommsManagerSkeleton *skeleton)
{
	skeleton->priv = G_TYPE_INSTANCE_GET_PRIVATE(skeleton,
						COMMS_TYPE_MANAGER_SKELETON,
						CommsManagerSkeletonPrivate);

	skeleton->priv->properties = g_new0(GValue, 4);
	g_value_init(&skeleton->priv->properties[0], G_TYPE_BOOLEAN);
	g_value_init(&skeleton->priv->properties[1], G_TYPE_BOOLEAN);
	g_value_init(&skeleton->priv->properties[2], G_TYPE_STRING);
	g_value_init(&skeleton->priv->properties[3], G_TYPE_BOOLEAN);

	bt_object = g_dbus_object_skeleton_new(BLUETOOTH_PATH);
}

typedef struct
{
	const GDBusPropertyInfo *info;
	guint prop_id;
	GValue orig_value;
} ChangedProperty;

static const GDBusMethodInfo * const _method_info_pointers[] =
{
	GDBUS_METHOD("EnableBluetoothService", NULL, NULL),
	GDBUS_METHOD("DisableBluetoothService", NULL, NULL),
	GDBUS_METHOD("SetDefaultAdapter",
			GDBUS_ARGS(_ARG("adapter", "s")), NULL),
	GDBUS_METHOD("GetAdapterVisibleTime",
			NULL, GDBUS_ARGS(_ARG("time", "u"))),
	GDBUS_METHOD("SetAdapterConnectable",
			GDBUS_ARGS(_ARG("connectable", "b")), NULL),
	GDBUS_METHOD("GetAdapterConnectable",
			NULL, GDBUS_ARGS(_ARG("connectable", "b"))),
	NULL
};

static const GDBusPropertyInfo * const _manager_property_info_pointers[] =
{
	GDBUS_PROPERTY("BluetoothInService", "b",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("BluetoothActivating", "b",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("DefaultAdapter", "s",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("AdapterConnectable", "b",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	NULL
};

static const GDBusInterfaceInfo _manager_interface_info =
{
	-1,
	(gchar *) "org.tizen.comms.manager",
	(GDBusMethodInfo **) &_method_info_pointers,
	NULL,
	(GDBusPropertyInfo **) &_manager_property_info_pointers,
	NULL
};

static GDBusInterfaceInfo *manager_skeleton_get_info(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceInfo *) &_manager_interface_info;
}

bluez_adapter_t *default_adapter;
guint bt_activate_timeout_id;

static inline gboolean get_boolean(CommsManagerSkeleton *skeleton,
					const gchar *property_name)
{
	GValue value = G_VALUE_INIT;
	gboolean ret;

	g_value_init(&value, G_TYPE_BOOLEAN);
	g_object_get_property(G_OBJECT(skeleton), property_name, &value);
	ret = g_value_get_boolean(&value);
	g_value_unset(&value);

	return ret;
}

static inline void set_boolean(CommsManagerSkeleton *skeleton,
				const gchar *property_name, gboolean val)
{
	GValue value = G_VALUE_INIT;

	g_value_init(&value, G_TYPE_BOOLEAN);
	g_value_set_boolean(&value, val);
	g_object_set_property(G_OBJECT(skeleton), property_name, &value);
	g_value_unset(&value);
}

static inline gchar *get_string(CommsManagerSkeleton *skeleton,
					const gchar *property_name)
{
	GValue value = G_VALUE_INIT;
	gchar *str;

	g_value_init(&value, G_TYPE_STRING);
	g_object_get_property(G_OBJECT(skeleton), property_name, &value);
	str = g_strdup(g_value_get_string(&value));
	g_value_unset(&value);

	return str;
}

static inline void set_string(CommsManagerSkeleton *skeleton,
				const gchar *property_name, const gchar *str)
{
	GValue value = G_VALUE_INIT;

	g_value_init(&value, G_TYPE_STRING);
	g_value_set_string(&value, str);
	g_object_set_property(G_OBJECT(skeleton), property_name, &value);
	g_value_unset(&value);
}

static inline void set_bluetooth_activating(CommsManagerSkeleton *skeleton,
							gboolean activating)
{
	set_boolean(skeleton, "BluetoothActivating", activating);
}

static inline gboolean get_bluetooth_activating(CommsManagerSkeleton *skeleton)
{
	return get_boolean(skeleton, "BluetoothActivating");
}

static inline void set_bluetooth_in_service(CommsManagerSkeleton *skeleton,
							gboolean in_service)
{
	set_boolean(skeleton, "BluetoothInService", in_service);
}

static inline gboolean get_bluetooth_in_service(CommsManagerSkeleton *skeleton)
{
	return get_boolean(skeleton, "BluetoothInService");
}

static inline void set_default_adapter(CommsManagerSkeleton *skeleton,
						const gchar *default_adapter)
{
	set_string(skeleton, "DefaultAdapter", default_adapter);
}

static inline void set_adapter_connectable(CommsManagerSkeleton *skeleton,
						const gboolean connectable)
{
	set_boolean(skeleton, "AdapterConnectable", connectable);
}

static inline gchar *get_default_adapter(CommsManagerSkeleton *skeleton)
{
	return get_string(skeleton, "DefaultAdapter");
}

static inline gboolean get_adapter_connectable(CommsManagerSkeleton *skeleton)
{
	return get_boolean(skeleton, "AdapterConnectable");
}

struct bt_activate_data {
	CommsManagerSkeleton *skeleton;
	GDBusMethodInvocation *invocation;
};

struct visible_time_t {
	GTimeVal start_time;
	guint32 timeout;
};

struct visible_time_t visible_time;

static void adapter_powered_on(CommsManagerSkeleton *skeleton)
{
	GDBusConnection *connection;

	DBG("");

	set_bluetooth_activating(skeleton, FALSE);
	set_bluetooth_in_service(skeleton, TRUE);

	connection = g_dbus_interface_skeleton_get_connection(
				G_DBUS_INTERFACE_SKELETON(skeleton));

	bt_service_pairing_init(bt_object, connection, default_adapter);
	bt_service_opp_init(bt_object, connection);

#ifdef TIZEN_2_MOBILE
	bt_map_agent_init();
#endif

	g_dbus_object_manager_server_export(manager_server, bt_object);
}

static gboolean destruct_bluez_lib(gpointer user_data)
{
	bluez_lib_deinit();

	return FALSE;
}

static void adapter_powered_off(CommsManagerSkeleton *skeleton)
{
	DBG("");

	set_bluetooth_activating(skeleton, FALSE);
	set_bluetooth_in_service(skeleton, FALSE);

	bt_service_pairing_deinit();
	bt_service_opp_deinit();

#ifdef TIZEN_2_MOBILE
	bt_map_agent_deinit();
#endif

	g_dbus_object_manager_server_unexport(manager_server,
						BLUETOOTH_PATH);

	g_idle_add(destruct_bluez_lib, NULL);
}

static void adapter_powered_changed(bluez_adapter_t *adapter,
					gboolean powered, void *user_data)
{
	struct bt_activate_data *adapter_activate_data = user_data;

	DBG("");

	if (adapter_activate_data->invocation) {
		g_dbus_method_invocation_return_value(
				adapter_activate_data->invocation, NULL);

		adapter_activate_data->invocation = NULL;
	}

	if (powered == FALSE) {
		adapter_powered_off(adapter_activate_data->skeleton);

		vertical_notify_bt_disabled();

		set_bluetooth_in_service(adapter_activate_data->skeleton,
						FALSE);

		g_free(adapter_activate_data);
	} else
		adapter_powered_on(adapter_activate_data->skeleton);
}

static void device_connected_changed(bluez_device_t *device,
					int connected, void *user_data)
{
	CommsManagerSkeleton *skeleton = user_data;
	gboolean connectable = TRUE;

	DBG("");

	if (skeleton)
		connectable = get_adapter_connectable(skeleton);

	if (connected && !connectable) {
		DBG("disconnection all profile");
		bluez_device_disconnect_all(device, NULL);
		bluez_device_set_blocked(device, TRUE);
	}
}

static void set_device_property_changed_callback(bluez_device_t *device,
					CommsManagerSkeleton *skeleton)
{
	DBG("");

	bluez_device_set_connected_changed_cb(device,
					device_connected_changed,
					skeleton);
}

static void unset_device_property_changed_callback(bluez_device_t *device)
{
	DBG("");

	bluez_device_unset_connected_changed_cb(device);
}

static void foreach_device_property_callback(GList *list,
					gboolean flag,
					CommsManagerSkeleton *skeleton)
{
	bluez_device_t *device;
	GList *iter, *next;

	DBG("");

	for (iter = g_list_first(list); iter; iter = next) {
		next = g_list_next(iter);

		device = iter->data;

		if (flag)
			set_device_property_changed_callback(device,
							skeleton);
		else
			unset_device_property_changed_callback(device);
	}
}

static void bt_device_set_connection_state_changed(
					CommsManagerSkeleton *skeleton)
{
	GList *list;

	DBG("");

	if (default_adapter == NULL)
		return;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, TRUE, skeleton);
}

static void bt_device_unset_connection_state_changed(void)
{
	GList *list;

	DBG("");

	if (default_adapter == NULL)
		return;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, FALSE, NULL);
}

static void bt_adapter_device_callback(struct _bluez_device *device,
						gpointer user_data)
{
	gboolean connectable;
	CommsManagerSkeleton *skeleton = user_data;

	DBG("");

	if (!skeleton)
		return;

	set_device_property_changed_callback(device, skeleton);

	connectable = get_adapter_connectable(skeleton);
	DBG("connectable = %d", connectable);

	if (!connectable)
		bluez_device_set_blocked(device, TRUE);
}

static void bt_adapter_set_enable(bluez_adapter_t *adapter, void *user_data)
{
	struct bt_activate_data *adapter_activate_data = user_data;
	gboolean powered;
	int ret = 0;

	bluez_adapter_set_powered_changed_cb(default_adapter,
						adapter_powered_changed,
						adapter_activate_data);

	bluez_adapter_get_property_powered(default_adapter, &powered);
	if (powered == FALSE)
		ret = bluez_adapter_set_powered(default_adapter, TRUE);

	bt_device_set_connection_state_changed(adapter_activate_data->skeleton);
	bluez_adapter_set_device_created_cb(default_adapter,
					bt_adapter_device_callback,
					adapter_activate_data->skeleton);

	if (ret) {
		bt_activate_timeout(adapter_activate_data);
		adapter_activate_data = NULL;
	} else {
		if (adapter_activate_data->invocation)
			g_dbus_method_invocation_return_value(
				adapter_activate_data->invocation, NULL);
		adapter_activate_data->invocation = NULL;

		if (powered == TRUE)
			adapter_powered_on
				(adapter_activate_data->skeleton);
	}
}

static void discoverable_changed(bluez_adapter_t *adapter,
				gboolean discoverable, void *user_data)
{
	guint32 timeout;

	bluez_adapter_get_property_discoverable_timeout(adapter, &timeout);
	if (timeout == 0)
		return;

	if (discoverable == FALSE)
		return;

	g_get_current_time(&visible_time.start_time);
	visible_time.timeout = timeout;
}

static void discoverable_timeout_changed(bluez_adapter_t *adapter,
					guint32 timeout, void *user_data)
{
	gboolean discoverable;

	bluez_adapter_get_property_discoverable(adapter, &discoverable);
	if (discoverable == FALSE)
		return;

	g_get_current_time(&visible_time.start_time);
	visible_time.timeout = timeout;
}

static void set_discoverable_timer(void)
{
	guint32 discoverable_timeout;
	gboolean discoverable;

	bluez_adapter_get_property_discoverable(default_adapter,
						&discoverable);
	bluez_adapter_get_property_discoverable_timeout(default_adapter,
						&discoverable_timeout);

	if (discoverable && discoverable_timeout > 0) {
		g_get_current_time(&visible_time.start_time);
		visible_time.timeout = discoverable_timeout;
	}

	bluez_adapter_set_discoverable_changed_cb(default_adapter,
					discoverable_changed, NULL);
	bluez_adapter_set_discoverable_timeout_changed_cb(default_adapter,
					discoverable_timeout_changed, NULL);
}

static void adapter_added_cb(bluez_adapter_t *adapter, void *user_data)
{
	struct bt_activate_data *data = user_data;
	gchar *default_adapter_name;

	DBG("");

	default_adapter_name = get_default_adapter(data->skeleton);

	default_adapter = bluez_adapter_get_adapter(default_adapter_name);

	g_free(default_adapter_name);

	if (default_adapter == NULL)
		return;

	set_discoverable_timer();

	bt_adapter_set_enable(default_adapter, data);

	bluez_adapter_unset_adapter_added();

	if (bt_activate_timeout_id > 0) {
		g_source_remove(bt_activate_timeout_id);
		bt_activate_timeout_id = 0;
	}

	if (data)
		g_free(data);
}

static gboolean bt_activate_timeout(gpointer user_data)
{
	struct bt_activate_data *data = user_data;

	DBG("");

	comms_error_failed(data->invocation, "Activate failed");

	bluez_adapter_unset_adapter_added();

	set_bluetooth_activating(data->skeleton, FALSE);
	set_bluetooth_in_service(data->skeleton, FALSE);

	g_free(data);

	bluez_lib_deinit();

	ERROR("Activate bluetooth service timeout");

	return FALSE;
}

static void handle_enable_bluetooth_service(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	gchar *default_adapter_name;
	gboolean state;
	struct bt_activate_data *adapter_activate_data;

	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);

	state = get_bluetooth_activating(skeleton);
	if (state == TRUE) {
		comms_error_in_progress(invocation);

		return;
	}

	state = get_bluetooth_in_service(skeleton);
	if (state == TRUE) {
		comms_error_already_done(invocation);

		return;
	}

	if (vertical_notify_bt_enabled() != 0) {
		comms_error_failed(invocation, "Can't load vertical");

		return;
	}

	default_adapter_name = get_default_adapter(skeleton);
	DBG("adapter: %s", default_adapter_name);

	set_bluetooth_activating(skeleton, TRUE);

	if (bluez_lib_init()) {
		comms_error_failed(invocation, "Failed");

		g_free(default_adapter_name);
		return;
	}

	adapter_activate_data = g_new0(struct bt_activate_data, 1);
	if (adapter_activate_data == NULL) {
		ERROR("no memory");

		comms_error_failed(invocation, "Failed");

		g_free(default_adapter_name);

		return;
	}

	default_adapter = bluez_adapter_get_adapter(default_adapter_name);

	g_free(default_adapter_name);

	adapter_activate_data->skeleton = skeleton;
	adapter_activate_data->invocation = invocation;

	if (!default_adapter) {
		bluez_adapter_set_adapter_added(adapter_added_cb,
						adapter_activate_data);

		bt_activate_timeout_id = g_timeout_add(500, bt_activate_timeout,
							adapter_activate_data);

		return;
	}

	set_discoverable_timer();

	bt_adapter_set_enable(default_adapter, adapter_activate_data);

	return;
}

static void handle_disable_bluetooth_service(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = user_data;
	gboolean state;
	int ret;

	DBG("");
	state = get_bluetooth_activating(skeleton);
	if (state == TRUE) {
		comms_error_busy(invocation);

		return;
	}

	if (!default_adapter) {
		comms_error_not_ready(invocation);

		return;
	}

	ret = bluez_adapter_set_powered(default_adapter, FALSE);

	bt_device_unset_connection_state_changed();

	default_adapter = NULL;

	if (ret)
		comms_error_failed(invocation,
						"set powered off");
	else
		g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_set_default_adapter(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	gchar *adapter_name;

	if (get_bluetooth_activating(skeleton) ||
			get_bluetooth_in_service(skeleton)) {
		comms_error_busy(invocation);

		return;
	}

	g_variant_get(parameters, "(s)", &adapter_name);
	set_default_adapter(skeleton, adapter_name);
	g_free(adapter_name);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_get_adapter_visible_time(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	guint32 remain_time, during, timeout;
	gboolean discoverable;
	GTimeVal current_time;

	if (get_bluetooth_activating(skeleton)) {
		comms_error_busy(invocation);
		return;
	}

	if (default_adapter == NULL) {
		comms_error_no_such_adapter(invocation);
		return;
	}

	if (!get_bluetooth_in_service(skeleton)) {
		comms_error_not_available(invocation);
		return;
	}

	bluez_adapter_get_property_discoverable(default_adapter,
						&discoverable);
	bluez_adapter_get_property_discoverable_timeout(default_adapter,
						&timeout);

	if (discoverable == FALSE || timeout == 0) {
		remain_time = 0;
		goto done;
	}

	g_get_current_time(&current_time);

	during = current_time.tv_sec - visible_time.start_time.tv_sec;
	remain_time = visible_time.timeout - during;

	if (remain_time < 0)
		remain_time = 0;

done:
	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(u)", remain_time));
}

static void foreach_device_set_blocked(GList *list,
				gboolean connectable)
{
	bluez_device_t *device;
	GList *iter, *next;

	DBG("");

	for (iter = g_list_first(list); iter; iter = next) {
		next = g_list_next(iter);
		device = iter->data;
		bluez_device_set_blocked(device, connectable);
	}
}

static void handle_set_adapter_connectable(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	gboolean connectable;
	gchar *default_adapter_name;
	GList *list;

	DBG("");

	if (!skeleton) {
		comms_error_failed(invocation, "Failed");
		return;
	}

	if (default_adapter == NULL) {
		default_adapter_name = get_default_adapter(skeleton);
		DBG("adapter: %s", default_adapter_name);

		default_adapter = bluez_adapter_get_adapter(
						default_adapter_name);
	}

	g_variant_get(parameters, "(b)", &connectable);
	set_adapter_connectable(skeleton, connectable);
	if (default_adapter) {
		list = bluez_adapter_get_devices(default_adapter);
		foreach_device_set_blocked(list, !connectable);
	}

	opp_set_adapter_connectable(connectable);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_get_adapter_connectable(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	gboolean connectable;

	connectable = get_adapter_connectable(skeleton);

	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(b)", connectable));
}

static void _manager_skeleton_handle_method_call(
				GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("Method name %s", method_name);
	if (g_strcmp0(method_name, "EnableBluetoothService") == 0)
		handle_enable_bluetooth_service(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "DisableBluetoothService") == 0)
		handle_disable_bluetooth_service(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "SetDefaultAdapter") == 0)
		handle_set_default_adapter(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "GetAdapterVisibleTime") == 0)
		handle_get_adapter_visible_time(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "SetAdapterConnectable") == 0)
		handle_set_adapter_connectable(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "GetAdapterConnectable") == 0)
		handle_get_adapter_connectable(connection, parameters,
						invocation, user_data);
	else
		WARN("Unknown method");
} 

static GVariant *_manager_skeleton_handle_get_property(
				GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *property_name,
				GError **error, gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	GValue value = G_VALUE_INIT;
	GParamSpec *pspec;
	GVariant *ret;
	GDBusPropertyInfo *info;

	DBG("property_name %s", property_name);

	pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(skeleton),
								property_name);
	if (pspec == NULL) {
		g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
				"No property with name %s", property_name);
		return NULL;
	}

	g_value_init(&value, pspec->value_type);
	g_object_get_property(G_OBJECT(skeleton), property_name, &value);
	info = g_dbus_interface_info_lookup_property(
						(GDBusInterfaceInfo *)
						&_manager_interface_info,
								property_name);
	g_assert(info != NULL);
	ret = g_dbus_gvalue_to_gvariant(&value, G_VARIANT_TYPE(info->signature));
	g_value_unset(&value);

	gchar *out = g_variant_print(ret, TRUE);

	DBG("ret %s", out);
	g_free(out);
	return ret;
}

static gboolean _manager_skeleton_handle_set_property(
					GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *property_name,
					GVariant *variant,
					GError **error,
					gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	GValue value = G_VALUE_INIT;
	GParamSpec *pspec;

	pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(skeleton),
								property_name);
	if (pspec == NULL) {
		g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
				"No property with name %s", property_name);
		return FALSE;
	}

	g_value_set_variant(&value, variant);
	g_object_set_property(G_OBJECT(skeleton), property_name, &value);
	g_value_unset(&value);

	return TRUE;
}

static const GDBusInterfaceVTable _manager_skeleton_vtable =
{
	_manager_skeleton_handle_method_call,
	_manager_skeleton_handle_get_property,
	_manager_skeleton_handle_set_property,
};

static GDBusInterfaceVTable *manager_skeleton_get_vtable(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceVTable *) &_manager_skeleton_vtable;
}

static GVariant *manager_skeleton_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(_skeleton);
	GVariantBuilder builder;
	guint n;

	DBG("");

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));

	if (_manager_interface_info.properties == NULL)
		goto out;

	for (n = 0; _manager_interface_info.properties[n] != NULL; n++) {
		GVariant *value;
		GDBusPropertyInfo *info =
				_manager_interface_info.properties[n];
		if (!(info->flags & G_DBUS_PROPERTY_INFO_FLAGS_READABLE))
			continue;

		value = _manager_skeleton_handle_get_property(NULL, NULL, NULL,
					NULL, info->name, NULL, skeleton);
	        if (value == NULL)
			continue;

		g_variant_take_ref(value);
		g_variant_builder_add(&builder, "{sv}", info->name, value);
		g_variant_unref(value);
	}
out:
	return g_variant_builder_end (&builder);
}

static void schedule_emit_changed(GList **changed_properties,
				const GDBusPropertyInfo *info,
				guint prop_id, const GValue *orig_value)
{
	ChangedProperty *cp;
	GList *l;
	cp = NULL;

	DBG("");

	for (l = *changed_properties; l != NULL; l = l->next) {

		ChangedProperty *i_cp = l->data;

		if (i_cp->info != info)
			continue;

		cp = i_cp;
		break;
	}

	if (cp != NULL)
		return;

	cp = g_new0(ChangedProperty, 1);
	cp->prop_id = prop_id;
	cp->info = info;
	*changed_properties = g_list_prepend(*changed_properties, cp);
	g_value_init(&cp->orig_value, G_VALUE_TYPE(orig_value));
	g_value_copy(orig_value, &cp->orig_value);
}

static void manager_skeleton_set_property(GObject *object, guint prop_id,
			const GValue *value, GParamSpec *pspec)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(object);

	g_assert(prop_id != 0 && prop_id - 1 < 4);

	DBG("prop_id %d", prop_id);

	if (_g_value_equal(value, &skeleton->priv->properties[prop_id - 1]))
		return;

	if (g_dbus_interface_skeleton_get_connection(
			G_DBUS_INTERFACE_SKELETON(skeleton)) != NULL)
		schedule_emit_changed(&skeleton->priv->changed_properties,
				_manager_property_info_pointers[prop_id - 1],
				prop_id, &skeleton->priv->properties[prop_id - 1]);

	g_value_copy(value, &skeleton->priv->properties[prop_id - 1]);

	g_object_notify_by_pspec(object, pspec);
}

static void _emit_signal(GVariantBuilder *builder,
			GVariantBuilder *invalidated_builder,
			CommsManagerSkeleton *skeleton)
{
	GList *connections, *l;
	GVariant *signal_variant;
	signal_variant = g_variant_ref_sink(g_variant_new("(sa{sv}as)",
					"org.tizen.comms.manager",
					builder, invalidated_builder));

	connections = g_dbus_interface_skeleton_get_connections(
				G_DBUS_INTERFACE_SKELETON(skeleton));

	for (l = connections; l != NULL; l = l->next) {
		GDBusConnection *connection = l->data;

	        g_dbus_connection_emit_signal(connection, NULL,
					"/org/tizen/comms/manager",
					"org.freedesktop.DBus.Properties",
					"PropertiesChanged",
					signal_variant, NULL);
	}

	g_variant_unref(signal_variant);
	g_list_free_full(connections, g_object_unref);
}

static void _changed_property_free(ChangedProperty *data)
{
	g_value_unset(&data->orig_value);
	g_free (data);
}

static gboolean _manager_emit_changed(gpointer user_data)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(user_data);
	GVariantBuilder invalidated_builder;
	GVariantBuilder builder;
	guint num_changes = 0;
	GList *l;

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_init(&invalidated_builder, G_VARIANT_TYPE("as"));

	for (l = skeleton->priv->changed_properties; l != NULL; l = l->next) {
		ChangedProperty *cp = l->data;
		GVariant *variant;
		const GValue *cur_value = 
				&skeleton->priv->properties[cp->prop_id - 1];

		if (_g_value_equal(cur_value, &cp->orig_value))
			continue;

		variant = g_dbus_gvalue_to_gvariant(cur_value,
				G_VARIANT_TYPE(cp->info->signature));
		g_variant_builder_add(&builder, "{sv}", cp->info->name, variant);
		g_variant_unref(variant);
		num_changes++;
	}

	if (num_changes == 0)
		goto out;

	_emit_signal(&builder, &invalidated_builder, skeleton);

out:
	g_variant_builder_clear(&builder);
	g_variant_builder_clear(&invalidated_builder);

	g_list_free_full(skeleton->priv->changed_properties,
			(GDestroyNotify)_changed_property_free);

	skeleton->priv->changed_properties = NULL;

	skeleton->priv->changed_properties_idle = 0;

	return FALSE;
}

static void manager_skeleton_notify(GObject *object, GParamSpec *pspec)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(object);

	DBG("");

	if (skeleton->priv->changed_properties == NULL)
		return;

	if (skeleton->priv->changed_properties_idle)
		return;

	skeleton->priv->changed_properties_idle =
			g_idle_add(_manager_emit_changed, skeleton);
}

static void manager_skeleton_get_property(GObject *object, guint prop_id,
					GValue *value, GParamSpec *pspec)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(object);

	DBG("prop_id %d", prop_id);

	g_assert(prop_id != 0 && prop_id - 1 < 4);

	g_value_copy(&skeleton->priv->properties[prop_id - 1], value);
}

static void bluetooth_flight_mode_cb(gboolean flight_mode, void *user_data)
{
	gboolean powered = FALSE;
	gboolean state;
	gchar *default_adapter_name;
	struct bt_activate_data *adapter_activate_data;
	CommsManagerSkeleton *skeleton = user_data;

	DBG("+");

	if (!skeleton)
		return;

	if (default_adapter == NULL) {
		default_adapter_name = get_default_adapter(skeleton);
		DBG("adapter: %s", default_adapter_name);

		default_adapter = bluez_adapter_get_adapter(
						default_adapter_name);
		if (default_adapter_name)
			g_free(default_adapter_name);
		if (default_adapter)
			bluez_adapter_get_property_powered(
					default_adapter, &powered);
	} else {
		bluez_adapter_get_property_powered(
					default_adapter, &powered);
	}

	if (!flight_mode) {
		if (!powered) {
			set_bluetooth_activating(skeleton, TRUE);

			if (bluez_lib_init())
				return;

			adapter_activate_data =
				g_new0(struct bt_activate_data, 1);
			if (adapter_activate_data == NULL) {
				ERROR("no memory");
				return;
			}
			adapter_activate_data->skeleton = skeleton;
			if (!default_adapter) {
				bluez_adapter_set_adapter_added(
						adapter_added_cb,
						adapter_activate_data);

				bt_activate_timeout_id = g_timeout_add(500,
						bt_activate_timeout,
						adapter_activate_data);
				return;
			}

			set_discoverable_timer();

			bt_adapter_set_enable(default_adapter,
						adapter_activate_data);
		}
	} else {
		if (powered) {
			state = get_bluetooth_activating(skeleton);
			DBG("state = %d", state);
			if (state == TRUE)
				return;

			if (!default_adapter)
				return;

			bluez_adapter_set_powered(default_adapter, FALSE);
			default_adapter = NULL;
		}
	}

	DBG("-");
}

static void bluetooth_set_name_cb(char *name, void *user_data)
{
	gchar *default_adapter_name;
	CommsManagerSkeleton *skeleton = user_data;

	DBG("+");

	if (!skeleton)
		return;

	if (default_adapter == NULL) {
		default_adapter_name = get_default_adapter(skeleton);
		DBG("adapter: %s", default_adapter_name);

		default_adapter = bluez_adapter_get_adapter(
						default_adapter_name);
		if (default_adapter_name)
			g_free(default_adapter_name);
		if (default_adapter)
			bluez_adapter_set_alias(default_adapter, name);
	} else
		bluez_adapter_set_alias(default_adapter, name);

	return;
}

static void manager_skeleton_finalize(GObject *object)
{
	CommsManagerSkeleton *skeleton = COMMS_MANAGER_SKELETON(object);

	DBG("");

	g_object_unref(bt_object);

	g_value_unset(&skeleton->priv->properties[0]);
	g_value_unset(&skeleton->priv->properties[1]);
	g_value_unset(&skeleton->priv->properties[2]);
	g_value_unset(&skeleton->priv->properties[3]);

	g_free(skeleton->priv->properties);

	g_list_free_full(skeleton->priv->changed_properties,
				(GDestroyNotify) _changed_property_free);

	if (skeleton->priv->changed_properties_idle)
		g_source_remove(skeleton->priv->changed_properties_idle);

	G_OBJECT_CLASS(comms_manager_skeleton_parent_class)->finalize(object);

	vertical_notify_bt_set_flight_mode_cb(NULL, NULL);
	vertical_notify_bt_set_name_cb(NULL, NULL);
}

static void comms_manager_skeleton_class_init(CommsManagerSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *skeleton_class;

	DBG("");

	g_type_class_add_private(klass, sizeof(CommsManagerSkeletonPrivate));

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = manager_skeleton_finalize;
	gobject_class->get_property = manager_skeleton_get_property;
	gobject_class->set_property = manager_skeleton_set_property;
	gobject_class->notify = manager_skeleton_notify;

	skeleton_class = G_DBUS_INTERFACE_SKELETON_CLASS(klass);

	skeleton_class->get_info = manager_skeleton_get_info;
	skeleton_class->get_properties = manager_skeleton_get_properties;
	skeleton_class->get_vtable = manager_skeleton_get_vtable;

	g_object_class_install_property(gobject_class, 1,
			g_param_spec_boolean("BluetoothInService",
						"BluetoothInService",
						"BluetoothInService",
						FALSE, G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, 2,
			g_param_spec_boolean("BluetoothActivating",
						"BluetoothActivating",
						"BluetoothActivating",
						FALSE, G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, 3,
			g_param_spec_string("DefaultAdapter",
						"DefaultAdapter",
						"DefaultAdapter",
						"hci0", G_PARAM_READWRITE));

	g_object_class_install_property(gobject_class, 4,
			g_param_spec_boolean("AdapterConnectable",
						"AdapterConnectable",
						"AdapterConnectable",
						TRUE, G_PARAM_READWRITE));
}

CommsManagerSkeleton *comms_service_manager_new(
				GDBusObjectManagerServer *server)
{
	CommsManagerSkeleton *object;

	manager_server = server;

	object = g_object_new(COMMS_TYPE_MANAGER_SKELETON,
				"BluetoothInService", FALSE,
				"BluetoothActivating", FALSE,
				"DefaultAdapter", DEFAULT_ADAPTER,
				"AdapterConnectable", TRUE,
				NULL);

	vertical_notify_bt_set_flight_mode_cb(bluetooth_flight_mode_cb,
							object);
	vertical_notify_bt_set_name_cb(bluetooth_set_name_cb, object);

	return object;
}

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

#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "media.h"
#include "vertical.h"

#define BLUETOOTH_OBJECT "/org/tizen/comms/bluetooth"
#define BT_MEDIA_OBJECT_PATH "/Musicplayer"
#define MEDIA_PLAYER_INTERFACE  "org.mpris.MediaPlayer2.Player"

struct agent {
	gchar *owner;
	gchar *object_path;
	guint watch_id;
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
	bluez_adapter_discoverable_cb_t discoverable_cb;
	gpointer discoverable_cb_data;
	bluez_adapter_discoverable_tm_cb_t discoverable_timeout_cb;
	gpointer discoverable_timeout_cb_data;
};

static struct agent *relay_agent;

static const GDBusMethodInfo *_media_method_info_pointers[] =
{
	GDBUS_METHOD("RegisterMediaAgent",
				GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("UnregisterMediaAgent",
				GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("MediaPlayerChangeProperty",
				GDBUS_ARGS(_ARG("type", "u"),
				_ARG("value", "u")), NULL),
	GDBUS_METHOD("MediaPlayerChangeProperties",
				GDBUS_ARGS(_ARG("properties", "a{sv}")),
				NULL),
	GDBUS_METHOD("MediaPlayerChangeTrack",
				GDBUS_ARGS(_ARG("Track", "a{sv}")),
				NULL),
	NULL
};

static const GDBusInterfaceInfo _media_interface_info =
{
	-1,
	"org.tizen.comms.mediaplayer",
	(GDBusMethodInfo **) &_media_method_info_pointers,
	NULL,
	NULL,
	NULL
};

G_DEFINE_TYPE(MediaSkeleton, media_skeleton,
			G_TYPE_DBUS_INTERFACE_SKELETON);

static GDBusInterfaceInfo *media_skeleton_dbus_interface_get_info(
				GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceInfo *) &_media_interface_info;
}

static GDBusObjectSkeleton *bt_object_skeleton;
static bluez_adapter_t *default_adapter;
static MediaSkeleton *bt_media;

static void bt_media_register_dbus_interface(MediaSkeleton *skeleton,
					GDBusConnection *connection)
{
	GDBusInterfaceSkeleton *media_interface;

	DBG("");

	media_interface = G_DBUS_INTERFACE_SKELETON(skeleton);

	g_dbus_object_skeleton_add_interface(bt_object_skeleton,
						media_interface);
}

static void bt_media_unregister_dbus_interface()
{
	GDBusInterfaceSkeleton *media_interface;

	media_interface = G_DBUS_INTERFACE_SKELETON(bt_media);

	g_dbus_object_skeleton_remove_interface(bt_object_skeleton,
						media_interface);
}

static void free_relay_agent(struct agent *agent)
{
	g_free(agent->owner);
	g_free(agent->object_path);

	g_free(agent);
}

static void relay_agent_disconnected(GDBusConnection *connection,
				const gchar *name, gpointer user_data)
{
	DBG("");

	if (!relay_agent)
		return;

	free_relay_agent(relay_agent);

	relay_agent = NULL;
}

static struct agent *create_relay_agent(const gchar *sender,
					const gchar *path,
					guint watch_id)
{
	struct agent *agent;

	agent = g_new0(struct agent, 1);
	if (agent == NULL) {
		ERROR("no memory");
		return NULL;
	}

	agent->owner = g_strdup(sender);
	agent->object_path = g_strdup(path);
	agent->watch_id = watch_id;

	return agent;
}

static void register_relay_agent_handler(
					GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	const gchar *sender;
	gchar *agent_path;
	guint relay_agent_watch_id;

	DBG("");

	if (relay_agent)
		return comms_error_already_exists(invocation);

	g_variant_get(parameters, "(o)", &agent_path);
	if (agent_path == NULL)
		return comms_error_invalid_args(invocation);

	sender = g_dbus_method_invocation_get_sender(invocation);

	relay_agent_watch_id =
			g_bus_watch_name_on_connection(connection, sender,
					G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
					NULL, relay_agent_disconnected,
					NULL, NULL);

	relay_agent = create_relay_agent(sender, agent_path,
						relay_agent_watch_id);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void unregister_relay_agent_handler(
					GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	gchar *relay_agent_path;

	DBG("");

	if (relay_agent == NULL)
		return comms_error_does_not_exist(invocation);

	g_variant_get(parameters, "(o)", &relay_agent_path);
	if (relay_agent_path == NULL)
		return comms_error_invalid_args(invocation);

	if (g_strcmp0(relay_agent_path, relay_agent->object_path))
		return comms_error_does_not_exist(invocation);

	g_free(relay_agent_path);

	free_relay_agent(relay_agent);
	relay_agent = NULL;

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_change_track(GVariant *parameters)
{
	GVariantIter *valueIter;
	GVariant *value;
	media_metadata_attributes_t metadata;
	gchar *key, *val;
	gint32 track_num;
	gint64 duration;

	DBG("");

	g_variant_get(parameters, "(a{sv})", &valueIter);
	while (g_variant_iter_next(valueIter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "xesam:title") == 0) {
			g_variant_get(value, "s", &val);
			metadata.title = g_strdup(val);
			DBG("metadata.title = %s", metadata.title);
		} else if (g_strcmp0(key, "xesam:artist") == 0) {
			g_variant_get(value, "s", &val);
			metadata.artist = g_malloc0(sizeof(char *));
			if (metadata.artist != NULL)
				metadata.artist[0] = g_strdup(val);
			DBG("metadata.artist = %s", metadata.artist[0]);
		} else if (g_strcmp0(key, "xesam:genre") == 0) {
			g_variant_get(value, "s", &val);
			metadata.genre = g_malloc0(sizeof(char *));
			if (metadata.genre != NULL)
				metadata.genre[0] = g_strdup(val);
			DBG("metadata.genre = %s", metadata.genre[0]);
		} else if (g_strcmp0(key, "xesam:album") == 0) {
			g_variant_get(value, "s", &val);
			metadata.album = g_strdup(val);
			DBG("metadata.album = %s", metadata.album);
		} else if (g_strcmp0(key, "xesam:trackNumber") == 0) {
			g_variant_get(value, "i", &track_num);
			metadata.tracknumber = track_num;
			DBG("metadata.tracknumber = %d",
					metadata.tracknumber);
		} else if (g_strcmp0(key, "mpris:length") == 0) {
			g_variant_get(value, "x", &duration);
			metadata.duration = duration;
			DBG("metadata.duration = %d", metadata.duration);
		}

		g_variant_unref(value);
		g_free(key);
	}

	bluez_media_player_set_track_info(default_adapter, &metadata);
}

static void media_skeleton_handle_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	DBG("method: %s", method_name);

	if (default_adapter == NULL){
		DBG("no adapter");
		return;
	}

	if (g_strcmp0(method_name, "RegisterMediaAgent") == 0) {
		register_relay_agent_handler(connection, parameters,
						invocation, user_data);
		return;
	} else if (g_strcmp0(method_name, "UnregisterMediaAgent") == 0) {
		unregister_relay_agent_handler(connection, parameters,
						invocation, user_data);
		return;
	} else if (g_strcmp0(method_name, "MediaPlayerChangeProperty") == 0) {
		guint32 type, value;

		g_variant_get(parameters, "(uu)", &type, &value);
		DBG("type =%d, value = %d", type, value);
		bluez_media_player_change_property(default_adapter,
							type, value);
	} else if (g_strcmp0(method_name,
				"MediaPlayerChangeTrack") == 0) {
		handle_change_track(parameters);
	} else {
		WARN("Unknown method");
		return;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static const GDBusInterfaceVTable media_skeleton_vtable =
{
	media_skeleton_handle_method_call,
	NULL,
	NULL
};

static GDBusInterfaceVTable *media_skeleton_dbus_interface_get_vtable(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceVTable *) &media_skeleton_vtable;
}

static void media_skeleton_object_finalize(GObject *object)
{
	DBG("Finalize");

	G_OBJECT_CLASS(media_skeleton_parent_class)->finalize(object);
}

static void media_skeleton_init(MediaSkeleton *skeleton)
{
	DBG("Instance Init");
}

static GVariant *media_skeleton_dbus_interface_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	GVariantBuilder builder;

	DBG("");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	return g_variant_builder_end (&builder);
}

static void media_skeleton_class_init(MediaSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *gdbus_skeleton_class;

	DBG("Class Init");

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = media_skeleton_object_finalize;

	gdbus_skeleton_class = G_DBUS_INTERFACE_SKELETON_CLASS(klass);
	gdbus_skeleton_class->get_info =
				media_skeleton_dbus_interface_get_info;
	gdbus_skeleton_class->get_vtable =
				media_skeleton_dbus_interface_get_vtable;
	gdbus_skeleton_class->get_properties =
				media_skeleton_dbus_interface_get_properties;
}

MediaSkeleton *bt_service_media_new(void)
{
	return (MediaSkeleton *)g_object_new(TYPE_MEDIA_SKELETON, NULL);
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
	GVariantBuilder *builder;
	GVariant *val, *signal_variant;

	DBG("property_name = %s", property_name);

	if (relay_agent == NULL) {
		DBG("relay_agent == NULL");
		return false;
	}

	if (g_strcmp0(property_name, "LoopStatus") == 0) {
		const gchar *loopstatus = g_variant_get_string(value, NULL);
		DBG("loopstatus = %s", loopstatus);

		val = g_variant_new("s", loopstatus);
		builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
		g_variant_builder_add(builder, "{sv}", "LoopStatus", val);

		signal_variant = g_variant_ref_sink(g_variant_new("(sa{sv}as)",
					MEDIA_PLAYER_INTERFACE,
					builder, NULL));

		g_dbus_connection_emit_signal(connection, NULL,
					relay_agent->object_path,
					"org.freedesktop.DBus.Properties",
					"PropertiesChanged",
					signal_variant, NULL);

		g_variant_unref(signal_variant);
	} else if (g_strcmp0(property_name, "Shuffle") == 0) {
		gboolean shuffle_mode = g_variant_get_boolean(value);
		if (shuffle_mode == TRUE)
			DBG("shuffle_mode TRUE");
		else
			DBG("shuffle_mode FALSE");

		val = g_variant_new("b", shuffle_mode);
		builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
		g_variant_builder_add(builder, "{sv}", "Shuffle", val);

		signal_variant = g_variant_ref_sink(g_variant_new("(sa{sv}as)",
					MEDIA_PLAYER_INTERFACE,
					builder, NULL));

		g_dbus_connection_emit_signal(connection, NULL,
					relay_agent->object_path,
					"org.freedesktop.DBus.Properties",
					"PropertiesChanged",
					signal_variant, NULL);

		g_variant_unref(signal_variant);
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

static guint bt_register_avrcp_property(struct _bluez_adapter *adapter)
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

static void bt_unregister_avrcp_property(struct _bluez_adapter *adapter,
						int avrcp_registration_id)
{
	GDBusConnection  *conn;

	conn = g_dbus_proxy_get_connection(adapter->media_proxy);

	g_dbus_connection_unregister_object(conn,
					avrcp_registration_id);
}

static void handle_media_proxy_cb(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	struct _bluez_adapter *adapter = user_data;
	enum bluez_error_type error_type = ERROR_NONE;

	DBG("");

	if (adapter == NULL)
		return;

	ret = g_dbus_proxy_call_finish(adapter->media_proxy, res,
							&error);
	if (ret == NULL) {
		error_type = get_error_type(error);
		DBG("error_type = %d", error_type);
		g_error_free(error);
	} else
		g_variant_unref(ret);
}

void bt_media_register_player(struct _bluez_adapter *adapter)
{
	GVariant *str_array[1];
	GVariant *val_array;
	GVariant *val_metadata;

	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	GVariantBuilder *builder_array =
				g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

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

	DBG("+");

	if (adapter == NULL) {
		ERROR("adapter is NULL");
		return;
	}

	if (adapter->media_proxy == NULL) {
		ERROR("adapter->mediaprooxy is NULL");
		return;
	}

	if (adapter->avrcp_registration_id == 0)
		adapter->avrcp_registration_id =
			bt_register_avrcp_property(adapter);

	g_dbus_proxy_call(adapter->media_proxy,
			"RegisterPlayer",
			g_variant_new("(oa{sv})",
				BT_MEDIA_OBJECT_PATH, builder),
			0, -1, NULL,
			handle_media_proxy_cb,
			adapter);

	DBG("-");
	return;
}

void bt_media_unregister_player(struct _bluez_adapter *adapter)
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

	g_dbus_proxy_call(adapter->media_proxy,
			"UnregisterPlayer",
			g_variant_new("(o)", BT_MEDIA_OBJECT_PATH),
			0, -1, NULL,
			handle_media_proxy_cb,
			adapter);

	if (adapter->avrcp_registration_id)
		bt_unregister_avrcp_property(adapter,
				adapter->avrcp_registration_id);

	adapter->avrcp_registration_id = 0;

	DBG("-");
	return;
}

void bt_service_media_init(GDBusObjectSkeleton *gdbus_object_skeleton,
						GDBusConnection *connection,
						bluez_adapter_t *adapter)
{
	DBG("");

	if (bt_media)
		return;

	bt_object_skeleton = gdbus_object_skeleton;

	default_adapter = adapter;

	bt_media = bt_service_media_new();

	bt_media_register_dbus_interface(bt_media, connection);

	bt_media_register_player(default_adapter);
}

void bt_service_media_deinit(void)
{
	DBG("");

	if (bt_media == NULL)
		return;

	bt_media_unregister_player(default_adapter);

	bt_media_unregister_dbus_interface();

	g_object_unref(bt_media);
	bt_media = NULL;
}

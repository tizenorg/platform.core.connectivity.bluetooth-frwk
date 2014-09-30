/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <dlog.h>
#include <string.h>
#if !defined(LIBNOTIFY_SUPPORT) && !defined(LIBNOTIFICATION_SUPPORT)
#include <syspopup_caller.h>
#endif

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-avrcp.h"
#include "bt-service-event.h"
#include "bt-service-util.h"

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

static struct player_settinngs_t repeat_settings[] = {
	{ REPEAT_INVALID, "" },
	{ REPEAT_MODE_OFF, "off" },
	{ REPEAT_SINGLE_TRACK, "singletrack" },
	{ REPEAT_ALL_TRACK, "alltracks" },
	{ REPEAT_INVALID, "" }
};

typedef struct {
	GObject parent;
} BtMediaAgent;

typedef struct {
	GObjectClass parent;
} BtMediaAgentClass;

GType bt_media_agent_get_type(void);

DBusConnection *g_bt_dbus_conn = NULL;

#define BT_MEDIA_TYPE_AGENT (bt_media_agent_get_type())
#define BT_MEDIA_GET_AGENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), BT_MEDIA_TYPE_AGENT, BtMediaAgent))
#define BT_MEDIA_IS_AGENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), BT_MEDIA_TYPE_AGENT))
#define BT_MEDIA_AGENT_CLASS(class) (G_TYPE_CHECK_CLASS_CAST((class), BT_MEDIA_TYPE_AGENT, \
										BtMediaAgentClass))
#define BT_MEDIA_GET_AGENT_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), BT_MEDIA_TYPE_AGENT, \
										BtMediaAgentClass))
#define BT_MEDIA_IS_AGENT_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE((class), BT_MEDIA_TYPE_AGENT))

G_DEFINE_TYPE(BtMediaAgent, bt_media_agent, G_TYPE_OBJECT)

static gboolean bt_media_agent_set_property(BtMediaAgent *agent,
						const char *property, GValue *value,
						DBusGMethodInvocation *context);

static BtMediaAgent *bt_media_obj = NULL;

#include "bt-media-agent-method.h"

typedef enum {
	BT_MEDIA_AGENT_ERROR_INVALID_PARAM,
	BT_MEDIA_AGENT_ERROR_NOT_AVAILABLE,
	BT_MEDIA_AGENT_ERROR_BUSY,
} BtMediaAgentError;

#define BT_MEDIA_AGENT_ERROR (bt_media_agent_error_quark())

static GQuark bt_media_agent_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GError *bt_media_agent_error(BtMediaAgentError error, const char *err_msg)
{
	return g_error_new(BT_MEDIA_AGENT_ERROR, error, err_msg, NULL);
}

static void bt_media_agent_init(BtMediaAgent *agent)
{
	BT_DBG("agent %p\n", agent);
}

static void bt_media_agent_finalize(GObject *agent)
{
	BT_DBG("Free agent %p\n", agent);

	G_OBJECT_CLASS(bt_media_agent_parent_class)->finalize(agent);
}

static void bt_media_agent_class_init(BtMediaAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;

	BT_DBG("class %p\n", klass);

	object_class->finalize = bt_media_agent_finalize;

	dbus_g_object_type_install_info(BT_MEDIA_TYPE_AGENT,
					&dbus_glib_bt_media_agent_object_info);
}

static BtMediaAgent *__bt_media_agent_new(void)
{
	BtMediaAgent *agent;

	agent = BT_MEDIA_GET_AGENT(g_object_new(BT_MEDIA_TYPE_AGENT, NULL));

	BT_DBG("agent %p\n", agent);

	return agent;
}

static gboolean bt_media_agent_set_property(BtMediaAgent *agent,
						const char *property, GValue *val,
						DBusGMethodInvocation *context)
{
	GError *error;
	const gchar *value;
	unsigned int status;

	BT_DBG("property %s\n", property);

	dbus_g_method_return(context);
	return TRUE;

}

static const char *loopstatus_to_repeat(const char *value)
{
	if (strcasecmp(value, "None") == 0)
		return "off";
	else if (strcasecmp(value, "Track") == 0)
		return "singletrack";
	else if (strcasecmp(value, "Playlist") == 0)
		return "alltracks";

	return NULL;
}

void set_shuffle(DBusMessageIter *iter)
{
	dbus_bool_t shuffle;
	const char *value;
	unsigned int status;

	if (dbus_message_iter_get_arg_type(iter) !=
					DBUS_TYPE_BOOLEAN) {
		BT_DBG("Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &shuffle);
	value = shuffle ? "alltracks" : "off";

	if (g_strcmp0(value, "alltracks") == 0)
		status = SHUFFLE_ALL_TRACK;
	else if (g_strcmp0(value, "off") == 0)
		status = SHUFFLE_MODE_OFF;
	else
		status = SHUFFLE_INVALID;

	_bt_send_event(BT_AVRCP_EVENT,
			BLUETOOTH_EVENT_AVRCP_SETTING_SHUFFLE_STATUS,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID);
}

void set_loopstatus(DBusMessageIter *iter)
{
	const char *value;
	unsigned int status;

	if (dbus_message_iter_get_arg_type(iter) !=
					DBUS_TYPE_STRING) {
		BT_DBG("Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &value);

	value = loopstatus_to_repeat(value);

	if (g_strcmp0(value, "singletrack") == 0)
		status = REPEAT_SINGLE_TRACK;
	else if (g_strcmp0(value, "alltracks") == 0)
		status = REPEAT_ALL_TRACK;
	else if (g_strcmp0(value, "off") == 0)
		status = REPEAT_MODE_OFF;
	else
		status = REPEAT_INVALID;

	_bt_send_event(BT_AVRCP_EVENT,
			BLUETOOTH_EVENT_AVRCP_SETTING_REPEAT_STATUS,
			DBUS_TYPE_UINT32, &status,
			DBUS_TYPE_INVALID);
}

static DBusHandlerResult bt_properties_message(DBusConnection *connection,
						DBusMessage *message)
{
	DBusMessageIter iter, sub;
	const char *name, *interface;
	DBusMessage *reply;

	if (!dbus_message_iter_init(message, &iter)){
		reply = dbus_message_new_error(message,
			DBUS_ERROR_INVALID_ARGS, "No arguments given");
		goto done;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING){
		reply = dbus_message_new_error(message,
			DBUS_ERROR_INVALID_ARGS, "Invalid argument type");
		goto done;
	}

	dbus_message_iter_get_basic(&iter, &interface);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING){
		reply = dbus_message_new_error(message,
			DBUS_ERROR_INVALID_ARGS, "Invalid argument type");
		goto done;
	}

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT){
		reply = dbus_message_new_error(message,
			DBUS_ERROR_INVALID_ARGS, "Invalid argument type");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &sub);

	if (g_strcmp0(interface, BT_MEDIA_PLAYER_INTERFACE) == 0){
		if (g_strcmp0(name, "LoopStatus") == 0)
			set_loopstatus(&sub);
		else if (g_strcmp0(name, "Shuffle") == 0)
			set_shuffle(&sub);
	}

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

done:
	dbus_connection_send(connection, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult bt_dbus_message(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	const char *interface;

	interface = dbus_message_get_interface(message);

	if (interface == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (g_strcmp0(interface, BT_PROPERTIES_INTERFACE) == 0)
		return bt_properties_message(connection, message);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable bt_object_table = {
        .message_function       = bt_dbus_message,
};

gboolean bt_dbus_register_object_path(DBusConnection *connection,
						const char *path)
{
	if (!dbus_connection_register_object_path(connection, path,
				&bt_object_table, NULL))
		return FALSE;

	return TRUE;
}

void bt_dbus_unregister_object_path(DBusConnection *connection,
						const char *path)
{
	dbus_connection_unregister_object_path(connection, path);
}

static inline void bt_dbus_queue_dispatch(DBusConnection *conn,
					DBusDispatchStatus status)
{
	if (status == DBUS_DISPATCH_DATA_REMAINS){
		dbus_connection_ref(conn);
		 while (dbus_connection_dispatch(conn)
				== DBUS_DISPATCH_DATA_REMAINS)
				;

		dbus_connection_unref(conn);
	}
}

static void bt_dbus_dispatch_status(DBusConnection *conn,
				DBusDispatchStatus status, void *data)
{
	if (!dbus_connection_get_is_connected(conn))
		return;

	bt_dbus_queue_dispatch(conn, status);
}

DBusConnection *bt_dbus_setup_private(DBusBusType type, DBusError *error)
{
	DBusConnection *conn;
	DBusDispatchStatus status;

	conn = dbus_bus_get_private(type, error);

	if (conn == NULL)
		return NULL;

	dbus_connection_set_dispatch_status_function(conn,
				bt_dbus_dispatch_status, NULL, NULL);

	status = dbus_connection_get_dispatch_status(conn);
	bt_dbus_queue_dispatch(conn, status);

	return conn;
}

static void __bt_media_append_variant(DBusMessageIter *iter,
			int type, void *value)
{
	char sig[2] = { type, '\0'};
	DBusMessageIter value_iter;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig,
							&value_iter);

	dbus_message_iter_append_basic(&value_iter, type, value);

	dbus_message_iter_close_container(iter, &value_iter);
}

static void __bt_media_append_dict_entry(DBusMessageIter *iter,
			const char *key, int type, void *property)
{
	DBusMessageIter dict_entry;
	const char *str_ptr;

	if (type == DBUS_TYPE_STRING) {
		str_ptr = *((const char **)property);
		ret_if(str_ptr == NULL);
	}

	dbus_message_iter_open_container(iter,
					DBUS_TYPE_DICT_ENTRY,
					NULL, &dict_entry);

	dbus_message_iter_append_basic(&dict_entry, DBUS_TYPE_STRING, &key);

	__bt_media_append_variant(&dict_entry, type, property);

	dbus_message_iter_close_container(iter, &dict_entry);
}

static void __bt_media_append_array_variant(DBusMessageIter *iter, int type,
			void *val, int n_elements)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	if (dbus_type_is_fixed(type) == TRUE) {
		dbus_message_iter_append_fixed_array(&array, type, val,
							n_elements);
	} else if (type == DBUS_TYPE_STRING ||
				type == DBUS_TYPE_OBJECT_PATH) {
		const char ***str_array = val;
		int i;

		for (i = 0; i < n_elements; i++)
			dbus_message_iter_append_basic(&array, type,
						&((*str_array)[i]));
	}

	dbus_message_iter_close_container(&variant, &array);
	dbus_message_iter_close_container(iter, &variant);
}

static void __bt_media_append_array(DBusMessageIter *dict, const char *key,
			int type, void *val, int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	BT_DBG("key = %s", key);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	__bt_media_append_array_variant(&entry, type, val, n_elements);

	dbus_message_iter_close_container(dict, &entry);
}

static void __bt_media_append_metadata_variant(DBusMessageIter *iter,
		const char *key, int type, void *property, int count)
{
	DBusMessageIter value, metadata;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "a{sv}",
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	if (type == DBUS_TYPE_ARRAY)
		__bt_media_append_array(&metadata, key,
			DBUS_TYPE_STRING, property, count);
	else
	__bt_media_append_dict_entry(&metadata, key, type, property);

	dbus_message_iter_close_container(&value, &metadata);
	dbus_message_iter_close_container(iter, &value);
}

static void __bt_media_append_metadata_dict_entry(DBusMessageIter *iter,
			const char *key, int type, void *property, int count)
{
	DBusMessageIter dict_entry;
	const char *str_ptr;
	char * metadata = "Metadata";

	if (type == DBUS_TYPE_STRING) {
		str_ptr = *((const char **)property);
		ret_if(str_ptr == NULL);
	}

	dbus_message_iter_open_container(iter,
					DBUS_TYPE_DICT_ENTRY,
					NULL, &dict_entry);

	dbus_message_iter_append_basic(&dict_entry, DBUS_TYPE_STRING, &metadata);

	__bt_media_append_metadata_variant(&dict_entry, key, type, property, count);

	dbus_message_iter_close_container(iter, &dict_entry);
}

static void __bt_metadata_append_property_changed(DBusMessageIter *property_dict,
                                        media_metadata_attributes_t *metadata)
{
	if(property_dict == NULL || metadata == NULL)
		return

	__bt_media_append_metadata_dict_entry(property_dict,
		"xesam:title",
		DBUS_TYPE_STRING, &metadata->title, 0);

	__bt_media_append_array(property_dict,
		"xesam:artist",
		DBUS_TYPE_ARRAY,&metadata->artist, 1);

	__bt_media_append_metadata_dict_entry(property_dict,
		"xesam:album",
		DBUS_TYPE_STRING, &metadata->album, 0);

	__bt_media_append_array(property_dict,
		"xesam:genre",
		DBUS_TYPE_ARRAY,&metadata->genre, 1);

	__bt_media_append_metadata_dict_entry(property_dict,
		"mpris:length",
		DBUS_TYPE_INT64, &metadata->duration, 0);

	__bt_media_append_metadata_dict_entry(property_dict,
		"xesam:trackNumber",
		DBUS_TYPE_INT32, &metadata->tracknumber, 0);
}

static gboolean __bt_media_emit_property_changed(
                                DBusConnection *connection,
                                const char *path,
                                const char *interface,
                                const char *name,
                                int type,
                                void *property)
{
	DBusMessage *sig;
	DBusMessageIter entry, dict;
	gboolean ret;

	BT_DBG("+");
	sig = dbus_message_new_signal(path, DBUS_INTERFACE_PROPERTIES,
						"PropertiesChanged");
	retv_if(sig == NULL, FALSE);

	dbus_message_iter_init_append(sig, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &interface);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	if (g_strcmp0(name, "Metadata") == 0)
		__bt_metadata_append_property_changed(&dict,
			(media_metadata_attributes_t *)property);
	else
		__bt_media_append_dict_entry(&dict,
					name, type, property);

	dbus_message_iter_close_container(&entry, &dict);

	ret = dbus_connection_send(connection, sig, NULL);
	dbus_message_unref(sig);

	BT_DBG("-");

	return ret;
}

int _bt_register_media_player(void)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter property_dict;
	DBusError err;
	char *object;
	char *adapter_path;
	DBusConnection *conn;
	DBusGConnection *gconn;

	media_player_settings_t player_settings = {0,};
	media_metadata_attributes_t metadata = {0,};

	player_settings.loopstatus  = REPEAT_MODE_OFF;
	player_settings.playbackstatus = STATUS_STOPPED;
	player_settings.shuffle = FALSE;
	player_settings.position = 0;

	metadata.title = "\0";
	metadata.album = "\0";
	metadata.tracknumber = 0;
	metadata.duration = 0;

	gconn = _bt_get_system_gconn();
	retv_if(gconn  == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = bt_dbus_setup_private(DBUS_BUS_SYSTEM, NULL);
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);
	g_bt_dbus_conn = conn;

	if (!bt_media_obj) {
		bt_media_obj = __bt_media_agent_new();

		retv_if(bt_media_obj == NULL, BLUETOOTH_ERROR_INTERNAL);

		dbus_g_connection_register_g_object(gconn,
							BT_MEDIA_OBJECT_PATH,
							G_OBJECT(bt_media_obj));
	}

	if (!bt_dbus_register_object_path(conn, BT_MEDIA_OBJECT_PATH)){
		BT_DBG("Could not register interface %s",
					MPRIS_PLAYER_INTERFACE);
	}

	adapter_path = _bt_get_adapter_path();
	retv_if(adapter_path == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, adapter_path,
					BT_MEDIA_INTERFACE, "RegisterPlayer");

	g_free(adapter_path);

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	object = g_strdup(BT_MEDIA_OBJECT_PATH);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);
	g_free(object);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING
			DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &property_dict);

	__bt_media_append_dict_entry(&property_dict,
		"LoopStatus",
		DBUS_TYPE_STRING,
		&loopstatus_settings[player_settings.loopstatus].property);

	__bt_media_append_dict_entry(&property_dict,
		"Shuffle",
		DBUS_TYPE_BOOLEAN,
		&player_settings.shuffle);

	__bt_media_append_dict_entry(&property_dict,
		"PlaybackStatus",
		DBUS_TYPE_STRING,
		&playback_status[player_settings.playbackstatus].property);

	__bt_media_append_dict_entry(&property_dict,
		"Position",
		DBUS_TYPE_INT64, &player_settings.position);

	__bt_media_append_metadata_dict_entry(&property_dict,
		"xesam:title",
		DBUS_TYPE_STRING, &metadata.title, 0);

	metadata.artists = g_malloc0(sizeof(char *));
	metadata.artists[0] = "";

	__bt_media_append_metadata_dict_entry(&property_dict,
		"xesam:artist",
		DBUS_TYPE_ARRAY, &metadata.artists, 1);

	__bt_media_append_metadata_dict_entry(&property_dict,
		"xesam:album",
		DBUS_TYPE_STRING, &metadata.album, 0);

	metadata.genres = g_malloc0(sizeof(char *));
	metadata.genres[0] = "";

	__bt_media_append_metadata_dict_entry(&property_dict,
		"xesam:genre",
		DBUS_TYPE_ARRAY, &metadata.genres, 1);

	__bt_media_append_metadata_dict_entry(&property_dict,
		"mpris:length",
		DBUS_TYPE_INT64, &metadata.duration, 0);

	__bt_media_append_metadata_dict_entry(&property_dict,
		"xesam:trackNumber",
		DBUS_TYPE_INT32, &metadata.tracknumber, 0);

	dbus_message_iter_close_container(&iter, &property_dict);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn,
					msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_DBG("Error in registering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_ERROR_INTERNAL;
		}

		if (bt_media_obj) {
			dbus_g_connection_unregister_g_object(gconn,
						G_OBJECT(bt_media_obj));
			g_object_unref(bt_media_obj);
			bt_media_obj = NULL;
		}
	}

	if (reply)
		dbus_message_unref(reply);

	g_free(metadata.artist);
	g_free(metadata.genre);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_unregister_media_player(void)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	char *object;
	char *adapter_path;
	DBusConnection *conn;

	conn = g_bt_dbus_conn;
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	adapter_path = _bt_get_adapter_path();
	retv_if(adapter_path == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, adapter_path,
				BT_MEDIA_INTERFACE, "UnregisterPlayer");

	g_free(adapter_path);

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	object = g_strdup(BT_MEDIA_OBJECT_PATH);

	dbus_message_append_args(msg,
				DBUS_TYPE_OBJECT_PATH, &object,
				DBUS_TYPE_INVALID);

	g_free(object);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn,
				msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Error in unregistering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			BT_DBG("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_ERROR_INTERNAL;
		}
	} else {
		dbus_message_unref(reply);
	}

	if (bt_media_obj) {
		dbus_g_connection_unregister_g_object(_bt_get_system_gconn(),
						G_OBJECT(bt_media_obj));
		g_object_unref(bt_media_obj);
		bt_media_obj = NULL;
	}

	bt_dbus_unregister_object_path(conn, BT_MEDIA_OBJECT_PATH);
	g_bt_dbus_conn = NULL;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_set_interal_property(int type, media_player_settings_t *properties)
{
	DBusConnection *conn;
	int value;
	media_metadata_attributes_t meta_data;
	dbus_bool_t shuffle;

	conn = g_bt_dbus_conn;
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	switch (type) {
	case LOOPSTATUS:
		value = properties->loopstatus;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"LoopStatus",
			DBUS_TYPE_STRING,
			&loopstatus_settings[value].property)) {
			BT_DBG("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	case SHUFFLE:
		value = properties->shuffle;
		if (g_strcmp0(repeat_settings[value].property, "alltracks") == 0)
			shuffle = 1;
		else
			shuffle = 0;

		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"Shuffle",
			DBUS_TYPE_BOOLEAN,
			&shuffle)) {
			BT_DBG("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	case PLAYBACKSTATUS:
		value = properties->playbackstatus;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"PlaybackStatus",
			DBUS_TYPE_STRING,
			&playback_status[value].property)) {
			BT_DBG("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	case POSITION:
		value = properties->position;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"Position",
			DBUS_TYPE_UINT32,
			&value)) {
			BT_DBG("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	case METADATA:
		meta_data = properties->metadata;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"Metadata",
			DBUS_TYPE_ARRAY,
			&meta_data)) {
			BT_DBG("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	default:
		BT_DBG("Invalid Type\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_set_properties(media_player_settings_t *properties)
{
	if (_bt_avrcp_set_interal_property(LOOPSTATUS,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(SHUFFLE,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(PLAYBACKSTATUS,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(POSITION,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(METADATA,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_set_property(int type, unsigned int value)
{
	media_player_settings_t properties;

	BT_DBG("+");

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
		BT_DBG("Invalid Type\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	_bt_avrcp_set_interal_property(type, &properties);

	BT_DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

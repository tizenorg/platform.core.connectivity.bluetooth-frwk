/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
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
#include "bt-service-audio.h"

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


static struct player_settinngs_t shuffle_settings[] = {
	{ SHUFFLE_INVALID, "" },
	{ SHUFFLE_MODE_OFF, "off" },
	{ SHUFFLE_ALL_TRACK, "alltracks" },
	{ SHUFFLE_GROUP, "group" },
	{ SHUFFLE_INVALID, "" }
};

static struct player_settinngs_t player_status[] = {
	{ STATUS_STOPPED, "stopped" },
	{ STATUS_PLAYING, "playing" },
	{ STATUS_PAUSED, "paused" },
	{ STATUS_FORWARD_SEEK, "forward-seek" },
	{ STATUS_REVERSE_SEEK, "reverse-seek" },
	{ STATUS_ERROR, "error" },
	{ STATUS_INVALID, "" }
};

static struct player_settinngs_t repeat_status[] = {
	{ REPEAT_INVALID, "" },
	{ REPEAT_MODE_OFF, "off" },
	{ REPEAT_SINGLE_TRACK, "singletrack" },
	{ REPEAT_ALL_TRACK, "alltracks" },
	{ REPEAT_GROUP, "group" },
	{ REPEAT_INVALID, "" }
};

static struct player_settinngs_t equalizer_status[] = {
	{ EQUALIZER_INVALID, "" },
	{ EQUALIZER_OFF, "off" },
	{ EQUALIZER_ON, "on" },
	{ EQUALIZER_INVALID, "" },
};

static struct player_settinngs_t scan_status[] = {
	{ SCAN_INVALID, "" },
	{ SCAN_MODE_OFF, "off" },
	{ SCAN_ALL_TRACK, "alltracks" },
	{ SCAN_GROUP, "group" },
	{ SCAN_INVALID, "" },
};

DBusConnection *g_bt_dbus_conn = NULL;
static char *avrcp_control_path = NULL;

static DBusHandlerResult _bt_avrcp_handle_set_property(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	BT_DBG("+");
	const gchar *value;
	unsigned int status;
	gboolean shuffle_status;
	DBusMessageIter args;
	const char *property = NULL;
	const char *interface = NULL;
	DBusMessage *reply = NULL;
	DBusHandlerResult result = DBUS_HANDLER_RESULT_HANDLED;
	DBusMessageIter entry;
	int type;


	dbus_message_iter_init(message, &args);
	dbus_message_iter_get_basic(&args, &interface);
	dbus_message_iter_next(&args);

	if (g_strcmp0(interface, BT_MEDIA_PLAYER_INTERFACE) != 0) {
		result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		goto finish;
	}

	dbus_message_iter_get_basic(&args, &property);
	dbus_message_iter_next(&args);
	dbus_message_iter_recurse(&args, &entry);
	type = dbus_message_iter_get_arg_type(&entry);

	BT_DBG("property %s\n", property);

	if (g_strcmp0(property, "Shuffle") == 0) {
		if (type != DBUS_TYPE_BOOLEAN) {
			BT_DBG("Error");
			reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					"Invalid arguments");
			dbus_connection_send(connection, reply, NULL);
			result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			goto finish;
		}
		dbus_message_iter_get_basic(&entry, &shuffle_status);
		BT_DBG("value %d\n", shuffle_status);
		if (shuffle_status == TRUE)
			status = SHUFFLE_ALL_TRACK;
		else
			status = SHUFFLE_MODE_OFF;

		_bt_send_event(BT_AVRCP_EVENT,
				BLUETOOTH_EVENT_AVRCP_SETTING_SHUFFLE_STATUS,
				DBUS_TYPE_UINT32, &status,
				DBUS_TYPE_INVALID);

	} else if (g_strcmp0(property, "LoopStatus") == 0) {
		if (type != DBUS_TYPE_STRING) {
			BT_DBG("Error");
			reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
					"Invalid arguments");
			dbus_connection_send(connection, reply, NULL);
			result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
			goto finish;
		}
		dbus_message_iter_get_basic(&entry, &value);
		BT_DBG("value %s\n", value);

		if (g_strcmp0(value, "Track") == 0)
			status = REPEAT_SINGLE_TRACK;
		else if (g_strcmp0(value, "Playlist") == 0)
			status = REPEAT_ALL_TRACK;
		else if (g_strcmp0(value, "None") == 0)
			status = REPEAT_MODE_OFF;
		else
			status = REPEAT_INVALID;

		_bt_send_event(BT_AVRCP_EVENT,
				BLUETOOTH_EVENT_AVRCP_SETTING_REPEAT_STATUS,
				DBUS_TYPE_UINT32, &status,
				DBUS_TYPE_INVALID);
	}
finish:
	if (reply)
		dbus_message_unref(reply);

	return result;
}

static DBusHandlerResult _bt_avrcp_message_handle(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	BT_DBG("+");

	if (dbus_message_is_method_call(msg, DBUS_INTERFACE_PROPERTIES, "Set"))
		return _bt_avrcp_handle_set_property(conn, msg, user_data);

	BT_DBG("-");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable bt_object_table = {
        .message_function       = _bt_avrcp_message_handle,
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

	sig = dbus_message_new_signal(path, DBUS_INTERFACE_PROPERTIES,
						"PropertiesChanged");
	retv_if(sig == NULL, FALSE);

	dbus_message_iter_init_append(sig, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &interface);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	__bt_media_append_dict_entry(&dict,
					name, type, property);

	dbus_message_iter_close_container(&entry, &dict);

	ret = dbus_connection_send(connection, sig, NULL);
	dbus_message_unref(sig);

	return ret;
}

void _bt_set_control_device_path(const char *path)
{

	ret_if(path == NULL);

	g_free(avrcp_control_path);
	BT_DBG("control_path = %s", path);
	avrcp_control_path = g_strdup(path);
}

void _bt_remove_control_device_path(const char *path)
{
	ret_if(path == NULL);

	if (avrcp_control_path &&
			!g_strcmp0(avrcp_control_path, path)) {
		BT_DBG("control_path = %s", path);
		g_free(avrcp_control_path);
		avrcp_control_path = NULL;
	}
}

static char *__bt_get_control_device_path(void)
{
	char *adapter_path;
	char *control_path;
	char connected_address[BT_ADDRESS_STRING_SIZE + 1];

	BT_DBG("+");

	retv_if(avrcp_control_path != NULL, avrcp_control_path);

	retv_if(!_bt_is_headset_type_connected(BT_AVRCP,
			connected_address), NULL);

	BT_DBG("device address = %s", connected_address);

	adapter_path = _bt_get_device_object_path(connected_address);
	retv_if(adapter_path == NULL, NULL);

	control_path = g_strdup_printf(BT_MEDIA_CONTROL_PATH, adapter_path);
	g_free(adapter_path);

	avrcp_control_path = control_path;
	BT_DBG("control_path = %s", control_path);
	return control_path;
}

static int __bt_media_send_control_msg(const char *name)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	DBusConnection *conn;
	char *control_path;

	retv_if(name == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	control_path = __bt_get_control_device_path();
	retv_if(control_path == NULL, BLUETOOTH_ERROR_NOT_CONNECTED);
	BT_DBG("control_path %s", control_path);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, control_path,
				BT_PLAYER_CONTROL_INTERFACE, name);

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn,
				msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Error in Sending Control Command");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}


int _bt_register_media_player(void)
{
	BT_DBG("+");
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter property_dict;
	DBusError err;
	char *object;
	char *adapter_path;
	DBusConnection *conn;
	DBusGConnection *gconn;
	gboolean shuffle_status;

	media_player_settings_t player_settings = {0,};

	player_settings.repeat  = REPEAT_MODE_OFF;

	player_settings.shuffle = SHUFFLE_MODE_OFF;
	player_settings.status = STATUS_STOPPED;
	player_settings.position = 0;


	gconn = _bt_get_system_gconn();
	retv_if(gconn  == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);
	g_bt_dbus_conn = conn;


	if (!bt_dbus_register_object_path(conn, BT_MEDIA_OBJECT_PATH)){
		BT_DBG("Could not register interface %s",
				BT_MEDIA_PLAYER_INTERFACE);
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
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &property_dict);

	__bt_media_append_dict_entry(&property_dict,
		"LoopStatus",
		DBUS_TYPE_STRING,
		&loopstatus_settings[player_settings.repeat].property);

	if (player_settings.shuffle == SHUFFLE_MODE_OFF)
		shuffle_status = FALSE;
	else
		shuffle_status = TRUE;

	__bt_media_append_dict_entry(&property_dict,
		"Shuffle",
		DBUS_TYPE_BOOLEAN,
		&shuffle_status);

	__bt_media_append_dict_entry(&property_dict,
		"PlaybackStatus",
		DBUS_TYPE_STRING,
		&player_status[player_settings.status].property);


	__bt_media_append_dict_entry(&property_dict,
		"Position",
		DBUS_TYPE_UINT32, &player_settings.position);

	dbus_message_iter_close_container(&iter, &property_dict);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn,
				msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Error in registering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_ERROR_INTERNAL;
		}
	}

	if (reply)
		dbus_message_unref(reply);

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_unregister_media_player(void)
{
	BT_DBG("+");
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
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_ERROR_INTERNAL;
		}
	} else {
		dbus_message_unref(reply);
	}

	bt_dbus_unregister_object_path(conn, BT_MEDIA_OBJECT_PATH);
	g_bt_dbus_conn = NULL;

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

static void __bt_media_append_metadata_entry(DBusMessageIter *metadata,
			void *key_type, void *value, int type)
{
	BT_DBG("+");
	DBusMessageIter string_entry;

	dbus_message_iter_open_container(metadata,
				DBUS_TYPE_DICT_ENTRY,
				NULL, &string_entry);

	dbus_message_iter_append_basic(&string_entry, DBUS_TYPE_STRING, key_type);

	__bt_media_append_variant(&string_entry, type, value);

	dbus_message_iter_close_container(metadata, &string_entry);
	BT_DBG("-");
}

static void __bt_media_append_metadata_array(DBusMessageIter *metadata,
			void *key_type, void *value, int type)
{
	BT_DBG("+");
	DBusMessageIter string_entry, variant, array;
	char array_sig[3] = { type, DBUS_TYPE_STRING, '\0' };

	dbus_message_iter_open_container(metadata,
				DBUS_TYPE_DICT_ENTRY,
				NULL, &string_entry);
	dbus_message_iter_append_basic(&string_entry, DBUS_TYPE_STRING, key_type);

	dbus_message_iter_open_container(&string_entry, DBUS_TYPE_VARIANT,
			array_sig, &variant);

	dbus_message_iter_open_container(&variant, type,
				DBUS_TYPE_STRING_AS_STRING, &array);
	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, value);

	dbus_message_iter_close_container(&variant, &array);
	dbus_message_iter_close_container(&string_entry, &variant);
	dbus_message_iter_close_container(metadata, &string_entry);
	BT_DBG("-");
}

int _bt_avrcp_set_track_info(media_metadata_attributes_t *meta_data)
{
	BT_DBG("+");
	DBusMessage *sig;
	DBusMessageIter iter;
	DBusMessageIter property_dict, metadata_dict, metadata_variant, metadata;
	DBusConnection *conn;
	char *interface = BT_MEDIA_PLAYER_INTERFACE;
	char * metadata_str = "Metadata";
	const char *key_type;

	retv_if(meta_data == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = g_bt_dbus_conn;
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	sig = dbus_message_new_signal(BT_MEDIA_OBJECT_PATH, DBUS_INTERFACE_PROPERTIES,
				"PropertiesChanged");
	retv_if(sig == NULL, FALSE);

	dbus_message_iter_init_append(sig, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &property_dict);

	dbus_message_iter_open_container(&property_dict,
				DBUS_TYPE_DICT_ENTRY,
				NULL, &metadata_dict);

	dbus_message_iter_append_basic(&metadata_dict, DBUS_TYPE_STRING, &metadata_str);

	dbus_message_iter_open_container(&metadata_dict, DBUS_TYPE_VARIANT, "a{sv}",
				&metadata_variant);

	dbus_message_iter_open_container(&metadata_variant, DBUS_TYPE_ARRAY,
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata);

	if (meta_data->title) {
		key_type = "xesam:title";
		__bt_media_append_metadata_entry(&metadata, &key_type,
				&meta_data->title, DBUS_TYPE_STRING);
	}

	if (meta_data->artist) {
		key_type = "xesam:artist";
		__bt_media_append_metadata_array(&metadata, &key_type,
				&meta_data->artist, DBUS_TYPE_ARRAY);
	}

	if (meta_data->album) {
		key_type = "xesam:album";
		__bt_media_append_metadata_entry(&metadata, &key_type,
				&meta_data->album, DBUS_TYPE_STRING);
	}

	if (meta_data->genre) {
		key_type = "xesam:genre";
		__bt_media_append_metadata_array(&metadata, &key_type,
				&meta_data->genre, DBUS_TYPE_ARRAY);
	}

	if (0 != meta_data->total_tracks) {
		key_type = "xesam:totalTracks";
		__bt_media_append_metadata_entry(&metadata, &key_type,
				&meta_data->total_tracks, DBUS_TYPE_INT32);
	}

	if (0 != meta_data->number) {
		key_type = "xesam:trackNumber";
		__bt_media_append_metadata_entry(&metadata, &key_type,
				&meta_data->number, DBUS_TYPE_INT32);
	}

	if (0 != meta_data->duration) {
		key_type = "mpris:length";
		__bt_media_append_metadata_entry(&metadata, &key_type,
				&meta_data->duration, DBUS_TYPE_INT64);
	}

	dbus_message_iter_close_container(&metadata_variant, &metadata);
	dbus_message_iter_close_container(&metadata_dict, &metadata_variant);
	dbus_message_iter_close_container(&property_dict, &metadata_dict);
	dbus_message_iter_close_container(&iter, &property_dict);

	if (!dbus_connection_send(conn, sig, NULL))
		BT_ERR("Unable to send TrackChanged signal\n");

	dbus_message_unref(sig);
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}


int _bt_avrcp_set_interal_property(int type, media_player_settings_t *properties)
{
	BT_DBG("+");
	DBusConnection *conn;
	int value;
	media_metadata_attributes_t meta_data;
	dbus_bool_t shuffle;

	conn = g_bt_dbus_conn;
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	switch (type) {
	case REPEAT:
		value = properties->repeat;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"LoopStatus",
			DBUS_TYPE_STRING,
			&loopstatus_settings[value].property)) {
			BT_ERR("Error sending the PropertyChanged signal \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		break;
	case SHUFFLE:
		value = properties->shuffle;
		if (g_strcmp0(shuffle_settings[value].property, "off") == 0)
			shuffle = 0;
		else
			shuffle = 1;

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
	case STATUS:
		value = properties->status;
		if (!__bt_media_emit_property_changed(
			conn,
			BT_MEDIA_OBJECT_PATH,
			BT_MEDIA_PLAYER_INTERFACE,
			"PlaybackStatus",
			DBUS_TYPE_STRING,
			&player_status[value].property)) {
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
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_set_properties(media_player_settings_t *properties)
{
	BT_DBG("+");

	if (_bt_avrcp_set_interal_property(REPEAT,
				properties) != BLUETOOTH_ERROR_NONE) {
			return BLUETOOTH_ERROR_INTERNAL;
	}
	if (_bt_avrcp_set_interal_property(SHUFFLE,
			properties) != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(STATUS,
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
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_set_property(int type, unsigned int value)
{
	BT_DBG("+");
	media_player_settings_t properties;

	switch (type) {
	case REPEAT:
		properties.repeat = value;
		break;
	case SHUFFLE:
		properties.shuffle = value;
		break;
	case STATUS:
		properties.status = value;
		break;
	case POSITION:
		properties.position = value;
		break;
	default:
		BT_DBG("Invalid Type\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (_bt_avrcp_set_interal_property(type,
			&properties) != BLUETOOTH_ERROR_NONE)
		return BLUETOOTH_ERROR_INTERNAL;

	BT_DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_control_cmd(int type)
{
	int ret = BLUETOOTH_ERROR_INTERNAL;
	BT_DBG("+");

	switch (type) {
	case PLAY:
		ret = __bt_media_send_control_msg("Play");
		break;
	case PAUSE:
		ret = __bt_media_send_control_msg("Pause");
		break;
	case STOP:
		ret = __bt_media_send_control_msg("Stop");
		break;
	case NEXT:
		ret = __bt_media_send_control_msg("Next");
		break;
	case PREVIOUS:
		ret = __bt_media_send_control_msg("Previous");
		break;
	case FAST_FORWARD:
		ret = __bt_media_send_control_msg("FastForward");
		break;
	case REWIND:
		ret = __bt_media_send_control_msg("Rewind");
		break;
	default:
		BT_DBG("Invalid Type\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}
	BT_DBG("-");
	return ret;
}

DBusGProxy *__bt_get_control_properties_proxy(void)
{
	DBusGProxy *proxy;
	char *control_path;
	DBusGConnection *conn;

	control_path = __bt_get_control_device_path();
	retv_if(control_path == NULL, NULL);
	BT_DBG("control_path = %s", control_path);

	conn = _bt_get_system_gconn();
	retv_if(conn == NULL, NULL);

	proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				control_path, BT_PROPERTIES_INTERFACE);
	return proxy;
}

static int __bt_media_attr_to_event(const char *str)
{
	if (!strcasecmp(str, "Equalizer"))
		return BLUETOOTH_EVENT_AVRCP_CONTROL_EQUALIZER_STATUS;
	else if (!strcasecmp(str, "Repeat"))
		return BLUETOOTH_EVENT_AVRCP_CONTROL_REPEAT_STATUS;
	else if (!strcasecmp(str, "Shuffle"))
		return BLUETOOTH_EVENT_AVRCP_CONTROL_SHUFFLE_STATUS;
	else if (!strcasecmp(str, "Scan"))
		return BLUETOOTH_EVENT_AVRCP_CONTROL_SCAN_STATUS;
	else if (!strcasecmp(str, "Position"))
		return BLUETOOTH_EVENT_AVRCP_SONG_POSITION_STATUS;
	else if (!strcasecmp(str, "Track"))
		return BLUETOOTH_EVENT_AVRCP_TRACK_CHANGED;
	else if (!strcasecmp(str, "Status"))
		return BLUETOOTH_EVENT_AVRCP_PLAY_STATUS_CHANGED;

	return 0;
}

static int __bt_media_attr_to_type(const char *str)
{
	if (!strcasecmp(str, "Equalizer"))
		return EQUALIZER;
	else if (!strcasecmp(str, "Repeat"))
		return REPEAT;
	else if (!strcasecmp(str, "Shuffle"))
		return SHUFFLE;
	else if (!strcasecmp(str, "Scan"))
		return SCAN;
	else if (!strcasecmp(str, "Position"))
		return POSITION;
	else if (!strcasecmp(str, "Track"))
		return METADATA;
	else if (!strcasecmp(str, "Status"))
		return STATUS;

	return 0;
}

static const char *__bt_media_type_to_str(int type)
{
	switch (type) {
	case EQUALIZER:
		return "Equalizer";
	case REPEAT:
		return "Repeat";
	case SHUFFLE:
		return "Shuffle";
	case SCAN:
		return "Scan";
	case POSITION:
		return "Position";
	case METADATA:
		return "Track";
	case STATUS:
		return "Status";
	}
	return NULL;
}

static int __bt_media_attrval_to_val(int type, const char *value)
{
	int ret = 0;

	switch (type) {
	case EQUALIZER:
		if (!strcmp(value, "off"))
			ret = EQUALIZER_OFF;
		else if (!strcmp(value, "on"))
			ret = EQUALIZER_ON;
		else
			ret = EQUALIZER_INVALID;
		break;

	case REPEAT:
		if (!strcmp(value, "off"))
			ret = REPEAT_MODE_OFF;
		else if (!strcmp(value, "singletrack"))
			ret = REPEAT_SINGLE_TRACK;
		else if (!strcmp(value, "alltracks"))
			ret = REPEAT_ALL_TRACK;
		else if (!strcmp(value, "group"))
			ret = REPEAT_GROUP;
		else
			ret = REPEAT_INVALID;
		break;

	case SHUFFLE:
		if (!strcmp(value, "off"))
			ret = SHUFFLE_MODE_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = SHUFFLE_ALL_TRACK;
		else if (!strcmp(value, "group"))
			ret = SHUFFLE_GROUP;
		else
			ret = SHUFFLE_INVALID;
		break;

	case SCAN:
		if (!strcmp(value, "off"))
			ret = SCAN_MODE_OFF;
		else if (!strcmp(value, "alltracks"))
			ret = SCAN_ALL_TRACK;
		else if (!strcmp(value, "group"))
			ret = SCAN_GROUP;
		else
			ret = SCAN_INVALID;
		break;

	case STATUS:
		if (!strcmp(value, "stopped"))
			ret = STATUS_STOPPED;
		else if (!strcmp(value, "playing"))
			ret = STATUS_PLAYING;
		else if (!strcmp(value, "paused"))
			ret = STATUS_PAUSED;
		else if (!strcmp(value, "forward-seek"))
			ret = STATUS_FORWARD_SEEK;
		else if (!strcmp(value, "reverse-seek"))
			ret = STATUS_REVERSE_SEEK;
		else if (!strcmp(value, "error"))
			ret = STATUS_ERROR;
		else
			ret = STATUS_INVALID;
	}
	return ret;
}

int _bt_avrcp_control_get_property(int type, unsigned int *value)
{
	DBusGProxy *proxy;
	char *name = NULL;
	int ret = BLUETOOTH_ERROR_NONE;
	GError *err = NULL;
	GValue attr_value = { 0 };

	BT_CHECK_PARAMETER(value, return);

	proxy = __bt_get_control_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_NOT_CONNECTED);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_PLAYER_CONTROL_INTERFACE,
			G_TYPE_STRING, __bt_media_type_to_str(type),
			G_TYPE_INVALID,
			G_TYPE_VALUE, &attr_value,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	g_object_unref(proxy);

	switch (type) {
	case EQUALIZER:
	case REPEAT:
	case SHUFFLE:
	case SCAN:
	case STATUS:
		name = (char *)g_value_get_string(&attr_value);
		*value = __bt_media_attrval_to_val(type, name);
		BT_DBG("Type[%s] and Value[%s]", __bt_media_type_to_str(type), name);
		break;
	case POSITION:
		*value = g_value_get_uint(&attr_value);
		break;
	default:
		BT_DBG("Invalid Type\n");
		ret =  BLUETOOTH_ERROR_INTERNAL;
	}

	return ret;
}

int _bt_avrcp_control_set_property(int type, unsigned int value)
{
	GValue attr_value = { 0 };
	DBusGProxy *proxy;
	GError *error = NULL;

	proxy = __bt_get_control_properties_proxy();

	retv_if(proxy == NULL, BLUETOOTH_ERROR_NOT_CONNECTED);
	g_value_init(&attr_value, G_TYPE_STRING);

	switch (type) {
	case EQUALIZER:
		g_value_set_string(&attr_value, equalizer_status[value].property);
		BT_DBG("equalizer_status %s", equalizer_status[value].property);
		break;
	case REPEAT:
		g_value_set_string(&attr_value, repeat_status[value].property);
		BT_DBG("repeat_status %s", repeat_status[value].property);
		break;
	case SHUFFLE:
		g_value_set_string(&attr_value, shuffle_settings[value].property);
		BT_DBG("shuffle_settings %s", shuffle_settings[value].property);
		break;
	case SCAN:
		g_value_set_string(&attr_value, scan_status[value].property);
		BT_DBG("scan_status %s", scan_status[value].property);
		break;
	default:
		BT_ERR("Invalid property type: %d", type);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(proxy, "Set", &error,
			G_TYPE_STRING, BT_PLAYER_CONTROL_INTERFACE,
			G_TYPE_STRING, __bt_media_type_to_str(type),
			G_TYPE_VALUE, &attr_value,
			G_TYPE_INVALID, G_TYPE_INVALID);

	g_value_unset(&attr_value);
	g_object_unref(proxy);

	if (error) {
		BT_ERR("SetProperty Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

static gboolean __bt_avrcp_control_parse_metadata(
					char **value_string,
					unsigned int *value_uint,
					int type,
					DBusMessageIter *iter)
{
	if (dbus_message_iter_get_arg_type(iter) != type)
		return FALSE;

	if (type == DBUS_TYPE_STRING) {
		char *value;
		dbus_message_iter_get_basic(iter, &value);
		*value_string = g_strdup(value);
	} else if (type == DBUS_TYPE_UINT32) {
		int value;
		dbus_message_iter_get_basic(iter, &value);
		*value_uint = value;
	} else
		return FALSE;

	return TRUE;
}


static int __bt_avrcp_control_parse_properties(
				media_metadata_attributes_t *metadata,
				DBusMessageIter *iter)
{
	DBusMessageIter dict;
	DBusMessageIter var;
	int ctype;
	char *value_string;
	unsigned int value_uint;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY) {
		BT_ERR("ctype error %d", ctype);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(iter, &dict);

	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key;

		if (ctype != DBUS_TYPE_DICT_ENTRY) {
			BT_ERR("ctype error %d", ctype);
			return BLUETOOTH_ERROR_INTERNAL;
		}

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) !=
							DBUS_TYPE_STRING) {
			BT_ERR("ctype not DBUS_TYPE_STRING");
			return BLUETOOTH_ERROR_INTERNAL;
		}

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) !=
							DBUS_TYPE_VARIANT) {
			BT_ERR("ctype not DBUS_TYPE_VARIANT");
			return FALSE;
		}

		dbus_message_iter_recurse(&entry, &var);

		BT_ERR("Key value is %s", key);

		if (strcasecmp(key, "Title") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_STRING, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			BT_DBG("Value : %s ", value_string);
			metadata->title = value_string;
		} else if (strcasecmp(key, "Artist") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_STRING, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			BT_DBG("Value : %s ", value_string);
			metadata->artist = value_string;
		} else if (strcasecmp(key, "Album") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_STRING, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			BT_DBG("Value : %s ", value_string);
			metadata->album = value_string;
		} else if (strcasecmp(key, "Genre") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_STRING, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			BT_DBG("Value : %s ", value_string);
			metadata->genre = value_string;
		} else if (strcasecmp(key, "Duration") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_UINT32, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			metadata->duration = value_uint;
		} else if (strcasecmp(key, "NumberOfTracks") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_UINT32, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			metadata->total_tracks = value_uint;
		} else if (strcasecmp(key, "TrackNumber") == 0) {
			if (!__bt_avrcp_control_parse_metadata(&value_string,
					&value_uint, DBUS_TYPE_UINT32, &var))
				return BLUETOOTH_ERROR_INTERNAL;
			metadata->number = value_uint;
		} else
			BT_DBG("%s not supported, ignoring", key);
		dbus_message_iter_next(&dict);
	}

	if (!metadata->title)
		metadata->title = g_strdup("");
	if (!metadata->artist)
		metadata->artist = g_strdup("");
	if (!metadata->album)
		metadata->album = g_strdup("");
	if (!metadata->genre)
		metadata->genre = g_strdup("");

	return BLUETOOTH_ERROR_NONE;
}

int _bt_avrcp_control_get_track_info(media_metadata_attributes_t *metadata)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	DBusConnection *conn;
	char *control_path;
	char *interface_name;
	char *property_name;
	DBusMessageIter arr, iter;
	int ret = BLUETOOTH_ERROR_NONE;

	retv_if(metadata == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	control_path = __bt_get_control_device_path();
	retv_if(control_path == NULL, BLUETOOTH_ERROR_NOT_CONNECTED);
	BT_DBG("control_path %s", control_path);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, control_path,
				BT_PROPERTIES_INTERFACE, "Get");

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	interface_name = g_strdup(BT_PLAYER_CONTROL_INTERFACE);
	property_name = g_strdup("Track");

	dbus_message_append_args(msg,
		DBUS_TYPE_STRING, &interface_name,
		DBUS_TYPE_STRING, &property_name,
		DBUS_TYPE_INVALID);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn,
				msg, -1, &err);

	g_free(interface_name);
	g_free(property_name);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Error in getting Metadata");
		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &arr);

	ret = __bt_avrcp_control_parse_properties(metadata, &arr);
	dbus_message_unref(reply);

	BT_DBG("-");
	return ret;
}

void _bt_handle_avrcp_control_event(DBusMessageIter *msg_iter, const char *path)
{
	DBusMessageIter value_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter item_iter;
	const char *property = NULL;

	dbus_message_iter_recurse(msg_iter, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_DICT_ENTRY) {
		BT_ERR("This is bad format dbus");
		return;
	}

	dbus_message_iter_recurse(&item_iter, &dict_iter);

	dbus_message_iter_get_basic(&dict_iter, &property);
	ret_if(property == NULL);

	BT_DBG("property : %s ", property);
	ret_if(!dbus_message_iter_next(&dict_iter));

	if ((strcasecmp(property, "Equalizer") == 0) ||
		(strcasecmp(property, "Repeat") == 0) ||
		(strcasecmp(property, "Shuffle") == 0) ||
		(strcasecmp(property, "Scan") == 0) ||
		(strcasecmp(property, "Status") == 0)) {

		const char *valstr;
		int type, value;

		dbus_message_iter_recurse(&dict_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &valstr);
		BT_DBG("Value : %s ", valstr);
		type = __bt_media_attr_to_type(property);
		value = __bt_media_attrval_to_val(type, valstr);

				/* Send event to application */
		_bt_send_event(BT_AVRCP_CONTROL_EVENT,
			__bt_media_attr_to_event(property),
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID);
	} else if (strcasecmp(property, "Position") == 0) {
		unsigned int value;

		dbus_message_iter_recurse(&dict_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &value);
		BT_DBG("Value : %d ", value);

				/* Send event to application */
		_bt_send_event(BT_AVRCP_CONTROL_EVENT,
			__bt_media_attr_to_event(property),
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID);
	} else if (strcasecmp(property, "Track") == 0) {
		int ret = BLUETOOTH_ERROR_NONE;
		media_metadata_attributes_t metadata;

		dbus_message_iter_recurse(&dict_iter, &value_iter);
		memset(&metadata, 0x00, sizeof(media_metadata_attributes_t));

		ret = __bt_avrcp_control_parse_properties(
							&metadata, &value_iter);
		if (BLUETOOTH_ERROR_NONE != ret)
			return;

				/* Send event to application */
		_bt_send_event(BT_AVRCP_CONTROL_EVENT,
			BLUETOOTH_EVENT_AVRCP_TRACK_CHANGED,
			DBUS_TYPE_STRING, &metadata.title,
			DBUS_TYPE_STRING, &metadata.artist,
			DBUS_TYPE_STRING, &metadata.album,
			DBUS_TYPE_STRING, &metadata.genre,
			DBUS_TYPE_UINT32, &metadata.total_tracks,
			DBUS_TYPE_UINT32, &metadata.number,
			DBUS_TYPE_UINT32, &metadata.duration,
			DBUS_TYPE_INVALID);

		g_free(metadata.title);
		g_free(metadata.artist);
		g_free(metadata.album);
		g_free(metadata.genre);
	} else {
		BT_DBG("Preprty not handled");
	}

	BT_DBG("-");
}

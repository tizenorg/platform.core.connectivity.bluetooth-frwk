/*
 *   bluetooth-media-control
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 *		Girishashok Joshi <girish.joshi@samsung.com>
 *		Chanyeol Park <chanyeol.park@samsung.com>
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/types.h>
#include <glib.h>
#include <string.h>

#include "bluetooth-control-api.h"

#define BLUEZ_SERVICE	"org.bluez"
#define BLUEZ_MANAGER_INTERFACE "org.bluez.Manager"

#define BLUEZ_MEDIA_INTERFACE	"org.bluez.Media"
#define BLUEZ_MEDIA_PLAYER_OBJECT_PATH	"/Musicplayer"


#define BLUEZ_MEDIA_PLAYER_INTERFACE	"org.bluez.MediaPlayer"

#ifndef BT_EXPORT_API
#define BT_EXPORT_API __attribute__((visibility("default")))
#endif

#define BT_CONTROL "BT_CONTROL"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_CONTROL, \
				"%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_CONTROL, \
				"%s():%d "fmt, __func__, __LINE__, ##args)

typedef struct {
	DBusGConnection *avrcp_conn;
	char avrcp_obj_path[MEDIA_OBJECT_PATH_LENGTH];
} avrcp_dbus_info_t;

static avrcp_dbus_info_t g_avrcp_dbus_info;
static DBusConnection *g_avrcp_connection = NULL;

struct player_settinngs_t {
	int key;
	const char *property;
};

static struct player_settinngs_t equilizer_settings[] = {
	{ EQUILIZER_OFF, "off" },
	{ EQUILIZER_ON, "on" },
	{ EQUILIZER_INVALID, "" }
};

static struct player_settinngs_t repeat_settings[] = {
	{ REPEAT_MODE_OFF, "off" },
	{ REPEAT_SINGLE_TRACK, "singletrack" },
	{ REPEAT_ALL_TRACK, "alltracks" },
	{ REPEAT_GROUP, "group" },
	{ REPEAT_INVALID, "" }
};

static struct player_settinngs_t shuffle_settings[] = {
	{ SHUFFLE_MODE_OFF, "off" },
	{ SHUFFLE_ALL_TRACK, "alltracks" },
	{ SHUFFLE_GROUP, "group" },
	{ SHUFFLE_INVALID, "" }
};

static struct player_settinngs_t scan_settings[] = {
	{ SCAN_MODE_OFF, "off" },
	{ SCAN_ALL_TRACK, "alltracks" },
	{ SCAN_GROUP, "group" },
	{ SCAN_INVALID, "" }
};

static struct player_settinngs_t player_status[] = {
	{ STATUS_PLAYING, "playing" },
	{ STATUS_STOPPED, "stopped" },
	{ STATUS_PAUSED, "paused" },
	{ STATUS_FORWARD_SEEK, "forward-seek" },
	{ STATUS_REVERSE_SEEK, "reverse-seek" },
	{ STATUS_ERROR, "error" },
	{ STATUS_INVALID, "" }
};

static int __bluetooth_media_get_avrcp_adapter_path(
		DBusGConnection *gconn, char *path)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	char *adapter_path = NULL;
	int ret = 0;

	DBG("__bluetooth_media_get_avrcp_adapter_path +\n");

	manager_proxy = dbus_g_proxy_new_for_name(gconn, BLUEZ_SERVICE, "/",
					BLUEZ_MANAGER_INTERFACE);

	if (manager_proxy == NULL) {
		DBG("Could not create a dbus proxy\n");
		return BLUETOOTH_CONTROL_ERROR;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
			       G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			       &adapter_path, G_TYPE_INVALID)) {
		DBG("Getting DefaultAdapter failed: [%s]\n", err->message);
		g_error_free(err);
		ret = BLUETOOTH_CONTROL_ERROR;
		goto done;
	}

	if (strlen(adapter_path) >= MEDIA_OBJECT_PATH_LENGTH) {
		DBG("Path too long.\n");
		ret = BLUETOOTH_CONTROL_ERROR;
		goto done;
	}
	DBG("path = %s\n", adapter_path);
	g_strlcpy(path, adapter_path, MEDIA_OBJECT_PATH_LENGTH);

done:
	g_object_unref(manager_proxy);

	DBG("Adapter [%s]\n", path);

	DBG("__bluetooth_media_get_avrcp_adapter_path -\n");
	return ret;
}

static void __bluetooth_media_append_variant(DBusMessageIter *iter,
			int type, void *val)
{
	DBusMessageIter value_iter;
	const char *contained_signature;

	switch (type) {
	case DBUS_TYPE_BYTE:
		contained_signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		contained_signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BOOLEAN:
		contained_signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		contained_signature = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		contained_signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		contained_signature = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		contained_signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		contained_signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		contained_signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
			contained_signature, &value_iter);
	dbus_message_iter_append_basic(&value_iter, type, val);
	dbus_message_iter_close_container(iter, &value_iter);
}

static void __bluetooth_media_append_dict_entry(DBusMessageIter *dict,
			const char *key, int type, void *property)
{
	DBusMessageIter iter;

	if (type == DBUS_TYPE_STRING) {
		const char *str_ptr = *((const char **)property);
		if (!str_ptr)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
				NULL, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &key);

	__bluetooth_media_append_variant(&iter, type, property);

	dbus_message_iter_close_container(dict, &iter);
}

static dbus_bool_t __bluetooth_media_emit_property_changed(
				DBusConnection *conn, const char *path,
				const char *interface, const char *name,
				int type, void *value)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	dbus_bool_t result;

	message = dbus_message_new_signal(path, interface, "PropertyChanged");

	if (!message)
		return FALSE;

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	__bluetooth_media_append_variant(&iter, type, value);

	result = dbus_connection_send(conn, message, NULL);
	dbus_message_unref(message);

	return result;
}

static void __bluetooth_handle_trackchanged(
					DBusMessage *msg)
{
	const char *path = dbus_message_get_path(msg);
	media_metadata_attributes_t metadata = {0,};
	DBusMessage *signal = NULL;
	DBusMessageIter iter;
	DBusMessageIter metadata_dict;

	DBG("Path = %s\n", path);

	if (!dbus_message_get_args(msg, NULL,
		DBUS_TYPE_STRING, &metadata.title,
		DBUS_TYPE_STRING, &metadata.artist,
		DBUS_TYPE_STRING, &metadata.album,
		DBUS_TYPE_STRING, &metadata.genre,
		DBUS_TYPE_UINT32, &metadata.total_tracks,
		DBUS_TYPE_UINT32, &metadata.number,
		DBUS_TYPE_UINT32, &metadata.duration,
		DBUS_TYPE_INVALID)) {
		DBG("Unexpected parameters in signal");
		return;
	}

	signal = dbus_message_new_signal(BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE, "TrackChanged");
	if (!signal) {
		DBG("Unable to allocate TrackChanged signal\n");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata_dict);

	if (NULL != metadata.title) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Title",
			DBUS_TYPE_STRING, &metadata.title);
	}

	if (NULL != metadata.artist) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Artist",
			DBUS_TYPE_STRING, &metadata.artist);
	}

	if (NULL != metadata.album) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Album",
			DBUS_TYPE_STRING, &metadata.album);
	}

	if (NULL != metadata.genre) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Genre",
			DBUS_TYPE_STRING, &metadata.genre);
	}

	if (0 != metadata.total_tracks)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"NumberOfTracks",
			DBUS_TYPE_UINT32, &metadata.total_tracks);

	if (0 != metadata.number)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Number",
			DBUS_TYPE_UINT32, &metadata.number);

	if (0 != metadata.duration)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Duration",
			DBUS_TYPE_UINT32, &metadata.duration);

	dbus_message_iter_close_container(&iter, &metadata_dict);

	if (!dbus_connection_send(g_avrcp_connection, signal, NULL))
		DBG("Unable to send TrackChanged signal\n");
	dbus_message_unref(signal);

}

static void __bluetooth_handle_property_changed(
					DBusMessage *msg)
{
	const char *path = dbus_message_get_path(msg);
	unsigned int type;
	unsigned int value;
	DBG("Path = %s\n", path);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &type,
				DBUS_TYPE_UINT32, &value,
				DBUS_TYPE_INVALID)) {
		DBG("Unexpected parameters in signal");
		return;
	}

	DBG("type = [%d] and value = [%d]\n", type, value);

	switch (type) {
	case EQUILIZER:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Equalizer",
			DBUS_TYPE_STRING,
			&equilizer_settings[value].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	case REPEAT:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Repeat",
			DBUS_TYPE_STRING,
			&repeat_settings[value].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	case SHUFFLE:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Shuffle",
			DBUS_TYPE_STRING,
			&shuffle_settings[value].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	case SCAN:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Scan",
			DBUS_TYPE_STRING,
			&scan_settings[value].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	case STATUS:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Status",
			DBUS_TYPE_STRING,
			&player_status[value].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	case POSITION:
		if (!__bluetooth_media_emit_property_changed(
			g_avrcp_connection,
			BLUEZ_MEDIA_PLAYER_OBJECT_PATH,
			BLUEZ_MEDIA_PLAYER_INTERFACE,
			"Position",
			DBUS_TYPE_UINT32,
			&value)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
		break;
	default:
		DBG("Invalid Type\n");
		break;
	}
}

static DBusHandlerResult __bluetooth_media_event_filter(
					DBusConnection *sys_conn,
					DBusMessage *msg, void *data)
{
	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_signal(msg, BT_MEDIA_PLAYER_DBUS_INTERFACE,
					"TrackChanged")) {
		__bluetooth_handle_trackchanged(msg);
	} else if (dbus_message_is_signal(msg, BT_MEDIA_PLAYER_DBUS_INTERFACE,
					"PropertyChanged")) {
		__bluetooth_handle_property_changed(msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

BT_EXPORT_API int bluetooth_media_init(void)
{
	GError *err = NULL;
	char default_obj_path[MEDIA_OBJECT_PATH_LENGTH] = {0,};
	DBusError dbus_error;

	DBG("bluetooth_media_init +\n");

	g_avrcp_dbus_info.avrcp_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (!g_avrcp_dbus_info.avrcp_conn) {
		DBG("Can not get DBUS Gconnection [%s]\n", err->message);
		g_error_free(err);
		return BLUETOOTH_CONTROL_ERROR;
	}

	DBG("bluetooth_media_init\n");

	g_avrcp_connection = dbus_g_connection_get_connection(
						g_avrcp_dbus_info.avrcp_conn);

	dbus_error_init(&dbus_error);

	dbus_connection_add_filter(g_avrcp_connection,
				__bluetooth_media_event_filter, NULL, NULL);

	dbus_bus_add_match(g_avrcp_connection,
			"type='signal',interface="  \
			BT_MEDIA_PLAYER_DBUS_INTERFACE,
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		return BLUETOOTH_CONTROL_ERROR;
	}

	if (__bluetooth_media_get_avrcp_adapter_path(
		g_avrcp_dbus_info.avrcp_conn,
		 default_obj_path) < 0) {
		DBG("Could not get adapter path\n");
		goto error;
	}

	DBG("bluetooth_media_init\n");

	if (default_obj_path != NULL)
		g_strlcpy(g_avrcp_dbus_info.avrcp_obj_path, default_obj_path,
			MEDIA_OBJECT_PATH_LENGTH);
	else
		goto error;

	DBG("bluetooth_media_init -\n");
	return BLUETOOTH_CONTROL_SUCCESS;

error:
	dbus_g_connection_unref(g_avrcp_dbus_info.avrcp_conn);
	g_avrcp_dbus_info.avrcp_conn = NULL;
	g_avrcp_connection = NULL;
	return BLUETOOTH_CONTROL_ERROR;
}

BT_EXPORT_API int bluetooth_media_register_player(void)
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter property_dict;
	DBusMessageIter metadata_dict;
	DBusError err;


	media_player_settings_t player_settings = {0,};
	media_metadata_attributes_t metadata = {0,};

	player_settings.equilizer = EQUILIZER_OFF;
	player_settings.repeat  = REPEAT_MODE_OFF;
	player_settings.shuffle = SHUFFLE_MODE_OFF;
	player_settings.scan = SCAN_MODE_OFF;
	player_settings.status = STATUS_STOPPED;
	player_settings.position = 0;

	metadata.title = "\0";
	metadata.artist = "\0";
	metadata.album = "\0";
	metadata.genre = "\0";

	if (strlen(g_avrcp_dbus_info.avrcp_obj_path) <= 0)
		return BLUETOOTH_CONTROL_ERROR;

	const char *object = g_strdup(BLUEZ_MEDIA_PLAYER_OBJECT_PATH);

	DBG("bluetooth_media_register_player +\n");

	msg = dbus_message_new_method_call(
				BLUEZ_SERVICE,
				g_avrcp_dbus_info.avrcp_obj_path,
				BLUEZ_MEDIA_INTERFACE,
				"RegisterPlayer");
	if (!msg) {
		DBG("dbus_message_new_method_call failed\n");
		g_free((void *)object);
		return BLUETOOTH_CONTROL_ERROR;
	}

	DBG("object = [%s] \n", object);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);
	g_free((void *)object);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &property_dict);

	if (player_settings.equilizer < EQUILIZER_INVALID) {
		__bluetooth_media_append_dict_entry(&property_dict,
			"Equalizer",
			DBUS_TYPE_STRING,
			&equilizer_settings[
				player_settings.equilizer].property);
	}

	if (player_settings.repeat < REPEAT_INVALID) {
		__bluetooth_media_append_dict_entry(&property_dict,
			"Repeat",
			DBUS_TYPE_STRING,
			&repeat_settings[player_settings.repeat].property);
	}

	if (player_settings.shuffle < SHUFFLE_INVALID) {
		__bluetooth_media_append_dict_entry(&property_dict,
			"Shuffle",
			DBUS_TYPE_STRING,
			&shuffle_settings[player_settings.shuffle].property);
	}

	if (player_settings.scan < SCAN_INVALID) {
		__bluetooth_media_append_dict_entry(&property_dict,
			"Scan",
			DBUS_TYPE_STRING,
			&scan_settings[player_settings.scan].property);
	}

	if (player_settings.status < STATUS_INVALID) {
		__bluetooth_media_append_dict_entry(&property_dict,
			"Status",
			DBUS_TYPE_STRING,
			&player_status[player_settings.status].property);
	}

	if (0 != player_settings.position)
		__bluetooth_media_append_dict_entry(&property_dict,
			"Position",
			DBUS_TYPE_UINT32, &player_settings.position);

	dbus_message_iter_close_container(&iter, &property_dict);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata_dict);

	if (NULL != metadata.title) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Title",
			DBUS_TYPE_STRING, &metadata.title);
	}

	if (NULL != metadata.artist) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Artist",
			DBUS_TYPE_STRING, &metadata.artist);
	}

	if (NULL != metadata.album) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Album",
			DBUS_TYPE_STRING, &metadata.album);
	}

	if (NULL != metadata.genre) {
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Genre",
			DBUS_TYPE_STRING, &metadata.genre);
	}

	if (0 != metadata.total_tracks)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"NumberOfTracks",
			DBUS_TYPE_UINT32, &metadata.total_tracks);

	if (0 != metadata.number)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Number",
			DBUS_TYPE_UINT32, &metadata.number);

	if (0 != metadata.duration)
		__bluetooth_media_append_dict_entry(&metadata_dict,
			"Duration",
			DBUS_TYPE_UINT32, &metadata.duration);

	dbus_message_iter_close_container(&iter, &metadata_dict);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(g_avrcp_connection,
				msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("Error in registering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_CONTROL_ERROR;
		}
	}

	if (reply)
		dbus_message_unref(reply);

	DBG("bluetooth_media_register_player -\n");

	return BLUETOOTH_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_unregister_player(void)
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	const char *object = g_strdup(BLUEZ_MEDIA_PLAYER_OBJECT_PATH);

	DBG("bluetooth_media_unregister_player +\n");

	msg = dbus_message_new_method_call(BLUEZ_SERVICE,
					g_avrcp_dbus_info.avrcp_obj_path,
					BLUEZ_MEDIA_INTERFACE,
					"UnregisterPlayer");

	if (NULL == msg) {
		g_free((void *)object);
		return BLUETOOTH_CONTROL_ERROR;
	}

	dbus_message_append_args(msg,
				DBUS_TYPE_OBJECT_PATH, &object,
				DBUS_TYPE_INVALID);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(g_avrcp_connection,
				msg, -1, &err);
	dbus_message_unref(msg);
	g_free((void *)object);

	if (!reply) {
		DBG("Error in unregistering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
			return BLUETOOTH_CONTROL_ERROR;
		}
	} else
		dbus_message_unref(reply);

	DBG("bluetooth_media_unregister_player -\n");
	return BLUETOOTH_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_deinit(void)
{
	DBG("bluetooth_media_deinit +\n");

	if (g_avrcp_dbus_info.avrcp_conn) {
		dbus_g_connection_unref(g_avrcp_dbus_info.avrcp_conn);
		g_avrcp_dbus_info.avrcp_conn = NULL;
	}

	DBG("bluetooth_media_deinit -\n");
	return BLUETOOTH_CONTROL_SUCCESS;
}

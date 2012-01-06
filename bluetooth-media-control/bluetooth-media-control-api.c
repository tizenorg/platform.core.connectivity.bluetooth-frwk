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

#include "bluetooth-media-control-api.h"

#define BLUEZ_SERVICE	"org.bluez"
#define BLUEZ_MANAGER_INTERFACE "org.bluez.Manager"

#define MEDIA_INTERFACE	"org.bluez.Media"
#define MEDIA_PLAYER_OBJECT	"/Musicplayer"


#define MEDIA_PLAYER_INTERFACE	"org.bluez.MediaPlayer"


static avrcp_dbus_info_t g_avrcp_dbus_info;
static DBusConnection *g_avrcp_connection = NULL;

struct player_settinngs_t  {
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

static int __bluetooth_media_control_get_avrcp_adapter_path(
		DBusGConnection *gconn, char *path)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	char *adapter_path = NULL;
	int ret = 0;

	DBG("+\n");

	manager_proxy = dbus_g_proxy_new_for_name(gconn, BLUEZ_SERVICE, "/",
					BLUEZ_MANAGER_INTERFACE);

	if (manager_proxy == NULL) {
		DBG("Could not create a dbus proxy\n");
		ret = BT_MEDIA_CONTROL_ERROR;
		goto done;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
			       G_TYPE_INVALID,DBUS_TYPE_G_OBJECT_PATH,
			       &adapter_path,G_TYPE_INVALID)) {
		DBG("Getting DefaultAdapter failed: [%s]\n", err->message);
		g_error_free(err);
		ret = BT_MEDIA_CONTROL_ERROR;
		goto done;
	}

	if (adapter_path == NULL) {
		ret = BT_MEDIA_CONTROL_ERROR;
		DBG("Adapter path is NULL\n");
		goto done;
	}

	if (strlen(adapter_path) >= MEDIA_OBJECT_PATH_LENGTH) {
		DBG("Path too long.\n");
		ret = BT_MEDIA_CONTROL_ERROR;
		goto done;
	}
	DBG("path = %s\n", adapter_path);
	g_strlcpy(path, adapter_path, MEDIA_OBJECT_PATH_LENGTH);

 done:

	if (manager_proxy != NULL) {
		g_object_unref(manager_proxy);
	}
	if (adapter_path != NULL) {
		free(adapter_path);
	}
	DBG("Adapter [%s]\n", path);

	DBG("-\n");
	return ret;
}

static void __bluetooth_media_control_append_variant(DBusMessageIter *iter,
			int type, void *val)
{
	DBusMessageIter value_iter;
	const char *signature;

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		signature = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		signature = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, signature, &value_iter);
	dbus_message_iter_append_basic(&value_iter, type, val);
	dbus_message_iter_close_container(iter, &value_iter);
}

static void __bluetooth_media_control_append_dict_entry(DBusMessageIter *dict,
			const char *key, int type, void *property)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str_ptr = *((const char **)property);
		if (str_ptr == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	__bluetooth_media_control_append_variant(&entry, type, property);

	dbus_message_iter_close_container(dict, &entry);
}

BT_EXPORT_API int bluetooth_media_control_init(void)
{
	GError *err = NULL;
	char default_obj_path[MEDIA_OBJECT_PATH_LENGTH] = {0,};

	DBG("+\n");

	g_avrcp_dbus_info.avrcp_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (!g_avrcp_dbus_info.avrcp_conn) {
		DBG("Can not get DBUS Gconnection [%s]\n",err->message);
		g_error_free(err);
		return BT_MEDIA_CONTROL_ERROR;
	}

	g_avrcp_connection = (DBusConnection *)dbus_g_connection_get_connection(
						g_avrcp_dbus_info.avrcp_conn);

	if (__bluetooth_media_control_get_avrcp_adapter_path(
		g_avrcp_dbus_info.avrcp_conn,
		 default_obj_path) < 0) {
		DBG("Could not get adapter path\n");
		goto error;
	}

	if (default_obj_path != NULL)
		g_strlcpy(g_avrcp_dbus_info.avrcp_obj_path, default_obj_path,
			MEDIA_OBJECT_PATH_LENGTH);
	else
		goto error;

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;

error:
	dbus_g_connection_unref(g_avrcp_dbus_info.avrcp_conn);
	g_avrcp_dbus_info.avrcp_conn = NULL;
	g_avrcp_connection = NULL;
	return BT_MEDIA_CONTROL_ERROR;
}

BT_EXPORT_API int bluetooth_media_control_register_player(
			media_player_settings_t player_settings,
			media_metadata_attributes_t metadata )
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter property_dict;
	DBusMessageIter metadata_dict;
	DBusError err;

	const char *object = g_strdup(MEDIA_PLAYER_OBJECT);

	DBG("+\n");

	msg = dbus_message_new_method_call(
				BLUEZ_SERVICE,
				g_avrcp_dbus_info.avrcp_obj_path,
				MEDIA_INTERFACE,
				"RegisterPlayer");
	if (!msg) {
		DBG("dbus_message_new_method_call failed\n");
		g_free((void *)object);
		return BT_MEDIA_CONTROL_ERROR;
	}

	DBG("object = [%s] \n",object);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &property_dict);

	if (player_settings.equilizer < EQUILIZER_INVALID) {
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Equalizer",
			DBUS_TYPE_STRING,
			&equilizer_settings[player_settings.equilizer].property);
	}

	if (player_settings.repeat < REPEAT_INVALID) {
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Repeat",
			DBUS_TYPE_STRING,
			&repeat_settings[player_settings.repeat].property);
	}

	if (player_settings.shuffle < SHUFFLE_INVALID) {
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Shuffle",
			DBUS_TYPE_STRING,
			&shuffle_settings[player_settings.shuffle].property);
	}

	if (player_settings.scan < SCAN_INVALID) {
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Scan",
			DBUS_TYPE_STRING,
			&scan_settings[player_settings.scan].property);
	}

	if (player_settings.status < STATUS_INVALID) {
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Status",
			DBUS_TYPE_STRING,
			&player_status[player_settings.status].property);
	}

	if(0 != player_settings.position)
		__bluetooth_media_control_append_dict_entry(&property_dict,
			"Position",
			DBUS_TYPE_UINT32, &player_settings.position);

	dbus_message_iter_close_container(&iter, &property_dict);

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata_dict);

	if (NULL != metadata.title) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Title",
			DBUS_TYPE_STRING, &metadata.title);
	}

	if (NULL != metadata.artist) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Artist",
			DBUS_TYPE_STRING, &metadata.artist);
	}

	if (NULL != metadata.album) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Album",
			DBUS_TYPE_STRING, &metadata.album);
	}

	if ( NULL != metadata.genre ) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Genre",
			DBUS_TYPE_STRING, &metadata.genre);
	}

	if (0 != metadata.total_tracks)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"NumberOfTracks",
			DBUS_TYPE_UINT32, &metadata.total_tracks);

	if (0 != metadata.number)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Number",
			DBUS_TYPE_UINT32, &metadata.number);

	if (0 != metadata.duration)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
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
			g_free((void *)object);
			return BT_MEDIA_CONTROL_ERROR;
		}
	}
	g_free((void *)object);

	DBG("-\n");

	return BT_MEDIA_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_control_unregister_player(void)
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	const char *object = g_strdup(MEDIA_PLAYER_OBJECT);

	DBG("+\n");

	msg = dbus_message_new_method_call(BLUEZ_SERVICE,
					g_avrcp_dbus_info.avrcp_obj_path,
					MEDIA_INTERFACE,
					"UnregisterPlayer");

	if (NULL == msg) {
		g_free((void *)object);
		return BT_MEDIA_CONTROL_ERROR;
	}

	dbus_message_append_args(msg,
				DBUS_TYPE_OBJECT_PATH, &object,
				DBUS_TYPE_INVALID);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(g_avrcp_connection,
				msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("Error in unregistering the Music Player \n");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
			g_free((void *)object);
			return BT_MEDIA_CONTROL_ERROR;
		}
	}
	g_free((void *)object);

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}

static dbus_bool_t __bluetooth_media_control_emit_property_changed(
				DBusConnection *conn,
				const char *path,
				const char *interface,
				const char *name,
				int type, void *value)
{
	DBusMessage *signal = NULL;
	DBusMessageIter iter;
	dbus_bool_t result;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");

	if (!signal) {
		DBG("Unable to allocate new %s.PropertyChanged signal",
			 interface);
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	__bluetooth_media_control_append_variant(&iter, type, value);

	result = dbus_connection_send(conn, signal, NULL);
	dbus_message_unref(signal);

	return result;
}

BT_EXPORT_API int bluetooth_media_control_player_property_changed(
			media_player_settings_t player_settings)
{
	DBG("+\n");

	if (player_settings.equilizer < EQUILIZER_INVALID) {
		if (!__bluetooth_media_control_emit_property_changed(
			g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Equalizer",
			DBUS_TYPE_STRING,
			&equilizer_settings[player_settings.equilizer].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (player_settings.repeat < REPEAT_INVALID) {
		if (!__bluetooth_media_control_emit_property_changed(g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Repeat",
			DBUS_TYPE_STRING,
			&repeat_settings[player_settings.repeat].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (player_settings.shuffle < SHUFFLE_INVALID) {
		if (!__bluetooth_media_control_emit_property_changed(g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Shuffle",
			DBUS_TYPE_STRING,
			&shuffle_settings[player_settings.shuffle].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (player_settings.scan < SCAN_INVALID) {
		if (!__bluetooth_media_control_emit_property_changed(g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Scan",
			DBUS_TYPE_STRING,
			&scan_settings[player_settings.scan].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (player_settings.status < STATUS_INVALID) {
		if (!__bluetooth_media_control_emit_property_changed(g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Status",
			DBUS_TYPE_STRING,
			&player_status[player_settings.status].property)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (0 != player_settings.position) {
		if (!__bluetooth_media_control_emit_property_changed(g_avrcp_connection,
			MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE,
			"Position",
			DBUS_TYPE_UINT32,
			&player_settings.position)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_control_player_track_changed(
		media_metadata_attributes_t metadata)
{
	DBusMessage *signal= NULL;
	DBusMessageIter iter;
	DBusMessageIter metadata_dict;

	DBG("+\n");

	signal = dbus_message_new_signal(MEDIA_PLAYER_OBJECT,
			MEDIA_PLAYER_INTERFACE, "TrackChanged");
	if (!signal) {
		DBG("Unable to allocate TrackChanged signal\n");
		return BT_MEDIA_CONTROL_ERROR;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &metadata_dict);

	if (NULL != metadata.title) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Title",
			DBUS_TYPE_STRING, &metadata.title);
	}

	if (NULL != metadata.artist) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Artist",
			DBUS_TYPE_STRING, &metadata.artist);
	}

	if (NULL != metadata.album) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Album",
			DBUS_TYPE_STRING, &metadata.album);
	}

	if (NULL != metadata.genre) {
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Genre",
			DBUS_TYPE_STRING, &metadata.genre);
	}

	if (0 != metadata.total_tracks)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"NumberOfTracks",
			DBUS_TYPE_UINT32, &metadata.total_tracks);

	if (0 != metadata.number)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Number",
			DBUS_TYPE_UINT32, &metadata.number);

	if (0 != metadata.duration)
		__bluetooth_media_control_append_dict_entry(&metadata_dict,
			"Duration",
			DBUS_TYPE_UINT32, &metadata.duration);

	dbus_message_iter_close_container(&iter, &metadata_dict);

	if (!dbus_connection_send(g_avrcp_connection, signal, NULL))
		DBG("Unable to send TrackChanged signal\n");
	dbus_message_unref(signal);

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_control_deinit(void)
{
	DBG("+\n");

	if (g_avrcp_dbus_info.avrcp_conn) {
		dbus_g_connection_unref(g_avrcp_dbus_info.avrcp_conn);
		g_avrcp_dbus_info.avrcp_conn = NULL;
	}

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}



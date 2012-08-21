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
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/types.h>
#include <glib.h>
#include <string.h>

#include "bluetooth-media-control-internal.h"
#include "bluetooth-media-control.h"

#define BT_ADDRESS_STR_LEN 18

#define BLUEZ "org.bluez"
#define BLUEZ_AUDIO_SINK "org.bluez.AudioSink"

#define MEDIA_PLAYER_OBJECT_PATH "/Tizen/Player"
#define MEDIA_PLAYER_INTERFACE	"org.tizen.player"

typedef struct {
	media_cb_func_ptr app_cb;
	DBusGConnection *conn;
	DBusConnection *sys_conn;
	void *user_data;
} bt_media_info_t;

static bt_media_info_t bt_media_info;

static int __bluetooth_media_dbus_signal_send(const char *path,
		const char *interface, const char *method, int type, ...)
{
	DBusMessage *msg;
	DBusConnection *conn;
	va_list args;
	DBG("+\n");

	conn  = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (NULL == conn)
		return FALSE;

	msg = dbus_message_new_signal(path, interface, method);
	if (!msg) {
		DBG("Unable to allocate new D-Bus %s message", method);
		dbus_connection_unref(conn);
		return FALSE;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		dbus_connection_unref(conn);
		return FALSE;
	}

	va_end(args);

	if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_SIGNAL)
		dbus_message_set_no_reply(msg, TRUE);

	if (!dbus_connection_send(conn, msg, NULL)) {
		DBG("dbus_connection_send - ERROR\n");
		dbus_message_unref(msg);
		dbus_connection_unref(conn);
		return FALSE;
	}
	dbus_message_unref(msg);
	dbus_connection_unref(conn);

	DBG(" -\n");
	return TRUE;
}

static void __connection_changed_cb(gboolean connected,
					char *device_addr)
{
	media_event_param_t bt_event = { 0, };

	DBG("+");

	bt_event.event = connected ? BT_A2DP_CONNECTED : \
				BT_A2DP_DISCONNECTED;
	bt_event.result = BT_MEDIA_ERROR_NONE;
	bt_event.param_data = (void *)device_addr;

	if (bt_media_info.app_cb)
		bt_media_info.app_cb(bt_event.event, &bt_event, bt_media_info.user_data);

	DBG("-");
}

static DBusHandlerResult __audio_sink_event_filter(
					DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	const char *path = dbus_message_get_path(msg);
	char address[BT_ADDRESS_STR_LEN] = {0,};
	char *dev_addr = NULL;
	DBusMessageIter item_iter;
	DBusMessageIter value_iter;
	const char *property;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_is_signal(msg, BLUEZ_AUDIO_SINK, "PropertyChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (path != NULL) {
		if (strcmp(path, "/") == 0) {
			__connection_changed_cb(FALSE, NULL);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		dev_addr = strstr(path, "dev_");
	}

	if (dev_addr != NULL) {
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));
		g_strdelimit(address, "_", ':');
		DBG("address is %s \n", address);
	}

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		DBG("This is bad format dbus\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);
	DBG("Property (%s)\n", property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!strcmp(property, "Connected")) {
		gboolean connected;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &connected);

		__connection_changed_cb(connected, address);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

BT_EXPORT_API int bluetooth_media_player_init(media_cb_func_ptr callback_ptr,
						void *user_data)
{
	GError *err = NULL;

	DBusError dbus_error;

	DBG("+");

	if (bt_media_info.conn != NULL) {
		DBG("Already initilize");
		bt_media_info.app_cb = callback_ptr;
		bt_media_info.user_data = user_data;
		return BT_MEDIA_ERROR_ALREADY_INITIALIZED;
	}

	bt_media_info.conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (!bt_media_info.conn) {
		DBG("Can not get DBUS Gconnection [%s]\n", err->message);
		g_error_free(err);
		goto error;
	}

	bt_media_info.sys_conn = dbus_g_connection_get_connection(bt_media_info.conn);

	dbus_error_init(&dbus_error);
	dbus_connection_add_filter(bt_media_info.sys_conn,
				   __audio_sink_event_filter, NULL,
				   NULL);
	dbus_bus_add_match(bt_media_info.sys_conn,
			   "type='signal',interface='"
			   BLUEZ_AUDIO_SINK
			   "',member='PropertyChanged'", &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		goto error;
	}

	DBG("-\n");

	bt_media_info.app_cb = callback_ptr;
	bt_media_info.user_data = user_data;

	return BT_MEDIA_ERROR_NONE;
 error:
	if (bt_media_info.conn) {
		dbus_g_connection_unref(bt_media_info.conn);
		bt_media_info.conn = NULL;
	}

	bt_media_info.sys_conn = NULL;
	return BT_MEDIA_ERROR_INTERNAL;

}

BT_EXPORT_API int bluetooth_media_player_deinit(void)
{
	DBG("+");

	if (bt_media_info.sys_conn) {
		dbus_connection_remove_filter(bt_media_info.sys_conn,
					      __audio_sink_event_filter,
					      NULL);
		bt_media_info.sys_conn = NULL;
	}

	if (bt_media_info.conn) {
		dbus_g_connection_unref(bt_media_info.conn);
		bt_media_info.conn = NULL;
	}

	bt_media_info.app_cb = NULL;
	bt_media_info.user_data = NULL;

	DBG("-");
	return BT_MEDIA_ERROR_NONE;
}


BT_EXPORT_API int bluetooth_media_player_change_property(
			media_player_property_type type,
			unsigned int value)
{
	DBG("+\n");

	if (type > POSITION)
		return BT_MEDIA_ERROR_INTERNAL;

	switch (type) {
	case EQUILIZER:
		if (value >= EQUILIZER_INVALID) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	case REPEAT:
		if (value >= REPEAT_INVALID) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	case SHUFFLE:
		if (value >= SHUFFLE_INVALID) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	case SCAN:
		if (value >= SCAN_INVALID) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	case STATUS:
		if (value >= STATUS_INVALID) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	case POSITION:
		if (0 == value) {
			return BT_MEDIA_ERROR_INTERNAL;
		}
		break;
	}

	if (!__bluetooth_media_dbus_signal_send(
		MEDIA_PLAYER_OBJECT_PATH,
		MEDIA_PLAYER_INTERFACE,
		"PropertyChanged",
		DBUS_TYPE_UINT32, &type,
		DBUS_TYPE_UINT32, &value,
		DBUS_TYPE_INVALID)) {
		DBG("Error sending the PropertyChanged signal \n");
		return BT_MEDIA_ERROR_INTERNAL;
	}

	DBG("-\n");
	return BT_MEDIA_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_media_player_set_properties(
			media_player_settings_t *setting)
{
	DBG("+\n");

	unsigned int type = 0;
	unsigned int value = 0;

	if (setting == NULL) {
		DBG("setting is NULL");
		return BT_MEDIA_ERROR_INTERNAL;
	}

	if (setting->equilizer < EQUILIZER_INVALID) {
		type = EQUILIZER;
		value = (unsigned int)setting->equilizer;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (setting->repeat < REPEAT_INVALID) {
		type = REPEAT;
		value = (unsigned int)setting->repeat;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (setting->shuffle < SHUFFLE_INVALID) {
		type = SHUFFLE;
		value = (unsigned int)setting->shuffle;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (setting->scan < SCAN_INVALID) {
		type = SCAN;
		value = (unsigned int)setting->scan;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (setting->status < STATUS_INVALID) {
		type = STATUS;
		value = (unsigned int)setting->status;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}
	}

	if (0 != setting->position) {
		type = POSITION;
		value = (unsigned int)setting->position;

		if (!__bluetooth_media_dbus_signal_send(
			MEDIA_PLAYER_OBJECT_PATH,
			MEDIA_PLAYER_INTERFACE,
			"PropertyChanged",
			DBUS_TYPE_UINT32, &type,
			DBUS_TYPE_UINT32, &value,
			DBUS_TYPE_INVALID)) {
			DBG("Error sending the PropertyChanged signal \n");
		}

	}

	DBG("-\n");
	return BT_MEDIA_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_media_player_change_track(
		media_metadata_attributes_t *metadata)
{
	DBG("+\n");

	if (metadata == NULL) {
		DBG("metadata is NULL");
		return BT_MEDIA_ERROR_INTERNAL;
	}

	if (!__bluetooth_media_dbus_signal_send(
		MEDIA_PLAYER_OBJECT_PATH,
		MEDIA_PLAYER_INTERFACE,
		"TrackChanged",
		DBUS_TYPE_STRING, &metadata->title,
		DBUS_TYPE_STRING, &metadata->artist,
		DBUS_TYPE_STRING, &metadata->album,
		DBUS_TYPE_STRING, &metadata->genre,
		DBUS_TYPE_UINT32, &metadata->total_tracks,
		DBUS_TYPE_UINT32, &metadata->number,
		DBUS_TYPE_UINT32, &metadata->duration,
		DBUS_TYPE_INVALID)) {
		DBG("Error sending the PropertyChanged signal \n");
		return BT_MEDIA_ERROR_INTERNAL;
	}

	DBG("-\n");
	return BT_MEDIA_ERROR_NONE;
}

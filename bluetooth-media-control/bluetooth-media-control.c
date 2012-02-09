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

#include "bluetooth-media-control.h"

#define MEDIA_PLAYER_OBJECT_PATH	"/Samsung/Player"
#define MEDIA_PLAYER_INTERFACE	"com.samsung.player"

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

BT_EXPORT_API int bluetooth_media_player_change_property(
			media_player_property_type type,
			unsigned int value)
{
	DBG("+\n");

	if (type > POSITION)
		return BT_MEDIA_CONTROL_ERROR;

	switch (type) {
	case EQUILIZER:
		if (value >= EQUILIZER_INVALID) {
			return BT_MEDIA_CONTROL_ERROR;
		}
		break;
	case REPEAT:
		if (value >= REPEAT_INVALID) {
			return BT_MEDIA_CONTROL_ERROR;
		}
		break;
	case SHUFFLE:
		if (value >= SHUFFLE_INVALID) {
			return BT_MEDIA_CONTROL_ERROR;
		}
		break;
	case SCAN:
		if (value >= SCAN_INVALID) {
			return BT_MEDIA_CONTROL_ERROR;
		}
		break;
	case STATUS:
		if (value >= STATUS_INVALID) {
			return BT_MEDIA_CONTROL_ERROR;
		}
		break;
	case POSITION:
		if (0 == value) {
			return BT_MEDIA_CONTROL_ERROR;
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
		return BT_MEDIA_CONTROL_ERROR;
	}

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}

BT_EXPORT_API int bluetooth_media_player_change_track(
		media_metadata_attributes_t metadata)
{
	DBusMessage *signal = NULL;
	DBusMessageIter iter;
	DBusMessageIter metadata_dict;

	DBG("+\n");

	if (!__bluetooth_media_dbus_signal_send(
		MEDIA_PLAYER_OBJECT_PATH,
		MEDIA_PLAYER_INTERFACE,
		"TrackChanged",
		DBUS_TYPE_STRING, &metadata.title,
		DBUS_TYPE_STRING, &metadata.artist,
		DBUS_TYPE_STRING, &metadata.album,
		DBUS_TYPE_STRING, &metadata.genre,
		DBUS_TYPE_UINT32, &metadata.total_tracks,
		DBUS_TYPE_UINT32, &metadata.number,
		DBUS_TYPE_UINT32, &metadata.duration,
		DBUS_TYPE_INVALID)) {
		DBG("Error sending the PropertyChanged signal \n");
		return BT_MEDIA_CONTROL_ERROR;
	}

	DBG("-\n");
	return BT_MEDIA_CONTROL_SUCCESS;
}



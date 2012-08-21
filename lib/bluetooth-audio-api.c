/*
 * Bluetooth-audio-api
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 * 		GirishAshok Joshi <girish.joshi@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-bindings.h>

#include "vconf.h"
#include "vconf-keys.h"

#include "bluetooth-audio-api.h"
#include "bluetooth-api-common.h"

#define AUDIO_DBUS_SERVICE	"org.bluez"
#define AUDIO_AG_DBUS_INTERFACE	"org.bluez.Headset"
#define AUDIO_SINK_DBUS_INTERFACE	"org.bluez.AudioSink"
#define AUDIO_DBUS_INTERFACE	"org.bluez.Audio"

#define BLUETOOTH_PHONE_STATUS_HEADSET_STATE	VCONFKEY_BT_DEVICE

#ifndef VCONFKEY_BT_HEADSET_NAME
#define VCONFKEY_BT_HEADSET_NAME	"memory/bluetooth/sco_headset_name"
#endif
#define BLUETOOTH_SCO_HEADSET_NAME	VCONFKEY_BT_HEADSET_NAME
#define BLUETOOTH_AG_ADAPTER_PATH_LENGTH	50

typedef enum {
	BT_AUDIO_HSP = 0x00,
	BT_AUDIO_A2DP,
	BT_AUDIO_ALL,
} bt_audio_type_t;

typedef struct {
	DBusGConnection *audio_conn;
	DBusGProxy *manager_proxy;
	char *audio_obj_path;
} audio_dbus_info_t;

static bt_audio_info_t audio_info;
static audio_dbus_info_t audio_dbus_info;
static DBusConnection *audio_connection = NULL;

#define BT_AUDIO "BT_AUDIO"

#ifdef DBG
#undef DBG
#endif
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_AUDIO,\
				"%s():%d "fmt, __func__, __LINE__, ##args)

#ifdef ERR
#undef ERR
#endif
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_AUDIO, \
				"%s():%d "fmt, __func__, __LINE__, ##args)

static DBusGProxy *current_proxy;
static DBusGProxyCall *current_call;

static void __bluetooth_audio_internal_event_cb(int event, int result,
							void *param_data)
{
	bt_audio_event_param_t bt_event = { 0, };

	DBG("__bluetooth_audio_internal_event_cb +\n");

	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param_data;

	if (audio_info.audio_cb)
		audio_info.audio_cb(bt_event.event, &bt_event,
					audio_info.user_data);

	DBG("__bluetooth_audio_internal_event_cb -\n");
}

static DBusGProxy *__bluetooth_get_adapter_proxy(void)
{
	DBusGProxy *proxy;
	char *adapter_path = NULL;

	if (audio_dbus_info.manager_proxy == NULL)
		return NULL;

	if (!dbus_g_proxy_call(audio_dbus_info.manager_proxy,
			"DefaultAdapter", NULL,
			G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			&adapter_path, G_TYPE_INVALID)) {
		ERR("Fait to get DefaultAdapter");
		return NULL;
	}

	adapter_path = g_strdup(adapter_path);
	if (adapter_path == NULL)
		return NULL;

	proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
				AUDIO_DBUS_SERVICE,
				adapter_path,
				"org.bluez.Adapter");

	g_free(adapter_path);

	return proxy;
}

static char *__bluetooth_get_audio_path(bluetooth_device_address_t *address)
{

	char *object_path = NULL;
	char addr_str[BT_ADDRESS_STRING_SIZE + 1] = { 0 };
	DBusGProxy *proxy;
	DBusGProxy *adapter;
	GError *error = NULL;

	if (audio_dbus_info.audio_conn == NULL)
		return NULL;

	if (address == NULL)
		return NULL;

	adapter = __bluetooth_get_adapter_proxy();

	if (adapter == NULL)
		return NULL;

	_bluetooth_internal_addr_type_to_addr_string(addr_str, address);

	dbus_g_proxy_call(adapter, "FindDevice",
			  &error, G_TYPE_STRING, addr_str,
			  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			  &object_path, G_TYPE_INVALID);

	g_object_unref(adapter);

	if (error != NULL) {
		DBG("Failed to Find device: %s\n", error->message);
		g_error_free(error);
		return NULL;
	}

	if (object_path == NULL)
		return NULL;

	proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
					AUDIO_DBUS_SERVICE,
					object_path,
					AUDIO_AG_DBUS_INTERFACE);

	if (proxy == NULL)
		return NULL;

	g_object_unref(proxy);

	return g_strdup(object_path);
}

static char *__bluetooth_get_connected_audio_path(void)
{
	int i;
	char *audio_path = NULL;
	GPtrArray *devinfo = NULL;
	bluetooth_device_info_t *ptr;

	/* allocate the g_pointer_array */
	devinfo = g_ptr_array_new();

	if (bluetooth_get_bonded_device_list(&devinfo)
					!= BLUETOOTH_ERROR_NONE) {
		g_ptr_array_free(devinfo, TRUE);
		return NULL;
	}

	DBG("g pointer arrary count : [%d]", devinfo->len);
	for (i = 0; i < devinfo->len; i++) {
		ptr = g_ptr_array_index(devinfo, i);
		if(ptr != NULL) {
			if (ptr->connected == TRUE) {
				audio_path = __bluetooth_get_audio_path(&ptr->device_address);
				if (audio_path)
					break;
			}
		}
	}

	g_ptr_array_free(devinfo, TRUE);

	return audio_path;
}

static void __bluetooth_ag_set_name(const char *address)
{
	DBusGProxy *device_proxy = NULL;
	DBusGProxy *adapter_proxy;
	GHashTable *hash = NULL;
	GValue *property_value;
	char *dev_name = NULL;
	char *device_path = NULL;

	DBG("__bluetooth_ag_get_name +\n");

	if (NULL == audio_dbus_info.audio_conn)
		return;

	adapter_proxy = __bluetooth_get_adapter_proxy();
	if (adapter_proxy == NULL)
		return;

	dbus_g_proxy_call(adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, address, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	g_object_unref(adapter_proxy);

	if (device_path == NULL)
		return;

	device_proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
			AUDIO_DBUS_SERVICE, device_path,
			"org.bluez.Device");

	if (NULL == device_proxy) {
		DBG("Getting proxy Failed!\n");
		return;
	}

	dbus_g_proxy_call(device_proxy, "GetProperties", NULL, G_TYPE_INVALID,
			dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
					G_TYPE_VALUE), &hash, G_TYPE_INVALID);

	if (hash == NULL) {
		g_object_unref(device_proxy);
		return;
	}

	property_value = g_hash_table_lookup(hash, "Name");
	dev_name = (char *)(property_value ?
			g_value_get_string(property_value) : NULL);
	if (NULL != dev_name) {
		DBG("Name - [%s]\n", dev_name);
		int ret = 0;
		ret = vconf_set_str(BLUETOOTH_SCO_HEADSET_NAME,
				(char *)dev_name);
		if (ret != 0) {
			DBG("vconf_set_str failed for [%s]\n",
				BLUETOOTH_SCO_HEADSET_NAME);
		} else {
			DBG("Set device_name is  [%s]\n", dev_name);
		}
	}

	g_object_unref(device_proxy);
	DBG("__bluetooth_ag_get_name -\n");
}

static void __bluetooth_set_ag_state(bt_ag_conn_status_t state)
{
	DBG("__bluetooth_set_ag_state +\n");

	switch (audio_info.ag_state) {
	case BLUETOOTH_AG_STATE_NONE:
		audio_info.ag_state = state;
		break;
	case BLUETOOTH_AG_STATE_CONNECTING:
		if (BLUETOOTH_AG_STATE_CONNECTED == state) {
			DBG("Successfully connected\n");
			audio_info.ag_state = state;

		} else if (BLUETOOTH_AG_STATE_DISCONNECTED == state) {
			DBG("Connection attempt failed\n");
			audio_info.ag_state = state;
		}
		break;
	case BLUETOOTH_AG_STATE_CONNECTED:
		if (BLUETOOTH_AG_STATE_PLAYING == state) {
			DBG("SCO audio connection successfully opened\n");
			audio_info.ag_state = state;
			audio_info.ag_audio_flag = TRUE;
		} else if (BLUETOOTH_AG_STATE_DISCONNECTED == state) {
			DBG("Disconnected from the remote device");
			audio_info.ag_state = state;
			audio_info.ag_audio_flag = FALSE;
			audio_info.ag_spkr_gain = 0;
		}
		break;
	case BLUETOOTH_AG_STATE_PLAYING:
		if (BLUETOOTH_AG_STATE_CONNECTED == state) {
			DBG("SCO audio connection closed\n");
			audio_info.ag_state = state;
			audio_info.ag_audio_flag = FALSE;
		} else if (BLUETOOTH_AG_STATE_DISCONNECTED == state) {
			DBG("Disconnected from the remote devicen");
			audio_info.ag_state = state;
			audio_info.ag_audio_flag = FALSE;
		}
		break;
	case BLUETOOTH_AG_STATE_DISCONNECTED:
		if (BLUETOOTH_AG_STATE_CONNECTING == state) {
			DBG("Either an incoming or outgoing connection"\
				"attempt ongoing.\n");
			audio_info.ag_state = state;
		}
		break;
	default:
		break;
	}
	DBG("__bluetooth_set_ag_state -\n");
}

static void __bluetooth_set_ag_remote_speaker_gain(unsigned int speaker_gain)
{
	DBG("__bluetooth_set_ag_remote_speaker_gain +\n");

	DBG("speaker_gain = [%d]\n", speaker_gain);
	audio_info.ag_spkr_gain = speaker_gain;

	__bluetooth_audio_internal_event_cb(BLUETOOTH_EVENT_AG_SPEAKER_GAIN,
				BLUETOOTH_AUDIO_ERROR_NONE,
				(void *)&speaker_gain);

	DBG("__bluetooth_set_ag_remote_speaker_gain -\n");
}

static void __bluetooth_set_ag_remote_mic_gain(unsigned int microphone_gain)
{
	DBG("__bluetooth_set_ag_remote_mic_gain +\n");

	DBG("microphone_gain = [%d]\n", microphone_gain);

	__bluetooth_audio_internal_event_cb(BLUETOOTH_EVENT_AG_MIC_GAIN,
				BLUETOOTH_AUDIO_ERROR_NONE,
				(void *)&microphone_gain);

	DBG("__bluetooth_set_ag_remote_mic_gain -\n");
}

static int __bluetooth_audio_proxy_init(void)
{
	GError *error = NULL;
	DBusGProxy *manager_proxy;

	DBG("__bluetooth_audio_proxy_init +\n");
	audio_dbus_info.audio_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!audio_dbus_info.audio_conn) {
		if (NULL != error) {
			DBG("dbus_g_bus_get() failed:[%d:%s]\n",
					error->code, error->message);
			g_error_free(error);
		}
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	audio_connection = dbus_g_connection_get_connection(
					audio_dbus_info.audio_conn);


	manager_proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
						AUDIO_DBUS_SERVICE, "/",
						"org.bluez.Manager");

	if (manager_proxy == NULL) {
		DBG("Could not create a dbus proxy\n");
		goto error;
	}

	audio_dbus_info.manager_proxy = manager_proxy;

	DBG("__bluetooth_audio_proxy_init -\n");
	return BLUETOOTH_AUDIO_ERROR_NONE;

error:
	dbus_g_connection_unref(audio_dbus_info.audio_conn);
	audio_dbus_info.audio_conn = NULL;
	audio_connection = NULL;
	return BLUETOOTH_AUDIO_ERROR_INTERNAL;

}

static void __bluetooth_audio_proxy_deinit(void)
{
	DBG("__bluetooth_audio_proxy_deinit +\n");

	/* To prevent the crash */
	if (current_proxy && current_call) {
		dbus_g_proxy_cancel_call(current_proxy, current_call);
		current_proxy = NULL;
		current_call = NULL;
	}

	if (audio_dbus_info.audio_conn) {
		dbus_g_connection_unref(audio_dbus_info.audio_conn);
		audio_dbus_info.audio_conn = NULL;
	}

	if (audio_dbus_info.manager_proxy) {
		g_object_unref(audio_dbus_info.manager_proxy);
		audio_dbus_info.manager_proxy = NULL;
	}

	audio_connection = NULL;

	DBG("__bluetooth_audio_proxy_deinit -\n");
}

static void __bluetooth_ag_state_event_handler(char *state)
{
	DBG("__bluetooth_ag_state_event_handler +\n");

	DBG("state[%s]\n", state);
	if (g_strcmp0(state, "connecting") == 0)
		__bluetooth_set_ag_state(BLUETOOTH_AG_STATE_CONNECTING);
	else if (g_strcmp0(state, "connected") == 0)
		__bluetooth_set_ag_state(BLUETOOTH_AG_STATE_CONNECTED);
	else if (g_strcmp0(state, "playing") == 0)
		__bluetooth_set_ag_state(BLUETOOTH_AG_STATE_PLAYING);
	else if (g_strcmp0(state, "disconnected") == 0)
		__bluetooth_set_ag_state(BLUETOOTH_AG_STATE_DISCONNECTED);

	DBG("__bluetooth_ag_state_event_handler -\n");
}

static void __bluetooth_ag_handle_connect(const char *str_address)
{
	int ret = FALSE;
	int bt_device_state = 0;

	DBG("__bluetooth_ag_handle_connect +\n");

	ret = vconf_get_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
							&bt_device_state);
	if (ret != 0) {
		DBG("No value for [%s]\n",
				BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Read bt_device_state is  [%d]\n",
				bt_device_state);
	}

	bt_device_state |= BLUETOOTH_STATE_HEADSET_CONNECTED;
	DBG("bt_device_state = [%d]\n", bt_device_state);

	ret = vconf_set_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
							bt_device_state);
	if (ret != 0) {
		DBG("vconf_set_int failed for [%s]\n",
				BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Set bt_device_state is  [%d]\n",
				bt_device_state);
	}

	__bluetooth_ag_set_name(str_address);

	DBG("BT_STATE_HEADSET_CONNECTED\n");

	__bluetooth_audio_internal_event_cb(BLUETOOTH_EVENT_AG_CONNECTED,
				BLUETOOTH_AUDIO_ERROR_NONE,
				(void *)str_address);

	DBG("__bluetooth_ag_handle_connect -\n");
	return;
}

static void __bluetooth_ag_handle_disconnect(const char *str_address)
{
	int ret = FALSE;
	int bt_device_state = 0;

	DBG("__bluetooth_ag_handle_disconnect +\n");

	ret = vconf_get_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
						&bt_device_state);
	if (ret != 0) {
		DBG("No value for [%s]\n",
				BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Read bt_device_state is  [%d]\n",
				bt_device_state);
	}
	if (bt_device_state & BLUETOOTH_STATE_HEADSET_CONNECTED)
		bt_device_state ^= BLUETOOTH_STATE_HEADSET_CONNECTED;

	ret = vconf_set_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
						bt_device_state);
	if (ret != 0) {
		DBG("vconf_set_int failed for [%s]\n",
				BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Set bt_device_state is  [%d]\n",
				bt_device_state);
	}

	audio_info.ag_state = BLUETOOTH_AG_STATE_DISCONNECTED;
	audio_info.ag_audio_flag = FALSE;
	audio_info.ag_spkr_gain = 0;

	DBG("BT_EVENT_AG_DISCONNECTED = 0\n");

	vconf_set_str(BLUETOOTH_SCO_HEADSET_NAME, (char *) "");

	__bluetooth_audio_internal_event_cb(BLUETOOTH_EVENT_AG_DISCONNECTED,
						BLUETOOTH_AUDIO_ERROR_NONE,
						(void *)str_address);

	DBG("__bluetooth_ag_handle_disconnect -\n");
	return;
}

static void __bluetooth_ag_connect_cb(DBusGProxy *proxy, DBusGProxyCall *call,
		gpointer user_data)
{
	GError *err = NULL;
	char *address = (char *)user_data;

	DBG("__bluetooth_ag_connect_cb +\n");

	dbus_g_proxy_end_call(proxy, call, &err, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n",
				err->message);
		g_error_free(err);

		__bluetooth_audio_internal_event_cb(
					BLUETOOTH_EVENT_AG_CONNECTED,
					BLUETOOTH_AG_ERROR_CONNECTION_ERROR,
					(void *)address);
	}
	g_object_unref(proxy);
	g_free(user_data);

	current_proxy = NULL;
	current_call = NULL;

	DBG("__bluetooth_ag_connect_cb -\n");
	return;
}

static void __bluetooth_av_connect_cb(DBusGProxy *proxy,
				DBusGProxyCall *call,
				gpointer user_data)
{
	GError *err = NULL;
	char *address = (char *)user_data;
	DBG("__bluetooth_av_connect_cb +\n");

	dbus_g_proxy_end_call(proxy, call, &err, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n",
			     err->message);
		audio_info.av_state = BLUETOOTH_AV_STATE_NONE;
		g_error_free(err);

		__bluetooth_audio_internal_event_cb(
					BLUETOOTH_EVENT_AV_CONNECTED,
					BLUETOOTH_AV_ERROR_CONNECTION_ERROR,
					(void *)address);
	}
	g_object_unref(proxy);
	g_free(user_data);

	current_proxy = NULL;
	current_call = NULL;

	DBG("__bluetooth_av_connect_cb -\n");
	return;
}

static DBusHandlerResult __bluetooth_ag_event_filter(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	char address[BT_ADDRESS_STRING_SIZE] = {0,};
	char *dev_addr = NULL;
	DBusMessageIter item_iter;
	DBusMessageIter value_iter;
	const char *property;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!dbus_message_is_signal(
			msg, AUDIO_AG_DBUS_INTERFACE, "PropertyChanged") &&
			!dbus_message_is_signal(msg, "org.bluez.Manager",
					"AdapterRemoved")) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (path == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(path, "/") == 0) {
		if (audio_info.ag_state ==
			BLUETOOTH_AG_STATE_CONNECTED) {
			char str_deviceAddr[BT_ADDRESS_STRING_SIZE];

			_bluetooth_internal_addr_type_to_addr_string(
					str_deviceAddr,
					&audio_info.local_address);
			__bluetooth_ag_handle_disconnect(
						str_deviceAddr);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	dev_addr = strstr(path, "dev_");

	if (dev_addr != NULL) {
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));
		g_strdelimit(address, "_", ':');
		DBG("address is %s \n", address);
		_bluetooth_internal_convert_addr_string_to_addr_type(
					&audio_info.remote_address, address);
	}

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);
	DBG("Property (%s)\n", property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!strcmp(property, "State")) {
		char *state = NULL;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &state);
		if (NULL == state) {
			DBG("State is null\n");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		DBG("State %s\n", state);

		__bluetooth_ag_state_event_handler(state);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(property, "Connected")) {
		gboolean connected;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &connected);
		DBG("Connected %d\n", connected);

		if (connected)
			__bluetooth_ag_handle_connect(address);
		else
			__bluetooth_ag_handle_disconnect(address);

		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (!strcmp(property, "SpeakerGain")) {
		guint16 spkr_gain;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &spkr_gain);

		DBG("spk_gain[%d]\n", spkr_gain);
		__bluetooth_set_ag_remote_speaker_gain(spkr_gain);

		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (!strcmp(property, "MicrophoneGain")) {
		guint16 mic_gain;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &mic_gain);

		DBG("mic_gain[%d]\n", mic_gain);
		__bluetooth_set_ag_remote_mic_gain(mic_gain);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __bluetooth_av_handle_connect(const char *str_address)
{
	int ret = FALSE;
	int bt_device_state = 0;

	DBG("__bluetooth_av_handle_connect +\n");

	audio_info.av_state = BLUETOOTH_AV_STATE_CONNECTED;

	ret = vconf_get_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
						&bt_device_state);
	if (ret != 0) {
		DBG("No value for [%s]\n",
			     BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Read bt_device_state is  [%d]\n",
			     bt_device_state);
	}

	bt_device_state |= BLUETOOTH_STATE_A2DP_HEADSET_CONNECTED;
	DBG("bt_device_state = [%d]\n", bt_device_state);

	ret = vconf_set_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
						bt_device_state);
	if (ret != 0) {
		DBG("vconf_set_int failed for [%s]\n",
			     BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Set bt_device_state is  [%d]\n",
			     bt_device_state);
	}

	__bluetooth_audio_internal_event_cb(BLUETOOTH_EVENT_AV_CONNECTED,
			BLUETOOTH_AUDIO_ERROR_NONE, (void *)str_address);

	DBG("__bluetooth_av_handle_connect -\n");
	return;

}

static void __bluetooth_av_handle_disconnect(const char *str_address)
{
	int ret = FALSE;
	int bt_device_state = 0;

	DBG("__bluetooth_av_handle_disconnect +\n");

	audio_info.av_state = BLUETOOTH_AV_STATE_DISCONNECTED;

	ret = vconf_get_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
						&bt_device_state);
	if (ret != 0) {
		DBG("No value for [%s]\n",
			     BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Read bt_device_state is  [%d]\n",
			     bt_device_state);
	}
	if (bt_device_state & BLUETOOTH_STATE_A2DP_HEADSET_CONNECTED)
		bt_device_state ^= BLUETOOTH_STATE_A2DP_HEADSET_CONNECTED;

	ret = vconf_set_int(BLUETOOTH_PHONE_STATUS_HEADSET_STATE,
					bt_device_state);
	if (ret != 0) {
		DBG("vconf_set_int failed for [%s]\n",
			     BLUETOOTH_PHONE_STATUS_HEADSET_STATE);
	} else {
		DBG("Set bt_device_state is  [%d]\n",
			     bt_device_state);
	}

	__bluetooth_audio_internal_event_cb(
			BLUETOOTH_EVENT_AV_DISCONNECTED,
			BLUETOOTH_AUDIO_ERROR_NONE, (void *)str_address);

	DBG("__bluetooth_av_handle_disconnect -\n");
	return;
}

static void __bluetooth_av_handle_play(const char *address)
{
	DBG("A2DP playing [%s]\n", address);
}

static void __bluetooth_av_handle_stop(const char *address)
{

	DBG("A2DP stopped [%s]\n", address);
}

static void __bluetooth_av_state_event_handler(const char *audio_sink_state)
{
	DBG("Audio Sink State is %s\n", audio_sink_state);
}

static DBusHandlerResult __bluetooth_audio_sink_event_filter(
						DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	const char *path = dbus_message_get_path(msg);
	char address[BT_ADDRESS_STRING_SIZE] = {0,};
	char *dev_addr = NULL;
	DBusMessageIter item_iter, value_iter;
	const char *property;
	char *state;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!dbus_message_is_signal
	    (msg, AUDIO_SINK_DBUS_INTERFACE, "PropertyChanged") &&
	    	!dbus_message_is_signal(msg, "org.bluez.Manager",
				       "AdapterRemoved")) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (path == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(path, "/") == 0) {
		if (audio_info.av_state ==
		    BLUETOOTH_AV_STATE_CONNECTED) {
			char str_deviceAddr
			    [BT_ADDRESS_STRING_SIZE];

			_bluetooth_internal_addr_type_to_addr_string(
					str_deviceAddr,
					&audio_info.local_address);

			__bluetooth_av_handle_disconnect(
				str_deviceAddr);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	dev_addr = strstr(path, "dev_");

	if (dev_addr != NULL) {
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));
		g_strdelimit(address, "_", ':');
		DBG("address is %s \n", address);
		_bluetooth_internal_convert_addr_string_to_addr_type(
					&audio_info.remote_address, address);
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

	if (!strcmp(property, "State")) {
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &state);

		__bluetooth_av_state_event_handler(state);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (!strcmp(property, "Connected")) {
		gboolean audio_sink_connected;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &audio_sink_connected);

		if (audio_sink_connected)
			__bluetooth_av_handle_connect(address);
		else
			__bluetooth_av_handle_disconnect(address);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (!strcmp(property, "Playing")) {
		gboolean audio_sink_playing;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &audio_sink_playing);

		if (audio_sink_playing)
			__bluetooth_av_handle_play(address);
		else
			__bluetooth_av_handle_stop(address);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

BT_EXPORT_API int bluetooth_audio_init(bt_audio_func_ptr cb, void  *user_data)
{
	DBusError dbus_error;
	DBG("bluetooth_audio_init +\n");

	if (NULL == cb)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	audio_info.audio_cb = cb;
	audio_info.user_data = user_data;

	if (__bluetooth_audio_proxy_init()) {
		DBG("__bluetooth_audio_proxy_init failed\n");
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	dbus_error_init(&dbus_error);

	dbus_connection_add_filter(audio_connection,
				__bluetooth_ag_event_filter,
				NULL, NULL);

	dbus_connection_add_filter(audio_connection,
				__bluetooth_audio_sink_event_filter,
				NULL, NULL);

	dbus_bus_add_match(audio_connection,
			"type='signal',interface='" AUDIO_AG_DBUS_INTERFACE
			"',member='PropertyChanged'", &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		__bluetooth_audio_proxy_deinit();
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	dbus_bus_add_match(audio_connection,
			   "type='signal',interface='"
			   AUDIO_SINK_DBUS_INTERFACE
			   "',member='PropertyChanged'", &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		__bluetooth_audio_proxy_deinit();
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	DBG("bluetooth_audio_init -\n");
	return BLUETOOTH_AUDIO_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_audio_deinit(void)
{
	DBG("bluetooth_audio_deinit +\n");

	audio_info.audio_cb = NULL;

	if (audio_connection) {
		dbus_connection_remove_filter(audio_connection,
				__bluetooth_ag_event_filter, NULL);

		dbus_connection_remove_filter(audio_connection,
				      __bluetooth_audio_sink_event_filter,
				      NULL);
	}

	if (NULL != audio_dbus_info.audio_obj_path) {
		g_free(audio_dbus_info.audio_obj_path);
		audio_dbus_info.audio_obj_path = NULL;
	}

	__bluetooth_audio_proxy_deinit();

	DBG("bluetooth_audio_deinit -\n");
	return BLUETOOTH_AUDIO_ERROR_NONE;
}

static int __bluetooth_audio_connect(int type, bluetooth_device_address_t *device_address, void *cb_func)
{
	const char *device_path = NULL;
	char *interface;
	char *address;
	DBusGProxy *adapter_proxy;
	DBusGProxy *profile_proxy;

	DBG("+");

	if (device_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	if (audio_dbus_info.audio_conn == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;

	switch (type) {
	case BT_AUDIO_HSP:
		interface = AUDIO_AG_DBUS_INTERFACE;
		break;
	case BT_AUDIO_A2DP:
		interface = AUDIO_SINK_DBUS_INTERFACE;
		break;
	case BT_AUDIO_ALL:
		interface = AUDIO_DBUS_INTERFACE;
		break;
	default:
		ERR("Unknown role");
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	adapter_proxy = __bluetooth_get_adapter_proxy();
	if (adapter_proxy == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;


	address = g_malloc0(BT_ADDRESS_STRING_SIZE);

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	dbus_g_proxy_call(adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, address, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	g_object_unref(adapter_proxy);

	if (device_path == NULL) {
		DBG("No paired device");
		g_free(address);
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	profile_proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
					AUDIO_DBUS_SERVICE,
				      device_path, interface);

	if (profile_proxy == NULL) {
		g_free(address);
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	current_proxy = NULL;

	current_call = dbus_g_proxy_begin_call(profile_proxy, "Connect",
			(DBusGProxyCallNotify)cb_func,
			address, NULL,
			G_TYPE_INVALID);

	if (current_call == NULL) {
		DBG("Audio connect Dbus Call Error");
		g_object_unref(profile_proxy);
		g_free(address);
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	current_proxy = profile_proxy;

	DBG("-\n");

	return BLUETOOTH_AUDIO_ERROR_NONE;
}


static int __bluetooth_audio_disconnect(int type, bluetooth_device_address_t *device_address)
{
	const char *device_path = NULL;
	char *interface;
	char *address;
	DBusGProxy *adapter_proxy;
	DBusGProxy *profile_proxy;

	DBG("+");

	if (device_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	if (audio_dbus_info.audio_conn == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;

	switch (type) {
	case BT_AUDIO_HSP:
		interface = AUDIO_AG_DBUS_INTERFACE;
		break;
	case BT_AUDIO_A2DP:
		interface = AUDIO_SINK_DBUS_INTERFACE;
		break;
	case BT_AUDIO_ALL:
		interface = AUDIO_DBUS_INTERFACE;
		break;
	default:
		ERR("Unknown role");
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	adapter_proxy = __bluetooth_get_adapter_proxy();
	if (adapter_proxy == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;


	address = g_malloc0(BT_ADDRESS_STRING_SIZE);

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	dbus_g_proxy_call(adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, address, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	g_object_unref(adapter_proxy);
	g_free(address);

	if (device_path == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;

	profile_proxy = dbus_g_proxy_new_for_name(audio_dbus_info.audio_conn,
					AUDIO_DBUS_SERVICE,
				      device_path, interface);

	if (profile_proxy == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(profile_proxy, "Disconnect",
				NULL, G_TYPE_INVALID,
				G_TYPE_INVALID)) {
		DBG("Audio disconnect Dbus Call Error");
		g_object_unref(profile_proxy);
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;
	}

	g_object_unref(profile_proxy);

	DBG("-\n");

	return BLUETOOTH_AUDIO_ERROR_NONE;
}


BT_EXPORT_API int bluetooth_audio_connect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_ag_connect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_connect(BT_AUDIO_ALL,
					remote_address,
					__bluetooth_ag_connect_cb);
}

BT_EXPORT_API int bluetooth_audio_disconnect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_ag_disconnect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_disconnect(BT_AUDIO_ALL,
					remote_address);
}

BT_EXPORT_API int bluetooth_ag_connect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_ag_connect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_connect(BT_AUDIO_HSP,
					remote_address,
					__bluetooth_ag_connect_cb);
}

BT_EXPORT_API int bluetooth_ag_disconnect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_ag_disconnect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_disconnect(BT_AUDIO_HSP,
					remote_address);
}

BT_EXPORT_API int bluetooth_ag_set_speaker_gain(unsigned short speaker_gain)
{
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusMessageIter value;
	char *audio_path;
	char *spkr_gain_str = "SpeakerGain";
	int ret = BLUETOOTH_AUDIO_ERROR_NONE;

	DBG("bluetooth_ag_set_speaker_gain +\n");
	DBG(" speaker_gain= [%d]\n", speaker_gain);

	audio_path = __bluetooth_get_connected_audio_path();

	if (audio_path == NULL)
		return BLUETOOTH_AUDIO_ERROR_INTERNAL;

	DBG("audio_path: %s", audio_path);

	msg = dbus_message_new_method_call(AUDIO_DBUS_SERVICE,
			audio_path, AUDIO_AG_DBUS_INTERFACE,
			"SetProperty");
	if (NULL != msg) {
		char sig[2] = {DBUS_TYPE_UINT16, '\0'};

		dbus_message_iter_init_append(msg, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
				&spkr_gain_str);

		dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, sig,
				&value);
		dbus_message_iter_append_basic(&value, DBUS_TYPE_UINT16,
				&speaker_gain);

		dbus_message_iter_close_container(&iter, &value);

		if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_METHOD_CALL)
			dbus_message_set_no_reply(msg, TRUE);

		if (!dbus_connection_send(audio_connection, msg, NULL)) {
			DBG(" bluetooth_ag_set_speaker_gain - \
				dbus_connection_send failed\n");
			ret = BLUETOOTH_AUDIO_ERROR_INTERNAL;
		}
		dbus_message_unref(msg);
	} else
		ret = BLUETOOTH_AUDIO_ERROR_INTERNAL;

	DBG("bluetooth_ag_set_speaker_gain -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_ag_get_headset_volume(unsigned int *speaker_gain)
{
	DBG("bluetooth_ag_get_headset_volume +\n");

	if (NULL == speaker_gain)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	DBG(" Current Speaker gain audio_info.ag_spkr_gain= [%d]\n",
			audio_info.ag_spkr_gain);

	*speaker_gain = audio_info.ag_spkr_gain;

	DBG(" *speaker_gain = [%d]\n", *speaker_gain);
	DBG("bluetooth_ag_get_headset_volume -\n");

	return BLUETOOTH_AUDIO_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_av_connect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_av_connect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_connect(BT_AUDIO_A2DP,
					remote_address,
					__bluetooth_av_connect_cb);
}

BT_EXPORT_API int bluetooth_av_disconnect(
				bluetooth_device_address_t *remote_address)
{
	DBG("bluetooth_av_disconnect +\n");

	if (remote_address == NULL)
		return BLUETOOTH_AUDIO_ERROR_INVALID_PARAM;

	return __bluetooth_audio_disconnect(BT_AUDIO_A2DP,
					remote_address);
}

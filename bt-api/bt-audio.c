/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdio.h>

#include "bluetooth-api.h"
#include "bluetooth-audio-api.h"
#include "bt-internal-types.h"

#include "bt-common.h"
#include "bt-request-sender.h"
#include "bt-event-handler.h"

BT_EXPORT_API int bluetooth_audio_init(bt_audio_func_ptr cb, void *user_data)
{
	int ret;

	if (cb == NULL) {
		BT_ERR("callback is NULL");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}
	ret = _bt_init_event_handler();

	if (ret != BLUETOOTH_ERROR_NONE &&
	     ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		BT_ERR("Fail to init the event handler");
		return ret;
	}

	_bt_set_user_data(BT_AUDIO, (void *)cb, user_data);

	/* Register All events */
	ret = _bt_register_event(BT_HEADSET_EVENT, (void *)cb, user_data);
	if (ret != BLUETOOTH_ERROR_NONE &&
	    ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		_bt_deinit_event_handler();
		return ret;
	}

	ret = _bt_register_event(BT_A2DP_SOURCE_EVENT, (void *)cb, user_data);
	if (ret != BLUETOOTH_ERROR_NONE &&
			ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		_bt_deinit_event_handler();
		return ret;
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_audio_deinit(void)
{
	_bt_unregister_event(BT_HEADSET_EVENT);
	_bt_unregister_event(BT_A2DP_SOURCE_EVENT);
	_bt_set_user_data(BT_AUDIO, NULL, NULL);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_audio_connect(bluetooth_device_address_t *remote_address)
{
	int service_function = BT_AUDIO_CONNECT;
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AUDIO_CONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, service_function,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_audio_disconnect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AUDIO_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AUDIO_DISCONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_ag_connect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AG_CONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AG_CONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_ag_disconnect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AG_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AG_DISCONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_av_connect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AV_CONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AV_CONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_av_source_connect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AV_SOURCE_CONNECT)
		 == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AV_SOURCE_CONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_av_disconnect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AV_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AV_DISCONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_av_source_disconnect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_AV_SOURCE_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_AUDIO);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_AV_SOURCE_DISCONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_ag_get_headset_volume(unsigned int *speaker_gain)
{
	int result;

	BT_CHECK_PARAMETER(speaker_gain, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_SPEAKER_GAIN,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*speaker_gain = g_array_index(out_param,
				unsigned int, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_ag_set_speaker_gain(unsigned int speaker_gain)
{
	int result;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &speaker_gain, sizeof(unsigned int));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_SET_SPEAKER_GAIN,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

#define BT_HF_SERVICE_NAME "org.bluez.hf_agent"
#define BT_HF_OBJECT_PATH "/org/bluez/handsfree_agent"
#define BT_HF_INTERFACE "org.tizen.HfApp"


static GVariant* __bt_hf_agent_dbus_send(const char *path, const char *interface,
				const char *method, GError **err, GVariant *parameters)
{
	GVariant *reply = NULL;
	GDBusProxy *proxy = NULL;
	GDBusConnection *conn = NULL;

	conn = _bt_gdbus_get_system_gconn();
	retv_if(conn == NULL, NULL);

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
		NULL, BT_HF_SERVICE_NAME, path, interface, NULL, err);
	if (proxy == NULL) {
		BT_ERR("Unable to allocate new proxy");
		return NULL;
	}

	reply = g_dbus_proxy_call_sync(proxy, method, parameters,
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, err);

	g_object_unref(proxy);
	return reply;
}

static int __bt_hf_agent_read_call_list(GVariant *reply,
				bt_hf_call_list_s **call_list) {

	GVariantIter iter;
	GVariant *var_temp = NULL;
	int32_t call_count;
	gchar *num = NULL;
	int dir, status, mpart, idx;

	BT_DBG("+");

	g_variant_get(reply, "(i@a(siiii))", &call_count, &var_temp);

	if(call_count <= 0) {
		*call_list = NULL;
		return BLUETOOTH_ERROR_NOT_FOUND;
	}
	BT_DBG("Call count = %d", call_count);

	*call_list = g_malloc0(sizeof(bt_hf_call_list_s));
	/* Fix : NULL_RETURNS */
	retv_if(*call_list == NULL, BLUETOOTH_ERROR_MEMORY_ALLOCATION);

	(*call_list)->count = call_count;

	g_variant_iter_init(&iter, var_temp);
	while(g_variant_iter_loop(&iter, "(siiii)", &num, &dir, &status, &mpart, &idx)){
		bt_hf_call_status_info_t *call_info;

		call_info = g_malloc0(sizeof(bt_hf_call_status_info_t));
		/* Fix : NULL_RETURNS */
		retv_if(call_info == NULL, BLUETOOTH_ERROR_MEMORY_ALLOCATION);

		call_info->number = g_strdup(num);
		call_info->direction = dir;
		call_info->status = status;
		call_info->mpart= mpart;
		call_info->idx = idx;

		(*call_list)->list = g_list_append((*call_list)->list,
							(gpointer)call_info);
	}
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_init(bt_hf_func_ptr cb, void *user_data)
{
	int ret;

	if (cb == NULL) {
		BT_ERR("callback is NULL");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	ret = _bt_init_event_handler();

	if (ret != BLUETOOTH_ERROR_NONE &&
	     ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		BT_ERR("Fail to init the event handler");
		return ret;
	}

	_bt_set_user_data(BT_HF, (void *)cb, user_data);

	/* Register All events */
	ret = _bt_register_event(BT_HF_AGENT_EVENT, (void *)cb, user_data);
	if (ret != BLUETOOTH_ERROR_NONE &&
	     ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		_bt_deinit_event_handler();
		return ret;
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_deinit(void)
{
	int ret;

	ret = _bt_unregister_event(BT_HF_AGENT_EVENT);
	if (ret != BLUETOOTH_ERROR_NONE )
		BT_ERR("_bt_unregister_event failed");

	_bt_set_user_data(BT_HF, NULL, NULL);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_connect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_ENABLED(return);
	BT_CHECK_PARAMETER(remote_address, return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_HF_CONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_HF);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_HF_CONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_hf_disconnect(bluetooth_device_address_t *remote_address)
{
	int result;
	bt_user_info_t *user_info;

	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_ENABLED(return);

	if (_bt_check_privilege(BT_CHECK_PRIVILEGE, BT_HF_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	user_info = _bt_get_user_data(BT_HF);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, remote_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_HF_DISCONNECT,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_hf_answer_call()
{
	GVariant *reply = NULL;
	GError *err = NULL;
	int ret = BLUETOOTH_ERROR_INTERNAL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"AnswerCall", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_dbus_error_strip_remote_error(err);
			if (strcmp(err->message, "Operation not supported") == 0)
				ret = BLUETOOTH_ERROR_NOT_IN_OPERATION;
			else if (strcmp(err->message, "Operation not allowed") == 0)
				ret = BLUETOOTH_ERROR_PERMISSION_DEINED;
			else
				ret = BLUETOOTH_ERROR_INTERNAL;
			g_clear_error(&err);
		}
		return ret;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;

}

BT_EXPORT_API int bluetooth_hf_terminate_call()
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"TerminateCall", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_initiate_call(char *number)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	GVariant *param = NULL;
	int ret = BLUETOOTH_ERROR_INTERNAL;

	BT_CHECK_ENABLED(return);

	if (!number)
		number = "";

	param = g_variant_new("(s)", number);
	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"InitiateCall", &err, param);
	if (!reply) {
		BT_ERR("Error returned in method call");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_dbus_error_strip_remote_error(err);
			if (strcmp(err->message, "NotConnected") == 0)
				ret = BLUETOOTH_ERROR_NOT_CONNECTED;
			else if (strcmp(err->message, "Operation not allowed") == 0)
				ret = BLUETOOTH_ERROR_IN_PROGRESS;
			else
				ret = BLUETOOTH_ERROR_INTERNAL;
			g_clear_error(&err);
		}
		return ret;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_voice_recognition(unsigned int status)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	GVariant *param = NULL;

	BT_CHECK_ENABLED(return);

	param = g_variant_new("(i)", status);
	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"VoiceRecognition", &err, param);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_audio_disconnect(void)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"ScoDisconnect", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_set_speaker_gain(unsigned int speaker_gain)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	GVariant *param = NULL;

	BT_CHECK_ENABLED(return);

	param = g_variant_new("(u)", speaker_gain);
	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"SpeakerGain", &err, param);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_send_dtmf(char *dtmf)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	GVariant *param = NULL;

	BT_CHECK_ENABLED(return);

	param = g_variant_new("(s)", dtmf);
	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"SendDtmf", &err, param);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_send_xsat_cmd(int app_id, char *xsat_cmd)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	GVariant *param = NULL;
	char buffer[200] = {0,};
	char *ptr = buffer;

	BT_CHECK_ENABLED(return);

	strcpy(buffer, "AT+XSAT=");
	snprintf(buffer + strlen(buffer), sizeof(buffer), "%d,", app_id);
	strncat(buffer, xsat_cmd, (sizeof(buffer) - 1) - strlen(buffer));
	BT_DBG("Xsat cmd received = %s", buffer);

	param = g_variant_new("(s)", ptr);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
					"SendAtCmd", &err, param);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_release_and_accept(void)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"ReleaseAndAccept", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_swap_call(void)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"CallSwap", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_release_all_call(void)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"ReleaseAllCall", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_join_call(void)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"JoinCall", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_get_call_list(void *call_list,
								bt_hf_call_status_info_t **call_status)
{
	int i;
	GList *list = call_list;
	int call_count;
	bt_hf_call_status_info_t * call_info;

	BT_CHECK_ENABLED(return);
	retv_if(list == NULL, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(call_status == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	call_count = g_list_length(list);

	BT_DBG(" call_count = [%d]", call_count);

	for (i = 0; i < call_count; i++) {
		call_info = g_list_nth_data(list, i);
		BT_DBG(" direction = [%d]", call_info->direction);
		BT_DBG(" status = [%d]", call_info->status);
		BT_DBG(" mpart = [%d]", call_info->mpart);
		BT_DBG(" number = [%s]", call_info->number);
		BT_DBG(" idx = [%d]", call_info->idx);
		call_status[i] = call_info;
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_free_call_list(bt_hf_call_list_s *call_list)
{
	bt_hf_call_list_s *handle;
	bt_hf_call_status_info_t *call_status;

	retv_if(call_list == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	handle = (bt_hf_call_list_s *)call_list;
	do  {
		call_status = (bt_hf_call_status_info_t *)g_list_nth_data(
							handle->list, 0);
		if (call_status == NULL)
			break;
		handle->list = g_list_remove(handle->list, call_status);
		g_free(call_status->number);
		g_free(call_status);
	} while (1);
	g_free(handle);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_request_call_list(
					bt_hf_call_list_s **call_list)
{
	GVariant *reply = NULL;
	GError *err = NULL;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"RequestCallList", &err, NULL);
	if (!reply) {
		BT_ERR("dbus Error or call list is null\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		*call_list = NULL;
		return BLUETOOTH_ERROR_INTERNAL;
	}
	__bt_hf_agent_read_call_list(reply, call_list);

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_get_codec(unsigned int *codec_id)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	int32_t current_codec;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"GetCurrentCodec", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_get(reply, "(i)", &current_codec);
	*codec_id = current_codec;
	BT_DBG(" Codec ID is : %d", *codec_id);

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_get_audio_connected(unsigned int *audio_connected)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	int32_t sco_audio_connected_from_bt_agent;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"GetAudioConnected", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_get(reply, "(i)", &sco_audio_connected_from_bt_agent);
	*audio_connected = sco_audio_connected_from_bt_agent;

	if (*audio_connected == BLUETOOTH_HF_AUDIO_CONNECTED) {
		BT_DBG("SCO Audio is Connected");
	} else {
		BT_DBG("SCO Audio is Disconnected");
	}

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_hf_is_connected(gboolean *hf_connected)
{
	GVariant *reply = NULL;
	GError *err = NULL;
	gboolean hf_connected_from_bt_agent;

	BT_CHECK_ENABLED(return);

	reply = __bt_hf_agent_dbus_send(BT_HF_OBJECT_PATH, BT_HF_INTERFACE,
			"IsHfConnected", &err, NULL);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (err) {
			BT_ERR("Error = %s", err->message);
			g_clear_error(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_get(reply, "(b)", &hf_connected_from_bt_agent);
	*hf_connected = hf_connected_from_bt_agent;

	BT_DBG("%s", *hf_connected ? "Connected":"Disconnected");

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}


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

#include <vconf.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-common.h"
#include "bt-request-sender.h"
#include "bt-event-handler.h"

static int __bt_fill_device_list(GArray *out_param2, GPtrArray **dev_list)
{
	int i;
	guint size;
	bluetooth_device_info_t info;

	BT_CHECK_PARAMETER(out_param2, return);
	BT_CHECK_PARAMETER(dev_list, return);

	size = out_param2->len;

	if (size == 0) {
		BT_ERR("No bonded device");
		return BLUETOOTH_ERROR_NONE;
	}

	size = (out_param2->len) / sizeof(bluetooth_device_info_t);

	for (i = 0; i < size; i++) {
		bluetooth_device_info_t *dev_info = NULL;

		info = g_array_index(out_param2,
				bluetooth_device_info_t, i);

		dev_info = g_memdup(&info, sizeof(bluetooth_device_info_t));

		if (dev_info) {
			g_ptr_array_add(*dev_list, (gpointer)dev_info);
		}
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_check_adapter(void)
{
	int ret;
	int value;

	ret = _bt_get_adapter_path(_bt_gdbus_get_system_gconn(), NULL);

	if (ret != BLUETOOTH_ERROR_NONE) {
		return BLUETOOTH_ADAPTER_DISABLED;
	}

	/* check VCONFKEY_BT_STATUS */
	if (vconf_get_int(VCONFKEY_BT_STATUS, &value) != 0) {
		BT_ERR("fail to get vconf key!");
		return BLUETOOTH_ADAPTER_DISABLED;
	}

	return value == VCONFKEY_BT_STATUS_OFF ? BLUETOOTH_ADAPTER_DISABLED :
						BLUETOOTH_ADAPTER_ENABLED;
}

BT_EXPORT_API int bluetooth_enable_adapter(void)
{
	int result;
	bt_user_info_t *user_info;

	BT_INFO("");
	retv_if(bluetooth_check_adapter() == BLUETOOTH_ADAPTER_ENABLED,
				BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED);

#ifdef TIZEN_DPM_VCONF_ENABLE
	retv_if(bluetooth_dpm_is_bluetooth_mode_allowed() == BLUETOOTH_DPM_RESULT_ACCESS_DENIED,
				BLUETOOTH_ERROR_PERMISSION_DEINED);
#endif

	user_info = _bt_get_user_data(BT_COMMON);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_ENABLE_ADAPTER,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_disable_adapter(void)
{
	int result;
	bt_user_info_t *user_info;

	BT_INFO("");
	BT_CHECK_ENABLED(return);

	user_info = _bt_get_user_data(BT_COMMON);
	retv_if(user_info->cb == NULL, BLUETOOTH_ERROR_INTERNAL);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request_async(BT_BLUEZ_SERVICE, BT_DISABLE_ADAPTER,
		in_param1, in_param2, in_param3, in_param4,
		user_info->cb, user_info->user_data);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_recover_adapter(void)
{
	int result;

	BT_INFO("");
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_RECOVER_ADAPTER,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_reset_adapter(void)
{
	int result;

	BT_INFO("");
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_RESET_ADAPTER,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_local_address(bluetooth_device_address_t *local_address)
{
	int result;

	BT_CHECK_PARAMETER(local_address, return);
	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_LOCAL_ADDRESS,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*local_address = g_array_index(out_param,
			bluetooth_device_address_t, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_local_version(bluetooth_version_t *local_version)
{
	int result;

	BT_CHECK_PARAMETER(local_version, return);
	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_LOCAL_VERSION,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*local_version = g_array_index(out_param, bluetooth_version_t, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_local_name(bluetooth_device_name_t *local_name)
{
	int result;

	BT_CHECK_PARAMETER(local_name, return);
	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_LOCAL_NAME,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*local_name = g_array_index(out_param,
				bluetooth_device_name_t, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_set_local_name(const bluetooth_device_name_t *local_name)
{
	int result;

	BT_CHECK_PARAMETER(local_name, return);
	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, local_name, sizeof(bluetooth_device_name_t));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_SET_LOCAL_NAME,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_is_service_used(const char *service_uuid,
						gboolean *used)
{
	int result;
	char uuid[BLUETOOTH_UUID_STRING_MAX];

	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_PARAMETER(used, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_strlcpy(uuid, service_uuid, sizeof(uuid));
	g_array_append_vals(in_param1, uuid, BLUETOOTH_UUID_STRING_MAX);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_IS_SERVICE_USED,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*used = g_array_index(out_param, gboolean, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_discoverable_mode(bluetooth_discoverable_mode_t *
						  discoverable_mode_ptr)
{
	int result;

	BT_CHECK_PARAMETER(discoverable_mode_ptr, return);

#ifndef TIZEN_WEARABLE
	int timeout = 0;
	/* Requirement in OSP */
	if (bluetooth_check_adapter() == BLUETOOTH_ADAPTER_DISABLED) {
		if (vconf_get_int(BT_FILE_VISIBLE_TIME, &timeout) != 0) {
			BT_ERR("Fail to get the timeout value");
			return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
		}

		if (timeout == -1) {
			*discoverable_mode_ptr = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
		} else {
			*discoverable_mode_ptr = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		}

		return BLUETOOTH_ERROR_NONE;
	}
#else
	BT_CHECK_ENABLED(return);
#endif

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_DISCOVERABLE_MODE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*discoverable_mode_ptr = g_array_index(out_param, int, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_set_discoverable_mode(bluetooth_discoverable_mode_t discoverable_mode,
						  int timeout)
{
	int result;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &discoverable_mode, sizeof(int));
	g_array_append_vals(in_param2, &timeout, sizeof(int));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_SET_DISCOVERABLE_MODE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_timeout_value(int *timeout)
{
	int result;

	BT_CHECK_PARAMETER(timeout, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_DISCOVERABLE_TIME,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*timeout = g_array_index(out_param, int, 0);
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_start_discovery(unsigned short max_response,
					    unsigned short discovery_duration,
					    unsigned int classOfDeviceMask)
{
	int result;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_START_DISCOVERY,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_start_custom_discovery(bt_discovery_role_type_t role,
						unsigned short max_response,
						unsigned short discovery_duration,
						unsigned int classOfDeviceMask)
{
	int result;

	if (role == DISCOVERY_ROLE_LE)
		BT_CHECK_ENABLED_LE(return);
	else
		BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &role, sizeof(bt_discovery_role_type_t));
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_START_CUSTOM_DISCOVERY,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_cancel_discovery(void)
{
	int result;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_CANCEL_DISCOVERY,
		in_param1, in_param2, in_param3, in_param4, &out_param);


	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_is_discovering(void)
{
	int result;
	int is_discovering = FALSE;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_IS_DISCOVERYING,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		is_discovering = g_array_index(out_param,
				int, 0);
	} else {
		BT_ERR("Fail to send request");
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return is_discovering;
}

BT_EXPORT_API int bluetooth_is_connectable(gboolean *is_connectable)
{
	int result;

	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_IS_CONNECTABLE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE) {
		*is_connectable = g_array_index(out_param, int, 0);
	} else {
		BT_ERR("Fail to send request");
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_set_connectable(gboolean is_connectable)
{
	int result;

	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &is_connectable, sizeof(gboolean));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_SET_CONNECTABLE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_get_bonded_device_list(GPtrArray **dev_list)
{
	int result;

	BT_CHECK_PARAMETER(dev_list, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_GET_BONDED_DEVICES,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_ERROR_NONE)
		result = __bt_fill_device_list(out_param, dev_list);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_set_manufacturer_data(const bluetooth_manufacturer_data_t *value)
{
	int result;

	BT_CHECK_PARAMETER(value, return);
	BT_CHECK_ENABLED_ANY(return);

	if (value->data_len > BLUETOOTH_MANUFACTURER_DATA_LENGTH_MAX)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, value, sizeof(bluetooth_manufacturer_data_t));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_SET_MANUFACTURER_DATA,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

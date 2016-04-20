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
#include "bt-event-handler.h"

BT_EXPORT_API int bluetooth_dpm_is_bluetooth_mode_allowed(void)
{
	int value;
	/* check VCONFKEY_BT_STATUS */
	if (vconf_get_int(VCONFKEY_BT_DPM_STATUS, &value) != 0) {
		BT_ERR("fail to get vconf key!");
		return BLUETOOTH_DPM_RESULT_FAIL;
	}
	if (value != VCONFKEY_BT_DPM_STATUS_RESTRICTED)
		return BLUETOOTH_DPM_RESULT_SUCCESS;
	else
		return BLUETOOTH_DPM_RESULT_ACCESS_DENIED;
}

BT_EXPORT_API int bluetooth_dpm_set_allow_bluetooth_mode(bt_dpm_allow_t value)
{
	int result =  BLUETOOTH_DPM_RESULT_SUCCESS;
/*	int bt_status; */

	BT_CHECK_ENABLED_ANY(return);
#if 0
	if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_status) < 0) {
			BT_DBG("BT is disabled");
	}

	if (bt_status == VCONFKEY_BT_STATUS_ON) {
		BT_INIT_PARAMS();
		BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

		g_array_append_vals(in_param1, &value, sizeof(int));

		result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_ALLOW_BT_MODE,
			in_param1, in_param2, in_param3, in_param4, &out_param);

		BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

		if (result == BLUETOOTH_DPM_RESULT_SUCCESS &&
			value == BLUETOOTH_DPM_BT_RESTRICTED) {
			result = bluetooth_disable_adapter();
		}
	} else {
		if (value == BLUETOOTH_DPM_BT_RESTRICTED) {
			if (vconf_set_int(VCONFKEY_BT_DPM_STATUS,
						VCONFKEY_BT_DPM_STATUS_RESTRICTED) != 0) {
				BT_ERR("Set vconf failed\n");
				result = BLUETOOTH_DPM_RESULT_FAIL;
			}
			result = BLUETOOTH_DPM_RESULT_SUCCESS;
		}
	}
#else
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &value, sizeof(int));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_ALLOW_BT_MODE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
#endif

	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_allow_bluetooth_mode(bt_dpm_allow_t *value)
{
	int result;
	BT_CHECK_ENABLED_ANY(return);

#if 0
	if (bluetooth_dpm_is_bluetooth_mode_allowed() != BLUETOOTH_DPM_RESULT_SUCCESS)
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
#endif

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_ALLOW_BT_MODE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_activate_bluetooth_device_restriction(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_DEVICE_RESTRITION,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_is_bluetooth_device_restriction_active(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DEVICE_RESTRITION,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_activate_bluetoooth_uuid_restriction(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_UUID_RESTRITION,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_is_bluetooth_uuid_restriction_active(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_UUID_RESTRITION,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_add_bluetooth_devices_to_blacklist(const bluetooth_device_address_t *device_address)
{
	int result;

	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_ENABLED_ANY(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, device_address, sizeof(bluetooth_device_address_t));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_ADD_DEVICES_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_dpm_add_bluetooth_devices_to_whitelist(const bluetooth_device_address_t *device_address)
{
	int result;

	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, device_address, sizeof(bluetooth_device_address_t));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_ADD_DEVICES_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_add_bluetooth_uuids_to_blacklist(const char *service_uuid)
{
	int result;
	char uuid[BLUETOOTH_UUID_STRING_MAX];
	
	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_strlcpy(uuid, service_uuid, sizeof(uuid));
	g_array_append_vals(in_param1, uuid, BLUETOOTH_UUID_STRING_MAX);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_ADD_UUIDS_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_add_bluetooth_uuids_to_whitelist(const char *service_uuid)
{
	int result;
	char uuid[BLUETOOTH_UUID_STRING_MAX];
	
	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_strlcpy(uuid, service_uuid, sizeof(uuid));
	g_array_append_vals(in_param1, uuid, BLUETOOTH_UUID_STRING_MAX);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_ADD_UUIDS_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_clear_bluetooth_devices_from_blacklist(void)
{
	int result;
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_CLEAR_DEVICES_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_clear_bluetooth_devices_from_whitelist(void)
{
	int result;
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_CLEAR_DEVICES_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_clear_bluetooth_uuids_from_blacklist(void)
{
	int result;
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_CLEAR_UUIDS_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_clear_bluetooth_uuids_from_whitelist(void)
{
	int result;
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_CLEAR_UUIDS_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

static void _bluetooth_extract_dpm_device_info(
	int count,
	bt_dpm_device_list_t *dst_info,
	bt_dpm_device_list_t *src_info)
{
	int i;

	for (i = 0; i < count; i++) {
		memset(dst_info->addresses[i].addr, 0,
			BT_ADDRESS_STRING_SIZE);

		g_strlcpy((gchar *)dst_info->addresses[i].addr, (gchar *)src_info->addresses[i].addr,
			BT_ADDRESS_STRING_SIZE);

//		BT_DBG("address[%d] : %s", i, dst_info->addresses[i].addr);
	}
}

static void _bluetooth_extract_dpm_uuid_info(
	int count,
	bt_dpm_uuids_list_t *dst_info,
	bt_dpm_uuids_list_t *src_info)
{
	int i;

	for (i = 0; i < count; i++) {
		memset(dst_info->uuids[i], 0,
			BLUETOOTH_UUID_STRING_MAX);

		g_strlcpy(dst_info->uuids[i], src_info->uuids[i],
			BLUETOOTH_UUID_STRING_MAX);

		BT_DBG("uuids[%d] : %s", i, dst_info->uuids[i]);
	}
}


BT_EXPORT_API int bluetooth_dpm_get_bluetooth_devices_from_blacklist(bt_dpm_device_list_t *device_list)
{
	int result;
	bt_dpm_device_list_t *devices = NULL;

	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DEVICES_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		devices = &g_array_index(out_param, bt_dpm_device_list_t, 0);
		BT_DBG("device_list->count : %d", devices->count);
	
		if (devices->count == 0) {
			BT_ERR("device_list->count is zero !");
			return BLUETOOTH_DPM_RESULT_FAIL;
		}
	
		device_list->count = devices->count;
	
		_bluetooth_extract_dpm_device_info(devices->count,
				device_list, devices);
	} else {
		BT_ERR("Get Devices list Failed");
	}

	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_devices_from_whitelist(bt_dpm_device_list_t *device_list)
{
	int result;
	bt_dpm_device_list_t *devices = NULL;

	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DEVICES_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		devices = &g_array_index(out_param, bt_dpm_device_list_t, 0);
		BT_DBG("device_list->count : %d", devices->count);
		
		if (devices->count == 0) {
			BT_ERR("device_list->count is zero !");
			return BLUETOOTH_DPM_RESULT_FAIL;
		}
		
		device_list->count = devices->count;
		
		_bluetooth_extract_dpm_device_info(devices->count,
				device_list, devices);

	} else {
		BT_ERR("Get Devices list Failed");
	}

	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_uuids_from_blacklist(bt_dpm_uuids_list_t *uuid_list)
{
	int result;
	bt_dpm_uuids_list_t *uuids;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_UUIDS_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		uuids = &g_array_index(out_param, bt_dpm_uuids_list_t, 0);
		BT_DBG("uuids->count : %d", uuids->count);

		if (uuids->count == 0) {
			BT_ERR("uuids->count is zero !");
			return BLUETOOTH_DPM_RESULT_FAIL;
		}

		uuid_list->count = uuids->count;
		_bluetooth_extract_dpm_uuid_info(uuids->count,
				uuid_list, uuids);
	} else {
		BT_ERR("Get UUIDS list Failed");
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_uuids_from_whitelist(bt_dpm_uuids_list_t *uuid_list)
{
	int result;
	bt_dpm_uuids_list_t *uuids;

	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_UUIDS_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		uuids = &g_array_index(out_param, bt_dpm_uuids_list_t, 0);
		BT_DBG("uuids->count : %d", uuids->count);
	
		if (uuids->count == 0) {
			BT_ERR("uuids->count is zero !");
			return BLUETOOTH_DPM_RESULT_FAIL;
		}
	
		uuid_list->count = uuids->count;
	
		_bluetooth_extract_dpm_uuid_info(uuids->count,
				uuid_list, uuids);
	} else {
		BT_ERR("Get UUIDS list Failed");
	}

	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_remove_bluetooth_device_from_whitelist(const bluetooth_device_address_t *device_address)
{
	int result;
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, device_address, sizeof(bluetooth_device_address_t));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_REMOVE_DEVICE_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_remove_bluetooth_device_from_blacklist(const bluetooth_device_address_t *device_address)
{
	int result;
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, device_address, sizeof(bluetooth_device_address_t));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_REMOVE_DEVICE_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;

}

BT_EXPORT_API int bluetooth_dpm_remove_bluetooth_uuid_from_whitelist(const char *service_uuid)
{
	int result;
	char uuid[BLUETOOTH_UUID_STRING_MAX];
	
	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_strlcpy(uuid, service_uuid, sizeof(uuid));
	g_array_append_vals(in_param1, uuid, BLUETOOTH_UUID_STRING_MAX);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_REMOVE_UUID_WHITELIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_remove_bluetooth_uuid_from_blacklist(const char *service_uuid)
{
	int result;
	char uuid[BLUETOOTH_UUID_STRING_MAX];
	
	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_strlcpy(uuid, service_uuid, sizeof(uuid));
	g_array_append_vals(in_param1, uuid, BLUETOOTH_UUID_STRING_MAX);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_REMOVE_UUID_BLACKLIST,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;

}

BT_EXPORT_API int bluetooth_dpm_set_allow_bluetooth_outgoing_call(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_ALLOW_OUTGOING_CALL,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_allow_bluetooth_outgoing_call(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_ALLOW_OUTGOING_CALL,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_pairing_state(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_PAIRING_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_pairing_state(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_ALLOW_BT_MODE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_profile_state(bt_dpm_profile_t profile, bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &profile, sizeof(int));
	g_array_append_vals(in_param2, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_PROFILE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_profile_state(bt_dpm_profile_t profile, bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &profile, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_PROFILE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_desktop_connectivity_state(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_DESKROP_CONNECTIVITY_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_desktop_connectivity_state(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DESKROP_CONNECTIVITY_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_discoverable_state(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_DISCOVERABLE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_discoverable_state(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DISCOVERABLE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

#if 0
BT_EXPORT_API bt_dpm_result_t bluetooth_dpm_clear_bluetooth_devices_from_list(void);
BT_EXPORT_API bt_dpm_result_t bluetooth_dpm_clear_bluetooth_uuids_from_list(void);
#endif

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_limited_discoverable_state(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_LIMITED_DISCOVERABLE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_limited_discoverable_state(bt_dpm_status_t *value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_LIMITED_DISCOVERABLE_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}
	
	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_set_bluetooth_data_transfer_state(bt_dpm_status_t value)
{
	int result;
	
	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	g_array_append_vals(in_param1, &value, sizeof(int));
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_SET_DATA_TRANSFER_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	return result;
}

BT_EXPORT_API int bluetooth_dpm_get_bluetooth_data_transfer_state(bt_dpm_status_t *value)
{
	int result;

	BT_CHECK_ENABLED_ANY(return);
	
	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);
	
	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_DPM_GET_DATA_TRANSFER_STATE,
		in_param1, in_param2, in_param3, in_param4, &out_param);
	
	if (result == BLUETOOTH_DPM_RESULT_SUCCESS) {
		if (out_param->len > 0) {
			*value = g_array_index(out_param,
					int, 0);
		} else {
			BT_ERR("out_param length is 0!!");
		}
	}

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}


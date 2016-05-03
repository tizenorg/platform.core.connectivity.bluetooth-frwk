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

#ifdef TIZEN_DPM_ENABLE
#include <vconf.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"
#include "bt-common.h"
#include "bt-request-sender.h"
#include "bt-event-handler.h"
#include "bt-event-handler.h"
#include "bt-dpm.h"

#ifdef TIZEN_DPM_VCONF_ENABLE
BT_EXPORT_API int bluetooth_dpm_is_bt_mode_allowed(void)
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
#endif

#if 0
static bt_dpm_status_e _bt_check_dpm_allow_restriction(void)
{
	bt_dpm_allow_t mode;

	bluetooth_dpm_get_allow_bt_mode(&mode);

	return (mode == BLUETOOTH_DPM_BT_RESTRICTED) ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED;
}
#endif

static bt_dpm_status_e _bt_check_dpm_handsfree_only(void)
{
	bt_dpm_allow_t mode;

	bluetooth_dpm_get_allow_bt_mode(&mode);

	return (mode == BLUETOOTH_DPM_HANDSFREE_ONLY ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}

static bt_dpm_status_e _bt_check_dpm_pairing_restriction(void)
{
	bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;

	bluetooth_dpm_get_pairing_state(&dpm_status);

	return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}

static bt_dpm_status_e _bt_check_dpm_desktop_connectivity_restriction(void)
{
	bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;

	bluetooth_dpm_get_desktop_connectivity_state(&dpm_status);

	return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}

#if 0
static bt_dpm_status_e _bt_check_dpm_visible_restriction(void)
{
	bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;

	bluetooth_dpm_get_desktop_connectivity_state(&dpm_status);

	return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}

static bt_dpm_status_e _bt_check_dpm_limited_discoverable_mode(void)
{
	bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;

	bluetooth_dpm_get_limited_discoverable_state(&dpm_status);

	return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}
#endif

static bt_dpm_status_e _bt_check_dpm_blacklist_device(bluetooth_device_address_t *address)
{
	int ret = BLUETOOTH_DPM_RESULT_SUCCESS;
	bt_dpm_device_list_t dev_list;
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };

	_bt_convert_addr_type_to_string(device_address,
			(unsigned char *)address->addr);

	ret = bluetooth_dpm_get_devices_from_blacklist(&dev_list);
	if (ret == BLUETOOTH_DPM_RESULT_SUCCESS) {
		int i = 0;
		for (i = 0; i < dev_list.count; i++) {
			char temp_address[BT_ADDRESS_STRING_SIZE] = { 0 };
			_bt_convert_addr_type_to_string(temp_address,
			(unsigned char *)dev_list.addresses[i].addr);
			if (g_strcmp0(device_address, temp_address) == 0)
				return BT_DPM_RESTRICTED;
			else
				return BT_DPM_ALLOWED;
		}
	} else {
		return BT_DPM_NO_SERVICE;
	}
	return BT_DPM_ALLOWED;
}

static bt_dpm_status_e _bt_check_dpm_blacklist_uuid(char *uuid)
{
	bt_dpm_status_e bt_dpm_status = BT_DPM_ALLOWED;
	bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;
	bt_dpm_profile_t dpm_profile = BLUETOOTH_DPM_PROFILE_NONE;
	bt_dpm_uuids_list_t uuid_list;
	int ret = BLUETOOTH_DPM_RESULT_SUCCESS;
	retv_if(!uuid, bt_dpm_status);

	ret = bluetooth_dpm_get_uuids_from_blacklist(&uuid_list);
	if (ret == BLUETOOTH_DPM_RESULT_SUCCESS) {
		int i = 0;
		for (i = 0; i < uuid_list.count; i++) {
			if (g_strcmp0(uuid, uuid_list.uuids[i]) == 0)
				return BT_DPM_RESTRICTED;
			else
				return BT_DPM_ALLOWED;
		}
	} else {
		return BT_DPM_NO_SERVICE;
	}

	if (g_strcmp0(BT_OPP_UUID, uuid) == 0) {
		bt_dpm_status_t dpm_status = BLUETOOTH_DPM_ALLOWED;
		bluetooth_dpm_get_data_transfer_state(&dpm_status);
		return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
	}

	/* ++ check MDM profile restriction ++ */
	if (g_strcmp0(BT_A2DP_UUID, uuid) == 0)
		dpm_profile = BLUETOOTH_DPM_POLICY_A2DP_PROFILE_STATE;
	else if (g_strcmp0(BT_AVRCP_TARGET_UUID, uuid) == 0)
		dpm_profile = BLUETOOTH_DPM_POLICY_AVRCP_PROFILE_STATE;
	else if (g_strcmp0(BT_HFP_AUDIO_GATEWAY_UUID, uuid) == 0)
		dpm_profile = BLUETOOTH_DPM_POLICY_HFP_PROFILE_STATE;
	else if (g_strcmp0(BT_HSP_AUDIO_GATEWAY_UUID, uuid) == 0)
		dpm_profile = BLUETOOTH_DPM_POLICY_HSP_PROFILE_STATE;
	else if (g_strcmp0(BT_OBEX_PSE_UUID, uuid) == 0)
		dpm_profile = BLUETOOTH_DPM_POLICY_PBAP_PROFILE_STATE;

	if (dpm_profile != BLUETOOTH_DPM_PROFILE_NONE) {
		ret = bluetooth_dpm_get_profile_state(dpm_profile, &dpm_status);
		return (dpm_status == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
	}
	/* -- check DPM profile restriction -- */

	return bt_dpm_status;
}

static bt_dpm_status_e _bt_check_dpm_transfer_restriction(void)
{
	bt_dpm_status_e dpm_status = BT_DPM_ALLOWED;
	bt_dpm_status_t dpm_value = BLUETOOTH_DPM_ALLOWED;

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_OPP_UUID);

	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}

	bluetooth_dpm_get_data_transfer_state(&dpm_value);

	return (dpm_value == BLUETOOTH_DPM_RESTRICTED ? BT_DPM_RESTRICTED : BT_DPM_ALLOWED);
}

static bt_dpm_status_e _bt_check_dpm_hsp_restriction(void)
{
	bt_dpm_status_e dpm_status = BT_DPM_ALLOWED;

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_HFP_AUDIO_GATEWAY_UUID);

	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_HSP_AUDIO_GATEWAY_UUID);
	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}
	return dpm_status;
}

static bt_dpm_status_e _bt_check_dpm_a2dp_restriction(void)
{
	bt_dpm_status_e dpm_status = BT_DPM_ALLOWED;

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_A2DP_UUID);

	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}

	return dpm_status;
}

static bt_dpm_status_e _bt_check_dpm_avrcp_restriction(void)
{
	bt_dpm_status_e dpm_status = BT_DPM_ALLOWED;

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_AVRCP_TARGET_UUID);

	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}

	return dpm_status;
}

static bt_dpm_status_e _bt_check_dpm_spp_restriction(void)
{
	bt_dpm_status_e dpm_status = BT_DPM_ALLOWED;

	dpm_status = _bt_check_dpm_blacklist_uuid(BT_SPP_UUID);

	if (dpm_status == BT_DPM_NO_SERVICE || dpm_status == BT_DPM_RESTRICTED) {
		return dpm_status;
	}

	return dpm_status;
}

int _bt_check_dpm(int service, void *param)
{
	bt_dpm_status_e status = BT_DPM_ALLOWED;

	BT_CHECK_ENABLED_ANY(return);

	switch (service) {
	case BT_DPM_HF_ONLY:
		status= _bt_check_dpm_handsfree_only();
		break;

	case BT_DPM_PAIRING:
		status = _bt_check_dpm_pairing_restriction();
		break;
	case BT_DPM_DESKTOP:
		status = _bt_check_dpm_desktop_connectivity_restriction();
		break;
	case BT_DPM_ADDRESS: {
		status = _bt_check_dpm_blacklist_device((bluetooth_device_address_t *)param);
		}
		break;
	case BT_DPM_UUID: {
		char *uuid;
		uuid = (char *)param;
		status = _bt_check_dpm_blacklist_uuid(uuid);
		}
		break;
	case BT_DPM_OPP:
		status = _bt_check_dpm_transfer_restriction();
		break;
	case BT_DPM_HSP:
		status = _bt_check_dpm_hsp_restriction();
		break;
	case BT_DPM_A2DP:
		status = _bt_check_dpm_a2dp_restriction();
		break;
	case BT_DPM_AVRCP:
		status = _bt_check_dpm_avrcp_restriction();
		break;
	case BT_DPM_SPP:
		status = _bt_check_dpm_spp_restriction();
		break;

	default:
		BT_ERR("Unknown service");
		return status;
	}

	if (status == BT_DPM_RESTRICTED)
		BT_INFO("Service [%d], DPM permission denied", service);
	else if (status == BT_DPM_NO_SERVICE)
		BT_DBG("DPM no service [%d]",status);

	return status;
}

BT_EXPORT_API int bluetooth_dpm_set_allow_bt_mode(bt_dpm_allow_t value)
{
	int result =  BLUETOOTH_DPM_RESULT_SUCCESS;
#ifdef TIZEN_DPM_VCONF_ENABLE
	int bt_status;
#endif

#ifdef TIZEN_DPM_VCONF_ENABLE
	if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_status) < 0) {
		BT_ERR("Error in reading VCONFKEY_BT_STATUS");
	}

	if (bt_status == VCONFKEY_BT_STATUS_ON) {
		if (vconf_set_int(VCONFKEY_BT_DPM_STATUS, value) != 0) {
			BT_ERR("Set VCONFKEY_BT_DPM_STATUS failed\n");
			result = BLUETOOTH_DPM_RESULT_FAIL;
		} else
			result = BLUETOOTH_DPM_RESULT_SUCCESS;

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
		if (value >= BLUETOOTH_DPM_BT_ALLOWED &&
			value <= BLUETOOTH_DPM_BT_RESTRICTED) {
			if (vconf_set_int(VCONFKEY_BT_DPM_STATUS, value) != 0) {
				BT_ERR("Set VCONFKEY_BT_DPM_STATUS failed\n");
				result = BLUETOOTH_DPM_RESULT_FAIL;
			} else
				result = BLUETOOTH_DPM_RESULT_SUCCESS;
		} else
			result = BLUETOOTH_DPM_RESULT_INVALID_PARAM;
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

BT_EXPORT_API int bluetooth_dpm_get_allow_bt_mode(bt_dpm_allow_t *value)
{
	int result;

#ifdef TIZEN_DPM_VCONF_ENABLE
	*value = bluetooth_dpm_is_bt_mode_allowed();
	return BLUETOOTH_DPM_RESULT_SUCCESS;
#else
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
#endif

	return result;
}


BT_EXPORT_API int bluetooth_dpm_activate_device_restriction(bt_dpm_status_t value)
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


BT_EXPORT_API int bluetooth_dpm_is_device_restriction_active(bt_dpm_status_t *value)
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


BT_EXPORT_API int bluetooth_dpm_activate_uuid_restriction(bt_dpm_status_t value)
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


BT_EXPORT_API int bluetooth_dpm_is_uuid_restriction_active(bt_dpm_status_t *value)
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


BT_EXPORT_API int bluetooth_dpm_add_devices_to_blacklist(const bluetooth_device_address_t *device_address)
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


BT_EXPORT_API int bluetooth_dpm_add_devices_to_whitelist(const bluetooth_device_address_t *device_address)
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


BT_EXPORT_API int bluetooth_dpm_add_uuids_to_blacklist(const char *service_uuid)
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


BT_EXPORT_API int bluetooth_dpm_add_uuids_to_whitelist(const char *service_uuid)
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


BT_EXPORT_API int bluetooth_dpm_clear_devices_from_blacklist(void)
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


BT_EXPORT_API int bluetooth_dpm_clear_devices_from_whitelist(void)
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


BT_EXPORT_API int bluetooth_dpm_clear_uuids_from_blacklist(void)
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


BT_EXPORT_API int bluetooth_dpm_clear_uuids_from_whitelist(void)
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


static void _bluetooth_extract_dpm_device_info(int count,
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

static void _bluetooth_extract_dpm_uuid_info(int count,
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

BT_EXPORT_API int bluetooth_dpm_get_devices_from_blacklist(bt_dpm_device_list_t *device_list)
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

BT_EXPORT_API int bluetooth_dpm_get_devices_from_whitelist(bt_dpm_device_list_t *device_list)
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

BT_EXPORT_API int bluetooth_dpm_get_uuids_from_blacklist(bt_dpm_uuids_list_t *uuid_list)
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

BT_EXPORT_API int bluetooth_dpm_get_uuids_from_whitelist(bt_dpm_uuids_list_t *uuid_list)
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

BT_EXPORT_API int bluetooth_dpm_remove_device_from_whitelist(const bluetooth_device_address_t *device_address)
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

BT_EXPORT_API int bluetooth_dpm_remove_device_from_blacklist(const bluetooth_device_address_t *device_address)
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

BT_EXPORT_API int bluetooth_dpm_remove_uuid_from_whitelist(const char *service_uuid)
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

BT_EXPORT_API int bluetooth_dpm_remove_uuid_from_blacklist(const char *service_uuid)
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

BT_EXPORT_API int bluetooth_dpm_set_allow_outgoing_call(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_allow_outgoing_call(bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_pairing_state(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_pairing_state(bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_profile_state(bt_dpm_profile_t profile, bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_profile_state(bt_dpm_profile_t profile, bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_desktop_connectivity_state(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_desktop_connectivity_state(bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_discoverable_state(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_discoverable_state(bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_limited_discoverable_state(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_limited_discoverable_state(bt_dpm_status_t *value)
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

BT_EXPORT_API int bluetooth_dpm_set_data_transfer_state(bt_dpm_status_t value)
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

BT_EXPORT_API int bluetooth_dpm_get_data_transfer_state(bt_dpm_status_t *value)
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
#endif /* #ifdef TIZEN_DPM_ENABLE */

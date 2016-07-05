/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd. All rights reserved.
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
#ifdef TIZEN_DPM_ENABLE

#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <string.h>
#include <syspopup_caller.h>
#include <bundle_internal.h>
#include <vconf.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-core-adapter.h"
#include "bt-service-dpm.h"

static dpm_policy_t policy_table[DPM_POLICY_END] = {
	[DPM_POLICY_ALLOW_BLUETOOTH] = { {DPM_BT_ERROR} },
	[DPM_POLICY_BLUETOOTH_DEVICE_RESTRICTION] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_UUID_RESTRICTION] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST] = { {NULL} },
	[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST] = { {NULL} },
	[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST] = { {NULL} },
	[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST] = { {NULL} },
	[DPM_POLICY_ALLOW_BLUETOOTH_OUTGOING_CALL] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_PAIRING_STATE] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_DESKTOP_CONNECTIVITY_STATE] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_DISCOVERABLE_STATE] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_LIMITED_DISCOVERABLE_STATE] = { {DPM_STATUS_ERROR} },
	[DPM_POLICY_BLUETOOTH_DATA_TRANSFER_STATE] = { {DPM_STATUS_ERROR} },
};


/**
 * @brief DPM profile state
 * @see
 */
static dpm_profile_state_t dpm_profile_state[DPM_PROFILE_NONE]  = {
	[DPM_POLICY_BLUETOOTH_A2DP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_AVRCP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_BPP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_DUN_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_FTP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_HFP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_HSP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_PBAP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_SAP_PROFILE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_SPP_PROFILE_STATE] = {DPM_STATUS_ERROR},
};

int _bt_launch_dpm_popup(char *mode)
{
	int ret = 0;
	bundle *b;

	b = bundle_create();
	retv_if(b == NULL, BLUETOOTH_ERROR_INTERNAL);

	bundle_add(b, "mode", mode);

	ret = syspopup_launch(BT_DPM_SYSPOPUP, b);

	if (ret < 0)
		BT_ERR("Popup launch failed: %d\n", ret);

	bundle_free(b);

	return ret;
}

dpm_result_t _bt_dpm_set_allow_bluetooth_mode(dpm_bt_allow_t value)
{
	BT_INFO("_bt_dpm_set_allow_bluetooth_mode");

#if 0
	if (value == DPM_BT_ALLOWED && value == DPM_BT_HANDSFREE_ONLY) {
		/* Update Bluetooth DPM Status to notify other modules */
		if (vconf_set_int(VCONFKEY_BT_DPM_STATUS, value) != 0)
			BT_ERR("Set vconf failed\n");
		return DPM_RESULT_FAIL;
	} else {
		/* Update Bluetooth DPM Status to notify other modules */
		if (vconf_set_int(VCONFKEY_BT_DPM_STATUS, VCONFKEY_BT_DPM_STATUS_RESTRICTED) != 0)
			BT_ERR("Set vconf failed\n");
		return DPM_RESULT_FAIL;
	}
#endif
	policy_table[DPM_POLICY_ALLOW_BLUETOOTH].value	= value;

	return DPM_RESULT_SUCCESS;
}

dpm_bt_allow_t _bt_dpm_get_allow_bluetooth_mode(void)
{
	BT_INFO("_bt_dpm_get_allow_bluetooth_mode");

	return policy_table[DPM_POLICY_ALLOW_BLUETOOTH].value;
}

dpm_result_t _bt_dpm_activate_bluetooth_device_restriction(dpm_status_t value)
{
	BT_INFO("_bt_dpm_activate_bluetooth_device_restriction");
	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	policy_table[DPM_POLICY_BLUETOOTH_DEVICE_RESTRICTION].value  = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_is_bluetooth_device_restriction_active(void)
{
	BT_INFO("_bt_dpm_is_bluetooth_device_restriction_active");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DEVICE_RESTRICTION].value;
}

dpm_result_t _bt_dpm_activate_bluetoooth_uuid_restriction(dpm_status_t value)
{
	BT_INFO("_bt_dpm_activate_bluetooth_device_restriction");
	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	policy_table[DPM_POLICY_BLUETOOTH_UUID_RESTRICTION].value  = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_is_bluetooth_uuid_restriction_active(void)
{
	BT_INFO("_bt_dpm_is_bluetooth_uuid_restriction_active");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_UUID_RESTRICTION].value;
}

dpm_result_t _bt_dpm_add_bluetooth_devices_to_blacklist(bluetooth_device_address_t *bd_addr)
{
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr = NULL;

	BT_INFO("_bt_dpm_add_bluetooth_devices_to_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	BT_CHECK_PARAMETER(bd_addr, return);

	_bt_convert_addr_type_to_string(device_address,
			(unsigned char *)bd_addr->addr);

	dev_addr = g_strdup(device_address);
	if (!dev_addr)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list, dev_addr);

	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_get_bluetooth_devices_from_blacklist(GArray **out_param1)
{
	dpm_result_t ret = DPM_RESULT_FAIL;
	bt_dpm_device_list_t device_list;
	GSList *list = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list;
	int i = 0;

	BT_INFO("_bt_dpm_get_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return ret;

	if (list) {
		ret = DPM_RESULT_SUCCESS;
		for (; list; list = list->next, i++) {
			memset(device_list.addresses[i].addr, 0, BT_ADDRESS_STRING_SIZE);
			_bt_convert_addr_string_to_type(device_list.addresses[i].addr, list->data);
		}
		device_list.count = g_slist_length(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list);
		g_array_append_vals(*out_param1, &device_list, sizeof(bt_dpm_device_list_t));
	} else {
		ret = DPM_RESULT_SUCCESS;
		device_list.count = 0;
		g_array_append_vals(*out_param1, &device_list, sizeof(bt_dpm_device_list_t));
	}
	return ret;
}

dpm_result_t _bt_dpm_add_bluetooth_devices_to_whitelist(bluetooth_device_address_t *bd_addr)
{
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr = NULL;

	BT_INFO("_bt_dpm_add_bluetooth_devices_to_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	BT_CHECK_PARAMETER(bd_addr, return);

	_bt_convert_addr_type_to_string(device_address,
			(unsigned char *)bd_addr->addr);

	dev_addr = g_strdup(device_address);
	if (!dev_addr)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, dev_addr);
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_get_bluetooth_devices_from_whitelist(GArray **out_param1)
{
	dpm_result_t ret = DPM_RESULT_FAIL;
	bt_dpm_device_list_t device_list;
	GSList *list = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list;
	int i = 0;

	BT_INFO("_bt_dpm_get_bluetooth_devices_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return ret;

	if (list) {
		ret = DPM_RESULT_SUCCESS;
		for (; list; list = list->next, i++) {
			memset(device_list.addresses[i].addr, 0, BT_ADDRESS_STRING_SIZE);
			_bt_convert_addr_string_to_type(device_list.addresses[i].addr, list->data);

		}
		device_list.count = g_slist_length(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list);
		g_array_append_vals(*out_param1, &device_list, sizeof(bt_dpm_device_list_t));
	} else {
		ret = DPM_RESULT_SUCCESS;
		device_list.count = 0;
		g_array_append_vals(*out_param1, &device_list, sizeof(bt_dpm_device_list_t));
	}
	return ret;
}

dpm_result_t _bt_dpm_add_bluetooth_uuids_to_blacklist(const char *uuid)
{
	char *l_uuid;
	BT_INFO("_bt_dpm_add_bluetooth_uuids_to_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	l_uuid = g_strdup(uuid);
	if (!l_uuid)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list, l_uuid);
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_get_bluetooth_uuids_from_blacklist(GArray **out_param1)
{
	dpm_result_t ret = DPM_RESULT_FAIL;
	bt_dpm_uuids_list_t uuids_list = {0, { {0}, } };
	GSList *list = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list;
	int i = 0;

	BT_INFO("_bt_dpm_get_bluetooth_uuids_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return ret;

	if (list) {
		ret = DPM_RESULT_SUCCESS;
		uuids_list.count = g_slist_length(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list);
		for (; list; list = list->next, i++) {
			memset(uuids_list.uuids[i], 0, BLUETOOTH_UUID_STRING_MAX);
			g_strlcpy(uuids_list.uuids[i], list->data,
					BLUETOOTH_UUID_STRING_MAX);
		}
		g_array_append_vals(*out_param1, &uuids_list, sizeof(bt_dpm_uuids_list_t));
	} else {
		ret = DPM_RESULT_SUCCESS;
		uuids_list.count = 0;
		g_array_append_vals(*out_param1, &uuids_list, sizeof(bt_dpm_uuids_list_t));
	}

	return ret;
}

dpm_result_t _bt_dpm_add_bluetooth_uuids_to_whitelist(const char *uuid)
{
	char *l_uuid;
	BT_INFO("_bt_dpm_add_bluetooth_uuids_to_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	l_uuid = g_strdup(uuid);
	if (!l_uuid)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list, l_uuid);
	return DPM_RESULT_SUCCESS;
}


dpm_result_t _bt_dpm_get_bluetooth_uuids_from_whitelist(GArray **out_param1)
{
	dpm_result_t ret = DPM_RESULT_FAIL;
	bt_dpm_uuids_list_t uuids_list = {0, { {0}, } };
	GSList *list = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list;
	int i = 0;

	BT_INFO("_bt_dpm_get_bluetooth_uuids_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return ret;

	if (list) {
		ret = DPM_RESULT_SUCCESS;
		uuids_list.count = g_slist_length(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list);
		for (; list; list = list->next, i++) {
			memset(uuids_list.uuids[i], 0, BLUETOOTH_UUID_STRING_MAX);
			g_strlcpy(uuids_list.uuids[i], list->data,
					BLUETOOTH_UUID_STRING_MAX);
		}
		g_array_append_vals(*out_param1, &uuids_list, sizeof(bt_dpm_uuids_list_t));
	} else {
		ret = DPM_RESULT_SUCCESS;
		uuids_list.count = 0;
		g_array_append_vals(*out_param1, &uuids_list, sizeof(bt_dpm_uuids_list_t));
	}

	return ret;

}

dpm_result_t _bt_dpm_set_allow_bluetooth_outgoing_call(dpm_status_t value)
{
	BT_INFO("_bt_dpm_activate_bluetooth_device_restriction");
	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	policy_table[DPM_POLICY_ALLOW_BLUETOOTH_OUTGOING_CALL].value  = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_allow_bluetooth_outgoing_call(void)
{
	BT_INFO("_bt_dpm_get_allow_bluetooth_outgoing_call");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_ALLOW_BLUETOOTH_OUTGOING_CALL].value;
}

dpm_result_t _bt_dpm_clear_bluetooth_devices_from_blacklist(void)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_clear_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list; l; l = g_slist_next(l)) {
		char *address = l->data;
		if (address) {
			policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list, address);
			g_free(address);
		}
	}
	g_slist_free(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list);
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list = NULL;
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_clear_bluetooth_devices_from_whitelist(void)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_clear_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list; l; l = g_slist_next(l)) {
		char *address = l->data;
		if (address) {
			policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, address);
			g_free(address);
		}
	}
	g_slist_free(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list);
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list = NULL;
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_clear_bluetooth_uuids_from_blacklist(void)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_clear_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list; l; l = g_slist_next(l)) {
		char *l_uuid = l->data;
		if (l_uuid)
			policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list, l_uuid);
		g_free(l_uuid);
	}
	g_slist_free(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list);
	policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list = NULL;
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_clear_bluetooth_uuids_from_whitelist(void)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_clear_bluetooth_uuids_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list; l; l = g_slist_next(l)) {
		char *l_uuid = l->data;
		if (l_uuid) {
			policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list, l_uuid);
			g_free(l_uuid);
		}
	}
	g_slist_free(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list);
	policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list = NULL;
	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_set_bluetooth_pairing_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_pairing_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	policy_table[DPM_POLICY_BLUETOOTH_PAIRING_STATE].value = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_bluetooth_pairing_state(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_pairing_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_PAIRING_STATE].value;
}

dpm_status_t _bt_dpm_set_bluetooth_profile_state(dpm_profile_t profile, dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_profile_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	dpm_profile_state[profile].value = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_bluetooth_profile_state(dpm_profile_t profile)
{
	BT_INFO("_bt_dpm_get_bluetooth_profile_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return dpm_profile_state[profile].value;
}

dpm_status_t _bt_dpm_set_bluetooth_desktop_connectivity_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_desktop_connectivity_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	policy_table[DPM_POLICY_BLUETOOTH_DESKTOP_CONNECTIVITY_STATE].value = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_bluetooth_desktop_connectivity_state(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_desktop_connectivity_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DESKTOP_CONNECTIVITY_STATE].value;
}

dpm_status_t _bt_dpm_set_bluetooth_discoverable_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_discoverable_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	if (value == DPM_RESTRICTED) {
		/* Since Discoverable mode is restricted, stop the ongoing discoverable mode */
		_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
	}

	policy_table[DPM_POLICY_BLUETOOTH_DISCOVERABLE_STATE].value = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_bluetooth_discoverable_state(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_discoverable_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DISCOVERABLE_STATE].value;
}

dpm_status_t _bt_dpm_set_bluetooth_limited_discoverable_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_limited_discoverable_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	if (value == DPM_RESTRICTED) {
		/* Since Discoverable mode is restricted, stop the ongoing discoverable mode */
		_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
	}

	policy_table[DPM_POLICY_BLUETOOTH_LIMITED_DISCOVERABLE_STATE].value = value;

	return DPM_RESULT_SUCCESS;
}

dpm_status_t _bt_dpm_get_bluetooth_limited_discoverable_state(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_limited_discoverable_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_LIMITED_DISCOVERABLE_STATE].value;
}

dpm_status_t _bt_dpm_set_bluetooth_data_transfer_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_set_bluetooth_data_transfer_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DATA_TRANSFER_STATE].value = value;
}

dpm_status_t _bt_dpm_get_allow_bluetooth_data_transfer_state(void)
{
	BT_INFO("_bt_dpm_get_allow_bluetooth_data_transfer_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DATA_TRANSFER_STATE].value;
}

dpm_result_t _bt_dpm_remove_bluetooth_devices_from_whitelist(bluetooth_device_address_t *device_address)
{
	GSList *l = NULL;
	char bd_addr[BT_ADDRESS_STRING_SIZE] = { 0 };
	BT_INFO("_bt_dpm_remove_bluetooth_devices_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	_bt_convert_addr_type_to_string(bd_addr,
			(unsigned char *)device_address->addr);

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list; l; l = g_slist_next(l)) {
		char *l_device = l->data;
		if (l_device && g_strcmp0(l_device, bd_addr)) {
			policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, l_device);
			g_free(l_device);
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_devices_from_blacklist(bluetooth_device_address_t *device_address)
{
	GSList *l = NULL;
	char bd_addr[BT_ADDRESS_STRING_SIZE] = { 0 };

	BT_INFO("_bt_dpm_remove_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	_bt_convert_addr_type_to_string(bd_addr,
			(unsigned char *)device_address->addr);

	for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list; l; l = g_slist_next(l)) {
		char *l_device = l->data;
		if (l_device && g_strcmp0(l_device, bd_addr)) {
			policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, l_device);
			g_free(l_device);
		}
	}

	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_uuids_from_whitelist(const char *uuids)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_uuids_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;
	for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list; l; l = g_slist_next(l)) {
		char *l_uuid = l->data;
		if (l_uuid && g_strcmp0(l_uuid, uuids)) {
			policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list, l_uuid);
			g_free(l_uuid);
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_uuids_from_blacklist(const char *uuids)
{
	GSList *l = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_uuids_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list; l; l = g_slist_next(l)) {
		char *l_uuid = l->data;
		if (l_uuid && g_strcmp0(l_uuid, uuids)) {
			policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list = g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list, l_uuid);
			g_free(l_uuid);
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_clear_bluetooth_uuids_from_list(void)
{
	BT_INFO("_bt_dpm_clear_bluetooth_uuids_from_list");
	dpm_result_t err = DPM_RESULT_FAIL;

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	err = _bt_dpm_clear_bluetooth_uuids_from_blacklist();
	if (!err)
		err = _bt_dpm_clear_bluetooth_uuids_from_blacklist();

	return err;
}

dpm_result_t _bt_dpm_clear_bluetooth_devices_from_list(void)
{
	BT_INFO("_bt_dpm_clear_bluetooth_devices_from_list");
	dpm_result_t err = DPM_RESULT_FAIL;

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	err = _bt_dpm_clear_bluetooth_devices_from_blacklist();
	if (!err)
		err = _bt_dpm_clear_bluetooth_devices_from_blacklist();

	return err;
}
#endif /* #ifdef TIZEN_DPM_ENABLE */

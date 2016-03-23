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

#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <string.h>
#include <syspopup_caller.h>
#include <bundle_internal.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-dpm.h"

static dpm_policy_t policy_table[DPM_POLICY_END] = {
	[DPM_POLICY_ALLOW_BLUETOOTH] = {DPM_BT_ERROR},
	[DPM_POLICY_BLUETOOTH_DEVICE_RESTRICTION] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_UUID_RESTRICTION] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST] = {NULL},
	[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST] = {NULL},
	[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST] = {NULL},
	[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST] = {NULL},
	[DPM_POLICY_ALLOW_BLUETOOTH_OUTGOING_CALL] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_PAIRING_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_DESKTOP_CONNECTIVITY_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_DISCOVERABLE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_LIMITED_DISCOVERABLE_STATE] = {DPM_STATUS_ERROR},
	[DPM_POLICY_BLUETOOTH_DATA_TRANSFER_STATE] = {DPM_STATUS_ERROR},
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

dpm_result_t _bt_dpm_set_allow_bluetooth_mode(dpm_bt_allow_t value)
{
	BT_INFO("_bt_dpm_set_allow_bluetooth_mode");
	policy_table[DPM_POLICY_ALLOW_BLUETOOTH].value  = value;

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

dpm_result_t _bt_dpm_add_bluetooth_devices_to_blacklist(char *device_address)
{
	char *dev_addr;
	BT_INFO("_bt_dpm_add_bluetooth_devices_to_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	dev_addr = g_strdup(device_address);
	if (!dev_addr)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list, dev_addr);
	return DPM_RESULT_SUCCESS;
}

GSList *_bt_dpm_get_bluetooth_devices_from_blacklist(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return NULL;

	return policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list;
}

dpm_result_t _bt_dpm_add_bluetooth_devices_to_whitelist(char *device_address)
{
	char *dev_addr;
	BT_INFO("_bt_dpm_add_bluetooth_devices_to_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	dev_addr = g_strdup(device_address);
	if (!dev_addr)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, dev_addr);
	return DPM_RESULT_SUCCESS;
}

GSList *_bt_dpm_get_bluetooth_devices_from_whitelist(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_devices_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return NULL;

	return policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list;
}

dpm_result_t _bt_dpm_add_bluetooth_uuids_to_blacklist(char *uuid)
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

GSList *_bt_dpm_get_bluetooth_uuids_from_blacklist(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_uuids_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return NULL;

	return policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list;
}

dpm_result_t _bt_dpm_add_bluetooth_uuids_to_whitelist(char *uuid)
{
	char *l_uuid;
	BT_INFO("_bt_dpm_add_bluetooth_uuids_to_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	l_uuid = g_strdup(uuid);
	if (!l_uuid)
		return DPM_RESULT_FAIL;
	policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list  = g_slist_append(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list, l_uuid);
	return DPM_RESULT_SUCCESS;
}


GSList *_bt_dpm_get_bluetooth_uuids_from_whitelist(void)
{
	BT_INFO("_bt_dpm_get_bluetooth_uuids_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return NULL;

	return policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list;
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

dpm_status_t _bt_dpm_get_allow_bluetooth_data_transfer_state(dpm_status_t value)
{
	BT_INFO("_bt_dpm_get_allow_bluetooth_data_transfer_state");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESTRICTED;

	return policy_table[DPM_POLICY_BLUETOOTH_DATA_TRANSFER_STATE].value;
}

dpm_result_t _bt_dpm_remove_bluetooth_devices_from_whitelist(GSList *device_addresses)
{
	GSList *l = NULL;
	GSList *device_list = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_devices_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (device_list = device_addresses; device_list; device_list = g_slist_next(device_list)) {
		for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list; l; l = g_slist_next(l)) {
			if (l->data == device_list->data) {
				char *addr = device_list->data;
				if (addr) {
					policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list =
						g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST].list, addr);
					g_free(addr);
					break;
				}
			}
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_devices_from_blacklist(GSList *device_addresses)
{
	GSList *l = NULL;
	GSList *device_list = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_devices_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (device_list = device_addresses; device_list; device_list = g_slist_next(device_list)) {
		for (l = policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list; l; l = g_slist_next(l)) {
			if (l->data == device_list->data) {
				char *addr = device_list->data;
				if (addr) {
					policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list =
						g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST].list, addr);
					g_free(addr);
					break;
				}
			}
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_uuids_from_whitelist(GSList *uuids)
{
	GSList *l = NULL;
	GSList *uuids_list = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_uuids_from_whitelist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (uuids_list = uuids; uuids_list; uuids_list = g_slist_next(uuids_list)) {
		for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list; l; l = g_slist_next(l)) {
			if (l->data == uuids_list->data) {
				char *uuid = uuids_list->data;
				if (uuid) {
					policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list =
						g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST].list, uuid);
					g_free(uuid);
					break;
				}
			}
		}
	}
	return DPM_RESULT_SUCCESS;
}

dpm_result_t _bt_dpm_remove_bluetooth_uuids_from_blacklist(GSList *uuids)
{
	GSList *l = NULL;
	GSList *uuids_list = NULL;
	BT_INFO("_bt_dpm_remove_bluetooth_uuids_from_blacklist");

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	for (uuids_list = uuids; uuids_list; uuids_list = g_slist_next(uuids_list)) {
		for (l = policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list; l; l = g_slist_next(l)) {
			if (l->data == uuids_list->data) {
				char *uuid = uuids_list->data;
				if (uuid) {
					policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list =
						g_slist_remove(policy_table[DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST].list, uuid);
					g_free(uuid);
					break;
				}
			}
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
	if (!err){
		err = _bt_dpm_clear_bluetooth_uuids_from_blacklist();
	}

	return err;
}

dpm_result_t _bt_dpm_clear_bluetooth_devices_from_list(void)
{
	BT_INFO("_bt_dpm_clear_bluetooth_devices_from_list");
	dpm_result_t err = DPM_RESULT_FAIL;

	if (_bt_dpm_get_allow_bluetooth_mode() == DPM_BT_RESTRICTED)
		return DPM_RESULT_ACCESS_DENIED;

	err = _bt_dpm_clear_bluetooth_devices_from_blacklist();
	if (!err){
		err = _bt_dpm_clear_bluetooth_devices_from_blacklist();
	}

	return err;
}
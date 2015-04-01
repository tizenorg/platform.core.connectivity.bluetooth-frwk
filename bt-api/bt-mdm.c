/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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

#ifdef TIZEN_MDM_ENABLE
#include <syspopup_caller.h>
#include "bt-internal-types.h"
#include "bt-common.h"
#include "bt-mdm.h"

int _bt_launch_mdm_popup(char *mode)
{
	int ret = 0;
	bundle *b;

	b = bundle_create();
	retv_if(b == NULL, BLUETOOTH_ERROR_INTERNAL);

	bundle_add(b, "mode", mode);

	ret = syspopup_launch(BT_MDM_SYSPOPUP, b);

	if (ret < 0)
		BT_ERR("Popup launch failed: %d\n", ret);

	bundle_free(b);

	return ret;
}

bt_mdm_status_e _bt_check_mdm_handsfree_only(void)
{
	mdm_bt_allow_t mode;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	mode = mdm_get_allow_bluetooth_mode();
	mdm_release_service();

	return (mode == MDM_BT_HANDSFREE_ONLY ? BT_MDM_RESTRICTED : BT_MDM_ALLOWED);
}

#ifdef MDM_PHASE_2
bt_mdm_status_e _bt_check_mdm_pairing_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS)
		return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_pairing_state() == MDM_RESTRICTED) {
		/* Not allow to visible on */
		BT_ERR("Pairing Restricted");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_transfer_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	mdm_status = _bt_check_mdm_blacklist_uuid(BT_OPP_UUID);

	if (mdm_status == BT_MDM_NO_SERVICE || mdm_status == BT_MDM_RESTRICTED) {
		return mdm_status;
	}

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_data_transfer_state() == MDM_RESTRICTED ||
	     mdm_get_allow_bluetooth_mode() == MDM_BT_HANDSFREE_ONLY) {
		/* Not allow to visible on */
		BT_ERR("Restricted to set visible mode");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_hsp_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	mdm_status = _bt_check_mdm_blacklist_uuid(BT_HFP_AUDIO_GATEWAY_UUID);

	if (mdm_status == BT_MDM_NO_SERVICE || mdm_status == BT_MDM_RESTRICTED) {
		return mdm_status;
	}

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_profile_state(BLUETOOTH_HSP_PROFILE) == MDM_RESTRICTED ||
		mdm_get_bluetooth_profile_state(BLUETOOTH_HFP_PROFILE) == MDM_RESTRICTED) {
		/* Not allow to visible on */
		BT_ERR("Restrict hsp / hfp profile");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_a2dp_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	mdm_status = _bt_check_mdm_blacklist_uuid(BT_A2DP_UUID);

	if (mdm_status == BT_MDM_NO_SERVICE || mdm_status == BT_MDM_RESTRICTED) {
		return mdm_status;
	}

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_profile_state(BLUETOOTH_A2DP_PROFILE) == MDM_RESTRICTED) {
		/* Not allow to visible on */
		BT_ERR("Restrict a2dp profile");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_avrcp_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;


	mdm_status = _bt_check_mdm_blacklist_uuid(BT_AVRCP_TARGET_UUID);

	if (mdm_status == BT_MDM_NO_SERVICE || mdm_status == BT_MDM_RESTRICTED) {
		return mdm_status;
	}

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_profile_state(BLUETOOTH_AVRCP_PROFILE) == MDM_RESTRICTED) {
		/* Not allow to visible on */
		BT_ERR("Restrict avrcp profile");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_spp_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	mdm_status = _bt_check_mdm_blacklist_uuid(BT_SPP_UUID);

	if (mdm_status == BT_MDM_NO_SERVICE || mdm_status == BT_MDM_RESTRICTED) {
		return mdm_status;
	}

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_profile_state(BLUETOOTH_SPP_PROFILE) == MDM_RESTRICTED) {
		/* Not allow to visible on */
		BT_ERR("Restrict spp profile");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_whitelist_devices(const bluetooth_device_address_t *address)
{
	mdm_data_t *lp_data = NULL;
	GList *whitelist = NULL;
	char *device_name;
	bluetooth_device_info_t dev_info;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));

	if (bluetooth_get_bonded_device(address,
				&dev_info) != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Not paired device");
		return mdm_status;
	}

	lp_data = mdm_get_bluetooth_devices_from_whitelist();
	if (lp_data == NULL) {
		BT_ERR("No whitelist");
		mdm_release_service();
		return mdm_status;
	}

	for (whitelist = (GList *)lp_data->data; whitelist; whitelist = whitelist->next) {
		device_name = whitelist->data;

		DBG_SECURE("whitelist device name: %s", device_name);

		if (g_strcmp0(dev_info.device_name.name,
					device_name) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	mdm_free_data(lp_data);
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_whitelist_uuid(char *uuid)
{
	mdm_data_t *lp_data;
	GList *blacklist;
	char *blacklist_uuid;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS)
		return BT_MDM_NO_SERVICE;

	if (uuid == NULL)
		return mdm_status;

	lp_data = mdm_get_bluetooth_uuids_from_blacklist();
	if (lp_data == NULL) {
		BT_ERR("No blacklist");
		mdm_release_service();
		return mdm_status;
	}

	for (blacklist = (GList *)lp_data->data; blacklist; blacklist = blacklist->next) {
		blacklist_uuid = blacklist->data;

		BT_DBG("blacklist_uuid: %s", blacklist_uuid);

		if (g_strcmp0(blacklist_uuid, uuid) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	mdm_free_data(lp_data);
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_blacklist_devices(const bluetooth_device_address_t *address)
{
	mdm_data_t *lp_data;
	GList *blacklist;
	char *device_name;
	bluetooth_device_info_t dev_info;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));

	if (bluetooth_get_bonded_device(address,
				&dev_info) != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Not paired device");
		return mdm_status;
	}

	lp_data = mdm_get_bluetooth_devices_from_blacklist();
	if (lp_data == NULL) {
		BT_ERR("No blacklist");
		mdm_release_service();
		return mdm_status;
	}

	for (blacklist = (GList *)lp_data->data; blacklist; blacklist = blacklist->next) {
		device_name = blacklist->data;

		DBG_SECURE("blacklist name: %s", device_name);

		if (g_strcmp0(dev_info.device_name.name,
					device_name) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	mdm_free_data(lp_data);
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_blacklist_uuid(char *uuid)
{
	mdm_data_t *lp_data;
	GList *blacklist;
	char *blacklist_uuid;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS)
		return BT_MDM_NO_SERVICE;

	if (uuid == NULL)
		return mdm_status;

	lp_data = mdm_get_bluetooth_uuids_from_blacklist();
	if (lp_data == NULL) {
		BT_ERR("No blacklist");
		mdm_release_service();
		return mdm_status;
	}

	for (blacklist = (GList *)lp_data->data; blacklist; blacklist = blacklist->next) {
		blacklist_uuid = blacklist->data;

		BT_DBG("blacklist_uuid: %s", blacklist_uuid);

		if (g_strcmp0(blacklist_uuid, uuid) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	mdm_free_data(lp_data);
	mdm_release_service();

	return mdm_status;
}
#endif
#endif


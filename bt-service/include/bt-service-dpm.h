/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Sandeep Hattiholi <h.sandeep@samsung.com>
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

#ifndef _BT_SERVICE_DPM_H_
#define _BT_SERVICE_DPM_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
 extern "C" {
#endif


 /**
 * @brief DPM BT allowance state
 * @see
 */
 typedef enum {
	 DPM_BT_ERROR	 = -1,	 /**< bluetooth allowance error */
	 DPM_BT_ALLOWED,		 /**< bluetooth allowance allowed */
	 DPM_BT_HANDSFREE_ONLY,  /**< bluetooth allowance handsfree only */
	 DPM_BT_RESTRICTED,	 /**< bluetooth allowance restricted */
 } dpm_bt_allow_t;

 /**
 * @brief DPM API result
 * @see
 */
typedef enum _dpm_result {
	DPM_RESULT_SERVICE_NOT_ENABLED = -5,	/**< DPM API result service not enabled. */
	DPM_RESULT_ACCESS_DENIED = -4,			/**< DPM API result access denied. */
	DPM_RESULT_INVALID_PARAM = -3,			/**< DPM API result invalid parameter. */
	DPM_RESULT_NOT_SUPPORTED = -2,			/**< DPM API result not supported. */
	DPM_RESULT_FAIL		 = -1,				/**< DPM API result fail. */
	DPM_RESULT_SUCCESS	 = 0,				/**< DPM API result success. */
} dpm_result_t;

/**
 * @brief DPM Policy status
 * @see
 */
typedef enum _dpm_status {
	DPM_STATUS_ERROR	= -1,

	DPM_ALLOWED			= 0,	/**< DPM Policy status allowed. */
	DPM_RESTRICTED		= 1,	/**< DPM Policy status restricted. */

	DPM_ENABLED			= 0,	/**< DPM Policy status enabled. */
	DPm_DISABLED		= 1,	/**< DPM Policy status disabled. */

	DPM_FALSE			= 0,	/**< DPM Policy status false. */
	DPM_TRUE			= 1,	/**< DPM Policy status true. */
} dpm_status_t;

typedef enum _dpm_policy_cmd {
	/* policy-group : BLUETOOTH */
	DPM_POLICY_ALLOW_BLUETOOTH,
	DPM_POLICY_BLUETOOTH_DEVICE_RESTRICTION,
	DPM_POLICY_BLUETOOTH_UUID_RESTRICTION,
	DPM_POLICY_BLUETOOTH_DEVICES_WHITELIST,
	DPM_POLICY_BLUETOOTH_DEVICES_BLACKLIST,
	DPM_POLICY_BLUETOOTH_UUIDS_WHITELIST,
	DPM_POLICY_BLUETOOTH_UUIDS_BLACKLIST,
	DPM_POLICY_ALLOW_BLUETOOTH_OUTGOING_CALL,
	DPM_POLICY_END,
} dpm_policy_cmd_t;

struct dpm_policy {
	union {
		int value;
		GSList *list;
	};
};
typedef struct dpm_policy dpm_policy_t;

dpm_result_t _bt_dpm_set_allow_bluetooth_mode(dpm_bt_allow_t value);
dpm_bt_allow_t _bt_dpm_get_allow_bluetooth_mode(void);
dpm_result_t _bt_dpm_activate_bluetooth_device_restriction(dpm_status_t value);
dpm_status_t _bt_dpm_is_bluetooth_device_restriction_active(void);
dpm_result_t _bt_dpm_activate_bluetoooth_uuid_restriction(dpm_status_t value);
dpm_status_t _bt_dpm_is_bluetooth_uuid_restriction_active(void);
dpm_result_t _bt_dpm_add_bluetooth_devices_to_blacklist(char *device_address);
dpm_result_t _bt_dpm_add_bluetooth_devices_to_whitelist(char *device_address);
dpm_result_t _bt_dpm_add_bluetooth_uuids_to_blacklist(char *uuid);
dpm_result_t _bt_dpm_add_bluetooth_uuids_to_whitelist(char *uuid);
dpm_result_t _bt_dpm_set_allow_bluetooth_outgoing_call(dpm_status_t value);
dpm_status_t _bt_dpm_get_allow_bluetooth_outgoing_call(void);
dpm_result_t _bt_dpm_clear_bluetooth_devices_from_blacklist(void);
dpm_result_t _bt_dpm_clear_bluetooth_devices_from_whitelist(void);
dpm_result_t _bt_dpm_clear_bluetooth_uuids_from_blacklist(void);
dpm_result_t _bt_dpm_clear_bluetooth_uuids_from_whitelist(void);
GSList *_bt_dpm_get_bluetooth_devices_from_blacklist(void);
GSList *_bt_dpm_get_bluetooth_devices_from_whitelist(void);
GSList *_bt_dpm_get_bluetooth_uuids_from_blacklist(void);
GSList *_bt_dpm_get_bluetooth_uuids_from_whitelist(void);
dpm_status_t _bt_dpm_is_bluetooth_device_restriction_active(void);
dpm_status_t _bt_dpm_is_bluetooth_uuid_restriction_active(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_DPM_H_*/


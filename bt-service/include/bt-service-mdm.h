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


#ifndef _BT_SERVICE_MDM_H_
#define _BT_SERVICE_MDM_H_

#include <sys/types.h>
#include <glib.h>

#include <mdm.h>

#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BT_MDM_NO_SERVICE,
	BT_MDM_ALLOWED,
	BT_MDM_RESTRICTED
} bt_mdm_status_e;

void _bt_init_mdm_handle(void);

void _bt_deinit_mdm_handle(void);

int _bt_launch_mdm_popup(char *mode);

bt_mdm_status_e _bt_check_mdm_allow_restriction(void);

#ifdef MDM_PHASE_2
bt_mdm_status_e _bt_check_mdm_desktop_connectivity_restriction(void);

bt_mdm_status_e _bt_check_mdm_visible_restriction(void);

bt_mdm_status_e _bt_check_mdm_limited_discoverable_mode(void);

bt_mdm_status_e _bt_check_mdm_blacklist_devices(bluetooth_device_address_t *address);

bt_mdm_status_e _bt_check_mdm_blacklist_uuid(char *uuid);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_MDM_H_*/


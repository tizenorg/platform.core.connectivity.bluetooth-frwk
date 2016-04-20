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

#ifndef _BT_DPM_H_
#define _BT_DPM_H_

#include <sys/types.h>
#include <glib.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BT_DPM_NO_SERVICE,
	BT_DPM_ALLOWED,
	BT_DPM_RESTRICTED
} bt_dpm_status_e;

typedef enum {
	BT_DPM_PAIRING,
	BT_DPM_HF_ONLY,
	BT_DPM_DESKTOP,
	BT_DPM_ADDRESS,
	BT_DPM_UUID,
	BT_DPM_OPP,
	BT_DPM_HSP,
	BT_DPM_A2DP,
	BT_DPM_AVRCP,
	BT_DPM_SPP,
} bt_dpm_service_e;

int _bt_check_dpm(int service, void *param);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_DPM_H_*/
#endif /* #ifdef TIZEN_DPM_ENABLE */

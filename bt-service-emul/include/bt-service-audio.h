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


#ifndef _BT_SERVICE_AUDIO_H_
#define _BT_SERVICE_AUDIO_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BT_AUDIO_HSP = 0x01,
	BT_AUDIO_A2DP,
	BT_AUDIO_ALL,
	BT_AVRCP,
	BT_AUDIO_A2DP_SOURCE
} bt_audio_type_t;

int _bt_audio_connect(int request_id, int type,
		bluetooth_device_address_t *device_address,
		GArray **out_param1);

int _bt_audio_disconnect(int request_id, int type,
		bluetooth_device_address_t *device_address,
		GArray **out_param1);

int _bt_hf_connect(int request_id,
		bluetooth_device_address_t *device_address,
		GArray **out_param1);

int _bt_hf_disconnect(int request_id,
		bluetooth_device_address_t *device_address,
		GArray **out_param1);


int _bt_audio_set_content_protect(gboolean status);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_AUDIO_H_*/


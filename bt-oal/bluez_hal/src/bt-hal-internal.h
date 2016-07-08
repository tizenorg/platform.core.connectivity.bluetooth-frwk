/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *              http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BT_HAL_INTERNAL_H_
#define _BT_HAL_INTERNAL_H_

#include <glib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
        BT_HAL_MANAGER_EVENT = 0x01,
        BT_HAL_ADAPTER_EVENT,
        BT_HAL_LE_ADAPTER_EVENT,
        BT_HAL_DEVICE_EVENT,
        BT_HAL_HID_EVENT,
        BT_HAL_NETWORK_EVENT,
        BT_HAL_HEADSET_EVENT,
        BT_HAL_AVRCP_EVENT,
        BT_HAL_OPP_CLIENT_EVENT,
        BT_HAL_OPP_SERVER_EVENT,
        BT_HAL_PBAP_CLIENT_EVENT,
        BT_HAL_RFCOMM_CLIENT_EVENT,
        BT_HAL_RFCOMM_SERVER_EVENT,
        BT_HAL_AGENT_EVENT,
        BT_HAL_OBJECT_MANAGER_EVENT,
        BT_HAL_MEDIA_TRANSFER_EVENT,
        BT_HAL_HF_AGENT_EVENT,
        BT_HAL_AVRCP_CONTROL_EVENT,
        BT_HAL_A2DP_SOURCE_EVENT,
        BT_HAL_HID_DEVICE_EVENT,
        /* Will be added */
} bt_hal_event_type_t;

/* Profile states matched to btd_service_state_t of bluez service.h */
typedef enum {
	BT_HAL_PROFILE_STATE_UNAVAILABLE,
	BT_HAL_PROFILE_STATE_DISCONNECTED,
	BT_HAL_PROFILE_STATE_CONNECTING,
	BT_HAL_PROFILE_STATE_CONNECTED,
	BT_HAL_PROFILE_STATE_DISCONNECTING,
} bt_hal_profile_state_t;

/* UUIDs */
#define HID_UUID                "00001124-0000-1000-8000-00805f9b34fb"

/* TODO  More declarations to be added in subsequent patches */
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_INTERNAL_H_ */

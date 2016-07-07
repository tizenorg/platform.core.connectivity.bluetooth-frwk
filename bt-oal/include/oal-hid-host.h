/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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

#ifndef _OAL_HID_HOST_H_
#define _OAL_HID_HOST_H_

#include <glib.h>
#include <sys/types.h>

#include <oal-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OAL_SMART_RC_FEATURE_REPORT_ID	0x03

/**
 * @brief HID Vendor specific report callback
*/
typedef void (*hid_report_callback)(bt_address_t *address, uint8_t* rpt_data, int rpt_size);

/**
 * @brief Enable HID Host Feature
 *
 * @remarks  HID mouse/keyboard/RC will be able to connect.
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre OAL API must be initialized with oal_bt_init().
 *
 * @see  hid_disable()
 */
oal_status_t hid_enable(void);


/**
 * @brief Disable HID Host Feature
 *
 * @remarks  HID mouse/keyboard/RC will not be able to connect.
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre HID host should be enabled with hid_enable().
 *
 * @see  hid_enable()
 */
oal_status_t hid_disable(void);

/**
 * @brief Initiate connection with an HID device
 *
 * @details  Result will be notified through an OAL event
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre HID host should be enabled with hid_enable().
 *
 * @see  OAL_EVENT_HID_CONNECTED
 */
oal_status_t hid_connect(bt_address_t *address);

/**
 * @brief Remove a connection with an HID device
 *
 * @details  Result will be notified through an OAL event
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre HID host should be connected with a device.
 *
 * @see  OAL_EVENT_HID_DISCONNECTED
 */
oal_status_t hid_disconnect(bt_address_t * address);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _OAL_HID_HOST_H_ */

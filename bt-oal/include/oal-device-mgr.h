/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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

#ifndef _OAL_DEVICE_MGR_H_
#define _OAL_DEVICE_MGR_H_

#include <glib.h>
#include <sys/types.h>

#include <oal-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Connection type
 *
 * @see  device_create_bond
 */

typedef enum {
        CONN_TYPE_DEFAULT = 0xFF, /* represents that connection type can both BR/EDR and LE */
        CONN_TYPE_BREDR = 0x00,
        CONN_TYPE_LE = 0x01,
} connection_type_e;

/**
 * @brief Request remote device attributes
 *
 * @details Attibutes such as name, vidpid, bond state etc are requested. remote_device_t is provided
 *		   with OAL_EVENT_DEVICE_PROPERTIES
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see  OAL_EVENT_DEVICE_PROPERTIES
 * @see  remote_device_t
 */
oal_status_t device_query_attributes(bt_address_t * addr);

/**
 * @brief Set alias for remote device
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see  remote_device_t
 */
oal_status_t device_set_alias(bt_address_t * addr, char * alias);


/**
 * @brief Initiate bonding with remote device
 *
 * @details Based on IO capabilties of 2 devices, different events can be generated
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see  OAL_EVENT_DEVICE_PIN_REQUEST
 * @see  OAL_EVENT_DEVICE_PASSKEY_ENTRY_REQUEST
 * @see  OAL_EVENT_DEVICE_PASSKEY_CONFIRMATION_REQUEST
 * @see  OAL_EVENT_DEVICE_PASSKEY_DISPLAY
 * @see  OAL_EVENT_DEVICE_SSP_CONSENT_REQUEST
 * @see  OAL_EVENT_DEVICE_BONDING_SUCCESS
 * @see  OAL_EVENT_DEVICE_BONDING_FAILED
 */
oal_status_t device_create_bond(bt_address_t * addr, connection_type_e transport);

/**
 * @brief Cancel already in-progress bonding procedure
 *
 * @details Based on current progress different events can be recieved.
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Bonding must be in progress by calling device_create_bond()
 *
 * @see  OAL_EVENT_DEVICE_BONDING_SUCCESS
 * @see  OAL_EVENT_DEVICE_BONDING_FAILED
 * @see  OAL_EVENT_DEVICE_BONDING_REMOVED
 */
oal_status_t device_stop_bond(bt_address_t * addr);


/**
 * @brief Remove the already created Bond with remote device
 *
 * @details Based on current progress different events can be recieved.
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Bond should exist
 *
 * @see  OAL_EVENT_DEVICE_BONDING_REMOVED
 */
oal_status_t device_destroy_bond(bt_address_t * addr);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_DEVICE_MGR_H_*/


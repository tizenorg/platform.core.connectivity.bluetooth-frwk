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

#ifndef _OAL_ADAPTER_MGR_H_
#define _OAL_ADAPTER_MGR_H_

#include <glib.h>
#include <sys/types.h>

#include <oal-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OAL_BT_ADDRESS_STRING_SIZE 18


/**
 * @brief Enable BT chip for usage.
 *
 * @remarks Other API can only be used after successful event. \n
 *
 * @details EVENT: OAL_EVENT_ADAPTER_ENABLED/OAL_EVENT_ADAPTER_DISABLED
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre OAL API must be initialized with oal_bt_init().
 *
 * @see  adapter_disable()
 */
oal_status_t adapter_enable(void);


/**
 * @brief Disable Adapter.
 *
 * @remarks  Disables the BT stack and chip. After this, no OAL API is valid except "adapter_enable()"
 *
 * @details EVENT: OAL_EVENT_ADAPTER_DISABLED
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS	Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see  adapter_enable()
 */
oal_status_t adapter_disable(void);

/**
 * @brief Get local BT chip address
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see OAL_EVENT_ADAPTER_PROPERTY_ADDRESS
 */
oal_status_t adapter_get_address(void);

/**
 * @brief Get local BT version
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see OAL_EVENT_ADAPTER_PROPERTY_VERSION
 */
oal_status_t adapter_get_version(void);

/**
 * @brief Get local BT chip name
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see OAL_EVENT_ADAPTER_PROPERTY_NAME
 */
oal_status_t adapter_get_name(void);

/**
 * @brief Sets output variable to TRUE if adapter is discoverable & connectable.
 */
oal_status_t adapter_is_discoverable(int *p_discoverable);

/**
 * @brief Sets output variable to TRUE if adapter is either discoverable or connectable.
 */
oal_status_t adapter_is_connectable(int *p_connectable);

/**
 * @brief Sets output variable to value of current discoverable timeout.
 */
oal_status_t adapter_get_discoverable_timeout(int *p_timeout);

/**
 * @brief Get List of UUIDs for services supported
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre Adapter must be enabled with adapter_enable() followed by OAL_EVENT_ADAPTER_ENABLED
 *
 * @see OAL_EVENT_ADAPTER_PROPERTY_SERVICES
 */
oal_status_t adapter_get_service_uuids(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_ADAPTER_MGR_H_*/


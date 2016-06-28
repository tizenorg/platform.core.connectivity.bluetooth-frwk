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

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_ADAPTER_MGR_H_*/


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

#ifndef _OAL_HARDWARE_H_
#define _OAL_HARDWARE_H_

#include <sys/types.h>
#include <oal-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FOREACH_TYPE(FUNC)	\
	FUNC(BT_CHIP_TYPE_PLATFORM,		"Tizen Plaftrom BT Chip")	\
	FUNC(BT_CHIP_TYPE_UNKNOWN,			"Unknown Chip Type")	\

#define GENERATE_TYPE_ENUM(ENUM, STRING) ENUM,
#define GENERATE_TYPE_STRING(ENUM, STRING) STRING,

typedef enum {
	FOREACH_TYPE(GENERATE_TYPE_ENUM)
} bt_chip_type_t;

/**
 * @brief Upgrade BT Chip Firmware.
 *
 * @remarks BT Chip will be reset and oal will start again after upgrade. \n
 *
 * @details EVENT: N/A. as this is a blocking call
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise OAL_STATUS_INTERNAL_ERROR.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *         #OAL_STATUS_INTERNAL_ERROR  Failure
 *
 * @pre N/A, as this is related to hardware, oal need not be initialised.
 *
 * @see  -
 */
oal_status_t hw_chip_firmware_update(void);

/**
 * @brief Check whether BT chip is connected or not.
 *
 * @remarks BT Chip state. \n
 *
 * @details EVENT: N/A.
 *
 * @return TRUE if chip connected, otherwise FALSE.
 * @retval #TRUE  Successful
 *
 * @pre N/A, as this is related to hardware, oal need not be initialised.
 *
 * @see  -
 */
int hw_is_chip_connected(void);

/**
 * @brief Get Connected BT Chip Type. (Single/Combo)
 *
 * @remarks BT Chip Type. \n
 *
 * @details EVENT: N/A
 *
 * @return BT_CHIP_TYPE_SINGLE if Single BT Chip connected,
 *         BT_CHIP_TYPE_COMBO if BT Combo Chip connected,
 *         otherwise BT_CHIP_TYPE_UNKNOWN on error.
 * @retval #BT_CHIP_TYPE_SINGLE  Single-BT Chip
 *
 * @pre N/A, as this is related to hardware, oal need not be initialised.
 *
 * @see  -
 */
bt_chip_type_t hw_get_chip_type(void);

/**
 * @brief Get driver state.
 *
 * @remarks BT Module State \n
 *
 * @details EVENT: N/A
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise OAL_STATUS_INTERNAL_ERROR.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *         #OAL_STATUS_INTERNAL_ERROR  Failure
 *
 * @pre N/A, as this is related to hardware, oal need not be initialised.
 *
 * @see  -
 */
oal_status_t hw_is_module_ready(void);

/**
 * @brief Firmware Upgrade Required Status
 *
 * @remarks whether upgrade firmwares required or not \n
 * 			*is_required = TRUE, if upgrade required, else FALSE
 *
 * @details EVENT: N/A
 *
 * @return OAL_STATUS_SUCCESS
 *
 * @pre N/A
 *
 * @see  N/A
 */
oal_status_t hw_is_fwupgrade_required(gboolean *is_required);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_HARDWARE_H_*/


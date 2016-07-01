/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*			   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#ifndef _OAL_MANAGER_H_
#define _OAL_MANAGER_H_

#include <glib.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BT_VERSION_STR_LEN_MAX       30 /**< This specifies maximum adapter version string length */

#define BT_DEVICE_NAME_LENGTH_MAX       248 /**< This specifies maximum device name length */

#define BT_ADDRESS_BYTES_NUM            6 /**< This specifies bluetooth device address length */

#define OAL_UUID_MAX_LENGTH				16/**< This specifies ble service UUID Length */

#define BLE_ADV_DATA_LENGTH            62 /**< This specifies Advertising Data Length */

#define BT_ADDRESS_STR_LEN 				18 /**< BT address String length> */

#define BT_MAX_SERVICES_FOR_DEVICE  60 /**< This specifies the Maximum UUID Id mentioned in bta_api.h>*/

#define BLUETOOTH_UUID_STRING_MAX       50

typedef void (*oal_event_callback)(int event, gpointer event_data, gsize size);

typedef struct {
	unsigned char addr[BT_ADDRESS_BYTES_NUM];
} bt_address_t;

typedef struct {
	char name[BT_DEVICE_NAME_LENGTH_MAX + 1];
} bt_name_t;

typedef enum {
	OAL_STATUS_SUCCESS,
	/* Generic */
	OAL_STATUS_INTERNAL_ERROR,
	OAL_STATUS_NOT_READY,
	OAL_STATUS_BUSY,
	OAL_STATUS_INVALID_PARAM,
	OAL_STATUS_RMT_DEVICE_DOWN,
	OAL_STATUS_AUTH_FAILED,
	OAL_STATUS_NOT_SUPPORT, //For APIs not supported
	OAL_STATUS_ALREADY_DONE,
	OAL_STATUS_PENDING,
	OAL_STATUS_CONN_TIMEOUT,
	/* HID */
	OAL_STATUS_HID_FAILED_MOUSE
} oal_status_t;



/* NOTE: If anything changes in bt_service_id_t enum definition of Bluedroid header, change here too */
typedef enum {
	A2DP_SRC_SERVICE_ID = 3,
	AVRCP_CT_SERVICE_ID = 9,
	A2DP_SERVICE_ID = 18,
	AVRCP_SERVICE_ID = 19,
	HID_SERVICE_ID = 20
} oal_service_t;

/** Bluetooth 128-bit UUID */
typedef struct {
   uint8_t uuid[16];
} oal_uuid_t;

typedef oal_uuid_t service_uuid_t;

typedef enum {
	DEV_TYPE_BREDR,
	DEV_TYPE_BLE_ONLY,
	DEV_TYPE_DUAL
} device_type_t;


typedef struct {
	char name[BT_DEVICE_NAME_LENGTH_MAX+1];
	bt_address_t address;
	int cod;
	int rssi;
	int vid;
	int pid;
	int is_bonded;
	int is_connected;
	device_type_t type;
	int uuid_count;
	oal_uuid_t uuid[BT_MAX_SERVICES_FOR_DEVICE];
	int is_trusted;
} remote_device_t;

/**
 * @brief Initializes OAL layer
 *
 * @remarks Other API can only be used after successful return. \n
 *
 * @details EVENT: N/A
 *
 * @return OAL_STATUS_SUCCESS on success, otherwise a non-zero error value.
 * @retval #OAL_STATUS_SUCCESS  Successful
 *
 * @pre N/A
 *
 * @see  oal_bt_deinit()
 */
oal_status_t oal_bt_init(oal_event_callback cb);

/**
 * @brief Deinitializes OAL Layer
 *
 * @remarks Other API can only be used after oal_bt_init done again. \n
 *
 * @details EVENT: N/A
 *
 * @return void.
 * @retval void
 *
 * @pre N/A
 *
 * @see  oal_bt_init()
 */
void oal_bt_deinit(void);

/**
 * @brief Initialize Stack lib based on chip
 *
 * @remarks Other API can only be used after oal_lib_init done. \n
 *
 * @details EVENT: OAL_EVENT_OAL_INITIALISED_SUCCESS, OAL_EVENT_OAL_INITIALISED_FAILED
 *
 * @return bool.
 * @retval bool
 *
 * @pre N/A
 *
 * @see  N/A
 */
gboolean oal_lib_init(gpointer data);

/**
 * @brief Set Debug Mode Flag to TRUE
 *
 * @remarks OAL will run in exclusive mode, no processing of api-call and no event sending. \n
 *
 * @details EVENT: N/A
 *
 * @return void
 * @retval void
 *
 * @pre N/A
 *
 * @see  oal_get_debug_mode()
 */
void oal_set_debug_mode(gboolean mode);

/**
 * @brief Set Debug Mode Flag
 *
 * @remarks To check whether Debug mode is running. \n
 *
 * @details EVENT: N/A
 *
 * @return TRUE if debug mode is on, otherwise FALSE
 * @retval #TRUE  Successful
 *
 * @pre N/A
 *
 * @see  oal_set_debug_mode()
 */
gboolean oal_get_debug_mode(void);

#ifdef OAL_DEBUG
/**
 * @brief Register the debug mode event catcher
 *
 * @remarks handles the incoming events and passes to debug handler. \n
 *
 * @details EVENT: N/A
 *
 * @return void
 * @retval void
 *
 * @pre N/A
 *
 * @see  N/A
 */
void server_event_catch_register(oal_event_callback dbg_cb);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_HARDWARE_H_*/


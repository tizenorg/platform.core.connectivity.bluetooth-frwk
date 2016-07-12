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

#include <stdint.h>

#ifndef _OAL_EVENT_H_
#define _OAL_EVENT_H_

#include <glib.h>
#include <sys/types.h>

#include <oal-manager.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FOREACH_EVENT(EVENT) \
	EVENT(OAL_EVENT_ADAPTER_ENABLED)	\
	EVENT(OAL_EVENT_ADAPTER_DISABLED)	\
	EVENT(OAL_EVENT_ADAPTER_HARDWARE_ERROR) \
	EVENT(OAL_EVENT_ADAPTER_PROPERTY_ADDRESS)			/* bt_address_t */	\
	EVENT(OAL_EVENT_ADAPTER_PROPERTY_NAME)				/* char string */\
	EVENT(OAL_EVENT_ADAPTER_PROPERTY_VERSION)			/* char string */\
	EVENT(OAL_EVENT_ADAPTER_PROPERTY_SERVICES)			/* event_adapter_services_t */\
	EVENT(OAL_EVENT_ADAPTER_MODE_NON_CONNECTABLE)	\
	EVENT(OAL_EVENT_ADAPTER_MODE_CONNECTABLE)	\
	EVENT(OAL_EVENT_ADAPTER_MODE_DISCOVERABLE)	\
	EVENT(OAL_EVENT_ADAPTER_MODE_DISCOVERABLE_TIMEOUT)	/* uint32_t */\
	EVENT(OAL_EVENT_ADAPTER_BONDED_DEVICE_LIST) 		/* event_device_list_t */\
	EVENT(OAL_EVENT_ADAPTER_INQUIRY_STARTED)	\
	EVENT(OAL_EVENT_ADAPTER_INQUIRY_RESULT_BREDR_ONLY)	/* event_dev_found_t */\
	EVENT(OAL_EVENT_ADAPTER_INQUIRY_RESULT_BLE) 		/* event_ble_dev_found_t */\
	EVENT(OAL_EVENT_ADAPTER_INQUIRY_FINISHED)	\
	EVENT(OAL_EVENT_DEVICE_PROPERTIES)					/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_NAME)						/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_VIDPID)						/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_SERVICES)					/* event_dev_services_t */\
	EVENT(OAL_EVENT_DEVICE_PIN_REQUEST) 				/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_PASSKEY_ENTRY_REQUEST)		/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_PASSKEY_CONFIRMATION_REQUEST)/* event_dev_passkey_t */\
	EVENT(OAL_EVENT_DEVICE_PASSKEY_DISPLAY) 			/* event_dev_passkey_t */\
	EVENT(OAL_EVENT_DEVICE_SSP_CONSENT_REQUEST) 		/* remote_device_t */\
	EVENT(OAL_EVENT_DEVICE_BONDING_SUCCESS) 			/* bt_address_t */\
	EVENT(OAL_EVENT_DEVICE_BONDING_REMOVED) 			/* bt_address_t */\
	EVENT(OAL_EVENT_DEVICE_BONDING_FAILED)				/* event_dev_bond_failed_t */\
	EVENT(OAL_EVENT_DEVICE_AUTHORIZE_REQUEST)			/* event_dev_authorize_req_t */\
	EVENT(OAL_EVENT_DEVICE_ACL_CONNECTED)				/* bt_address_t */\
	EVENT(OAL_EVENT_DEVICE_ACL_DISCONNECTED)			/* bt_address_t */\
	EVENT(OAL_EVENT_OAL_INITIALISED_SUCCESS)		/* OAL Initialisation event */	\
	EVENT(OAL_EVENT_OAL_INITIALISED_FAILED)			/* OAL Initialisation event */	\
	EVENT(OAL_EVENT_HID_CONNECTED)						/* event_hid_conn_t */\
	EVENT(OAL_EVENT_HID_DISCONNECTED)					/* event_hid_conn_t */\
	EVENT(OAL_EVENT_SOCKET_OUTGOING_CONNECTED)                 /* RFCOMM */  \
	EVENT(OAL_EVENT_SOCKET_DISCONNECTED)            /* RFCOMM */  \
	EVENT(OAL_EVENT_END)                                /* End of event*/\


#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

typedef enum EVENT_ENUM {
    FOREACH_EVENT(GENERATE_ENUM)
} oal_event_t;

#ifdef _OAL_EVENT_DISPATCHER_C_
const char *str_event[] = {
    FOREACH_EVENT(GENERATE_STRING)
};
#else
extern const char *str_event[];
#endif

/*********Datastructures for Local Adapter events ******************/
typedef struct {
	int num;
	bt_address_t devices[0];
} event_device_list_t;

typedef struct {
	remote_device_t device_info;
	uint8_t adv_data[62];
	int adv_len;
} event_ble_dev_found_t;

typedef struct {
	remote_device_t device_info;
} event_dev_found_t;

typedef struct {
	int num;
	service_uuid_t service_list[0];
} event_adapter_services_t;

typedef struct {
	remote_device_t device_info;
	uint8_t adv_data[62];
	int adv_len;
} event_dev_properties_t;

/*********Datastructures for Remote Device events ******************/
typedef struct {
	bt_address_t address;
	int num;
	service_uuid_t service_list[0];
} event_dev_services_t;

typedef struct {
	remote_device_t device_info;
	uint32_t pass_key;
} event_dev_passkey_t;

typedef struct {
	bt_address_t address;
	oal_service_t service_id;
} event_dev_authorize_req_t;

typedef struct {
	bt_address_t address;
	oal_status_t status;
} event_dev_conn_status_t;

typedef event_dev_conn_status_t event_dev_bond_failed_t;

/*********Datastructures for HID callback******************/
/* HID :: connection state callback response data */
typedef struct {
	bt_address_t address;
	oal_status_t status;
} event_hid_conn_t;

/********* Datastructures for Socket event ******************/
/* SOCKET:: socket outgoing client connection event data */
typedef struct {
	int fd;			/**< FD of Outgoing client */
	int sock_type;		/**< Type of socket */
	bt_address_t address;	/**< Address of remote server */
} event_socket_client_conn_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_EVENT_H_*/


/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __BT_HTTPPROXY_H__
#define __BT_HTTPPROXY_H__

#ifdef HPS_FEATURE

#define BT_HPS_LE_ADAPTER_INTERFACE	"org.bluez.Adapter1"
#define BT_HPS_LE_ADAPTER_PATH "/org/projectx/bt/le/adapter"

#define BT_HPS_SERVICE_NAME "org.projectx.httpproxy"
#define BT_HPS_OBJECT_PATH "/org/projectx/httpproxy"
#define BT_HPS_INTERFACE_NAME "org.projectx.httpproxy_service"

#define BT_HPS_CHAR_INTERFACE "org.bluez.GattCharacteristic1"
#define BT_HPS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

#define BLE_ENABLED "LeEnabled"
#define BLE_DISABLED "LeDisabled"
#define PROPERTIES_CHANGED "PropertiesChanged"

/* 512 is the max uri supported by http spec */
#define MAX_URI_LENGTH	512
/* 512 is the max Header length supported by http spec */
#define MAX_HEADER_LENGTH	512
/* 512 is the max entity body length supported by http spec */
#define MAX_ENTITY_LENGTH	512


/* HTTP Control Point Commands
   OPTIONS, TRACE, CONNECT are not supported
*/
enum {
	HTTP_REQUEST_NONE = 0x00,
	HTTP_GET_REQUEST = 0x01,
	HTTP_HEAD_REQUEST = 0x02,
	HTTP_POST_REQUEST = 0x03,
	HTTP_PUT_REQUEST = 0x04,
	HTTP_DELETE_REQUEST = 0x05,
	HTTPS_GET_REQUEST = 0x06,
	HTTPS_HEAD_REQUEST = 0x07,
	HTTPS_POST_REQUEST = 0x08,
	HTTPS_PUT_REQUEST = 0x09,
	HTTPS_DELETE_REQUEST = 0x0A,
	HTTP_REQUEST_CANCEL = 0x0B,
	HTTP_REQUEST_MAX = HTTP_REQUEST_CANCEL
};

enum {
	DS_NONE = 0x00,
	DS_HEADER_RECEIVED = 0x01,
	DS_HEADER_TRUNCATED = 0x02,
	DS_BODY_RECEIVED = 0x03,
	DS_BODY_TRUNCATED = 0x04,
	DS_MAX = DS_BODY_TRUNCATED
};

typedef enum http_request_state_tag {
	HTTP_REQ_STATE_IDLE = 0x00,
	HTTP_REQ_STATE_EXECUTED = HTTP_REQ_STATE_IDLE,
	HTTP_REQ_STATE_INPROGRESS = 0x01,
} http_request_state;


/* HPS UUIDs. defined by SIG */
#define HPS_UUID "1823"
#define HTTP_URI_UUID "2ab6"
#define HTTP_HDR_UUID "2ab7"
#define HTTP_ENTITY_UUID "2ab9"
#define HTTP_CP_UUID "2aba"
#define HTTP_STATUS_UUID "2ab8"
#define HTTP_SECURITY_UUID "2abb"
/* CCC descriptor UUID is predefined by SIG */
#define HTTP_STATUS_CCC_DESC_UUID "2902"

void _bt_hps_exit(void);
int _bt_hps_prepare_httpproxy(void);
int _bt_hps_set_advertising_data(void);


#endif

#endif

/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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

#ifndef _BLUETOOTH_RFCOMM_API_H_
#define _BLUETOOTH_RFCOMM_API_H_

#include "bluetooth-api-common.h"

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#define RFCOMM_MAX_CONN 5
#define RFCOMM_ADDRESS_STRING_LEN 24
typedef struct {
	int id;
	int server_sock_fd;
	GIOChannel *server_io_channel;
	guint server_event_src_id;
	gboolean is_listen;	/*server listen*/
	char *uds_name;	/*proxy name*/
	char *file_name;	/*device name*/

	int client_sock_fd;
	bluetooth_device_address_t device_addr;
	GIOChannel *client_io_channel;
	guint client_event_src_id;
} rfcomm_server_t;
static rfcomm_server_t rfcomm_server[RFCOMM_MAX_CONN];

typedef struct {
	int id;
	int sock_fd;
	GIOChannel *io_channel;
	guint event_src_id;
	char *dev_node_name;
	bluetooth_device_address_t device_addr;
} rfcomm_client_t;

static rfcomm_client_t rfcomm_client[RFCOMM_MAX_CONN] = { { 0, }, };

struct connect_param_t {
	char *remote_device_path;
	char *connect_uuid;
	bluetooth_device_address_t remote_bt_address;
};

#ifdef __cplusplus
}
#endif				/* __cplusplus */

#endif				/*_BLUETOOTH_RFCOMM_API_H_*/

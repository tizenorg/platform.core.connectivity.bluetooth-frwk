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

#ifndef BLUETOOTH_OBEX_SERVER_API_H
#define BLUETOOTH_OBEX_SERVER_API_H

#include "bluetooth-api-common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define FILE_PATH_LEN (4096 + 10)

#define OBEX_SERVER_SERVICE "org.openobex"
#define OBEX_SERVER_MANAGER "org.openobex.Manager"
#define BT_OBEX_SERVICE_INTERFACE "org.openobex.Agent"
#define OBEX_SERVER_AGENT_PATH "/org/bluez/obex_server_agent"
#define BT_INVALID_PATH "/Invalid/Path"
#define BT_OBEX_AGENT_ERROR (__bt_obex_agent_error_quark())

typedef enum {
	BT_OBEX_AGENT_ERROR_REJECT,
	BT_OBEX_AGENT_ERROR_CANCEL,
	BT_OBEX_AGENT_ERROR_TIMEOUT,
} bt_obex_agent_error_t;

typedef struct {
	DBusGConnection *bus;
	void *obex_server_agent;
	DBusGProxy *obex_proxy;
	DBusGMethodInvocation *reply_context;
	char *filename;
	char *transfer_path;
	char *device_name;
 	int file_size;
} obex_server_info_t;

typedef enum {
	BT_OBEX_AGENT_ACCEPT,
	BT_OBEX_AGENT_REJECT,
	BT_OBEX_AGENT_CANCEL,
	BT_OBEX_AGENT_TIMEOUT,
} bt_obex_server_accept_type_t;

typedef struct {
	DBusGProxy *transfer_proxy;
	char *filename;
	char *path;
	char *type;
	char *device_name;
 	int transfer_id;
	int file_size;
} transfer_info_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* BLUETOOTH_OBEX_SERVER_API_H */


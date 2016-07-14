/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Kumar Rai <a.rai@samsung.com>
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

#ifndef __BT_SERVICE_SOCKET_H__
#define __BT_SERVICE_SOCKET_H__

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOCK_TYPE_RFCOMM 0
#define SOCK_TYPE_SCO 1
#define SOCK_TYPE_L2CAP	2

typedef void (*bt_socket_client_conn_cb) (int result, int sock_fd, char *address, char *uuid, int chan);

int _bt_socket_init(void);
void _bt_socket_deinit(void);

int _bt_socket_client_connect(int sock_type, char *address,
		char *remote_uuid, int channel, bt_socket_client_conn_cb cb);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __BT_SERVICE_SOCKET_H__ */
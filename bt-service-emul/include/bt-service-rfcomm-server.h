/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef _BT_SERVICE_RFCOMM_SERVER_H_
#define _BT_SERVICE_RFCOMM_SERVER_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_RFCOMM_SERVER_H_*/

int _bt_rfcomm_create_socket(char *sender, char *uuid);

int _bt_rfcomm_remove_socket(int socket_fd);

int _bt_rfcomm_listen(int socket_fd, int max_pending, gboolean is_native);

int _bt_rfcomm_is_uuid_available(char *uuid, gboolean *available);

int _bt_rfcomm_accept_connection(void);

int _bt_rfcomm_reject_connection(void);


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


#ifndef _BT_SERVICE_OPP_CLIENT_H_
#define _BT_SERVICE_OPP_CLIENT_H_

#include <glib.h>
#include <sys/types.h>
#include <gio/gio.h>
#include "bluetooth-api.h"
#include "bt-internal-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char path[BT_FILE_PATH_MAX];
} bt_file_path_t;

int _bt_opp_client_push_files(int request_id, GDBusMethodInvocation *context,
				bluetooth_device_address_t *remote_address,
				char **file_path, int file_count);

int _bt_opp_client_cancel_push(void);

int _bt_opp_client_cancel_all_transfers(void);

int _bt_opp_client_is_sending(gboolean *sending);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_OPP_CLIENT_H_*/


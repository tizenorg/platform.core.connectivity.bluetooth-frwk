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


#ifndef _BT_SERVICE_NETWORK_H_
#define _BT_SERVICE_NETWORK_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

int _bt_network_activate(void);

int _bt_network_deactivate(void);

int _bt_network_connect(int request_id, int role,
		bluetooth_device_address_t *device_address);

int _bt_network_disconnect(int request_id,
		bluetooth_device_address_t *device_address);

int _bt_network_server_disconnect(int request_id,
		bluetooth_device_address_t *device_address);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_NETWORK_H_*/


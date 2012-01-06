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

#ifndef __BLUETOOTH_NETWORK_API_H
#define __BLUETOOTH_NETWORK_API_H

#ifdef __cplusplus
extern "C" {
#endif

#define BLUEZ_NET_SERVER_PATH "org.bluez.NetworkServer"
#define BLUEZ_NET_CLIENT_PATH "org.bluez.Network"
#define NAP_UUID_NAME "nap"
#define GN_UUID_NAME "gn"
#define PANU_UUID_NAME "panu"
#define NET_BRIDGE_INTERFACE "pan0"

void _bluetooth_network_server_add_signal(void);
void _bluetooth_network_server_remove_signal(void);

void _bluetooth_network_client_add_filter(void);
void _bluetooth_network_client_remove_filter(void);

#ifdef __cplusplus
}
#endif
#endif				/* __BLUETOOTH_NETWORK_API_H */

/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
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

#ifndef _BT_SERVICE_CORE_DEVICE_H_
#define _BT_SERVICE_CORE_DEVICE_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void _bt_device_state_handle_callback_set_request(void);

int _bt_device_get_bonded_device_info(bluetooth_device_address_t *addr);

int _bt_set_alias(bluetooth_device_address_t *device_address, const char *alias);

int _bt_bond_device(bluetooth_device_address_t *device_address,
                unsigned short conn_type, GArray **out_param1);

int _bt_unbond_device(bluetooth_device_address_t *device_address,
                        GArray **out_param1);

gboolean _bt_is_bonding_device_address(const char *address);

gboolean _bt_device_is_bonding(void);

gboolean _bt_device_is_pairing(void);

gboolean _bt_is_bonding_device_address(const char *address);

void _bt_set_autopair_status_in_bonding_info(gboolean is_autopair);

int _bt_passkey_reply(const char *passkey, gboolean authentication_reply);

int _bt_passkey_confirmation_reply(gboolean confirmation_reply);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_CORE_DEVICE_H_*/


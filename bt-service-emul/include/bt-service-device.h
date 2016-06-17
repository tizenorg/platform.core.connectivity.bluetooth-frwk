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


#ifndef _BT_SERVICE_DEVICE_H_
#define _BT_SERVICE_DEVICE_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

int _bt_bond_device(int request_id,
		bluetooth_device_address_t *device_address,
		unsigned short conn_type, GArray **out_param1);

int _bt_cancel_bonding(void);

int _bt_passkey_reply(const char *passkey, gboolean authentication_reply);

int _bt_passkey_confirmation_reply(gboolean confirmation_reply);

int _bt_unbond_device(int request_id,
			bluetooth_device_address_t *device_address,
			GArray **out_param1);

int _bt_cancel_search_device(void);

int _bt_search_device(int request_id,
			bluetooth_device_address_t *device_address);

int _bt_set_alias(bluetooth_device_address_t *device_address,
				      const char *alias);

int _bt_set_authorization(bluetooth_device_address_t *device_address,
				      gboolean authorize);

int _bt_is_gatt_connected(bluetooth_device_address_t *device_address,
			gboolean *is_connected);

int _bt_is_device_connected(bluetooth_device_address_t *device_address,
			int connection_type, gboolean *is_connected);

int _bt_get_connected_link(bluetooth_device_address_t *device_address,
			bluetooth_connected_link_t *connected);

int _bt_set_pin_code(bluetooth_device_address_t *device_address,
			bluetooth_device_pin_code_t *pin_code);

int _bt_unset_pin_code(bluetooth_device_address_t *device_address);

int _bt_get_device_pin_code(const char *address, char *pin_code);

gboolean _bt_is_device_creating(void);

int _bt_connect_le_device(int request_id,
		const bluetooth_device_address_t *bd_addr,
		gboolean auto_connect);

int _bt_disconnect_le_device(int request_id,
		const bluetooth_device_address_t *bd_addr);

int _bt_enable_rssi(bluetooth_device_address_t *bd_addr, int link_type,
		int low_threshold, int in_range_threshold, int high_threshold);

int _bt_get_rssi_strength(bluetooth_device_address_t *bd_addr,
		int link_type);

int _bt_le_conn_update(unsigned char *device_address,
				guint16 interval_min, guint16 interval_max,
				guint16 latency, guint16 time_out);

int _bt_get_le_connection_parameter(bluetooth_le_connection_mode_t mode,
		bluetooth_le_connection_param_t *param);

int _bt_connect_profile(char *address, char *uuid,
						void *cb, gpointer func_data);

int _bt_disconnect_profile(char *address, char *uuid,
						void *cb, gpointer func_data);
int _bt_connect_le_ipsp_device(const bluetooth_device_address_t *bd_addr);

int _bt_disconnect_le_ipsp_device(const bluetooth_device_address_t *bd_addr);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_ADAPTER_H_*/


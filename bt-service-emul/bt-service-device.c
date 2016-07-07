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

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-device.h"
#include "bt-service-util.h"

int _bt_bond_device(int request_id,
		bluetooth_device_address_t *device_address,
		unsigned short conn_type, GArray **out_param1)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_cancel_bonding(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_unbond_device(int request_id,
			bluetooth_device_address_t *device_address,
			GArray **out_param1)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_search_device(int request_id,
			bluetooth_device_address_t *device_address)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_cancel_search_device(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_alias(bluetooth_device_address_t *device_address,
				      const char *alias)
{
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_PARAMETER(alias, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_authorization(bluetooth_device_address_t *device_address,
				      gboolean authorize)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_is_device_connected(bluetooth_device_address_t *device_address,
			int connection_type, gboolean *is_connected)
{
	retv_if(device_address == NULL, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(is_connected == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	*is_connected = FALSE;

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_connected_link(bluetooth_device_address_t *device_address,
			bluetooth_connected_link_t *connected)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_connect_le_device(int request_id,
		const bluetooth_device_address_t *bd_addr,
		gboolean auto_connect)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_disconnect_le_device(int request_id,
		const bluetooth_device_address_t *bd_addr)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_connect_le_ipsp_device(const bluetooth_device_address_t *bd_addr)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_disconnect_le_ipsp_device(const bluetooth_device_address_t *bd_addr)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_connect_profile(char *address, char *uuid,
						void *cb, gpointer func_data)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_disconnect_profile(char *address, char *uuid,
						void *cb, gpointer func_data)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_enable_rssi(bluetooth_device_address_t *bd_addr, int link_type,
		int low_threshold, int in_range_threshold, int high_threshold)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_rssi_strength(bluetooth_device_address_t *bd_addr,
					int link_type)
{
	BT_CHECK_PARAMETER(bd_addr, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_le_conn_update(unsigned char *device_address,
				guint16 interval_min, guint16 interval_max,
				guint16 latency, guint16 time_out)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_pin_code(bluetooth_device_address_t *device_address,
				bluetooth_device_pin_code_t *pin_code)
{
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_PARAMETER(pin_code, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_unset_pin_code(bluetooth_device_address_t *device_address)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_device_pin_code(const char *address, char *pin_code)
{
	BT_CHECK_PARAMETER(address, return);
	BT_CHECK_PARAMETER(pin_code, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_le_connection_parameter(bluetooth_le_connection_mode_t mode,
		bluetooth_le_connection_param_t *param)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_passkey_reply(const char *passkey, gboolean authentication_reply)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_passkey_confirmation_reply(gboolean confirmation_reply)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}
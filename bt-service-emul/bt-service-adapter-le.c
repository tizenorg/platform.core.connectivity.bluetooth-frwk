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

#include <glib.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-adapter-le.h"
#include "bt-service-util.h"

static gboolean is_le_scanning = FALSE;

gboolean _bt_is_advertising(void)
{
	return FALSE;
}

int _bt_set_advertising(const char *sender, int adv_handle, gboolean enable, gboolean use_reserved_slot)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_custom_advertising(const char *sender, int adv_handle,
				gboolean enable, bluetooth_advertising_params_t *params, gboolean use_reserved_slot)
{
	BT_CHECK_PARAMETER(params, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_advertising_data(bluetooth_advertising_data_t *adv, int *length)
{
	BT_CHECK_PARAMETER(adv, return);
	BT_CHECK_PARAMETER(length, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_advertising_data(const char *sender, int adv_handle,
				bluetooth_advertising_data_t *adv, int length, gboolean use_reserved_slot)
{
	BT_CHECK_PARAMETER(adv, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_scan_response_data(bluetooth_scan_resp_data_t *response, int *length)
{
	BT_CHECK_PARAMETER(response, return);
	BT_CHECK_PARAMETER(length, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_scan_response_data(const char *sender, int adv_handle,
				bluetooth_scan_resp_data_t *response, int length, gboolean use_reserved_slot)
{
	BT_CHECK_PARAMETER(response, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_scan_parameters(bluetooth_le_scan_params_t *params)
{
	BT_CHECK_PARAMETER(params, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_register_scan_filter(const char *sender, bluetooth_le_scan_filter_t *filter, int *slot_id)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_unregister_scan_filter(const char *sender, int slot_id)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_unregister_all_scan_filters(const char *sender)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

void _bt_set_le_scan_status(gboolean mode)
{
	is_le_scanning = mode;
}

gboolean _bt_is_le_scanning(void)
{
	return is_le_scanning;
}

int _bt_start_le_scan(const char *sender)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_stop_le_scan(const char *sender)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_add_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_remove_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_clear_white_list(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_initialize_ipsp(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_deinitialize_ipsp(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_le_read_maximum_data_length(
		bluetooth_le_read_maximum_data_length_t *max_le_datalength)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}
int _bt_le_write_host_suggested_default_data_length(
	const unsigned int def_tx_Octets, const unsigned int def_tx_Time)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_le_read_host_suggested_default_data_length(
		bluetooth_le_read_host_suggested_data_length_t *def_data_length)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_le_set_data_length(bluetooth_device_address_t *device_address,
	const unsigned int max_tx_Octets, const unsigned int max_tx_Time)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

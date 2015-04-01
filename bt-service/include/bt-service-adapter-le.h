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


#ifndef _BT_SERVICE_ADAPTER_LE_H_
#define _BT_SERVICE_ADAPTER_LE_H_

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

int _bt_service_adapter_le_init(void);

void _bt_service_adapter_le_deinit(void);

gboolean _bt_update_le_feature_support(const char *item, const char *value);

const char* _bt_get_adv_slot_owner(int slot_id);

void _bt_set_advertising_status(int slot_id, gboolean mode);

gboolean _bt_is_advertising(void);

void _bt_stop_advertising_by_terminated_process(const char* terminated_name);

int _bt_set_advertising(gboolean enable, const char *sender, gboolean use_reserved_slot);

int _bt_set_custom_advertising(gboolean enable, bluetooth_advertising_params_t *params, const char *sender, gboolean use_reserved_slot);

int _bt_get_advertising_data(bluetooth_advertising_data_t *adv, int *length);

int _bt_set_advertising_data(bluetooth_advertising_data_t *data, int length, const char *sender, gboolean use_reserved_slot);

int _bt_get_scan_response_data(bluetooth_scan_resp_data_t *response, int *length);

int _bt_set_scan_response_data(bluetooth_scan_resp_data_t *response, int length, const char *sender, gboolean use_reserved_slot);

int _bt_set_scan_parameters(bluetooth_le_scan_params_t *params);

int _bt_add_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type);

int _bt_remove_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type);

int _bt_clear_white_list(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_ADAPTER_LE_H_*/


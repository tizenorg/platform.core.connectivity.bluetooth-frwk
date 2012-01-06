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


#ifndef _BLUETOOTH_GAP_API_H_
#define _BLUETOOTH_GAP_API_H_


#include "bluetooth-api-common.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define BLUETOOTH_CHANGE_STATUS_TIMEOUT	30
#define BLUETOOTH_BONDING_TIMEOUT		60

typedef struct device_list {
	char str_address[20];
	char str_name[50];
	int class;
	struct device_list *next;
} device_list_t;

typedef struct paired_info {
	int total_count;
} paired_info_t;


void _bluetooth_internal_enabled_cb(void);
void _bluetooth_internal_disabled_cb(void);

void _bluetooth_internal_adapter_name_changed_cb(void);

void _bluetooth_internal_discovery_started_cb(void);
void _bluetooth_internal_discovery_completed_cb(void);
void _bluetooth_internal_bonding_created_cb(const char *bond_address,
						gpointer user_data);
void _bluetooth_internal_bonding_removed_cb(const char *bond_address,
						gpointer user_data);
void _bluetooth_internal_remote_device_found_cb(const char *address,
				int rssi, unsigned int remote_class,
				gboolean paired);
void _bluetooth_internal_remote_device_name_updated_cb(const char *address,
							const char *name,
							int rssi, unsigned int remote_class,
							gboolean paired);

int _bluetooth_is_headset_device(DBusGProxy *proxy);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /*_BLUETOOTH_GAP_API_H_*/

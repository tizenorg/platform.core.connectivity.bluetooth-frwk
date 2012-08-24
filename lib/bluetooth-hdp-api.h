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

#ifndef __BLUETOOTH_HDP_API_H
#define __BLUETOOTH_HDP_API_H


#ifdef __cplusplus
extern "C" {
#endif
#include <sys/types.h>
#include <sys/socket.h>

#define BLUEZ_HDP_MANAGER_INTERFACE  "org.bluez.HealthManager"
#define BLUEZ_HDP_DEVICE_INTERFACE  "org.bluez.HealthDevice"
#define BLUEZ_HDP_CHANNEL_INTERFACE  "org.bluez.HealthChannel"

typedef struct {
	char *obj_channel_path;
	int fd;
} hdp_obj_info_t;

typedef struct {
	void *app_handle;
	GSList *obj_info;
} hdp_app_list_t;



#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_HDP_API_H */

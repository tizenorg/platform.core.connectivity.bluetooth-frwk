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


#ifndef _BT_SERVICE_EVENT_MANAGER_H_
#define _BT_SERVICE_EVENT_MANAGER_H_

#include <sys/types.h>
#include <bt-service-common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BT_EVENT_TIMER_ENABLE = 0x00,
	BT_EVENT_TIMER_DISABLE,
	BT_EVENT_TIMER_START_DISCOVERY,
	BT_EVENT_TIMER_STOP_DISCOVERY,
	BT_EVENT_TIMER_FOUND_DEVICE,
	BT_EVENT_MAX
} bt_event_timer_e;


void _bt_create_event_timer(int event_id, int interval, void *event_cb, void *user_data);

void _bt_delete_event_timer(int event_id);

void _bt_delete_all_event_timer(void);

int _bt_get_sample_device_number(void);

bt_remote_dev_info_t *_bt_get_sample_device(int index);


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_EVENT_MANAGER_H_*/


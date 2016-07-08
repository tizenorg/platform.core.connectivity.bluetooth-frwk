/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *              http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BT_HAL_EVENT_RECEIVER_H_
#define _BT_HAL_EVENT_RECEIVER_H_

#include <glib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DBUS_TIMEOUT 20 * 1000 /* 20 Sec */
#define BT_HAL_MAX_PROPERTY_BUF_SIZE 1024
#define BT_HAL_STACK_UUID_SIZE 16
#define MAX_UUID_COUNT 50
#define BT_HAL_DISCOVERY_FINISHED_DELAY 200

/* This is the callback method which handles events from stack */
typedef void (*handle_stack_msg) (int message, void *buf, uint16_t len);

int _bt_hal_initialize_event_receiver(handle_stack_msg cb);

void _bt_hal_register_hid_event_handler_cb(handle_stack_msg cb);

void _bt_hal_unregister_hid_event_handler_cb();

handle_stack_msg _bt_hal_get_stack_message_handler(void);

int __bt_insert_hal_properties(void *buf, uint8_t type, uint16_t len, const void *val);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_EVENT_RECEIVER_H_ */

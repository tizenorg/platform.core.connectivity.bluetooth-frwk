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

#ifndef _BT_HAL_ADAPTER_DBUS_HANDLER_H_
#define _BT_HAL_ADAPTER_DBUS_HANDLER_H_

#include <glib.h>
#include <sys/types.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"

#include "bt-hal-event-receiver.h"


#ifdef __cplusplus
extern "C" {
#endif

void _bt_hal_dbus_store_stack_msg_cb(handle_stack_msg cb);

int _bt_hal_dbus_enable_adapter(void);

int _bt_hal_dbus_disable_adapter(void);

int _bt_hal_dbus_get_adapter_property(bt_property_type_t type);

int _bt_hal_dbus_get_adapter_properties(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_ADAPTER_DBUS_HANDLER_H_ */

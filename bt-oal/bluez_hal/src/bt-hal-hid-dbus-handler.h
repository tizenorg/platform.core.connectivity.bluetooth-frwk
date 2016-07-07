/* Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Atul Kumar Rai <a.rai@samsung.com>
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


#ifndef _BT_HAL_HID_DBUS_HANDLER_H_
#define _BT_HAL_HID_DBUS_HANDLER_H_

#include <glib.h>
#include <sys/types.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"

#include "bt-hal-event-receiver.h"

#ifdef __cplusplus
extern "C" {
#endif

void _bt_hal_register_hid_dbus_handler_cb(handle_stack_msg cb);
void _bt_hal_unregister_hid_dbus_handler_cb();
bt_status_t _bt_hal_dbus_handler_hidhost_connect(bt_bdaddr_t *bd_addr);
bt_status_t _bt_hal_dbus_handler_hidhost_disconnect(bt_bdaddr_t *bd_addr);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_HID_DBUS_HANDLER_H_ */

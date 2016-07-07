/* Bluetooth-frwk
 *
 * Copyright (c) 20015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
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


#ifndef _BT_HAL_DEVICE_DBUS_HANDLER_H_
#define _BT_HAL_DEVICE_DBUS_HANDLER_H_

#include <glib.h>
#include <sys/types.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"

#include "bt-hal-event-receiver.h"


#ifdef __cplusplus
extern "C" {
#endif

int _bt_hal_device_create_bond(const bt_bdaddr_t *bd_addr, unsigned short transport);

int _bt_hal_device_remove_bond(const bt_bdaddr_t *bd_addr);

int _bt_hal_device_cancel_bond(const bt_bdaddr_t *bd_addr);

int _bt_hal_dbus_get_remote_device_properties(bt_bdaddr_t *remote_addr);

int _bt_hal_dbus_set_remote_device_property(
		bt_bdaddr_t *remote_addr, const bt_property_t *property);

int _bt_hal_device_legacy_pin_reply(const bt_bdaddr_t *bd_addr,
		gboolean accept, uint8_t pin_len, char *pincode);

int _bt_hal_device_ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
		uint8_t accept, uint32_t passkey);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_DEVICE_DBUS_HANDLER_H_ */

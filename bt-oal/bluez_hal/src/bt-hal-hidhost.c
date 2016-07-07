/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Kumar Rai <a.rai@samsung.com>
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

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <dlog.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"

static const bthh_callbacks_t *bt_hal_hid_cbacks;

static bool interface_ready(void)
{
	return bt_hal_hid_cbacks != NULL;
}

static bt_status_t hidhost_connect(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t hidhost_disconnect(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t virtual_unplug(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t hidhost_set_info(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocol_mode)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t set_protocol(bt_bdaddr_t *bd_addr,
					bthh_protocol_mode_t protocol_mode)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t report_type,
						uint8_t report_id,
						int buffer_size)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t set_report(bt_bdaddr_t *bd_addr,
						bthh_report_type_t report_type,
						char *report)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t hidhost_send_data(bt_bdaddr_t *bd_addr, char *data)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t init(bthh_callbacks_t *callbacks)
{
	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	bt_hal_hid_cbacks = callbacks;
	return BT_STATUS_SUCCESS;
}

static void cleanup(void)
{
	DBG("");

	if (!interface_ready())
		return;

	bt_hal_hid_cbacks = NULL;
}

static bthh_interface_t hidhost_if = {
	.size = sizeof(hidhost_if),
	.init = init,
	.connect = hidhost_connect,
	.disconnect = hidhost_disconnect,
	.virtual_unplug = virtual_unplug,
	.set_info = hidhost_set_info,
	.get_protocol = get_protocol,
	.set_protocol = set_protocol,
	.get_report = get_report,
	.set_report = set_report,
	.send_data = hidhost_send_data,
	.cleanup = cleanup
};

bthh_interface_t *bt_get_hidhost_interface(void)
{
	return &hidhost_if;
}

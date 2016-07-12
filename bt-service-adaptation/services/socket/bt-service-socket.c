/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Author: Atul Rai <a.rai@samsung.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <glib.h>
#include <dlog.h>

/* OAL headers */
#include <oal-event.h>
#include <oal-socket.h>

/* bt-service headers */
#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-util.h"
#include "bt-service-event-receiver.h"

static void __bt_socket_event_handler(int event_type, gpointer event_data)
{
	BT_INFO("OAL event = 0x%x, \n", event_type);

	switch(event_type) {
	default:
		BT_ERR("Invalid event:%d\n", event_type);
		break;
	}
}

int _bt_socket_init(void)
{
	BT_INFO("Socket Init");

	if(OAL_STATUS_SUCCESS != socket_enable()) {
		BT_ERR("Socket init failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* Register SOCKET event handler */
	_bt_service_register_event_handler_callback(BT_SOCKET_MODULE, __bt_socket_event_handler);
	return BLUETOOTH_ERROR_NONE;
}

void _bt_socket_deinit(void)
{
	BT_INFO("Socket de-init");

	if(OAL_STATUS_SUCCESS != socket_disable())
		BT_ERR("Socket de-init failed");

	/* Un-register SOCKET event handler */
	_bt_service_unregister_event_handler_callback(BT_SOCKET_MODULE);
}

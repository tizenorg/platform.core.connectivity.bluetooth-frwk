/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Rai <a.rai@samsung.com>
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
#include "bt-hal-rfcomm-dbus-handler.h"

static bt_status_t listen(btsock_type_t type, const char *service_name,
		const uint8_t *uuid, int channel, int *sock_fd, int flags)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t connect(const bt_bdaddr_t *bd_addr, btsock_type_t type,
		const uint8_t *uuid, int channel, int *sock_fd, int flags)
{
	bt_status_t status;

	DBG("+");

	if (bd_addr == NULL || sock_fd == NULL) {
		ERR("invalid parameters, bd_addr:%p, uuid:%p, channel:%d, sock_fd:%p",
				bd_addr, uuid, channel, sock_fd);
		return BT_STATUS_PARM_INVALID;
	}

	if (!uuid) {
		ERR("Currently we only support to connect using UUID");
		return BT_STATUS_UNSUPPORTED;
	}

	INFO("channel: %d, sock_fd: %d, type: %d", channel, sock_fd, type);

	switch (type) {
	case BTSOCK_RFCOMM:
		/* Call rfcomm dbus handler to connect rfcomm client */
		status = _bt_hal_dbus_handler_rfcomm_connect(
				(unsigned char *)bd_addr->address,
				(unsigned char *)uuid, sock_fd);
		break;
	case BTSOCK_L2CAP:
		ERR("bt l2cap socket type not supported");
		status = BT_STATUS_UNSUPPORTED;
		goto failed;
	case BTSOCK_SCO:
		ERR("bt sco socket not supported");
		status = BT_STATUS_UNSUPPORTED;
		goto failed;
	default:
		ERR("unknown bt socket type:%d", type);
		status = BT_STATUS_UNSUPPORTED;
		goto failed;
	}

	DBG("-");
	return status;

failed:
	*sock_fd = -1;
	return status;
}

static btsock_interface_t socket_if = {
	.size = sizeof(socket_if),
	.listen = listen,
	.connect = connect
};

btsock_interface_t *bt_get_socket_interface(void)
{
	return &socket_if;
}

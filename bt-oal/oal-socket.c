/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <dlog.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

#include <oal-event.h>
#include <oal-manager.h>
#include "oal-internal.h"

#include "bluetooth.h"
#include "bt_sock.h"
#include "oal-socket.h"
#include "oal-utils.h"

#define CHECK_OAL_SOCKET_ENABLED() \
	do { \
		if (socket_api == NULL) { \
			BT_ERR("Socket is not Initialized"); \
			return OAL_STATUS_NOT_READY; \
		} \
	} while (0)

/*
 * Global variables
 */
static const btsock_interface_t* socket_api = NULL;

oal_status_t socket_enable()
{
	const bt_interface_t *blued_api;

	API_TRACE("Socket Init");

	blued_api = adapter_get_stack_interface();
	if(blued_api == NULL) {
		BT_ERR("Stack is not initialized");
		return OAL_STATUS_NOT_READY;
	}

	if(socket_api != NULL) {
		BT_WARN("Socket Interface is already initialized...");
		return OAL_STATUS_ALREADY_DONE;
	}

	socket_api = (const btsock_interface_t*)blued_api->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!socket_api){
		BT_ERR("OAL Socket failed to initialize");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	BT_DBG("Socket successfully initiated");
	return OAL_STATUS_SUCCESS ;
}

oal_status_t socket_disable(void)
{

	API_TRACE("Socket Deinit");

	CHECK_OAL_SOCKET_ENABLED();
	socket_api = NULL;
	return OAL_STATUS_SUCCESS;
}

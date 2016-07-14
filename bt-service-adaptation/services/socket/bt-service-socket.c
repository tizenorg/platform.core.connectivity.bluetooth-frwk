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
#include "bt-service-socket.h"

typedef struct {
	int sock_fd;
	int chan;
	char uuid[BT_UUID_STRING_SIZE];
	char address[BT_ADDRESS_STRING_SIZE];
	bt_socket_client_conn_cb conn_cb;
} bt_socket_info_t;

bt_socket_info_t *pending_conn_info;

/* Function to handle socket disconnection */
void __handle_socket_disconnected(event_socket_client_conn_t *client_info)
{
	char address[BT_ADDRESS_STR_LEN];

	ret_if(NULL == client_info);

	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, client_info->address.addr);

	/*
	 * In case of an already connected socket, if disconnection happens, it will
	 * automatically detected in corresponding i/o handler and events will be sent
	 * from there. So here we only handle connection fail case.
	 */
	if (NULL != pending_conn_info &&
			!strncasecmp(address, pending_conn_info->address, strlen(address))) {
		/*
		 * Disconnection event is received for ongoing connection, invoke connection
		 * state callback with error.
		 */
		BT_INFO("socket_fd: %d, address: %s, uuid: %s, channel: %d",
				client_info->fd, address,
				pending_conn_info->uuid,
				pending_conn_info->chan);

		pending_conn_info->conn_cb(BLUETOOTH_ERROR_INTERNAL, client_info->fd, address,
				pending_conn_info->uuid, pending_conn_info->chan);

		g_free(pending_conn_info);
		pending_conn_info = NULL;
	} else {
		BT_INFO("Disconnected Address: [%s], socket_fd: %d", address, client_info->fd);
	}

	BT_DBG("-");
}

/* Handle outgoing client socket connection event */
static void __handle_outgoing_client_socket_connected(event_socket_client_conn_t *client_info)
{
	char address[BT_ADDRESS_STR_LEN];

	ret_if(NULL == client_info);
	ret_if(NULL == pending_conn_info);

	BT_DBG("+");

	/*
	 * Only one socket connect req at a time is allowed, so received address
	 * should match with pending request.
	 */
	_bt_convert_addr_type_to_string(address, client_info->address.addr);
	if (strncasecmp(address, pending_conn_info->address, strlen(address))) {
		BT_ERR("Address mismatch, Pending connection address: [%s]",
				pending_conn_info->address);
		BT_ERR("Client connection callback called with address: [%s]", address);
		return;
	}

	BT_INFO("socket_fd: %d, address: %s, uuid: %s, channel: %d",
			client_info->fd, address,
			pending_conn_info->uuid,
			pending_conn_info->chan);

	pending_conn_info->conn_cb(BLUETOOTH_ERROR_NONE, client_info->fd, address,
			pending_conn_info->uuid, pending_conn_info->chan);

	g_free(pending_conn_info);
	pending_conn_info = NULL;
	BT_DBG("-");
}

static void __bt_socket_event_handler(int event_type, gpointer event_data)
{
	BT_INFO("OAL event = 0x%x, \n", event_type);

	switch(event_type) {
	case OAL_EVENT_SOCKET_OUTGOING_CONNECTED: {
		event_socket_client_conn_t *client_info = event_data;

		__handle_outgoing_client_socket_connected(client_info);
		break;
	}
	case OAL_EVENT_SOCKET_DISCONNECTED: {
		event_socket_client_conn_t *client_info = event_data;

		__handle_socket_disconnected(client_info);
		break;
	}
	default:
		BT_ERR("Invalid event:%d\n", event_type);
		break;
	}
}

int _bt_socket_client_connect(int sock_type, char *address,
		char *remote_uuid, int channel, bt_socket_client_conn_cb cb)
{
	int sock_fd = -1;
	bt_address_t bd;
	oal_uuid_t uuid;

	retv_if(NULL == address, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(NULL != pending_conn_info, BLUETOOTH_ERROR_DEVICE_BUSY);

	BT_DBG("+");


	BT_INFO("sock_type: %d, address: %s, remote_uuid: %s, channel: %d",
			sock_type, address, remote_uuid, channel);

	_bt_convert_addr_string_to_type(bd.addr, address);
	if (remote_uuid)
		_bt_service_convert_uuid_string_to_type(uuid.uuid, remote_uuid);
	else
		memset(&uuid, 0x00, sizeof(oal_uuid_t));

	switch (sock_type) {
	case SOCK_TYPE_RFCOMM:
		sock_fd = socket_connect(OAL_SOCK_RFCOMM, &uuid, channel, &bd);
		break;
	default:
		BT_ERR("Socket type: %d not supported");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	if(0 > sock_fd) {
		BT_ERR("Bluetooth socket connect failed");
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	pending_conn_info = g_malloc0(sizeof(bt_socket_info_t));
	pending_conn_info->sock_fd = sock_fd;
	pending_conn_info->chan = channel;
	pending_conn_info->conn_cb = cb;
	g_strlcpy(pending_conn_info->address, address, BT_ADDRESS_STRING_SIZE);
	g_strlcpy(pending_conn_info->uuid, remote_uuid, BT_UUID_STRING_SIZE);

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
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

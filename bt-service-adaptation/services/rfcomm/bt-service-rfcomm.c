/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Author:  Atul Kumar Rai <a.rai@samsung.com>
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

#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <dlog.h>
#include <string.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"
#include "bt-request-handler.h"
#include "bt-service-util.h"
#include "bt-service-event.h"
#include "bt-service-common.h"
#include "bt-service-rfcomm.h"
#include "bt-service-socket.h"

static void __bt_rfcomm_reply_pending_request(int result,
		int service_function, void *user_data, unsigned int size)
{
	GSList *l;
	GArray *out_param;
	invocation_info_t *req_info;

	/* Get method invocation context */
	for (l = _bt_get_invocation_list(); l != NULL; l = g_slist_next(l)) {
		req_info = l->data;
		if (req_info == NULL || req_info->service_function != service_function)
			continue;

		/* Create out param */
		out_param = g_array_new(FALSE, FALSE, sizeof(gchar));

		switch(service_function) {
		case BT_RFCOMM_CLIENT_CONNECT: {
			GUnixFDList *fd_list = NULL;
			GError *error = NULL;

			g_array_append_vals(out_param, user_data, size);

			if (BLUETOOTH_ERROR_NONE == result) {
				bluetooth_rfcomm_connection_t *ptr = user_data;

				fd_list = g_unix_fd_list_new();
				g_unix_fd_list_append(fd_list, ptr->socket_fd, &error);
				g_assert_no_error (error);
				close(ptr->socket_fd);
			}

			_bt_service_method_return_with_unix_fd_list(
					req_info->context, out_param, result, fd_list);
			g_object_unref(fd_list);
			break;
		}
		default:
			BT_ERR("Unknown Service function");
		}

		g_array_free(out_param, TRUE);
		_bt_free_info_from_invocation_list(req_info);
	}

	return;
}

static void __bt_rfcomm_socket_conn_cb(int result, int sock_fd, char *address, char *uuid, int chan)
{
	bluetooth_rfcomm_connection_t conn_info;

	ret_if(NULL == address);
	ret_if(NULL == uuid);

	BT_DBG("+");

	BT_INFO("result: %d, socket_fd: %d, address: %s, uuid: %s, chan: %d",
			result, sock_fd, address, uuid, chan);

	/* Fill RFCOMM connection structure and send reply to pending request */
	memset(&conn_info, 0x00, sizeof(bluetooth_rfcomm_connection_t));
	conn_info.socket_fd = sock_fd;
	conn_info.device_role = RFCOMM_ROLE_CLIENT;
	g_strlcpy(conn_info.uuid, uuid, BLUETOOTH_UUID_STRING_MAX);
	_bt_convert_addr_string_to_type(conn_info.device_addr.addr, address);

	__bt_rfcomm_reply_pending_request(
			result, BT_RFCOMM_CLIENT_CONNECT,
			(void *)&conn_info, sizeof(bluetooth_rfcomm_connection_t));

	BT_DBG("-");
}

int _bt_rfcomm_connect_using_uuid(bluetooth_device_address_t *device_address, char *remote_uuid)
{
	int result;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	BT_DBG("+");

	retv_if(NULL == device_address, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(NULL == remote_uuid, BLUETOOTH_ERROR_INVALID_PARAM);

	_bt_convert_addr_type_to_string(address, device_address->addr);
	BT_INFO("RFCOMM connect called for [%s], uuid: [%s]", address, remote_uuid);

	result = _bt_socket_client_connect(SOCK_TYPE_RFCOMM,
			address, remote_uuid, -1, __bt_rfcomm_socket_conn_cb);
	if (BLUETOOTH_ERROR_NONE != result) {
		BT_ERR("_bt_socket_client_connect failed");
		return result;
	}

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

/* Range of the Channel : 0 <= channel <= 30 */
int _bt_rfcomm_connect_using_channel(bluetooth_device_address_t *device_address, char *chan_str)
{
	int channel;
	int result = BLUETOOTH_ERROR_NONE;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	BT_DBG("+");

	retv_if(NULL == device_address, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(NULL == chan_str, BLUETOOTH_ERROR_INVALID_PARAM);

	_bt_convert_addr_type_to_string(address, device_address->addr);
	channel = atoi(chan_str);
	BT_INFO("RFCOMM connect called for [%s], channel: %d", address, channel);

	result = _bt_socket_client_connect(SOCK_TYPE_RFCOMM,
			address, NULL, channel, __bt_rfcomm_socket_conn_cb);
	if (BLUETOOTH_ERROR_NONE != result) {
		BT_ERR("_bt_socket_client_connect failed");
		return result;
	}

	BT_DBG("-");
	return result;
}

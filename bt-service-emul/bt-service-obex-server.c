/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <string.h>


#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-util.h"
#include "bt-service-obex-server.h"

typedef struct {
	GDBusMethodInvocation *reply_context;
	guint64 file_size;
	char *filename;
	char *file_path;
	char *device_name;
	char *transfer_path;
	char *address;
} bt_auth_info_t;

typedef struct {
	char *dest_path;
	char *sender;
	int app_pid;
} bt_server_info_t;

typedef struct {
	GDBusProxy *proxy;
	int server_type;
	int accept_id;
	bt_auth_info_t *auth_info;
	bt_server_info_t *native_server;
	bt_server_info_t *custom_server;
} bt_obex_agent_info_t;

static bt_obex_agent_info_t agent_info;

int _bt_obex_server_allocate(char *sender, const char *dest_path, int app_pid, gboolean is_native)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_deallocate(int app_pid, gboolean is_native)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_accept_authorize(const char *filename, gboolean is_native)
{
	BT_CHECK_PARAMETER(filename, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_reject_authorize(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_set_destination_path(const char *dest_path,
						gboolean is_native)
{
	BT_CHECK_PARAMETER(dest_path, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_set_root(const char *root)
{
	BT_CHECK_PARAMETER(root, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_cancel_transfer(int transfer_id)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_cancel_all_transfers(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_is_activated(gboolean *activated)
{
	BT_CHECK_PARAMETER(activated, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

/* To support the BOT  */
int _bt_obex_server_accept_connection(int request_id)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

/* To support the BOT  */
int _bt_obex_server_reject_connection(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_server_is_receiving(gboolean *receiving)
{
	BT_CHECK_PARAMETER(receiving, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_obex_get_native_pid(void)
{
	return agent_info.native_server->app_pid;
}


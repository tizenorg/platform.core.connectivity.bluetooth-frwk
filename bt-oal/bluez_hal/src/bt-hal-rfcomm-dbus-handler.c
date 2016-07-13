/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Atul Kumar Rai <a.rai@samsung.com>
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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <vconf.h>

#include "bt-hal-rfcomm-dbus-handler.h"
#include "bt-hal-dbus-common-utils.h"

#define BT_HAL_RFCOMM_ID_MAX 245
#define BT_HAL_RFCOMM_MAX_BUFFER_SIZE 1024

typedef struct {
	char uuid[BT_HAL_UUID_STRING_LEN];
	char *device_path;
	char *obj_path;
	int object_id;
	int id;
	GSList *rfcomm_conns;
} rfcomm_cb_data_t;

typedef struct {
	char remote_addr[BT_HAL_ADDRESS_STRING_SIZE];
	int hal_fd;
	unsigned int hal_watch;
	int stack_fd;
	unsigned int bt_watch;
} rfcomm_conn_info_t;

static GSList *rfcomm_clients;
static int latest_id = -1;
static gboolean id_used[BT_HAL_RFCOMM_ID_MAX];

int __rfcomm_assign_id(void)
{
	int index;

	DBG("latest_id: %d", latest_id);

	index = latest_id + 1;
	if (index >= BT_HAL_RFCOMM_ID_MAX)
		index = 0;

	DBG("index: %d", index);

	while (id_used[index] == TRUE) {
		if (index == latest_id) {
			/* No available ID */
			ERR("All request ID is used");
			return -1;
		}

		index++;
		if (index >= BT_HAL_RFCOMM_ID_MAX)
			index = 0;
	}

	latest_id = index;
	id_used[index] = TRUE;
	DBG("Assigned Id: %d", latest_id);

	return latest_id;
}

void __rfcomm_delete_id(int id)
{
	if (id >= BT_HAL_RFCOMM_ID_MAX || id < 0) {
		ERR("Invalid id %d", id);
		return;
	}

	id_used[id] = FALSE;
	latest_id = id - 1;
	DBG("id: %d, latest_id: %d", id, latest_id);
}

static rfcomm_cb_data_t *__find_rfcomm_info_from_uuid(const char *uuid)
{
	GSList *l;

	for (l = rfcomm_clients; l != NULL; l = l->next) {
		rfcomm_cb_data_t *info = l->data;

		if (g_strcmp0(info->uuid, uuid) == 0)
			return info;
	}

	return NULL;
}

static rfcomm_cb_data_t *__find_rfcomm_info_from_path(const char *path)
{
	GSList *l;

	for (l = rfcomm_clients; l != NULL; l = l->next) {
		rfcomm_cb_data_t *info = l->data;

		if (info != NULL)
			if (g_strcmp0(info->obj_path, path) == 0)
				return info;
	}

	return NULL;
}

static void __bt_free_cb_data(rfcomm_cb_data_t *cb_data)
{
	DBG("+");

	if (cb_data->id >= 0)
		__rfcomm_delete_id(cb_data->id);

	if (cb_data->object_id > 0)
		_bt_unregister_gdbus_object(cb_data->object_id);

	if (cb_data->obj_path) {
		INFO("Unregister profile");
		_bt_unregister_profile(cb_data->obj_path);
	}

	g_free(cb_data->obj_path);

	g_free(cb_data->device_path);
	g_free(cb_data);

	DBG("-");
}

static void __rfcomm_cb_data_remove(rfcomm_cb_data_t *info)
{
	if (!info) {
		ERR("info == NULL");
		return;
	}

	if (info->rfcomm_conns == NULL) {
		INFO("No more device connected remove info");
		rfcomm_clients = g_slist_remove(rfcomm_clients, info);
		__bt_free_cb_data(info);
	}
}

static rfcomm_conn_info_t *__find_conn_info_with_stack_fd(rfcomm_cb_data_t *info, int fd)
{
	GSList *l;

	for (l = info->rfcomm_conns; l != NULL; l = l->next) {
		rfcomm_conn_info_t *conn_info = l->data;

		if (conn_info && (conn_info->stack_fd == fd))
			return conn_info;
	}

	return NULL;
}

static rfcomm_conn_info_t *__find_conn_info_with_hal_fd(rfcomm_cb_data_t *info, int fd)
{
	GSList *l;
	for (l = info->rfcomm_conns; l != NULL; l = l->next) {
		rfcomm_conn_info_t *conn_info = l->data;

		if (conn_info && (conn_info->hal_fd == fd))
			return conn_info;
	}

	return NULL;
}

static gint compare(gpointer *a, gpointer *b)
{
	rfcomm_conn_info_t *node = (rfcomm_conn_info_t *)a;
	char *address = (char *)b;
	return g_strcmp0(node->remote_addr, address);
}

static rfcomm_conn_info_t *__get_conn_info_from_address(rfcomm_cb_data_t *info,
		char *dev_address)
{
	GSList *l = NULL;
	rfcomm_conn_info_t *conn_info = NULL;
	l = g_slist_find_custom(info->rfcomm_conns, dev_address,
			(GCompareFunc)compare);
	if (l)
		conn_info = l->data;
	return conn_info;
}

static void __bt_free_conn(rfcomm_conn_info_t *conn)
{
	DBG("+");

	if (conn == NULL)
		return;

	if (0 < conn->hal_fd)
		close(conn->hal_fd);

	if (conn->hal_watch > 0) {
		g_source_remove(conn->hal_watch);
		conn->hal_watch = 0;
	}

	if (0 < conn->stack_fd)
		close(conn->stack_fd);

	if (conn->bt_watch > 0) {
		g_source_remove(conn->bt_watch);
		conn->bt_watch = 0;
	}

	g_free(conn);
	DBG("-");
}

static void __rfcomm_remove_conn_info_t(rfcomm_cb_data_t *info, char *address)
{
	rfcomm_conn_info_t *conn_info;

	conn_info = __get_conn_info_from_address(info, address);
	if (conn_info) {
		info->rfcomm_conns = g_slist_remove(info->rfcomm_conns, conn_info);
		__bt_free_conn(conn_info);
	}
}

static int write_all(int fd, unsigned char *buf, int len)
{
	int sent = 0;

	while (len > 0) {
		int written;

		written = write(fd, buf, len);
		if (written < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}

		if (!written)
			return 0;

		len -= written; buf += written; sent += written;
	}

	return sent;
}

static gboolean app_event_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	gsize len;
	unsigned int sent;
	rfcomm_cb_data_t *info = data;
	rfcomm_conn_info_t *conn_info;
	unsigned char buff[BT_HAL_RFCOMM_MAX_BUFFER_SIZE];
	GError *err = NULL;
	int fd;

	DBG("+");
	fd = g_io_channel_unix_get_fd(io);
	conn_info = __find_conn_info_with_hal_fd(info, fd);

	if (cond & G_IO_HUP) {
		ERR("Socket %d hang up", fd);
		goto fail;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		ERR("Socket %d error", fd);
		goto fail;
	}

	if (!conn_info) {
		ERR("conn_info is NULL");
		return TRUE;
	}

	/* Read data from application */
	if (g_io_channel_read_chars(io, (gchar *)buff,
			BT_HAL_RFCOMM_MAX_BUFFER_SIZE,
			&len, &err) == G_IO_STATUS_ERROR) {
		if( err )
			ERR("IO Channel read error: %s", err->message);
		else
			ERR("IO Channel read error client");
		goto fail;
	}

	DBG("len: %d", len);
	if (0 == len) {
		ERR("Other end of socket is closed");
		goto fail;
	}

	/* Send data to remote device */
	sent = write_all(conn_info->stack_fd, buff, len);
	if (sent < 0) {
		ERR("write(): %s", strerror(errno));
		goto fail;
	}

	DBG("-");
	return TRUE;
fail:
	__rfcomm_remove_conn_info_t(info, conn_info->remote_addr);
	__rfcomm_cb_data_remove(info);
	return FALSE;
}

static gboolean stack_event_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	unsigned int len;
	unsigned int sent;
	rfcomm_cb_data_t *info = data;
	rfcomm_conn_info_t *conn_info;
	unsigned char buff[BT_HAL_RFCOMM_MAX_BUFFER_SIZE];
	GError *err = NULL;
	int fd;

	DBG("+");

	fd = g_io_channel_unix_get_fd(io);
	conn_info = __find_conn_info_with_stack_fd(info, fd);

	if (cond & G_IO_HUP) {
		ERR("Socket %d hang up", fd);
		goto fail;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		ERR("Socket %d error", fd);
		goto fail;
	}

	if (!conn_info) {
		ERR("conn_info is NULL");
		return TRUE;
	}

	/* Read data from remote device */
	if (g_io_channel_read_chars(io, (gchar *)buff,
			BT_HAL_RFCOMM_MAX_BUFFER_SIZE,
			&len, &err) == G_IO_STATUS_ERROR) {
		if( err )
			ERR("IO Channel read error: %s", err->message);
		else
			ERR("IO Channel read error client");
		goto fail;
	}

	DBG("len: %d", len);
	if (0 == len) {
		ERR("Other end of socket is closed");
		goto fail;
	}

	/* Send data to application */
	sent = write_all(conn_info->hal_fd, buff, len);
	if (sent < 0) {
		ERR("write(): %s", strerror(errno));
		goto fail;
	}

	DBG("-");
	return TRUE;
fail:
	__rfcomm_remove_conn_info_t(info, conn_info->remote_addr);
	__rfcomm_cb_data_remove(info);
	return FALSE;
}

static int __new_connection(const char *path, int fd, bt_bdaddr_t *addr)
{
	char address[BT_HAL_ADDRESS_STRING_SIZE];
	rfcomm_cb_data_t *info;
	rfcomm_conn_info_t *conn_info;
	struct hal_ev_sock_connect ev;
	GIOCondition cond;
	int len;
	GIOChannel *io;

	/* TODO: Temperary, later need to fill correct channel form correct place */
	int chan = 0;

	if (NULL == path || NULL == addr) {
		ERR("NULL == path || NULL = addr");
		return -1;
	}

	_bt_convert_addr_type_to_string(address, addr->address);
	info = __find_rfcomm_info_from_path(path);
	if (info == NULL)
		return -1;

	conn_info = __get_conn_info_from_address(info, address);
	if (conn_info == NULL) {
		ERR("Device Address %s not found in connection list", address);
		return -1;
	}

	if (write(conn_info->hal_fd, &chan, sizeof(chan)) != sizeof(chan)) {
		ERR("Error sending RFCOMM channel");
		goto fail;
	}

	conn_info->stack_fd = fd;
	DBG("Remote address: %s, RFCOMM fd: %d", address, conn_info->stack_fd);

	/* Send rfcomm connected event */
	memset(&ev, 0, sizeof(ev));
	ev.size = sizeof(ev);
	memcpy(ev.bdaddr, addr->address, 6);
	ev.status = BT_STATUS_SUCCESS;
	len = write_all(conn_info->hal_fd, (unsigned char *)&ev, sizeof(ev));
	if (len < 0) {
		ERR("%s", strerror(errno));
		goto fail;
	}

	if (len != sizeof(ev)) {
		ERR("Error sending connect event");
		goto fail;;
	}

	/* Handle events from App */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io = g_io_channel_unix_new(conn_info->hal_fd);
	conn_info->hal_watch = g_io_add_watch(io, cond, app_event_cb, info);
	g_io_channel_unref(io);

	/* Handle rfcomm events from bluez */
	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	io = g_io_channel_unix_new(conn_info->stack_fd);
	conn_info->bt_watch = g_io_add_watch(io, cond, stack_event_cb, info);
	g_io_channel_unref(io);

	return 0;
fail:
	__rfcomm_remove_conn_info_t(info, address);
	__rfcomm_cb_data_remove(info);
	return -1;
}

static void __bt_connect_response_cb(GDBusProxy *proxy,
		GAsyncResult *res, gpointer user_data)
{
	GError *error = NULL;
	rfcomm_cb_data_t *cb_data;
	char dev_address[BT_HAL_ADDRESS_STRING_SIZE];
	const char *path;

	DBG("+");

	cb_data = user_data;
	if (cb_data == NULL) {
		ERR("cb_data == NULL");
		return;
	}

	if (!g_dbus_proxy_call_finish(proxy, res, &error)) {
		ERR("Error : %s \n", error->message);
		path = g_dbus_proxy_get_object_path(proxy);
		_bt_convert_device_path_to_address(path, dev_address);
		__rfcomm_remove_conn_info_t(cb_data, dev_address);
		__rfcomm_cb_data_remove(cb_data);
		g_error_free(error);
	}

	if (proxy)
		g_object_unref(proxy);

	DBG("-");
}

static void __bt_discover_service_response_cb(GDBusProxy *proxy,
		GAsyncResult *res, gpointer user_data)
{
	rfcomm_cb_data_t *cb_data;
	int ret = 0;
	GError *err = NULL;
	bt_hal_register_profile_info_t info = {0};
	char dev_address[BT_HAL_ADDRESS_STRING_SIZE];
	const char *path;

	DBG("+");

	cb_data = user_data;
	if (!cb_data) {
		ERR("cb_data == NULL");
		return;
	}

	path = g_dbus_proxy_get_object_path(proxy);
	_bt_convert_device_path_to_address(path, dev_address);
	DBG("Device Adress [%s]", dev_address);

	g_dbus_proxy_call_finish(proxy, res, &err);
	if (proxy)
		g_object_unref(proxy);
	if (err != NULL) {
		ERR("Error occured in Proxy call [%s]\n", err->message);
		__rfcomm_remove_conn_info_t(cb_data, dev_address);
		__rfcomm_cb_data_remove(cb_data);
		goto done;
	} else {
		INFO("Services are Updated checking required uuid is there");
		/* Check here for uuid present */
		ret = _bt_discover_service_uuids(dev_address, cb_data->uuid);
		if (ret == BT_STATUS_SUCCESS) {
			info.uuid = (char *)cb_data->uuid;
			info.obj_path = cb_data->obj_path;
			info.role = "client";

			ret = _bt_register_profile(&info, FALSE);
			if (ret < 0)
				DBG("Error: register profile");
			ret = _bt_connect_profile(dev_address, cb_data->uuid,
					__bt_connect_response_cb, cb_data);
			if (ret != BT_STATUS_SUCCESS) {
				ERR("ConnectProfile failed");
				__rfcomm_remove_conn_info_t(cb_data, dev_address);
				__rfcomm_cb_data_remove(cb_data);
				goto done;
			}
		} else {
			ERR("remote uuid not found");
			__rfcomm_remove_conn_info_t(cb_data, dev_address);
			__rfcomm_cb_data_remove(cb_data);
		}
	}
done:
	if (err)
		g_clear_error(&err);
}

static rfcomm_cb_data_t *__get_rfcomm_cb_data(char *remote_uuid)
{
	int id;
	int object_id;
	char *path;
	rfcomm_cb_data_t *cb_data;

	DBG("+");

	cb_data = __find_rfcomm_info_from_uuid(remote_uuid);
	if (!cb_data) {
		id = __rfcomm_assign_id();
		if (id < 0) {
			ERR("__rfcomm_assign_id failed");
			return NULL;
		}

		path = g_strdup_printf("/org/socket/client/%d/%d", getpid(), id);
		object_id = _bt_register_new_gdbus_object(path, __new_connection);
		if (object_id < 0) {
			ERR("_bt_register_new_gdbus_object failed");
			__rfcomm_delete_id(id);
			return NULL;
		}

		cb_data = g_malloc0(sizeof(rfcomm_cb_data_t));
		g_strlcpy(cb_data->uuid, remote_uuid, BT_HAL_UUID_STRING_LEN);
		cb_data->obj_path = path;
		cb_data->object_id = object_id;
		cb_data->id = id;
	}

	DBG("-");
	return cb_data;
}

static rfcomm_conn_info_t *__rfcomm_create_conn_info(char *addr, int *sock)
{
	int fds[2] = {-1, -1};
	rfcomm_conn_info_t *conn;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		ERR("socketpair(): %s", strerror(errno));
		*sock = -1;
		return NULL;
	}

	conn = g_malloc0(sizeof(rfcomm_conn_info_t));
	g_strlcpy(conn->remote_addr, addr, BT_HAL_ADDRESS_STRING_SIZE);
	conn->hal_fd = fds[0];
	conn->stack_fd = -1;
	*sock = fds[1];

	DBG("hal_fd: %d, sock: %d", conn->hal_fd, *sock);

	return conn;
}

int _bt_hal_dbus_handler_rfcomm_connect(unsigned char *addr, unsigned char *uuid, int *sock)
{
	int ret;
	rfcomm_cb_data_t *cb_data;
	rfcomm_conn_info_t *conn;
	char remote_addr[BT_HAL_ADDRESS_STRING_SIZE];
	char remote_uuid[BT_HAL_UUID_SIZE];

	if (!addr) {
		ERR("remote_addr is NULL");
		return BT_STATUS_PARM_INVALID;
	}

	if (!uuid) {
		ERR("remote_uuid is NULL");
		return BT_STATUS_PARM_INVALID;
	}

	if (!sock) {
		ERR("sock is NULL");
		return BT_STATUS_PARM_INVALID;
	}

	_bt_convert_uuid_type_to_string(remote_uuid, uuid);
	cb_data = __get_rfcomm_cb_data(remote_uuid);
	if (!cb_data)
		return BT_STATUS_FAIL;

	_bt_convert_addr_type_to_string(remote_addr, addr);
	DBG("Connecting to %s, uuid %s", remote_addr, remote_uuid);
	conn = __rfcomm_create_conn_info(remote_addr, sock);
	if (!conn)
		return BT_STATUS_FAIL;

	cb_data->rfcomm_conns = g_slist_append(cb_data->rfcomm_conns, conn);
	ret = _bt_discover_services(remote_addr, (char *)remote_uuid,
			__bt_discover_service_response_cb, cb_data);
	if (ret != BT_STATUS_SUCCESS) {
		ERR("Error returned while service discovery");
		__rfcomm_remove_conn_info_t(cb_data, conn->remote_addr);
		__rfcomm_cb_data_remove(cb_data);
		return BT_STATUS_FAIL;
	}

	if (g_slist_find(rfcomm_clients, cb_data) == NULL) {
		INFO("Adding callback information to rfcomm_clients");
		rfcomm_clients = g_slist_append(rfcomm_clients, cb_data);
	} else
		INFO("Callback information is already added");

	return BT_STATUS_SUCCESS;
}

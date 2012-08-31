/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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

/**
* This file implements bluetooth gap api based on bluez
* @file	bluetooth-rfcomm-api.c
*/
/*:Associate with "Bluetooth" */

#include <dbus/dbus.h>
#include <glib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <vconf.h>

#include "bluetooth-rfcomm-api.h"
#include <termios.h>

#define BLUEZ_SERIAL_CLIENT_INTERFACE "org.bluez.Serial"

#define BLUEZ_SERIAL_MANAGER_INTERFACE "org.bluez.SerialProxyManager"
#define BLUEZ_SERIAL_PROXY_INTERFACE	"org.bluez.SerialProxy"

#define RFCOMM_CLIENT_BUFFER_SIZE 1024
#define RFCOMM_UDS_PATH "/bluez/rfcomm"
#define RFCOMM_DEV_PATH "/dev/rfcomm"
#define RFCOMM_SER_DEV_PATH "x00/bluez/rfcomm"

#define BT_AGENT_SIGNAL_AUTHORIZE "Authorize"

gboolean rfcomm_connected;
int connected_fd;
int requested_server_fd;
static DBusConnection *connection = NULL;

static gboolean __rfcomm_server_connected_cb(GIOChannel *chan, GIOCondition cond, gpointer data);
static gboolean __rfcomm_server_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data);

static gboolean __rfcomm_client_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data);

static int __get_default_adapter_path(char **adapter_path);

static int __get_rfcomm_proxy_list(char ***proxy_list, int *len);

static int __bluetooth_rfcomm_internal_disconnect(int index);

static int __rfcomm_internal_terminate_server(rfcomm_server_t *server_info);

static int __rfcomm_internal_terminate_client(int index);

static int __bluetooth_rfcomm_internal_server_get_free_index(void);

static int __bluetooth_rfcomm_internal_server_get_index_from_socket(int fd);

static int __bluetooth_rfcomm_internal_client_get_index_from_socket(int fd);

static void __rfcomm_client_connected_cb(DBusGProxy *proxy, DBusGProxyCall *call,
				       gpointer user_data);

static int __bluetooth_internal_set_non_blocking(int sk);

static int __bluetooth_internal_set_non_blocking_tty(int sk);

/* To support the BOT  */
static void __unregister_agent_authorize_signal(DBusGConnection *conn, void *user_data);

/*Get the free index channel for server */
static int __bluetooth_rfcomm_internal_server_get_free_index(void)
{

	DBG("+ + + + + + + + \n");
	int ind = -1;
	int i = 0;
	for (; i < RFCOMM_MAX_CONN; i++) {
		if (rfcomm_server[i].id == 0) {
			ind = i;
			break;
		}
	}
	DBG("Free index: %d\n", ind);
	DBG("- - - - - - - - -\n");
	return ind;
}

/*Get the index channel from server socket */
static int __bluetooth_rfcomm_internal_server_get_index_from_client_socket(int client_fd)
{
	int ind = -1;
	int i = 0;
	for (; i < RFCOMM_MAX_CONN; i++) {
		if (rfcomm_server[i].client_sock_fd == client_fd) {
			ind = i;
			break;
		}
	}
	DBG("Index from fd %d is index(%d)\n", client_fd, ind);
	return ind;
}


/*Get the index channel from server socket */
static int __bluetooth_rfcomm_internal_server_get_index_from_socket(int fd)
{
	DBG("+ + + + + + + + \n");
	int ind = -1;
	int i = 0;
	for (; i < RFCOMM_MAX_CONN; i++) {
		if (rfcomm_server[i].server_sock_fd == fd) {
			ind = i;
			break;
		}
	}
	DBG("Index from fd %d is index(%d)\n", fd, ind);
	DBG("- - - - - - - - -\n");
	return ind;
}

/*Get the  index channel from client socket */
static int __bluetooth_rfcomm_internal_client_get_index_from_socket(int fd)
{
	DBG("+ + + + + + + + \n");
	int ind = -1;
	int i = 0;
	for (; i < RFCOMM_MAX_CONN; i++) {
		if (rfcomm_client[i].sock_fd == fd) {
			ind = rfcomm_client[i].id;
			break;
		}
	}

	DBG("Index from fd %d is index(%d)\n", fd, ind);
	DBG("- - - - - - - - -\n");
	return ind;
}

/*Internal server disconnection */
static int __rfcomm_internal_terminate_server(rfcomm_server_t *server_info)
{
	DBG("+\n");
	DBusMessage *msg, *reply;
	DBusError error;
	static char *default_adapter_obj_path = NULL;
	bluetooth_rfcomm_disconnection_t disconnection_ind;

	int index;

	index = __bluetooth_rfcomm_internal_server_get_index_from_socket(server_info->server_sock_fd);
	if (index < 0) {
		DBG("Invalid index %d", index);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (rfcomm_server[index].client_sock_fd != -1) {
		DBG("Trying for Proxy disable\n");
		DBG("Proxy disable for %s\n", rfcomm_server[index].uds_name);
		/* Proxy Disable  Part */
		msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
						   rfcomm_server[index].uds_name,
						   BLUEZ_SERIAL_PROXY_INTERFACE, "Disable");
		if (msg == NULL) {
			DBG("dbus method call is not allocated.");
			return -1;
		}

		dbus_error_init(&error);
		reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);

		dbus_message_unref(msg);

		if (!reply) {
			DBG("Can't Call DisableProxy\n");
			if (dbus_error_is_set(&error)) {
				DBG("%s\n", error.message);
				dbus_error_free(&error);
			}
			return -1;
		}
		dbus_message_unref(reply);

		if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
			DBG("Fail to get default hci adapter path\n");
			return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
		}

		/* Remove Proxy Part */
		DBG("RemoveProxy\n");
		msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
						   default_adapter_obj_path,
						   BLUEZ_SERIAL_MANAGER_INTERFACE, "RemoveProxy");

		g_free(default_adapter_obj_path);

		if (msg == NULL) {
			DBG("dbus method call is not allocated.");
			return -1;
		}

		dbus_message_append_args(msg, DBUS_TYPE_STRING, &rfcomm_server[index].uds_name,
					 DBUS_TYPE_INVALID);

		reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
		dbus_message_unref(msg);

		if (!reply) {
			DBG("Can't Call RemoveProxy\n");
			if (dbus_error_is_set(&error)) {
				DBG("%s\n", error.message);
				dbus_error_free(&error);
			}
			return -1;
		}

		dbus_message_unref(reply);

		disconnection_ind.socket_fd = rfcomm_server[index].client_sock_fd;
		disconnection_ind.device_addr = rfcomm_server[index].device_addr;
		disconnection_ind.uuid = g_strdup(rfcomm_server[index].uuid);
		disconnection_ind.device_role = RFCOMM_ROLE_SERVER;

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
						BLUETOOTH_ERROR_NONE, &disconnection_ind);

		g_free(disconnection_ind.uuid);

		if (rfcomm_server[index].client_sock_fd != -1) {
			g_source_remove(rfcomm_server[index].client_event_src_id);
			rfcomm_server[index].client_sock_fd = -1;
		}

	}

	DBG(" g_source_remove \n");
	if (rfcomm_server[index].is_listen)
		g_source_remove(rfcomm_server[index].server_event_src_id);

	if (rfcomm_server[index].sys_conn) {
		__unregister_agent_authorize_signal(
					rfcomm_server[index].sys_conn,
					&rfcomm_server[index].server_sock_fd);

		dbus_g_connection_unref(rfcomm_server[index].sys_conn);
		rfcomm_server[index].sys_conn = NULL;
	}

	close(rfcomm_server[index].server_sock_fd);
	rfcomm_server[index].server_sock_fd = -1;
	rfcomm_server[index].is_listen = FALSE;

	/*Resetting the connection */
	rfcomm_server[index].id = 0;

	/*Check free rfcomm_server[index].uds_name */
	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;

}

/*Internal client disconnection*/
static int __rfcomm_internal_terminate_client(int index)
{
	DBG("+\n");
	bluetooth_rfcomm_disconnection_t disconnection_ind;

	memset(&disconnection_ind, 0x00,
				sizeof(bluetooth_rfcomm_disconnection_t));

	__bluetooth_rfcomm_internal_disconnect(index);

	disconnection_ind.socket_fd = rfcomm_client[index].sock_fd;
	disconnection_ind.device_addr = rfcomm_client[index].device_addr;
	disconnection_ind.device_role = RFCOMM_ROLE_CLIENT;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
					BLUETOOTH_ERROR_NONE, &disconnection_ind);

	g_source_remove(rfcomm_client[index].event_src_id);
	rfcomm_client[index].event_src_id = -1;

	close(rfcomm_client[index].sock_fd);
	rfcomm_client[index].sock_fd = -1;
	if (rfcomm_client[index].dev_node_name != NULL)
		g_free(rfcomm_client[index].dev_node_name);
	rfcomm_client[index].dev_node_name = NULL;

	rfcomm_client[index].id = -1;
	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

/*Internal connection */
static gboolean __rfcomm_server_connected_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBG("+\n");
	DBG("rfcomm_server.server_io_channel has %d \n", cond);

	DBusMessage *msg, *reply;
	DBusError error;
	DBusMessageIter reply_iter, reply_iter_entry;
	const char *property;

	rfcomm_server_t *server_data = data;
	int fd = g_io_channel_unix_get_fd(chan);
	int index = __bluetooth_rfcomm_internal_server_get_index_from_socket(fd);
	if (index < 0) {
		ERR("Invalid index %d", index);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}
	int server_sock, client_sock;
	int client_addr_len;
	struct sockaddr_un client_sock_addr;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		__rfcomm_internal_terminate_server(server_data);
		return FALSE;
	}

	server_sock = g_io_channel_unix_get_fd(chan);

	memset(&client_sock_addr, 0, sizeof(struct sockaddr_un));
	client_addr_len = sizeof(struct sockaddr_un);

	client_sock = accept(server_sock,
			     (struct sockaddr *)&client_sock_addr, (socklen_t *)&client_addr_len);

	if (client_sock < 0) {
		ERR("Server Accept Error");
		return TRUE;

	} else {
		DBG("Accept Client Sock.(%d)\n", client_sock);

	}

	if (__bluetooth_internal_set_non_blocking_tty(client_sock) < 0) {
		/* Even if setting the tty fails we will continue */
		DBG("Warning!!Setting the tty properties failed(%d)\n", client_sock);
	}

	rfcomm_server[index].client_sock_fd = client_sock;

	rfcomm_server[index].client_io_channel = g_io_channel_unix_new(client_sock);

	g_io_channel_set_encoding(rfcomm_server[index].client_io_channel, NULL, NULL);
	g_io_channel_set_flags(rfcomm_server[index].client_io_channel,
				G_IO_FLAG_NONBLOCK, NULL);

	g_io_channel_set_close_on_unref(rfcomm_server[index].client_io_channel, TRUE);

	rfcomm_server[index].client_event_src_id =
	    g_io_add_watch(rfcomm_server[index].client_io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			   __rfcomm_server_data_received_cb, &rfcomm_server[index]);

	g_io_channel_unref(rfcomm_server[index].client_io_channel);

	/* GetInfo Proxy Part */
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   rfcomm_server[index].uds_name,
					   BLUEZ_SERIAL_PROXY_INTERFACE, "GetInfo");

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return FALSE;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("\nCan't Call GetInfo Proxy\n");
		if (dbus_error_is_set(&error)) {
			ERR("%s\n", error.message);
			dbus_error_free(&error);
		}
		return FALSE;
	}

	dbus_message_iter_init(reply, &reply_iter);

	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		ERR("Can't get reply arguments - DBUS_TYPE_ARRAY\n");
		goto done;
	}

	dbus_message_iter_recurse(&reply_iter, &reply_iter_entry);

	/*Parse the dict */
	while (dbus_message_iter_get_arg_type(&reply_iter_entry) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter dict_entry, dict_entry_val;

		dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);

		DBG("Looping....\n");

		dbus_message_iter_get_basic(&dict_entry, &property);	/*get key value*/
		DBG("String received = %s\n", property);

		if (g_strcmp0("connected", property) == 0) {
			dbus_bool_t value;

			if (!dbus_message_iter_next(&dict_entry)) {
				DBG("Fail 1..\n");
			} else {
				DBG("OK 1..\n");
			}

			if (dbus_message_iter_get_arg_type(&dict_entry) != DBUS_TYPE_VARIANT) {
				DBG("Fail 2..\n");
			} else {
				DBG("OK 2..\n");
			}

			/*Getting the value of the varient*/
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);

			if (dbus_message_iter_get_arg_type(&dict_entry_val) != DBUS_TYPE_BOOLEAN) {
				DBG("Fail 3..\n");
			} else {
				DBG("OK 3..\n");
			}

			dbus_message_iter_get_basic(&dict_entry_val, &value);	/*get value boolean
										value*/

			DBG("Value bool = %d", value);

			if (value == FALSE)
				goto done;

			/*Parsing the address */
			dbus_message_iter_next(&reply_iter_entry);
			dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);
			dbus_message_iter_get_basic(&dict_entry, &property);
			DBG("String received...... = %s\n", property);

			if (g_strcmp0("address", property) == 0) {
				if (!dbus_message_iter_next(&dict_entry)) {
					DBG("Failed getting next dict entry\n");
					goto done;
				}

				if (dbus_message_iter_get_arg_type(&dict_entry) !=
								DBUS_TYPE_VARIANT) {
					DBG("Failed get arg type varient\n");
					goto done;
				}
				/*Getting the value of the varient*/
				dbus_message_iter_recurse(&dict_entry,
							  &dict_entry_val);

				if (dbus_message_iter_get_arg_type(&dict_entry_val) !=
									DBUS_TYPE_STRING) {
					DBG("Failed get arg type string\n");
					goto done;
				}
				/*get  value string address*/
				dbus_message_iter_get_basic(&dict_entry_val, &property);

				DBG("String received >>> = %s\n", property);
				_bluetooth_internal_convert_addr_string_to_addr_type(
						&rfcomm_server[index].device_addr, property);

			}

		}

		dbus_message_iter_next(&reply_iter_entry);
	}

	dbus_message_unref(reply);

	bluetooth_rfcomm_connection_t con_ind;
	con_ind.device_role = RFCOMM_ROLE_SERVER;
	con_ind.device_addr = rfcomm_server[index].device_addr;
	con_ind.socket_fd = rfcomm_server[index].client_sock_fd;
	con_ind.uuid = g_strdup(rfcomm_server[index].uuid);

	/* Unblock the connection accept function */
	connected_fd = rfcomm_server[index].client_sock_fd;
	rfcomm_connected = TRUE;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
					BLUETOOTH_ERROR_NONE, &con_ind);

	g_free(con_ind.uuid);

	DBG("-\n");
	return TRUE;
done:
	dbus_message_unref(reply);
	return FALSE;
}

/*Internal: data indication*/
static gboolean __rfcomm_server_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBG("rfcomm_server.client_io_channel has %d \n", cond);

	char buf[RFCOMM_CLIENT_BUFFER_SIZE] = { 0 };
	unsigned int len;
	rfcomm_server_t *rfcomm_server_info = data;
	bluetooth_rfcomm_received_data_t rx_data;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		DBG("Unix server  disconnected (fd=%d)\n", rfcomm_server_info->client_sock_fd);
		bluetooth_rfcomm_server_disconnect(rfcomm_server_info->client_sock_fd);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));

	if (g_io_channel_read_chars(chan, buf, sizeof(buf), &len, NULL) == G_IO_STATUS_ERROR) {

		DBG("IO Channel read error server");
		bluetooth_rfcomm_server_disconnect(rfcomm_server_info->client_sock_fd);
		return FALSE;
	}

	if (len <= 0) {
		DBG("Read failed len=%d, fd=%d\n",
			len,  rfcomm_server_info->client_sock_fd);
		bluetooth_rfcomm_server_disconnect(rfcomm_server_info->client_sock_fd);
		return FALSE;
	}

	DBG("%s\n", buf);

	rx_data.socket_fd = rfcomm_server_info->client_sock_fd;
	rx_data.buffer_size = len;
	rx_data.buffer = buf;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED,
					BLUETOOTH_ERROR_NONE, &rx_data);

	return TRUE;
}

static gboolean __rfcomm_client_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBG("rfcomm_server.client_io_channel has %d \n", cond);

	char buf[RFCOMM_CLIENT_BUFFER_SIZE] = { 0 };
	unsigned int len;
	rfcomm_client_t *rfcomm_client_info = data;
	bluetooth_rfcomm_received_data_t rx_data;

	int index = rfcomm_client_info->id;
	if ((index < 0) || (index >= RFCOMM_MAX_CONN)) {
		DBG("Invalid index %d ", index);
		return FALSE;
	}

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		DBG("Unix client disconnected (fd=%d)\n", rfcomm_client_info->sock_fd);
		__rfcomm_internal_terminate_client(index);
		return FALSE;
	}

	if (g_io_channel_read_chars(chan, buf, sizeof(buf), &len, NULL) == G_IO_STATUS_ERROR) {

		DBG("IO Channel read error client");
		__rfcomm_internal_terminate_client(index);
		return FALSE;
	}

	if (len <= 0) {
		DBG("Read failed len=%d, Clientfd=%d\n",
			len, rfcomm_client_info->sock_fd);
		__rfcomm_internal_terminate_client(index);
		return FALSE;
	}

	DBG("%s  -  clientfd = %d\n", buf, rfcomm_client_info->sock_fd);
	rx_data.socket_fd = rfcomm_client_info->sock_fd;
	rx_data.buffer_size = len;
	rx_data.buffer = buf;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED,
					BLUETOOTH_ERROR_NONE, &rx_data);

	return TRUE;
}

static int __get_default_adapter_path(char **adapter_path)
{
	DBusError error;
	DBusMessage *msg, *reply;
	const char *reply_path;

	dbus_error_init(&error);
	if (connection == NULL) {
		DBG("Connection is NULL, so getting the System bus");
		connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
		if (connection == NULL)
			return -1;
	}

	if (dbus_error_is_set(&error)) {
		DBG("Unable to connect to DBus :%s \n", error.message);
		dbus_error_free(&error);
		return -1;
	}

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   BLUEZ_MANAGER_OBJ_PATH, BLUEZ_MANAGER_INTERFACE,
					   "DefaultAdapter");

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return -1;
	}

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);

	dbus_message_unref(msg);

	if (!reply) {
		DBG("Can't Call DefaultAdapater");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return -1;
	}

	if (!dbus_message_get_args(reply, &error,
				   DBUS_TYPE_OBJECT_PATH, &reply_path, DBUS_TYPE_INVALID)) {
		DBG("Can't get reply arguments\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		dbus_message_unref(reply);
		return -1;
	}

	*adapter_path = g_strdup(reply_path);
	dbus_message_unref(reply);

	return 0;
}

/* List Proxy */
static int __get_rfcomm_proxy_list(char ***proxy_list, int *len)
{
	DBusError error;
	DBusMessage *msg, *reply;
	int i;
	*len = 0;
	static char *default_adapter_obj_path = NULL;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   default_adapter_obj_path, BLUEZ_SERIAL_MANAGER_INTERFACE,
					   "ListProxies");

	g_free(default_adapter_obj_path);

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return -1;
	}

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("Can't Call CreateProxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return -1;
	}

	if (!dbus_message_get_args(reply, &error,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				   proxy_list, len, DBUS_TYPE_INVALID)) {
		DBG("Can't get reply arguments\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		dbus_message_unref(reply);
		return -1;
	}

	if (*len == 0)
		DBG("There are no previous Proxy: \n");

	for (i = 0; i < *len; i++) {
		DBG("proxy_list[%d]: %s \n", i, *((*proxy_list) + i));
	}

	dbus_message_unref(reply);

	return 0;
}


static gboolean __get_rfcomm_is_match_uuid(char *proxy, const char *uuid)
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	DBusMessageIter reply_iter;
	DBusMessageIter reply_iter_entry;
	const char *property;
	DBusConnection *conn = NULL;

	if (proxy == NULL || uuid == NULL)
		return FALSE;

	/* GetInfo Proxy Part */
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   proxy,
					   BLUEZ_SERIAL_PROXY_INTERFACE, "GetInfo");

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return FALSE;
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("\nCan't Call GetInfo Proxy\n");
		if (dbus_error_is_set(&error)) {
			ERR("%s\n", error.message);
			dbus_error_free(&error);
		}
		dbus_connection_unref(conn);
		return FALSE;
	}

	dbus_message_iter_init(reply, &reply_iter);

	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		ERR("Can't get reply arguments - DBUS_TYPE_ARRAY\n");
		goto done;
	}

	dbus_message_iter_recurse(&reply_iter, &reply_iter_entry);

	/*Parse the dict */
	while (dbus_message_iter_get_arg_type(&reply_iter_entry) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter dict_entry;
		DBusMessageIter dict_entry_val;

		dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);

		dbus_message_iter_get_basic(&dict_entry, &property);	/*get key value*/
		DBG("property = %s\n", property);

		if (g_strcmp0("uuid", property) == 0) {
			const char *value;

			if (!dbus_message_iter_next(&dict_entry))
				DBG("Fail\n");

			if (dbus_message_iter_get_arg_type(&dict_entry) != DBUS_TYPE_VARIANT)
				DBG("Fail\n");

			/*Getting the value of the varient*/
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);

			if (dbus_message_iter_get_arg_type(&dict_entry_val) != DBUS_TYPE_STRING)
				DBG("Fail\n");

			dbus_message_iter_get_basic(&dict_entry_val, &value);

			DBG("uuid = %s", value);

			if (g_ascii_strcasecmp(uuid, value) == 0) {
				dbus_message_unref(reply);
				dbus_connection_unref(conn);
				return TRUE;
			}

		}

		dbus_message_iter_next(&reply_iter_entry);
	}
done:
	dbus_message_unref(reply);
	dbus_connection_unref(conn);

	return FALSE;
}


/*Server Part */
/*
 * SLP 2.0 Bluetooth RFCOMM API
 * input:  UUID
 * Return: Success or negative error value
 * Register RFCOMM Sock with the given UUID on the SDP.
 *
 */
BT_EXPORT_API int bluetooth_rfcomm_create_socket(const char *uuid)
{
	DBG("+\n");
	DBusMessage *msg, *reply;
	const char *reply_path;
	DBusError error;
	char **proxy_list;
	int len;
	char address_string[RFCOMM_ADDRESS_STRING_LEN], tmp[8];
	char *address_string_ptr, *sock_addr_un_ptr;
	int index;
	int ret = 0;
	char *uds_proxy = NULL;
	static char *default_adapter_obj_path = NULL;
	if (NULL == uuid) {
		DBG("uuid is NULL\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	/*Get all the earlier proxies */
	if (__get_rfcomm_proxy_list(&proxy_list, &len) < 0) {
		DBG("Fail to RFCOMM List Proxy\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Proxy count = %d\n", len);
	index = __bluetooth_rfcomm_internal_server_get_free_index();
	if (index < 0) {
		DBG("MAX connection %d only supported", RFCOMM_MAX_CONN);
		return BLUETOOTH_ERROR_MAX_CONNECTION;
	}

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	DBG("Default Adapter Object Path:%s\n", default_adapter_obj_path);

	/* Create Proxy Part */

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   default_adapter_obj_path, BLUEZ_SERIAL_MANAGER_INTERFACE,
					   "CreateProxy");

	g_free(default_adapter_obj_path);

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_strlcpy(address_string, RFCOMM_SER_DEV_PATH, sizeof(address_string));
	DBG("address_string1 = %s\n", address_string);
	snprintf(tmp, 7, "%d", len);
	g_strlcat(address_string, tmp, sizeof(address_string));
	DBG("address_string final = %s\n", address_string);
	address_string_ptr = address_string;

	DBG("**** Dbus args : address = %s, uuid = %s ******\n", address_string_ptr, uuid);
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &uuid,
				 DBUS_TYPE_STRING, &address_string_ptr, DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("\nCan't Call CreateProxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &reply_path, DBUS_TYPE_INVALID)) {
		DBG("\nCan't get reply arguments\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		dbus_message_unref(reply);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	uds_proxy = g_strdup(reply_path);
	rfcomm_server[index].uds_name = uds_proxy;
	rfcomm_server[index].id = index + 1;	/*Incrementing the index by 1 */

	DBG(">>>>>>>>>>rfcomm_server[%d].id = %d\n", index, rfcomm_server[index].id);

	DBG("**** Unix Domain Socket Path %s *****\n", uds_proxy);

	dbus_message_unref(reply);

/* Proxy Enable Part */
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   uds_proxy, BLUEZ_SERIAL_PROXY_INTERFACE, "Enable");

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);

	dbus_message_unref(msg);

	if (!reply) {
		DBG("\nCan't Call CreateProxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}
	dbus_message_unref(reply);

	DBG("uds_proxy = %s, %s", uds_proxy, rfcomm_server[index].uds_name);

/* Make Unix Socket */
	int sk;
	struct sockaddr_un server_addr;

	sk = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sk < 0) {
		perror("\nCan't Create Socket");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	rfcomm_server[index].server_sock_fd = sk;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = PF_UNIX;

	strcpy(address_string, RFCOMM_UDS_PATH);
	snprintf(tmp, 7, "%d", len);
	strcat(address_string, tmp);
	DBG("address_string final = %s\n", address_string);
	sock_addr_un_ptr = address_string;

	DBG("Unix bind path = %s\n", sock_addr_un_ptr);
	strcpy(server_addr.sun_path + 1, sock_addr_un_ptr);

	if (bind(sk, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("\nCan't Bind Sock\n");
		close(sk);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Return fd = %d\n", sk);

	ret = __bluetooth_internal_set_non_blocking(sk);
	DBG("-\n");
	if (ret != 0) {
		DBG("Cannot set the tty%d\n", sk);
		close(sk);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Set the uuid");
	rfcomm_server[index].uuid = g_strdup(uuid);
	return sk;
}

BT_EXPORT_API gboolean bluetooth_rfcomm_is_server_uuid_available(const char *uuid)
{
	DBG("+\n");
	char **proxy_list = NULL;
	int i;
	int len;

	if (uuid == NULL)
		return FALSE;

	if (strlen(uuid) != BT_128_UUID_LEN)
		return FALSE;

	/*Get all proxies */
	if (__get_rfcomm_proxy_list(&proxy_list, &len) < 0) {
		DBG("Fail to RFCOMM List Proxy\n");
		return FALSE;
	}

	DBG("Proxy count = %d\n", len);

	for (i = 0; i < len; i++) {
		if (__get_rfcomm_is_match_uuid(proxy_list[i], uuid) == TRUE)
			return TRUE;
	}

	return FALSE;
}


/*
 * SLP 2.0 Bluetooth RFCOMM API
 * bluetooth_rfcomm_listen_and_accept(int sockfd, int max_pending_connection)"
 *
 */

BT_EXPORT_API int bluetooth_rfcomm_listen_and_accept(int socket_fd, int max_pending_connection)
{
	DBG("+\n");
	int is_success;
	int index;
	static char *default_adapter_obj_path = NULL;

	if (socket_fd <= 0) {
		DBG("\nInvalid fd..");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	index = __bluetooth_rfcomm_internal_server_get_index_from_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d", index);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}
	is_success = listen(socket_fd, max_pending_connection);

	if (is_success == 0)
		rfcomm_server[index].is_listen = TRUE;
	else {
		rfcomm_server[index].is_listen = FALSE;
		DBG("\nListen failed..");
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	if (vconf_set_str(BT_MEMORY_RFCOMM_UUID, "") != 0)
		DBG("\vconf set failed..");

	rfcomm_server[index].server_io_channel = g_io_channel_unix_new(socket_fd);
	g_io_channel_set_close_on_unref(rfcomm_server[index].server_io_channel, TRUE);

	g_io_channel_set_encoding(rfcomm_server[index].server_io_channel, NULL, NULL);
	g_io_channel_set_flags(rfcomm_server[index].server_io_channel,
				G_IO_FLAG_NONBLOCK, NULL);

	rfcomm_server[index].server_event_src_id =
	    g_io_add_watch(rfcomm_server[index].server_io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, __rfcomm_server_connected_cb,
			   &rfcomm_server[index]);
	g_io_channel_unref(rfcomm_server[index].server_io_channel);

	DBG(" -\n is success = %d\n", is_success);
	return is_success;

}

/* To support the BOT  */
static DBusHandlerResult __rfcomm_authorize_event_filter(DBusConnection *sys_conn,
			DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	bluetooth_rfcomm_connection_request_t req_ind = { 0 };
	const char *addr = NULL;
	const char *name = NULL;
	int socket_fd = *((int *)data);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (path == NULL || strcmp(path, "/") == 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_signal(msg, BT_AGENT_INTERFACE, BT_AGENT_SIGNAL_AUTHORIZE)) {
		dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID);
		DBG("Rfcomm Authorize request [%s], [%s]", addr, name);

		if (addr == NULL)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		DBG("socket_fd: %d", socket_fd);

		req_ind.socket_fd = socket_fd;
		requested_server_fd = socket_fd;
		_bluetooth_internal_convert_addr_string_to_addr_type(&req_ind.device_addr, addr);
		_bluetooth_internal_print_bluetooth_device_address_t(&req_ind.device_addr);

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_AUTHORIZE,
						BLUETOOTH_ERROR_NONE, &req_ind);

	} else {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

/* To support the BOT  */
DBusGConnection *__register_agent_authorize_signal(void *user_data)
{
	DBG("+\n");
	DBusGConnection *conn = NULL;
	DBusConnection *dbus_connection = NULL;
	GError *err = NULL;
	DBusError dbus_error;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);
	if (!conn) {
		DBG(" DBUS get failed\n");
		g_error_free(err);
		return NULL;
	}

	dbus_connection = dbus_g_connection_get_connection(conn);

	/* Add the filter for network client functions */
	dbus_error_init(&dbus_error);
	dbus_connection_add_filter(dbus_connection,
				__rfcomm_authorize_event_filter,
				user_data, NULL);
	dbus_bus_add_match(dbus_connection,
			   "type=signal,interface=" BT_AGENT_INTERFACE
			   ",member=Authorize", &dbus_error);
	if (dbus_error_is_set(&dbus_error)) {
		ERR("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
	}

	DBG("-\n");
	return conn;
}

/* To support the BOT  */
static void __unregister_agent_authorize_signal(DBusGConnection *conn, void *user_data)
{
	DBG("+");

	DBusConnection *dbus_connection = NULL;

	if (conn == NULL) {
		DBG("conn is NULL");
		return;
	}

	dbus_connection = dbus_g_connection_get_connection(conn);

	dbus_connection_remove_filter(dbus_connection,
				__rfcomm_authorize_event_filter,
				user_data);

	if (vconf_set_str(BT_MEMORY_RFCOMM_UUID, "") != 0 )
		DBG("\vconf set failed..");

	DBG("-");
}

/* To support the BOT  */
BT_EXPORT_API int bluetooth_rfcomm_listen(int socket_fd, int max_pending_connection)
{
	DBG("+\n");
	int is_success;
	int index;
	static char *default_adapter_obj_path = NULL;

	if (socket_fd <= 0) {
		DBG("\nInvalid fd..");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	index = __bluetooth_rfcomm_internal_server_get_index_from_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d", index);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	rfcomm_server[index].sys_conn = __register_agent_authorize_signal(
						&rfcomm_server[index].server_sock_fd);

	if (rfcomm_server[index].sys_conn == NULL) {
		DBG("Fail to get the dbus connection");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* Store the uuid info to vconf */
	if (rfcomm_server[index].uuid) {
		DBG("Set vconf: %s", rfcomm_server[index].uuid);

		if (vconf_set_str(BT_MEMORY_RFCOMM_UUID,
				rfcomm_server[index].uuid) != 0)
			DBG("\vconf set failed..");
	}

	is_success = listen(socket_fd, max_pending_connection);

	if (is_success == 0)
		rfcomm_server[index].is_listen = TRUE;
	else {
		rfcomm_server[index].is_listen = FALSE;
		DBG("\nListen failed..");
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	rfcomm_server[index].server_io_channel = g_io_channel_unix_new(socket_fd);
	g_io_channel_set_close_on_unref(rfcomm_server[index].server_io_channel, TRUE);

	g_io_channel_set_flags(rfcomm_server[index].server_io_channel,
				G_IO_FLAG_NONBLOCK, NULL);

	rfcomm_server[index].server_event_src_id =
	    g_io_add_watch(rfcomm_server[index].server_io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, __rfcomm_server_connected_cb,
			   &rfcomm_server[index]);
	g_io_channel_unref(rfcomm_server[index].server_io_channel);

	DBG(" -\n is success = %d\n", is_success);
	return is_success;
}

/* To support the BOT  */
BT_EXPORT_API int bluetooth_rfcomm_accept_connection(int server_fd, int *client_fd)
{
	DBG("+");

	int ret = BLUETOOTH_ERROR_NONE;
	unsigned long block_time = 0;
	DBusGConnection *conn = NULL;
	DBusGProxy *agent_proxy = NULL;

	if (server_fd != requested_server_fd) {
		DBG("Not requested fd");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	requested_server_fd = 0;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		DBG("conn is NULL\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	agent_proxy = dbus_g_proxy_new_for_name(conn,
			    "org.bluez.frwk_agent",
			    "/org/bluez/agent/frwk_agent",
			    "org.bluez.Agent");

	if (agent_proxy == NULL) {
		DBG("agent proxy is NULL");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	rfcomm_connected = FALSE;
	connected_fd = 0;

	if (!dbus_g_proxy_call(agent_proxy, "ReplyAuthorize", NULL,
			  G_TYPE_UINT, BT_ACCEPT,
			  G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Fail to ReplyAuthorize");
		ret = BLUETOOTH_ERROR_INTERNAL;
		goto done;
	}

	/* Block until recieve the event (Requirement from BADA) */
	while (rfcomm_connected == FALSE) {
		g_main_context_iteration(NULL, TRUE);
		usleep(SLEEP_TIME); /* Sleep 50ms */
		block_time += SLEEP_TIME;

		if (block_time >= BLOCK_MAX_TIMEOUT)
			return BLUETOOTH_ERROR_TIMEOUT;
	}

	*client_fd = connected_fd;
	rfcomm_connected = FALSE;

	DBG("-");
	return BLUETOOTH_ERROR_NONE;

done:
	g_object_unref(agent_proxy);
	dbus_g_connection_unref(conn);

	DBG("-");

	return ret;
}

/* To support the BOT  */
BT_EXPORT_API int bluetooth_rfcomm_reject_connection(int server_fd)
{
	DBG("+");

	int ret = BLUETOOTH_ERROR_NONE;
	DBusGConnection *conn = NULL;
	DBusGProxy *agent_proxy = NULL;

	if (server_fd != requested_server_fd) {
		DBG("Not requested fd");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	requested_server_fd = 0;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		DBG("conn is NULL\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	agent_proxy = dbus_g_proxy_new_for_name(conn,
			    "org.bluez.frwk_agent",
			    "/org/bluez/agent/frwk_agent",
			    "org.bluez.Agent");

	if (agent_proxy == NULL) {
		DBG("agent proxy is NULL");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_g_proxy_call(agent_proxy, "ReplyAuthorize", NULL,
			  G_TYPE_UINT, BT_REJECT,
			  G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Fail to ReplyAuthorize");
		ret = BLUETOOTH_ERROR_INTERNAL;
	}

	g_object_unref(agent_proxy);
	dbus_g_connection_unref(conn);

	DBG("-");
	return ret;
}

/*
 * SLP 2.0 Bluetooth RFCOMM API
 * bluetooth_rfcomm_remove_socket(int socket_fd)
 *
 */

BT_EXPORT_API int bluetooth_rfcomm_remove_socket(int socket_fd)
{
	DBG("+\n");
	DBusMessage *msg, *reply;
	DBusError error;
	int index;
	static char *default_adapter_obj_path = NULL;

	index = __bluetooth_rfcomm_internal_server_get_index_from_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d", index);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}
	if ((socket_fd != rfcomm_server[index].server_sock_fd)
	    || (NULL == rfcomm_server[index].uds_name)) {
		DBG("\nInvalid server socket \n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

/* Proxy Disable  Part */
	DBG("Proxy disable \n");
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   rfcomm_server[index].uds_name,
					   BLUEZ_SERIAL_PROXY_INTERFACE, "Disable");

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);

	dbus_message_unref(msg);

	if (!reply) {
		DBG("Can't Call DisableProxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}
	dbus_message_unref(reply);

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

/* Remove Proxy Part */
	DBG("- RemoveProxy \n");
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   default_adapter_obj_path, BLUEZ_SERIAL_MANAGER_INTERFACE,
					   "RemoveProxy");

	g_free(default_adapter_obj_path);

	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &rfcomm_server[index].uds_name,
				 DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("Can't Call RemoveProxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	if (rfcomm_server[index].client_sock_fd) {
		bluetooth_rfcomm_disconnection_t disconnection_ind;
		disconnection_ind.socket_fd = rfcomm_server[index].client_sock_fd;
		disconnection_ind.device_addr = rfcomm_server[index].device_addr;
		disconnection_ind.device_role = RFCOMM_ROLE_SERVER;
		disconnection_ind.uuid = g_strdup(rfcomm_server[index].uuid);

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
						BLUETOOTH_ERROR_NONE, &disconnection_ind);

		g_free(disconnection_ind.uuid);

		g_source_remove(rfcomm_server[index].client_event_src_id);
		close(rfcomm_server[index].client_sock_fd);
		rfcomm_server[index].client_sock_fd = -1;
	}

	if (rfcomm_server[index].is_listen)
		g_source_remove(rfcomm_server[index].server_event_src_id);

	if (rfcomm_server[index].sys_conn) {
		__unregister_agent_authorize_signal(
					rfcomm_server[index].sys_conn,
					&rfcomm_server[index].server_sock_fd);

		dbus_g_connection_unref(rfcomm_server[index].sys_conn);
		rfcomm_server[index].sys_conn = NULL;
	}

	close(rfcomm_server[index].server_sock_fd);
	rfcomm_server[index].server_sock_fd = -1;

	rfcomm_server[index].is_listen = FALSE;
	g_free(rfcomm_server[index].uds_name);
	rfcomm_server[index].uds_name = NULL;

	g_free(rfcomm_server[index].uuid);
	rfcomm_server[index].uuid = NULL;

	/*Resetting the connection */
	rfcomm_server[index].id = 0;

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_rfcomm_server_disconnect(int socket_fd)
{
	DBG("+\n");

	bluetooth_rfcomm_disconnection_t disconnection_ind;
	static char *default_adapter_obj_path = NULL;
	bt_info_t *bt_internal_info = NULL;
	int index = 0;
	int ret = BLUETOOTH_ERROR_NONE;

	if (socket_fd <= 0)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	index = __bluetooth_rfcomm_internal_server_get_index_from_client_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d  for socket %d\n", index, socket_fd);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	disconnection_ind.socket_fd = rfcomm_server[index].client_sock_fd;
	disconnection_ind.device_addr = rfcomm_server[index].device_addr;
	disconnection_ind.device_role = RFCOMM_ROLE_SERVER;
	disconnection_ind.uuid = g_strdup(rfcomm_server[index].uuid);
	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_DISCONNECTED,
					BLUETOOTH_ERROR_NONE, &disconnection_ind);

	g_free(disconnection_ind.uuid);

	g_source_remove(rfcomm_server[index].client_event_src_id);
	close(rfcomm_server[index].client_sock_fd);
	rfcomm_server[index].client_sock_fd = -1;

	DBG("-\n");

	return ret;

}

static int __rfcomm_server_disconnect(int socket_fd)
{
	DBG("+\n");

	static char *default_adapter_obj_path = NULL;
	bt_info_t *bt_internal_info = NULL;
	int index = 0;

	if (socket_fd <= 0)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	index = __bluetooth_rfcomm_internal_server_get_index_from_client_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d  for socket %d\n", index, socket_fd);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	g_source_remove(rfcomm_server[index].client_event_src_id);
	close(rfcomm_server[index].client_sock_fd);
	rfcomm_server[index].client_sock_fd = -1;

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;

}

/* Asynchrous implementation */
static void __rfcomm_client_connected_cb(DBusGProxy *proxy, DBusGProxyCall *call,
				       gpointer user_data)
{
	DBG("+\n");
	GError *err = NULL;
	bt_info_t *bt_internal_info = NULL;
	gchar *rfcomm_device_node;

	int dev_node_fd = -1;
	char *dev_node = NULL;
	char *dev_id_str = NULL;
	int result = BLUETOOTH_ERROR_NONE;
	int index = -1;

	bluetooth_event_param_t bt_event = { 0, };
	bluetooth_rfcomm_connection_t con_ind;

	bluetooth_device_address_t *remote_address = user_data;
	DBG("Received BD address = 0x%X:%X:%X:%X:%X:%X", remote_address->addr[0],
	    remote_address->addr[1], remote_address->addr[2], remote_address->addr[3],
	    remote_address->addr[4], remote_address->addr[5]);

	bt_internal_info = _bluetooth_internal_get_information();

	dbus_g_proxy_end_call(proxy, call, &err,
			      G_TYPE_STRING, &rfcomm_device_node, G_TYPE_INVALID);

	g_object_unref(proxy);
	bt_internal_info->rfcomm_proxy = NULL;

	if (err != NULL) {
		DBG("Error occured in connecting port [%s]", err->message);

		if (!strcmp("Host is down", err->message))
			result = BLUETOOTH_ERROR_HOST_DOWN;
		else
			result = BLUETOOTH_ERROR_CONNECTION_ERROR;

		g_error_free(err);

		goto done;
	}

	dev_node = g_strdup(rfcomm_device_node);

	DBG("Succss Connect REMOTE Device RFCOMM Node[%s]", dev_node);
	dev_id_str = dev_node + strlen(RFCOMM_DEV_PATH);

	DBG("ID str = [%s]", dev_id_str);
	if (NULL == dev_id_str) {
		DBG("Invalid index creation");
		result = BLUETOOTH_ERROR_CONNECTION_ERROR;
		goto done;
	}
	index = (int)strtol(dev_id_str, NULL, 10);
	DBG("Index ID = [%d]", index);

	if ((index < 0) || (index >= RFCOMM_MAX_CONN)) {
		DBG("Invalid index %d", index);
		result = BLUETOOTH_ERROR_INVALID_PARAM;
		goto done;
	}

	dev_node_fd = open(dev_node, O_RDWR | O_NOCTTY);

	if (dev_node_fd < 0) {
		DBG("\nCan't open TTY : %s(%d)");
		result = BLUETOOTH_ERROR_CONNECTION_ERROR;
		goto done;
	}

	DBG("\n/dev/rfcomm fd = %d\n", dev_node_fd);

	if (__bluetooth_internal_set_non_blocking_tty(dev_node_fd) < 0) {
		DBG("\nWarning! Unable to set the tty /dev/rfcomm fd = %d\n",
			dev_node_fd);
		/* Even if setting the tty fails we will continue */
	}

	rfcomm_client[index].id = index;
	rfcomm_client[index].sock_fd = dev_node_fd;
	rfcomm_client[index].dev_node_name = dev_node;
	memcpy(&rfcomm_client[index].device_addr, remote_address, BLUETOOTH_ADDRESS_LENGTH);

	rfcomm_client[index].io_channel = g_io_channel_unix_new(dev_node_fd);
	g_io_channel_set_close_on_unref(rfcomm_client[index].io_channel, TRUE);

	g_io_channel_set_flags(rfcomm_client[index].io_channel,
				G_IO_FLAG_NONBLOCK, NULL);

	rfcomm_client[index].event_src_id =
	    g_io_add_watch(rfcomm_client[index].io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			   __rfcomm_client_data_received_cb, &rfcomm_client[index]);

 done:
	memset(&con_ind, 0x00, sizeof(bluetooth_rfcomm_connection_t));
	memcpy(&con_ind.device_addr, remote_address, BLUETOOTH_ADDRESS_LENGTH);

	if (result == BLUETOOTH_ERROR_NONE) {
		con_ind.socket_fd = rfcomm_client[index].sock_fd;
	} else {
		con_ind.socket_fd = -1;

		/* We are freeing dev_node in error case only. Success case
		 * will be handled during disconnection */
		g_free(dev_node);
	}

	con_ind.device_role = RFCOMM_ROLE_CLIENT;
	con_ind.uuid = bt_internal_info->connecting_uuid;
	bt_event.event = BLUETOOTH_EVENT_RFCOMM_CONNECTED;
	bt_event.result = result;
	bt_event.param_data = (void *)&con_ind;

	if (bt_internal_info->bt_cb_ptr) {
		DBG("Going to call the callback");
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}

	g_free(bt_internal_info->connecting_uuid);
	bt_internal_info->connecting_uuid = NULL;

	free(remote_address);
	DBG("-\n");

}

static void __bluetooth_rfcomm_discover_services_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data)
{
	GError *err = NULL;
	GHashTable *hash;
	const char *dev_path = NULL;
	bt_info_t *bt_internal_info = NULL;
	DBusGConnection *conn;
	DBusGProxy *rfcomm_proxy = NULL;
	bluetooth_rfcomm_connection_t con_ind;
	bluetooth_device_address_t *remote_address = user_data;

	dbus_g_proxy_end_call(proxy, call, &err,
			dbus_g_type_get_map("GHashTable",
			G_TYPE_UINT, G_TYPE_STRING),
			&hash, G_TYPE_INVALID);

	bt_internal_info = _bluetooth_internal_get_information();

	memset(&con_ind, 0x00, sizeof(bluetooth_rfcomm_connection_t));
	memcpy(&con_ind.device_addr, remote_address, BLUETOOTH_ADDRESS_LENGTH);
	con_ind.device_role = RFCOMM_ROLE_CLIENT;
	con_ind.uuid = bt_internal_info->connecting_uuid;

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n", err->message);

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
					BLUETOOTH_ERROR_CONNECTION_ERROR, &con_ind);

		g_error_free(err);
		goto fail;
	}

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		DBG("ERROR: Can't get on system bus");
		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
					BLUETOOTH_ERROR_INTERNAL, &con_ind);

		goto fail;
	}

	dev_path = dbus_g_proxy_get_path(proxy);

	rfcomm_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
						dev_path,
						BLUEZ_SERIAL_CLIENT_INTERFACE);

	g_object_unref(proxy);
	proxy = NULL;

	dbus_g_connection_unref(conn);

	if (rfcomm_proxy == NULL) {
		DBG("Failed to get the rfcomm proxy\n");

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
					BLUETOOTH_ERROR_SERVICE_NOT_FOUND, &con_ind);

		goto fail;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	bt_internal_info->rfcomm_proxy = rfcomm_proxy;

	if (!dbus_g_proxy_begin_call(rfcomm_proxy, "Connect",
			(DBusGProxyCallNotify)__rfcomm_client_connected_cb,
			(gpointer)remote_address,	/*user_data*/
			NULL,	/*destroy*/
			G_TYPE_STRING, bt_internal_info->connecting_uuid,
			G_TYPE_INVALID)) {
		DBG("RFCOMM connect Dbus Call Error");

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_RFCOMM_CONNECTED,
					BLUETOOTH_ERROR_INTERNAL, &con_ind);
		goto fail;
	}

	DBG("-\n");

	return;
fail:
	if (rfcomm_proxy)
		g_object_unref(rfcomm_proxy);

	if (proxy)
		g_object_unref(proxy);

	g_free(remote_address);
	g_free(bt_internal_info->connecting_uuid);
	bt_internal_info->connecting_uuid = NULL;
	bt_internal_info->rfcomm_proxy = NULL;
}

BT_EXPORT_API int bluetooth_rfcomm_connect(const bluetooth_device_address_t *remote_bt_address,
						const char *remote_uuid)
{
	DBG("+\n");
	gchar *address_up;
	gchar *remote_device_path;
	char str_addr[20];
	DBusGProxy *device_proxy = NULL;
	bluetooth_device_address_t *remote_address;
	GError *err = NULL;
	DBusGConnection *conn;
	bt_info_t *bt_internal_info = NULL;
	static char *default_adapter_obj_path = NULL;
	memset(str_addr, 0, 20);

	if ((NULL == remote_bt_address) || (NULL == remote_uuid)) {
		DBG("Error: Invalid param\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	DBG("Default Adapter Object Path:%s\n", default_adapter_obj_path);
	_bluetooth_internal_addr_type_to_addr_string(str_addr, remote_bt_address);

	address_up = g_ascii_strup(str_addr, -1);
	DBG("BD addr str = %s, address_up = %s\n", str_addr, address_up);
	remote_device_path = g_strdup_printf("%s/dev_%s", default_adapter_obj_path, address_up);
	g_free(default_adapter_obj_path);
	g_strdelimit(remote_device_path, ":", '_');
	DBG("Remote device path = %s\n", remote_device_path);

	g_free(address_up);

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);
	if (!conn) {
		DBG("ERROR: Can't get on system bus [%s]", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	device_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
				      remote_device_path, BLUEZ_DEVICE_INTERFACE);

	dbus_g_connection_unref(conn);

	g_free(remote_device_path);

	if (device_proxy == NULL)
		return BLUETOOTH_ERROR_NOT_PAIRED;

	bt_internal_info = _bluetooth_internal_get_information();

	bt_internal_info->connecting_uuid = g_strdup(remote_uuid);
	remote_address = g_malloc0(sizeof(bluetooth_device_address_t));
	memcpy(remote_address, remote_bt_address, sizeof(bluetooth_device_address_t));

	DBG("Send BD address = 0x%X:%X:%X:%X:%X:%X", remote_address->addr[0],
	    remote_address->addr[1], remote_address->addr[2], remote_address->addr[3],
	    remote_address->addr[4], remote_address->addr[5]);

	if (!dbus_g_proxy_begin_call(device_proxy, "DiscoverServices",
			(DBusGProxyCallNotify)__bluetooth_rfcomm_discover_services_cb,
			(gpointer)remote_address, NULL,
			G_TYPE_STRING, bt_internal_info->connecting_uuid,
			G_TYPE_INVALID)) {
		DBG("Could not call dbus proxy\n");
		g_object_unref(device_proxy);
		g_free(remote_address);
		g_free(bt_internal_info->connecting_uuid);
		bt_internal_info->connecting_uuid = NULL;
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

static int __bluetooth_rfcomm_internal_disconnect(int index)
{
	DBusMessage *msg, *reply;
	DBusError error;

	gchar *address_up;
	gchar *remote_device_path;

	bluetooth_device_address_t remote_bt_address;
	char *dev_node;
	static char *default_adapter_obj_path = NULL;
	char str_addr[20];
	memset(str_addr, 0, 20);

	remote_bt_address = rfcomm_client[index].device_addr;
	dev_node = rfcomm_client[index].dev_node_name;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	DBG("Des add =  0x%x:%x:%x:%x:%x:%x\n", remote_bt_address.addr[0],
	    remote_bt_address.addr[1], remote_bt_address.addr[2], remote_bt_address.addr[3],
	    remote_bt_address.addr[4], remote_bt_address.addr[5]);
	DBG("Default Adapter Object Path:%s\n", default_adapter_obj_path);

	_bluetooth_internal_addr_type_to_addr_string(str_addr, &remote_bt_address);
	address_up = g_ascii_strup(str_addr, -1);

	DBG("BD addr str = %s, address_up = %s\n", str_addr, address_up);
	remote_device_path = g_strdup_printf("%s/dev_%s", default_adapter_obj_path, address_up);
	g_free(default_adapter_obj_path);
	g_strdelimit(remote_device_path, ":", '_');
	DBG("Remote device path == %s\n", remote_device_path);
	g_free(address_up);
	/* Disconnect */
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   remote_device_path, BLUEZ_SERIAL_CLIENT_INTERFACE,
					   "Disconnect");
	if (msg == NULL) {
		DBG("dbus method call is not allocated.");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Device node name = %s\n", dev_node);
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &dev_node, DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		int bt_rfcomm_client_return = BLUETOOTH_ERROR_ACCESS_DENIED;
		DBG("Error While Call Serial.Conncet\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);

			if (g_strcmp0("org.bluez.Error.InvalidArguments", error.message) == 0)
				bt_rfcomm_client_return = BLUETOOTH_ERROR_INVALID_PARAM;
			else if (g_strcmp0("org.bluez.Error.DoesNotExist", error.message) == 0)
				bt_rfcomm_client_return = BLUETOOTH_ERROR_NOT_SUPPORT;

			dbus_error_free(&error);
		}
		return bt_rfcomm_client_return;
	}
	DBG("Succss Disconnect REMOTE Device RFCOMM Node[%s]\n", dev_node);

	g_free(remote_device_path);
	dbus_message_unref(reply);
	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;

}

static int __bluetooth_cancel_connecting(DBusGProxy *proxy)
{

	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;
	GError *error = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->connecting_uuid == NULL) {
		DBG("uuid is NULL");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_g_proxy_call(proxy,
			"Disconnect",
			&error,
			G_TYPE_STRING, bt_internal_info->connecting_uuid,
			G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Disconnect Dbus Call Error, %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_free(bt_internal_info->connecting_uuid);
	bt_internal_info->connecting_uuid = NULL;

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}


BT_EXPORT_API int bluetooth_rfcomm_disconnect(int socket_fd)
{
	DBG("+\n");

	static char *default_adapter_obj_path = NULL;
	bt_info_t *bt_internal_info = NULL;
	int index = 0;
	int ret = BLUETOOTH_ERROR_NONE;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (socket_fd <= 0) {
		/* Cancel connecting request */
		if (bt_internal_info->rfcomm_proxy == NULL) {
			DBG("No connecting request");
			return BLUETOOTH_ERROR_NOT_IN_OPERATION;
		}

		if (__bluetooth_cancel_connecting(
			bt_internal_info->rfcomm_proxy) !=
					BLUETOOTH_ERROR_NONE) {
			return BLUETOOTH_ERROR_INTERNAL;
		}

		g_object_unref(bt_internal_info->rfcomm_proxy);
		bt_internal_info->rfcomm_proxy = NULL;
		return BLUETOOTH_ERROR_NONE;
	}

	index = __bluetooth_rfcomm_internal_client_get_index_from_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d  for socket %d\n", index, socket_fd);

		/* Try to disconnect server socket */
		return __rfcomm_server_disconnect(socket_fd);
	}

	if (!(socket_fd && (socket_fd == rfcomm_client[index].sock_fd)) ||
	       (NULL == rfcomm_client[index].dev_node_name)) {
		DBG("Invalid FD %d  - %d\n", socket_fd, rfcomm_client[index].sock_fd);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	ret = __bluetooth_rfcomm_internal_disconnect(index);

	if (ret != BLUETOOTH_ERROR_NONE)
		return ret;

	g_source_remove(rfcomm_client[index].event_src_id);
	rfcomm_client[index].event_src_id = -1;

	close(rfcomm_client[index].sock_fd);
	rfcomm_client[index].sock_fd = -1;
	if (rfcomm_client[index].dev_node_name != NULL)
		g_free(rfcomm_client[index].dev_node_name);
	rfcomm_client[index].dev_node_name = NULL;

	rfcomm_client[index].id = -1;

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;

}

BT_EXPORT_API int bluetooth_rfcomm_write(int fd, const char *buf, int length)
{
	DBG("\bluetooth_rfcomm_write() +\n");
	int wbytes = 0, written = 0;
	static char *default_adapter_obj_path = NULL;

	if ((fd <= 0) || (NULL == buf) || (length <= 0)) {
		DBG("Invalid arguments..\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	/*some times user may send huge data */
	while (wbytes < length) {
		written = write(fd, buf + wbytes, length - wbytes);
		if (written <= 0) {
			DBG("write failed..\n");
			return BLUETOOTH_ERROR_NOT_IN_OPERATION;
		}

		/* Synchronize the sending buffer */
		sync();
		fsync(fd);

		wbytes += written;
	}

	return BLUETOOTH_ERROR_NONE;
	DBG("-\n");
}

static gboolean __is_rfcomm_connected(DBusGConnection *conn, DBusGProxy *adapter,
				const bluetooth_device_address_t *bd_addr)
{
	DBG("+\n");

	char *object_path = NULL;
	char addr_str[BT_ADDRESS_STRING_SIZE];
	gboolean connected = FALSE;
	DBusGProxy *proxy = NULL;
	GError *error = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;

	if (adapter == NULL || bd_addr == NULL)
		return FALSE;

	_bluetooth_internal_addr_type_to_addr_string(addr_str, bd_addr);

	dbus_g_proxy_call(adapter, "FindDevice",
			  &error, G_TYPE_STRING, addr_str,
			  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
			  &object_path, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Failed to Find device: %s\n", error->message);
		g_error_free(error);
		return FALSE;
	}

	if (object_path == NULL)
		return FALSE;

	proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME, object_path,
						BLUEZ_SERIAL_CLIENT_INTERFACE);

	if (proxy == NULL)
		return FALSE;

	dbus_g_proxy_call(proxy, "GetProperties", &error,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Failed to get properties: %s\n", error->message);
		g_error_free(error);
		g_object_unref(proxy);
		return FALSE;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Connected");
		connected = value ? g_value_get_boolean(value) : FALSE;
	}

	g_object_unref(proxy);

	DBG("-\n");

	return connected;
}

BT_EXPORT_API gboolean bluetooth_rfcomm_is_client_connected()
{
	DBG("+\n");

	GError *error = NULL;
	DBusGConnection *conn = NULL;
	char *adapter_path = NULL;
	GPtrArray *dev_list = NULL;
	bluetooth_device_info_t *p = NULL;
	gboolean connected = FALSE;
	int ret = 0;
	int i;
	DBusGProxy *adapter = NULL;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);

	if (error != NULL) {
		DBG("Unable to connect to DBus :%s \n", error->message);
		g_error_free(error);
		goto done;
	}

	if (__get_default_adapter_path(&adapter_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		goto done;
	}

	adapter = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
					adapter_path, BLUEZ_ADAPTER_INTERFACE);

	g_free(adapter_path);

	if (adapter == NULL)
		goto done;

	dev_list = g_ptr_array_new();

	ret = bluetooth_get_bonded_device_list(&dev_list);

	if (ret != BLUETOOTH_ERROR_NONE) {
		DBG("Get bonded list failed : Error cause[%d]", ret);
		goto done;
	}

	if (dev_list == NULL || dev_list->len == 0) {
		DBG("There is no paired device");
		goto done;
	}

	for (i = 0; i < dev_list->len; i++) {
		p = g_ptr_array_index(dev_list, i);
		if (!p) {
			DBG("device is none");
			break;
		}

		if (__is_rfcomm_connected(conn, adapter, &p->device_address) == TRUE) {
			free(p);
			g_ptr_array_free(dev_list, TRUE);
			connected = TRUE;
			goto done;
		}

		free(p);
	}

	g_ptr_array_free(dev_list, TRUE);
done:
	if (adapter)
		g_object_unref(adapter);

	if (conn)
		dbus_g_connection_unref(conn);

	DBG("connected: %d", connected);

	return connected;
}


static int __bluetooth_internal_set_non_blocking(int sk)
{
	/* Set Nonblocking */
	long arg;

	arg = fcntl(sk, F_GETFL);

	if (arg < 0)
		return -errno;

	if (arg & O_NONBLOCK) {
		DBG("Already Non-blocking \n");
	}

	arg |= O_NONBLOCK;

	if (fcntl(sk, F_SETFL, arg) < 0)
		return -errno;

	return 0;
}

static int __bluetooth_internal_set_non_blocking_tty(int sk)
{
	struct termios ti = {0,};
	int err = 0;

	err = __bluetooth_internal_set_non_blocking(sk);

	if (err < 0) {
		ERR("Error in set non blocking!\n");
		return err;
	}

	/*Setting tty line disipline*/
	DBG("\nsetting  raw\n");

	tcflush(sk, TCIOFLUSH);

	/* Switch tty to RAW mode */
	cfmakeraw(&ti);
	tcsetattr(sk, TCSANOW, &ti);

	return 0;
}

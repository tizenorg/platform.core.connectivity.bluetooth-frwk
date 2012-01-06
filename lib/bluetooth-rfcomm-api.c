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
#include <sys/ioctl.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/stat.h>

#include "bluetooth-rfcomm-api.h"

#define BLUEZ_SERVICE_NAME "org.bluez"
#define BLUEZ_SERIAL_CLINET_INTERFACE "org.bluez.Serial"

#define BLUEZ_MANAGER_OBJ_PATH "/"
#define BLUEZ_MANAGER_INTERFACE "org.bluez.Manager"

#define BLUEZ_SERIAL_MANAGER_INTERFACE "org.bluez.SerialProxyManager"
#define BLUEZ_SERIAL_PROXY_INTERFACE	"org.bluez.SerialProxy"

#define RFCOMM_CLIENT_BUFFER_SIZE 1024
#define RFCOMM_UDS_PATH "/bluez/rfcomm"
#define RFCOMM_DEV_PATH "/dev/rfcomm"
#define RFCOMM_SER_DEV_PATH "x00/bluez/rfcomm"

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

static int __bluetooth_internal_set_nonblocking(int sk);

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
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	static char *default_adapter_obj_path = NULL;
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

		dbus_message_append_args(msg, DBUS_TYPE_STRING, &rfcomm_server[index].uds_name,
					 DBUS_TYPE_INVALID);

		dbus_error_init(&error);
		g_free(default_adapter_obj_path);
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
		bt_internal_info = _bluetooth_internal_get_information();
		if (bt_internal_info->bt_cb_ptr) {
			bluetooth_rfcomm_disconnection_t disconnection_ind;
			bt_event.event = BLUETOOTH_EVENT_RFCOMM_DISCONNECTED;
			bt_event.result = BLUETOOTH_ERROR_NONE;
			disconnection_ind.socket_fd = rfcomm_server[index].client_sock_fd;
			disconnection_ind.device_addr = rfcomm_server[index].device_addr;
			bt_event.param_data = (void *)(&disconnection_ind);
			bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event,
						    bt_internal_info->user_data);
		}

		if (rfcomm_server[index].client_sock_fd != -1) {
			g_source_remove(rfcomm_server[index].client_event_src_id);
			rfcomm_server[index].client_sock_fd = -1;
		}

	}

	DBG(" g_source_remove \n");
	if (rfcomm_server[index].is_listen)
		g_source_remove(rfcomm_server[index].server_event_src_id);
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
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	bt_internal_info = _bluetooth_internal_get_information();

	__bluetooth_rfcomm_internal_disconnect(index);

	if (bt_internal_info->bt_cb_ptr) {
		bluetooth_rfcomm_disconnection_t disconnection_ind;

		bt_event.event = BLUETOOTH_EVENT_RFCOMM_DISCONNECTED;
		bt_event.result = BLUETOOTH_ERROR_NONE;
		disconnection_ind.socket_fd = rfcomm_client[index].sock_fd;
		disconnection_ind.device_addr = rfcomm_client[index].device_addr;
		bt_event.param_data = (void *)(&disconnection_ind);

		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);

	}

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

	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	DBusMessage *msg, *reply;
	DBusError error;
	DBusMessageIter reply_iter, reply_iter_entry;
	const char *property;

	rfcomm_server_t *server_data = data;
	int fd = g_io_channel_unix_get_fd(chan);
	int index = __bluetooth_rfcomm_internal_server_get_index_from_socket(fd);
	if (index < 0) {
		DBG("Invalid index %d", index);
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
		perror("Server Accept Error");
		return TRUE;

	} else {
		DBG("Accept Client Sock.(%d)\n", client_sock);

	}

	long arg;

	arg = fcntl(client_sock, F_GETFL);

	if (arg < 0)
		return -errno;

	if (arg & O_NONBLOCK) {
		DBG("Already blocking \n");
		arg ^= O_NONBLOCK;
	}

	if (fcntl(client_sock, F_SETFL, arg) < 0)
		return -errno;

	rfcomm_server[index].client_sock_fd = client_sock;

	rfcomm_server[index].client_io_channel = g_io_channel_unix_new(client_sock);

	g_io_channel_set_close_on_unref(rfcomm_server[index].client_io_channel, TRUE);

	rfcomm_server[index].client_event_src_id =
	    g_io_add_watch(rfcomm_server[index].client_io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			   __rfcomm_server_data_received_cb, &rfcomm_server[index]);

	g_io_channel_unref(rfcomm_server[index].client_io_channel);
	bt_internal_info = _bluetooth_internal_get_information();



	/* GetInfo Proxy Part */
	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   rfcomm_server[index].uds_name,
					   BLUEZ_SERIAL_PROXY_INTERFACE, "GetInfo");

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &error);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("\nCan't Call GetInfo Proxy\n");
		if (dbus_error_is_set(&error)) {
			DBG("%s\n", error.message);
			dbus_error_free(&error);
		}
		return -1;
	}

	dbus_message_iter_init(reply, &reply_iter);

	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		DBG("Can't get reply arguments - DBUS_TYPE_ARRAY\n");
		dbus_message_unref(reply);
		return -1;
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

			/*Parsing the address */
			if (value == TRUE) {
				dbus_message_iter_next(&reply_iter_entry);
				dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);
				dbus_message_iter_get_basic(&dict_entry, &property);	/*get key
											value*/
				DBG("String received...... = %s\n", property);

				if (g_strcmp0("address", property) == 0) {
					if (!dbus_message_iter_next(&dict_entry)) {
						DBG("Failed getting next dict entry\n");
						return -1;
					}

					if (dbus_message_iter_get_arg_type(&dict_entry) !=
					    DBUS_TYPE_VARIANT) {
						DBG("Failed get arg type varient\n");
						return -1;
					}
					/*Getting the value of the varient*/
					dbus_message_iter_recurse(&dict_entry,
								  &dict_entry_val);

					if (dbus_message_iter_get_arg_type(&dict_entry_val)
					    != DBUS_TYPE_STRING) {
						DBG("Failed get arg type string\n");
						return -1;
					}
					/*get  value string address*/
					dbus_message_iter_get_basic(&dict_entry_val, &property);

					DBG("String received >>> = %s\n", property);
					_bluetooth_internal_convert_addr_string_to_addr_type(
							&rfcomm_server[index].device_addr, property);

				}

			} else
				return -1;

		}

		dbus_message_iter_next(&reply_iter_entry);
	}

	bluetooth_rfcomm_connection_t con_ind;
	con_ind.device_role = RFCOMM_ROLE_SERVER;
	con_ind.device_addr = rfcomm_server[index].device_addr;
	con_ind.socket_fd = rfcomm_server[index].client_sock_fd;
	bt_event.event = BLUETOOTH_EVENT_RFCOMM_CONNECTED;
	bt_event.result = BLUETOOTH_ERROR_NONE;
	bt_event.param_data = (void *)&con_ind;

	if (bt_internal_info->bt_cb_ptr) {
		DBG("\ngoing to call callback BLUETOOTH_EVENT_RFCOMM_CONNECTED \n");
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}

	DBG("-\n");
	return TRUE;
}

/*Internal: data indication*/
static gboolean __rfcomm_server_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBG("rfcomm_server.client_io_channel has %d \n", cond);

	char buf[RFCOMM_CLIENT_BUFFER_SIZE] = { 0 };
	unsigned int len;
	rfcomm_server_t *rfcomm_server_info = data;
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		DBG("Unix server  disconnected (fd=%d)\n", rfcomm_server_info->client_sock_fd);
		__rfcomm_internal_terminate_server(rfcomm_server_info);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));

	if (g_io_channel_read(chan, buf, sizeof(buf), &len) != G_IO_ERROR_NONE) {

		DBG("IO Channel read error server");
		__rfcomm_internal_terminate_server(rfcomm_server_info);
		return FALSE;
	}

	if (len <= 0) {
		DBG("Read failed len=%d, fd=%d\n",
			len,  rfcomm_server_info->client_sock_fd);
		__rfcomm_internal_terminate_server(rfcomm_server_info);
		return FALSE;
	}

	DBG("%s\n", buf);
	bt_internal_info = _bluetooth_internal_get_information();
	if (bt_internal_info->bt_cb_ptr) {
		bluetooth_rfcomm_received_data_t rx_data;
		rx_data.socket_fd = rfcomm_server_info->client_sock_fd;
		rx_data.buffer_size = len;
		rx_data.buffer = buf;
		bt_event.event = BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED;
		bt_event.result = BLUETOOTH_ERROR_NONE;
		bt_event.param_data = (void *)&rx_data;

		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);

	}

	return TRUE;
}

static gboolean __rfcomm_client_data_received_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBG("rfcomm_server.client_io_channel has %d \n", cond);

	char buf[RFCOMM_CLIENT_BUFFER_SIZE] = { 0 };
	unsigned int len;
	rfcomm_client_t *rfcomm_client_info = data;
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
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

	if (g_io_channel_read(chan, buf, sizeof(buf), &len) != G_IO_ERROR_NONE) {

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

	bt_internal_info = _bluetooth_internal_get_information();
	if (bt_internal_info->bt_cb_ptr) {
		DBG("%s  -  clientfd = %d\n", buf, rfcomm_client_info->sock_fd);
		bluetooth_rfcomm_received_data_t rx_data;
		rx_data.socket_fd = rfcomm_client_info->sock_fd;
		rx_data.buffer_size = len;
		rx_data.buffer = buf;
		bt_event.event = BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED;
		bt_event.result = BLUETOOTH_ERROR_NONE;
		bt_event.param_data = (void *)&rx_data;

		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);

	}
	return TRUE;
}

static int __get_default_adapter_path(char **adapter_path)
{
	DBusError error;
	DBusMessage *msg, *reply;
	const char *reply_path;

	dbus_error_init(&error);
	if (NULL == connection) {
		DBG("Connection is NULL, so getting the System bus");
		connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	}

	if (dbus_error_is_set(&error)) {
		DBG("Unable to connect to DBus :%s \n", error.message);
		dbus_error_free(&error);
		return -1;
	}

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					   BLUEZ_MANAGER_OBJ_PATH, BLUEZ_MANAGER_INTERFACE,
					   "DefaultAdapter");

	dbus_error_init(&error);
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

	dbus_error_init(&error);
	g_free(default_adapter_obj_path);
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

	/*Assign index */
	len = index;

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
	dbus_message_unref(reply);

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
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Return fd = %d\n", sk);
	DBG("-\n");

	ret = __bluetooth_internal_set_nonblocking(sk);
	if (ret != 0)
		return ret;
	else
		return sk;
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

	rfcomm_server[index].server_io_channel = g_io_channel_unix_new(socket_fd);
	g_io_channel_set_close_on_unref(rfcomm_server[index].server_io_channel, TRUE);

	rfcomm_server[index].server_event_src_id =
	    g_io_add_watch(rfcomm_server[index].server_io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, __rfcomm_server_connected_cb,
			   &rfcomm_server[index]);
	g_io_channel_unref(rfcomm_server[index].server_io_channel);

	DBG(" -\n is success = %d\n", is_success);
	return is_success;

}

/*
 * SLP 2.0 Bluetooth RFCOMM API
 * bluetooth_rfcomm_remove_socket(int socket_fd, const char *uuid)
 *
 */

BT_EXPORT_API int bluetooth_rfcomm_remove_socket(int socket_fd, const char *uuid)
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

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &rfcomm_server[index].uds_name,
				 DBUS_TYPE_INVALID);

	dbus_error_init(&error);
	g_free(default_adapter_obj_path);
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

	if (rfcomm_server[index].client_sock_fd) {
		bluetooth_event_param_t bt_event = { 0, };
		bt_info_t *bt_internal_info = NULL;
		bt_internal_info = _bluetooth_internal_get_information();
		if (bt_internal_info->bt_cb_ptr) {
			bluetooth_rfcomm_disconnection_t disconnection_ind;
			bt_event.event = BLUETOOTH_EVENT_RFCOMM_DISCONNECTED;
			bt_event.result = BLUETOOTH_ERROR_NONE;
			disconnection_ind.socket_fd = rfcomm_server[index].client_sock_fd;
			disconnection_ind.device_addr = rfcomm_server[index].device_addr;
			bt_event.param_data = (void *)(&disconnection_ind);
			bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event,
						    bt_internal_info->user_data);
		}

		g_source_remove(rfcomm_server[index].client_event_src_id);
		close(rfcomm_server[index].client_sock_fd);
		rfcomm_server[index].client_sock_fd = -1;
	}

	if (rfcomm_server[index].is_listen)
		g_source_remove(rfcomm_server[index].server_event_src_id);

	close(rfcomm_server[index].server_sock_fd);
	rfcomm_server[index].server_sock_fd = -1;

	rfcomm_server[index].is_listen = FALSE;
	g_free(rfcomm_server[index].uds_name);
	rfcomm_server[index].uds_name = NULL;

	/*Resetting the connection */
	rfcomm_server[index].id = 0;

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

	DBG("+");

	bt_internal_info = _bluetooth_internal_get_information();

	dbus_g_proxy_end_call(proxy, call, &err,
			      G_TYPE_STRING, &rfcomm_device_node, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in connecting port [%s]", err->message);

		if (!strcmp("Host is down", err->message))
			result = BLUETOOTH_ERROR_HOST_DOWN;
		else
			result = BLUETOOTH_ERROR_CONNECTION_ERROR;

		g_error_free(err);

		goto done;
	}

	g_object_unref(proxy);

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

	rfcomm_client[index].id = index;
	rfcomm_client[index].sock_fd = dev_node_fd;
	rfcomm_client[index].dev_node_name = dev_node;
	memcpy(&rfcomm_client[index].device_addr, remote_address, BLUETOOTH_ADDRESS_LENGTH);

	rfcomm_client[index].io_channel = g_io_channel_unix_new(dev_node_fd);

	g_io_channel_set_close_on_unref(rfcomm_client[index].io_channel, TRUE);

	rfcomm_client[index].event_src_id =
	    g_io_add_watch(rfcomm_client[index].io_channel,
			   G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			   __rfcomm_client_data_received_cb, &rfcomm_client[index]);

 done:

	if (result == BLUETOOTH_ERROR_NONE) {
		con_ind.socket_fd = rfcomm_client[index].sock_fd;
		con_ind.device_addr = rfcomm_client[index].device_addr;
	} else {
		con_ind.socket_fd = -1;
		memcpy(&con_ind.device_addr, remote_address, BLUETOOTH_ADDRESS_LENGTH);

		/* We are freeing dev_node in error case only. Success case
		 * will be handled during disconnection */
		g_free(dev_node);
	}

	con_ind.device_role = RFCOMM_ROLE_CLIENT;
	bt_event.event = BLUETOOTH_EVENT_RFCOMM_CONNECTED;
	bt_event.result = result;
	bt_event.param_data = (void *)&con_ind;

	if (bt_internal_info->bt_cb_ptr) {
		DBG("Going to call the callback");
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}

	free(remote_address);
	DBG("-\n");

}

DBusGProxy *proxy_rfcomm_client = NULL;

BT_EXPORT_API int bluetooth_rfcomm_connect(const bluetooth_device_address_t *remote_bt_address,
						const char *remote_uuid)
{
	DBG("+\n");
	gchar *address_up;
	gchar *remote_device_path;
	char str_addr[20];
	bluetooth_device_address_t *remote_address;
	GError *err = NULL;
	DBusGConnection *conn;
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
		return BLUETOOTH_ERROR_CONNECTION_ERROR;
	}

	proxy_rfcomm_client = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME,
							remote_device_path,
							BLUEZ_SERIAL_CLINET_INTERFACE);
	g_free(remote_device_path);

	if (proxy_rfcomm_client == NULL) {
		DBG("Failed to get the network server proxy\n");
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	remote_address = malloc(sizeof(bluetooth_device_address_t));
	memcpy(remote_address, remote_bt_address, sizeof(bluetooth_device_address_t));

	DBG("Send BD address = 0x%X:%X:%X:%X:%X:%X", remote_address->addr[0],
	    remote_address->addr[1], remote_address->addr[2], remote_address->addr[3],
	    remote_address->addr[4], remote_address->addr[5]);

	if (!dbus_g_proxy_begin_call(proxy_rfcomm_client, "Connect",
					(DBusGProxyCallNotify)__rfcomm_client_connected_cb,
					(gpointer)remote_address,	/*user_data*/
					NULL,	/*destroy*/
					G_TYPE_STRING, remote_uuid,	/*first_arg_type*/
					G_TYPE_INVALID)) {
		DBG("Network server register Dbus Call Error");
		free(remote_address);
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
					   remote_device_path, BLUEZ_SERIAL_CLINET_INTERFACE,
					   "Disconnect");
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

BT_EXPORT_API int bluetooth_rfcomm_disconnect(int socket_fd)
{

	DBG("+\n");

	static char *default_adapter_obj_path = NULL;
	int index = 0;

	if (__get_default_adapter_path(&default_adapter_obj_path) < 0) {
		DBG("Fail to get default hci adapter path\n");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	index = __bluetooth_rfcomm_internal_client_get_index_from_socket(socket_fd);
	if (index < 0) {
		DBG("Invalid index %d  for socket %d\n", index, socket_fd);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (!(socket_fd && (socket_fd == rfcomm_client[index].sock_fd)) ||
	       (NULL == rfcomm_client[index].dev_node_name)) {
		DBG("Invalid FD %d  - %d\n", socket_fd, rfcomm_client[index].sock_fd);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	__bluetooth_rfcomm_internal_disconnect(index);

	g_source_remove(rfcomm_client[index].event_src_id);
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
		wbytes += written;
	}

	return BLUETOOTH_ERROR_NONE;
	DBG("-\n");
}

static int __bluetooth_internal_set_nonblocking(int sk)
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

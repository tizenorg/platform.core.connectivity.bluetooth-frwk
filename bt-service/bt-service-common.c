/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <dlog.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>

#include "bluetooth-api.h"
#include "bt-service-common.h"
#include "bt-service-agent.h"

static DBusGConnection *system_conn;
static DBusGConnection *session_conn;
static DBusGProxy *manager_proxy;
static DBusGProxy *adapter_proxy;
static DBusGProxy *adapter_properties_proxy;

static DBusGProxy *__bt_init_manager_proxy(void)
{
	DBusGProxy *proxy;

	g_type_init();

	if (system_conn == NULL) {
		system_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(system_conn == NULL, NULL);
	}

	proxy = dbus_g_proxy_new_for_name(system_conn, BT_BLUEZ_NAME,
			BT_MANAGER_PATH, BT_MANAGER_INTERFACE);

	retv_if(proxy == NULL, NULL);

	manager_proxy = proxy;

	return proxy;
}

static DBusGProxy *__bt_init_adapter_proxy(void)
{
	DBusGProxy *manager_proxy;
	DBusGProxy *proxy;

	if (system_conn == NULL) {
		system_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(system_conn == NULL, NULL);
	}

	manager_proxy = _bt_get_manager_proxy();
	retv_if(manager_proxy == NULL, NULL);

	proxy = dbus_g_proxy_new_for_name(system_conn, BT_BLUEZ_NAME,
				BT_BLUEZ_HCI_PATH, BT_ADAPTER_INTERFACE);

	retv_if(proxy == NULL, NULL);

	adapter_proxy = proxy;

	return proxy;
}

static DBusGProxy *__bt_init_adapter_properties_proxy(void)
{
	DBusGProxy *manager_proxy;
	DBusGProxy *proxy;

	g_type_init();

	if (system_conn == NULL) {
		system_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(system_conn == NULL, NULL);
	}

	manager_proxy = _bt_get_manager_proxy();
	retv_if(manager_proxy == NULL, NULL);

	proxy = dbus_g_proxy_new_for_name(system_conn, BT_BLUEZ_NAME,
			BT_BLUEZ_HCI_PATH, BT_PROPERTIES_INTERFACE);

	retv_if(proxy == NULL, NULL);

	adapter_properties_proxy = proxy;

	return proxy;
}

DBusGConnection *__bt_init_system_gconn(void)
{
	g_type_init();

	if (system_conn == NULL)
		system_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	return system_conn;
}

DBusGConnection *__bt_init_session_conn(void)
{
	if (session_conn == NULL)
		session_conn = dbus_g_bus_get(DBUS_BUS_SESSION, NULL);

	return session_conn;
}

DBusGConnection *_bt_get_session_gconn(void)
{
	return (session_conn) ? session_conn : __bt_init_session_conn();
}

DBusGConnection *_bt_get_system_gconn(void)
{
	return (system_conn) ? system_conn : __bt_init_system_gconn();
}

DBusConnection *_bt_get_system_conn(void)
{
	DBusGConnection *g_conn;

	if (system_conn == NULL) {
		g_conn = __bt_init_system_gconn();
	} else {
		g_conn = system_conn;
	}

	retv_if(g_conn == NULL, NULL);

	return dbus_g_connection_get_connection(g_conn);
}

DBusGProxy *_bt_get_manager_proxy(void)
{
	return (manager_proxy) ? manager_proxy : __bt_init_manager_proxy();
}

DBusGProxy *_bt_get_adapter_proxy(void)
{
	return (adapter_proxy) ? adapter_proxy : __bt_init_adapter_proxy();
}

DBusGProxy *_bt_get_adapter_properties_proxy(void)
{
	return (adapter_properties_proxy) ? adapter_properties_proxy :
					__bt_init_adapter_properties_proxy();
}

gboolean _bt_get_adapter_power(void)
{
	DBusGProxy *proxy = NULL;
	gboolean powered;
	GValue powered_v = { 0 };
	GError *err = NULL;

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, FALSE);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Powered",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &powered_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return FALSE;
	}

	powered = (gboolean)g_value_get_boolean(&powered_v);

	BT_DBG("powered = %d", powered);

	return powered;
}

static char *__bt_extract_adapter_path(DBusMessageIter *msg_iter)
{
	char *object_path = NULL;
	DBusMessageIter value_iter;

	/* Parse the signature:  oa{sa{sv}}} */
	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
				DBUS_TYPE_OBJECT_PATH, NULL);

	dbus_message_iter_get_basic(msg_iter, &object_path);
	retv_if(object_path == NULL, NULL);

	/* object array (oa) */
	retv_if(dbus_message_iter_next(msg_iter) == FALSE, NULL);
	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
				DBUS_TYPE_ARRAY, NULL);

	dbus_message_iter_recurse(msg_iter, &value_iter);

	/* string array (sa) */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
					DBUS_TYPE_DICT_ENTRY) {
		char *interface_name = NULL;
		DBusMessageIter interface_iter;

		dbus_message_iter_recurse(&value_iter, &interface_iter);

		retv_if(dbus_message_iter_get_arg_type(&interface_iter) !=
			DBUS_TYPE_STRING, NULL);

		dbus_message_iter_get_basic(&interface_iter, &interface_name);

		if (g_strcmp0(interface_name, "org.bluez.Adapter1") == 0) {
			/* Tizen don't allow the multi-adapter */
			BT_DBG("Found an adapter: %s", object_path);
			return g_strdup(object_path);
		}

		dbus_message_iter_next(&value_iter);
	}

	BT_DBG("There is no adapter");

	return NULL;
}

char *_bt_get_adapter_path(void)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	char *adapter_path = NULL;

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, NULL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
						BT_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, NULL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
	    BT_ERR("Fail to iterate the reply");
	    return NULL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		adapter_path = __bt_extract_adapter_path(&msg_iter);
		if (adapter_path != NULL) {
			BT_DBG("Found the adapter path");
			break;
		}

		dbus_message_iter_next(&value_iter);
	}

	return adapter_path;
}

void _bt_deinit_bluez_proxy(void)
{
	if (manager_proxy) {
		g_object_unref(manager_proxy);
		manager_proxy = NULL;
	}

	if (adapter_proxy) {
		g_object_unref(adapter_proxy);
		adapter_proxy = NULL;
	}

	if (adapter_properties_proxy) {
		g_object_unref(adapter_properties_proxy);
		adapter_properties_proxy = NULL;
	}
}

void _bt_deinit_proxys(void)
{

	_bt_deinit_bluez_proxy();

	if (system_conn) {
		dbus_g_connection_unref(system_conn);
		system_conn = NULL;
	}

	if (session_conn) {
		dbus_g_connection_unref(session_conn);
		session_conn = NULL;
	}

}

void _bt_convert_device_path_to_address(const char *device_path,
						char *device_address)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr;

	ret_if(device_path == NULL);
	ret_if(device_address == NULL);

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		char *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL) {
			*pos = ':';
		}

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}


void _bt_convert_addr_string_to_type(unsigned char *addr,
					const char *address)
{
        int i;
        char *ptr = NULL;

	ret_if(address == NULL);
	ret_if(addr == NULL);

        for (i = 0; i < BT_ADDRESS_LENGTH_MAX; i++) {
                addr[i] = strtol(address, &ptr, 16);
                if (ptr != NULL) {
                        if (ptr[0] != ':')
                                return;

                        address = ptr + 1;
                }
        }
}

void _bt_convert_addr_type_to_string(char *address,
				unsigned char *addr)
{
	ret_if(address == NULL);
	ret_if(addr == NULL);

	snprintf(address, BT_ADDRESS_STRING_SIZE,
			"%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

void _bt_print_device_address_t(const bluetooth_device_address_t *addr)
{
	BT_DBG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", addr->addr[0], addr->addr[1], addr->addr[2],
				addr->addr[3], addr->addr[4], addr->addr[5]);
}

void _bt_divide_device_class(bluetooth_device_class_t *device_class,
				unsigned int cod)
{
	ret_if(device_class == NULL);

	device_class->major_class = (unsigned short)(cod & 0x00001F00) >> 8;
	device_class->minor_class = (unsigned short)((cod & 0x000000FC));
	device_class->service_class = (unsigned long)((cod & 0x00FF0000));

	if (cod & 0x002000) {
		device_class->service_class |=
		BLUETOOTH_DEVICE_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE;
	}
}

void _bt_free_device_info(bt_remote_dev_info_t *dev_info)
{
	int i;

	ret_if(dev_info == NULL);

	g_free(dev_info->address);
	g_free(dev_info->name);

	if (dev_info->uuids) {
		for (i = 0; dev_info->uuids[i] != NULL; i++)
			g_free(dev_info->uuids[i]);

		g_free(dev_info->uuids);
	}

	g_free(dev_info);
}

int _bt_register_osp_server_in_agent(int type, char *uuid)
{
	if (!_bt_agent_register_osp_server( type, uuid))
		return BLUETOOTH_ERROR_INTERNAL;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_unregister_osp_server_in_agent(int type, char *uuid)
{
	if (!_bt_agent_unregister_osp_server( type, uuid))
		return BLUETOOTH_ERROR_INTERNAL;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_socket_non_blocking(int socket_fd)
{
	/* Set Nonblocking */
	long arg;

	arg = fcntl(socket_fd, F_GETFL);

	if (arg < 0)
		return -errno;

	if (arg & O_NONBLOCK) {
		BT_ERR("Already Non-blocking \n");
	}

	arg |= O_NONBLOCK;

	if (fcntl(socket_fd, F_SETFL, arg) < 0)
		return -errno;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_non_blocking_tty(int sk)
{
	struct termios ti = {0,};
	int err;

	err = _bt_set_socket_non_blocking(sk);

	if (err < 0) {
		BT_ERR("Error in set non blocking!\n");
		return err;
	}

	tcflush(sk, TCIOFLUSH);

	/* Switch tty to RAW mode */
	cfmakeraw(&ti);
	tcsetattr(sk, TCSANOW, &ti);

	return BLUETOOTH_ERROR_NONE;
}

gboolean _bt_is_headset_class(int dev_class)
{
	gboolean is_headset = FALSE;

	switch ((dev_class & 0x1f00) >> 8) {
	case 0x04:
		switch ((dev_class & 0xfc) >> 2) {
		case 0x01:
		case 0x02:
			/* Headset */
			is_headset = TRUE;
			break;
		case 0x06:
			/* Headphone */
			is_headset = TRUE;
			break;
		case 0x0b:	/* VCR */
		case 0x0c:	/* Video Camera */
		case 0x0d:	/* Camcorder */
			break;
		default:
			/* Other audio device */
			is_headset = TRUE;
			break;
		}
		break;
	}

	return is_headset;
}

static char *__bt_extract_device_path(DBusMessageIter *msg_iter, char *address)
{
	char *object_path = NULL;
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };

	/* Parse the signature:  oa{sa{sv}}} */
	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
				DBUS_TYPE_OBJECT_PATH, NULL);

	dbus_message_iter_get_basic(msg_iter, &object_path);
	retv_if(object_path == NULL, NULL);

	_bt_convert_device_path_to_address(object_path, device_address);

	if (g_strcmp0(address, device_address) == 0) {
		return g_strdup(object_path);
	}

	return NULL;
}

char *_bt_get_device_object_path(char *address)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	char *object_path = NULL;

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, NULL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
						BT_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, NULL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
	    BT_ERR("Fail to iterate the reply");
	    return NULL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		object_path = __bt_extract_device_path(&msg_iter, address);
		if (object_path != NULL) {
			BT_DBG("Found the device path");
			break;
		}

		dbus_message_iter_next(&value_iter);
	}

	return object_path;
}


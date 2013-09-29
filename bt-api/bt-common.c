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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#include "bluetooth-api.h"
#include "bluetooth-audio-api.h"
#include "bluetooth-hid-api.h"
#include "bluetooth-media-control.h"
#include "bt-internal-types.h"

#include "bt-common.h"
#include "bt-request-sender.h"
#include "bt-event-handler.h"

static bt_user_info_t user_info[BT_MAX_USER_INFO];
static DBusGConnection *system_conn = NULL;

void _bt_print_device_address_t(const bluetooth_device_address_t *addr)
{
	BT_DBG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", addr->addr[0], addr->addr[1], addr->addr[2],
				addr->addr[3], addr->addr[4], addr->addr[5]);
}

void _bt_set_user_data(int type, void *callback, void *user_data)
{
	user_info[type].cb = callback;
	user_info[type].user_data = user_data;
}

bt_user_info_t *_bt_get_user_data(int type)
{
	return &user_info[type];
}

void _bt_common_event_cb(int event, int result, void *param,
					void *callback, void *user_data)
{
	bluetooth_event_param_t bt_event = { 0, };
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param;

	if (callback)
		((bluetooth_cb_func_ptr)callback)(bt_event.event, &bt_event,
					user_data);
}

void _bt_input_event_cb(int event, int result, void *param,
					void *callback, void *user_data)
{
	hid_event_param_t bt_event = { 0, };
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param;

	if (callback)
		((hid_cb_func_ptr)callback)(bt_event.event, &bt_event,
					user_data);
}

void _bt_headset_event_cb(int event, int result, void *param,
					void *callback, void *user_data)
{
	bt_audio_event_param_t bt_event = { 0, };
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param;

	if (callback)
		((bt_audio_func_ptr)callback)(bt_event.event, &bt_event,
					user_data);
}

void _bt_avrcp_event_cb(int event, int result, void *param,
					void *callback, void *user_data)
{
	media_event_param_t bt_event = { 0, };
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param;

	if (callback)
		((media_cb_func_ptr)callback)(bt_event.event, &bt_event,
					user_data);
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

	g_snprintf(address, BT_ADDRESS_STRING_SIZE,
			"%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

int _bt_copy_utf8_string(char *dest, const char *src, unsigned int length)
{
	int i;
	char *p = src;
	char *next;
	int count;

	if (dest == NULL || src == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	i = 0;
	while (*p != '\0' && i < length) {
		next = g_utf8_next_char(p);
		count = next - p;

		while (count > 0 && ((i + count) < length)) {
			dest[i++] = *p;
			p++;
			count --;
		}
		p = next;
	}
	return BLUETOOTH_ERROR_NONE;
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

/* TO DO */
/* Change DBusGConnection to DBusConnection*/
int _bt_get_adapter_path(DBusGConnection *g_conn, char *path)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	char *adapter_path = NULL;

	retv_if(g_conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = dbus_g_connection_get_connection(g_conn);
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
						BT_MANAGER_INTERFACE,
						"GetManagedObjects");

	if (msg == NULL) {
		BT_ERR("Can't allocate D-Bus message");
		goto fail;
	}

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
		goto fail;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
	    BT_ERR("Fail to iterate the reply");
	    goto fail;
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

	if (adapter_path == NULL ||
	     strlen(adapter_path) >= BT_ADAPTER_OBJECT_PATH_MAX) {
		BT_ERR("Adapter path is inproper\n");
		goto fail;
	}

	BT_DBG("adapter path: %s", adapter_path);

	if (path)
		g_strlcpy(path, adapter_path, BT_ADAPTER_OBJECT_PATH_MAX);

	g_free(adapter_path);

	return BLUETOOTH_ERROR_NONE;

fail:
	g_free(adapter_path);

	return BLUETOOTH_ERROR_INTERNAL;
}

DBusGProxy *_bt_get_adapter_proxy(DBusGConnection *conn)
{
	DBusGProxy *adapter_proxy = NULL;
	char adapter_path[BT_ADAPTER_OBJECT_PATH_MAX] = { 0 };

	retv_if(conn == NULL, NULL);

	if (_bt_get_adapter_path(conn, adapter_path) < 0) {
		BT_DBG("Could not get adapter path\n");
		return NULL;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				adapter_path, BT_ADAPTER_INTERFACE);

	return adapter_proxy;
}

void _bt_device_path_to_address(const char *device_path, char *device_address)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr = NULL;

	if (!device_path || !device_address)
		return;

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

DBusGConnection *__bt_init_system_gconn(void)
{
	g_type_init();

	if (system_conn == NULL)
		system_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	return system_conn;
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

BT_EXPORT_API int bluetooth_is_supported(void)
{
	int is_supported = 0;
	int len = 0;
	int fd = -1;
	rfkill_event event;

	fd = open(RFKILL_NODE, O_RDONLY);
	if (fd < 0) {
		BT_DBG("Fail to open RFKILL node");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		BT_DBG("Fail to set RFKILL node to non-blocking");
		close(fd);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	while (1) {
		len = read(fd, &event, sizeof(event));
		if (len < 0) {
			BT_DBG("Fail to read events");
			break;
		}

		if (len != RFKILL_EVENT_SIZE) {
			BT_DBG("The size is wrong\n");
			continue;
		}

		if (event.type == RFKILL_TYPE_BLUETOOTH) {
			is_supported = 1;
			break;
		}
	}

	close(fd);

	BT_DBG("supported: %d", is_supported);

	return is_supported;
}

BT_EXPORT_API int bluetooth_register_callback(bluetooth_cb_func_ptr callback_ptr, void *user_data)
{
	int ret;

	__bt_init_system_gconn();

	ret = _bt_init_event_handler();

	if (ret != BLUETOOTH_ERROR_NONE &&
	     ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		BT_ERR("Fail to init the event handler");
		return ret;
	}

	_bt_set_user_data(BT_COMMON, (void *)callback_ptr, user_data);

	/* Register All events */
	_bt_register_event(BT_ADAPTER_EVENT, (void *)callback_ptr, user_data);
	_bt_register_event(BT_DEVICE_EVENT, (void *)callback_ptr, user_data);
	_bt_register_event(BT_NETWORK_EVENT, (void *)callback_ptr, user_data);
	_bt_register_event(BT_RFCOMM_CLIENT_EVENT, (void *)callback_ptr, user_data);
	_bt_register_event(BT_RFCOMM_SERVER_EVENT, (void *)callback_ptr, user_data);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_unregister_callback(void)
{
	_bt_unregister_event(BT_ADAPTER_EVENT);
	_bt_unregister_event(BT_DEVICE_EVENT);
	_bt_unregister_event(BT_NETWORK_EVENT);
	_bt_unregister_event(BT_RFCOMM_CLIENT_EVENT);
	_bt_unregister_event(BT_RFCOMM_SERVER_EVENT);

	_bt_set_user_data(BT_COMMON, NULL, NULL);

	if (system_conn) {
		dbus_g_connection_unref(system_conn);
		system_conn = NULL;
	}

	return BLUETOOTH_ERROR_NONE;
}


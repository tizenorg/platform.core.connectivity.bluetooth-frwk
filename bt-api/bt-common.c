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
#include <security-server.h>

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
static char *cookie;
static size_t cookie_size;

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

int _bt_get_adapter_path(DBusGConnection *conn, char *path)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	char *adapter_path = NULL;
	int ret = BLUETOOTH_ERROR_NONE;

	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	manager_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				BT_MANAGER_PATH, BT_MANAGER_INTERFACE);

	retv_if(manager_proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
				G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
				&adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting DefaultAdapter failed: [%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(manager_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (adapter_path == NULL || strlen(adapter_path) >= BT_ADAPTER_OBJECT_PATH_MAX) {
		BT_ERR("Adapter path is inproper\n");
		ret = BLUETOOTH_ERROR_INTERNAL;
		goto done;
	}

	if (path)
		g_strlcpy(path, adapter_path, BT_ADAPTER_OBJECT_PATH_MAX);
done:
	g_free(adapter_path);
	g_object_unref(manager_proxy);

	return ret;
}

DBusGProxy *_bt_get_adapter_proxy(DBusGConnection *conn)
{
	GError *err = NULL;
	DBusGProxy *manager_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	char *adapter_path = NULL;

	retv_if(conn == NULL, NULL);

	manager_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				BT_MANAGER_PATH, BT_MANAGER_INTERFACE);

	retv_if(manager_proxy == NULL, NULL);

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &err,
				G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
				&adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting DefaultAdapter failed: [%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(manager_proxy);
		return NULL;
	}

	if (adapter_path == NULL || strlen(adapter_path) >= BT_ADAPTER_OBJECT_PATH_MAX) {
		BT_ERR("Adapter path is inproper\n");
		g_free(adapter_path);
		g_object_unref(manager_proxy);
		return NULL;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(conn,
					BT_BLUEZ_NAME,
					adapter_path,
					BT_ADAPTER_INTERFACE);
	g_free(adapter_path);
	g_object_unref(manager_proxy);

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

static void __bt_generate_cookie(void)
{
	int retval;

	ret_if(cookie != NULL);

	cookie_size = security_server_get_cookie_size();

	cookie = g_malloc0((cookie_size*sizeof(char))+1);

	retval = security_server_request_cookie(cookie, cookie_size);
	if(retval < 0) {
		BT_ERR("Fail to get cookie: %d", retval);
	}
}

static void __bt_destroy_cookie(void)
{
	g_free(cookie);
	cookie = NULL;
	cookie_size = 0;
}

char *_bt_get_cookie(void)
{
	return cookie;
}

int _bt_get_cookie_size(void)
{
	return cookie_size;
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

	__bt_generate_cookie();

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
	__bt_destroy_cookie();

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


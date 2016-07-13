/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <dlog.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <sys/prctl.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#include "bt-hal-dbus-common-utils.h"

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"
#include "bt-hal-internal.h"

/**
 * This is RFCOMM default Channel Value
 */
#define RFCOMM_DEFAULT_PROFILE_CHANNEL 0

static GDBusConnection *system_conn;
static GDBusConnection *session_conn;
static GDBusProxy *manager_proxy;
static GDBusProxy *adapter_proxy;
static GDBusProxy *profile_gproxy;

static GDBusProxy *adapter_properties_proxy;

static GDBusConnection *system_gconn = NULL;

static guint bus_id;
GDBusNodeInfo *new_conn_node;
static const gchar rfcomm_agent_xml[] =
"<node name='/'>"
" <interface name='org.bluez.Profile1'>"
"     <method name='NewConnection'>"
"          <arg type='o' name='object' direction='in'/>"
"          <arg type='h' name='fd' direction='in'/>"
"          <arg type='a{sv}' name='properties' direction='in'/>"
"     </method>"
"     <method name='RequestDisconnection'>"
"          <arg type='o' name='device' direction='in'/>"
"     </method>"
"  </interface>"
"</node>";

GDBusConnection *_bt_gdbus_init_system_gconn(void)
{
	GError *error = NULL;

	if (system_gconn != NULL)
		return system_gconn;

	system_gconn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

	if (!system_gconn) {
		ERR("Unable to connect to dbus: %s", error->message);
		g_clear_error(&error);
	}

	return system_gconn;
}

GDBusConnection *_bt_gdbus_get_system_gconn(void)
{
	GDBusConnection *local_system_gconn = NULL;
	GError *error = NULL;

	if (system_gconn == NULL) {
		system_gconn = _bt_gdbus_init_system_gconn();
	} else if (g_dbus_connection_is_closed(system_gconn)){

		local_system_gconn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

		if (!local_system_gconn) {
			ERR("Unable to connect to dbus: %s", error->message);
			g_clear_error(&error);
		}

		system_gconn = local_system_gconn;
	}

	return system_gconn;
}

static GDBusProxy *__bt_init_manager_proxy(void)
{
	GDBusProxy *proxy;

	if (system_conn == NULL) {
		system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
		if (system_conn == NULL)
			return  NULL;
	}

	proxy = g_dbus_proxy_new_sync(system_conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			BT_HAL_MANAGER_PATH, BT_HAL_MANAGER_INTERFACE,  NULL, NULL);

	if (proxy == NULL)
		return NULL;

	manager_proxy = proxy;

	return proxy;
}

static GDBusProxy *__bt_init_adapter_proxy(void)
{
	GDBusProxy *manager_proxy;
	GDBusProxy *proxy;
	char *adapter_path = NULL;

	if (system_conn == NULL) {
		system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
		if (system_conn == NULL)
			return  NULL;
	}

	manager_proxy = _bt_get_manager_proxy();
	if (manager_proxy == NULL)
		return  NULL;

	adapter_path = _bt_get_adapter_path();
	if (adapter_path == NULL)
		return  NULL;

	proxy = g_dbus_proxy_new_sync(system_conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			adapter_path, BT_HAL_ADAPTER_INTERFACE,  NULL, NULL);

	g_free(adapter_path);

	if (proxy == NULL)
		return NULL;

	adapter_proxy = proxy;

	return proxy;
}

static GDBusProxy *__bt_init_adapter_properties_proxy(void)
{
	GDBusProxy *manager_proxy;
	GDBusProxy *proxy;
	char *adapter_path = NULL;

	if (system_conn == NULL) {
		system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
		if (system_conn == NULL)
			return  NULL;
	}

	manager_proxy = _bt_get_manager_proxy();
	if (manager_proxy == NULL)
		return  NULL;

	adapter_path = _bt_get_adapter_path();
	if (adapter_path == NULL)
		return   NULL;

	proxy = g_dbus_proxy_new_sync(system_conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			adapter_path, BT_HAL_PROPERTIES_INTERFACE,  NULL, NULL);

	g_free(adapter_path);

	if (proxy == NULL)
		return  NULL;

	adapter_properties_proxy = proxy;

	return proxy;
}

GDBusConnection *__bt_init_system_gconn(void)
{
	if (system_conn == NULL)
		system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);

	return system_conn;
}

GDBusConnection *__bt_init_session_conn(void)
{
	if (session_conn == NULL)
		session_conn =g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);

	return session_conn;
}

GDBusConnection *_bt_get_session_gconn(void)
{
	return (session_conn) ? session_conn : __bt_init_session_conn();
}

GDBusConnection *_bt_get_system_gconn(void)
{
	return (system_conn) ? system_conn : __bt_init_system_gconn();
}

GDBusConnection *_bt_get_system_conn(void)
{
	GDBusConnection *g_conn;

	if (system_conn == NULL) {
		g_conn = __bt_init_system_gconn();
	} else {
		g_conn = system_conn;
	}

	if (g_conn == NULL)
		return  NULL;

	return g_conn;
}

GDBusProxy *_bt_get_manager_proxy(void)
{
	if (manager_proxy) {
		const gchar *path =  g_dbus_proxy_get_object_path(manager_proxy);
		if (path == NULL) {
			ERR("Already proxy released hence creating new proxy");
			return  __bt_init_manager_proxy();
		}
		return manager_proxy;
	}
	return  __bt_init_manager_proxy();
}

GDBusProxy *_bt_get_adapter_proxy(void)
{
	if (adapter_proxy) {
		const char *path =  g_dbus_proxy_get_object_path(adapter_proxy);
		if (path == NULL) {
			ERR("Already proxy released hence creating new proxy");
			return  __bt_init_adapter_proxy();
		}

		return adapter_proxy;
	}
	return  __bt_init_adapter_proxy();

}

GDBusProxy *_bt_get_adapter_properties_proxy(void)
{
	return (adapter_properties_proxy) ? adapter_properties_proxy :
		__bt_init_adapter_properties_proxy();
}

GDBusProxy *_bt_get_profile_proxy(void)
{
	GDBusConnection *gconn;
	GError *err = NULL;

	if (profile_gproxy)
		return profile_gproxy;

	gconn = _bt_get_system_gconn();
	if (gconn == NULL) {
		ERR("_bt_get_system_gconn failed");
		return NULL;
	}

	profile_gproxy = g_dbus_proxy_new_sync(gconn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			"/org/bluez",
			"org.bluez.ProfileManager1",
			NULL, &err);
	if (err) {
		ERR("Unable to create proxy: %s", err->message);
		g_clear_error(&err);
		return NULL;
	}

	return profile_gproxy;
}

static char *__bt_extract_adapter_path(GVariantIter *iter)
{
	char *object_path = NULL;
	GVariantIter *interface_iter;
	GVariantIter *svc_iter;
	char *interface_str = NULL;

	/* Parse the signature: oa{sa{sv}}} */
	while (g_variant_iter_loop(iter, "{&oa{sa{sv}}}", &object_path,
				&interface_iter)) {

		if (object_path == NULL)
			continue;

		while (g_variant_iter_loop(interface_iter, "{sa{sv}}",
					&interface_str, &svc_iter)) {
			if (g_strcmp0(interface_str, "org.bluez.Adapter1") != 0)
				continue;

			DBG("Object Path: %s", object_path);
			g_free(interface_str);
			g_variant_iter_free(svc_iter);
			g_variant_iter_free(interface_iter);
			return g_strdup(object_path);
		}
	}
	return NULL;
}

char *_bt_get_adapter_path(void)
{
	GDBusConnection *conn;
	GDBusProxy *manager_proxy;
	GVariant *result = NULL;
	GVariantIter *iter = NULL;
	char *adapter_path = NULL;

	conn = _bt_get_system_conn();
	if (conn == NULL)
		return  NULL;

	manager_proxy = _bt_get_manager_proxy();
	if (manager_proxy == NULL)
		return NULL;

	result = g_dbus_proxy_call_sync(manager_proxy, "GetManagedObjects",
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			NULL);
	if (!result) {
		ERR("Can't get managed objects");
		return NULL;
	}

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	g_variant_get(result, "(a{oa{sa{sv}}})", &iter);

	adapter_path = __bt_extract_adapter_path(iter);
	g_variant_iter_free(iter);
	g_variant_unref(result);
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
		g_object_unref(system_conn);
		system_conn = NULL;
	}

	if (session_conn) {
		g_object_unref(session_conn);
		session_conn = NULL;
	}
}

void _bt_convert_device_path_to_address(const char *device_path,
		char *device_address)
{
	char address[BT_HAL_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr;

	if (device_path == NULL || device_address == NULL)
		return;

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		char *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL) {
			*pos = ':';
		}

		g_strlcpy(device_address, address, BT_HAL_ADDRESS_STRING_SIZE);
	}
}

void _bt_convert_uuid_string_to_type(unsigned char *uuid,
                const char *device_uuid)
{
	uint32_t uuid0, uuid4;
	uint16_t uuid1, uuid2, uuid3, uuid5;

	sscanf(device_uuid, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
			&uuid0, &uuid1, &uuid2, &uuid3, &uuid4, &uuid5);

	uuid0 = htonl(uuid0);
	uuid1 = htons(uuid1);
	uuid2 = htons(uuid2);
	uuid3 = htons(uuid3);
	uuid4 = htonl(uuid4);
	uuid5 = htons(uuid5);

	memcpy(&(uuid[0]), &uuid0, 4);
	memcpy(&(uuid[4]), &uuid1, 2);
	memcpy(&(uuid[6]), &uuid2, 2);
	memcpy(&(uuid[8]), &uuid3, 2);
	memcpy(&(uuid[10]), &uuid4, 4);
	memcpy(&(uuid[14]), &uuid5, 2);
}

void _bt_convert_uuid_type_to_string(char *str, const unsigned char *uuid)
{
	if (!str) {
		ERR("str == NULL");
		return;
	}

	if (!uuid) {
		ERR("uuid == NULL");
		return;
	}

	snprintf(str, BT_HAL_UUID_STRING_LEN,
			"%2.2X%2.2X%2.2X%2.2X-%2.2X%2.2X-%2.2X%2.2X-%2.2X%2.2X-%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X",
			uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
			uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

void _bt_convert_addr_string_to_type(unsigned char *addr,
		const char *address)
{
	int i;
	char *ptr = NULL;

	if (address == NULL || addr == NULL)
		return;

	for (i = 0; i < BT_HAL_ADDRESS_LENGTH_MAX; i++) {
		addr[i] = strtol(address, &ptr, 16);

		if (ptr[0] != '\0') {
			if (ptr[0] != ':')
				return;

			address = ptr + 1;
		}
	}
}

void _bt_convert_addr_type_to_string(char *address,
		const unsigned char *addr)
{
	if (address == NULL || addr == NULL)
		return;

	snprintf(address, BT_HAL_ADDRESS_STRING_SIZE,
			"%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
}

void _bt_print_device_address_t(const bt_hal_device_address_t *addr)
{
	DBG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", addr->addr[0], addr->addr[1], addr->addr[2],
			addr->addr[3], addr->addr[4], addr->addr[5]);
}

void _bt_divide_device_class(bt_hal_device_class_t *device_class,
		unsigned int cod)
{
	if (device_class == NULL)
		return;

	device_class->major_class = (unsigned short)(cod & 0x00001F00) >> 8;
	device_class->minor_class = (unsigned short)((cod & 0x000000FC));
	device_class->service_class = (unsigned long)((cod & 0x00FF0000));

	if (cod & 0x002000) {
		device_class->service_class |=
			BT_HAL_DEVICE_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE;
	}
}

int _bt_copy_utf8_string(char *dest, const char *src, unsigned int length)
{
	int i;
	const char *p = src;
	char *next;
	int count;

	if (dest == NULL || src == NULL)
		return BT_HAL_ERROR_INVALID_PARAM;

	DBG("+src : %s", src);
	DBG("+dest : %s", dest);

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
	return BT_HAL_ERROR_NONE;
}

gboolean _bt_utf8_validate(char *name)
{
	DBG("+");
	gunichar2 *u16;
	glong items_written = 0;

	if (FALSE == g_utf8_validate(name, -1, NULL))
		return FALSE;

	u16 = g_utf8_to_utf16(name, -1, NULL, &items_written, NULL);
	if (u16 == NULL)
		return FALSE;

	g_free(u16);

	if (items_written != g_utf8_strlen(name, -1))
		return FALSE;

	DBG("-");
	return TRUE;
}

int _bt_set_socket_non_blocking(int socket_fd)
{
	/* Set Nonblocking */
	long arg;

	arg = fcntl(socket_fd, F_GETFL);

	if (arg < 0)
		return -errno;

	if (arg & O_NONBLOCK) {
		ERR("Already Non-blocking \n");
	}

	arg |= O_NONBLOCK;

	if (fcntl(socket_fd, F_SETFL, arg) < 0)
		return -errno;

	return BT_HAL_ERROR_NONE;
}

int _bt_set_non_blocking_tty(int sk)
{
	struct termios ti = {0,};
	int err;

	err = _bt_set_socket_non_blocking(sk);

	if (err < 0) {
		ERR("Error in set non blocking!\n");
		return err;
	}

	tcflush(sk, TCIOFLUSH);

	/* Switch tty to RAW mode */
	cfmakeraw(&ti);
	tcsetattr(sk, TCSANOW, &ti);

	return BT_HAL_ERROR_NONE;
}

static char *__bt_extract_device_path(GVariantIter *iter, char *address)
{
	char *object_path = NULL;
	char device_address[BT_HAL_ADDRESS_STRING_SIZE] = { 0 };

	/* Parse the signature: oa{sa{sv}}} */
	while (g_variant_iter_loop(iter, "{&oa{sa{sv}}}", &object_path, NULL)) {
		if (object_path == NULL)
			return  NULL;
		_bt_convert_device_path_to_address(object_path, device_address);
		if (g_strcmp0(address, device_address) == 0) {
			return g_strdup(object_path);
		}
	}
	return NULL;
}

char *_bt_get_device_object_path(char *address)
{
	char *object_path = NULL;
	GDBusConnection *conn;
	GDBusProxy *manager_proxy;
	GVariant *result = NULL;
	GVariantIter *iter = NULL;

	conn = _bt_get_system_conn();
	if (conn == NULL)
		return NULL;

	manager_proxy = _bt_get_manager_proxy();
	if (manager_proxy == NULL)
		return  NULL;

	result = g_dbus_proxy_call_sync(manager_proxy, "GetManagedObjects",
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			NULL);
	if (!result) {
		ERR("Can't get managed objects");
		return NULL;
	}

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	g_variant_get(result, "(a{oa{sa{sv}}})", &iter);
	object_path = __bt_extract_device_path(iter, address);
	g_variant_iter_free(iter);
	g_variant_unref(result);
	return object_path;
}

char *_bt_convert_error_to_string(int error)
{
	switch (error) {
	case BT_HAL_ERROR_CANCEL:
		return "CANCELLED";
	case BT_HAL_ERROR_INVALID_PARAM:
		return "INVALID_PARAMETER";
	case BT_HAL_ERROR_INVALID_DATA:
		return "INVALID DATA";
	case BT_HAL_ERROR_MEMORY_ALLOCATION:
	case BT_HAL_ERROR_OUT_OF_MEMORY:
		return "OUT_OF_MEMORY";
	case BT_HAL_ERROR_TIMEOUT:
		return "TIMEOUT";
	case BT_HAL_ERROR_NO_RESOURCES:
		return "NO_RESOURCES";
	case BT_HAL_ERROR_INTERNAL:
		return "INTERNAL";
	case BT_HAL_ERROR_NOT_SUPPORT:
		return "NOT_SUPPORT";
	case BT_HAL_ERROR_DEVICE_NOT_ENABLED:
		return "NOT_ENABLED";
	case BT_HAL_ERROR_DEVICE_ALREADY_ENABLED:
		return "ALREADY_ENABLED";
	case BT_HAL_ERROR_DEVICE_BUSY:
		return "DEVICE_BUSY";
	case BT_HAL_ERROR_ACCESS_DENIED:
		return "ACCESS_DENIED";
	case BT_HAL_ERROR_MAX_CLIENT:
		return "MAX_CLIENT";
	case BT_HAL_ERROR_NOT_FOUND:
		return "NOT_FOUND";
	case BT_HAL_ERROR_SERVICE_SEARCH_ERROR:
		return "SERVICE_SEARCH_ERROR";
	case BT_HAL_ERROR_PARING_FAILED:
		return "PARING_FAILED";
	case BT_HAL_ERROR_NOT_PAIRED:
		return "NOT_PAIRED";
	case BT_HAL_ERROR_SERVICE_NOT_FOUND:
		return "SERVICE_NOT_FOUND";
	case BT_HAL_ERROR_NOT_CONNECTED:
		return "NOT_CONNECTED";
	case BT_HAL_ERROR_ALREADY_CONNECT:
		return "ALREADY_CONNECT";
	case BT_HAL_ERROR_CONNECTION_BUSY:
		return "CONNECTION_BUSY";
	case BT_HAL_ERROR_CONNECTION_ERROR:
		return "CONNECTION_ERROR";
	case BT_HAL_ERROR_MAX_CONNECTION:
		return "MAX_CONNECTION";
	case BT_HAL_ERROR_NOT_IN_OPERATION:
		return "NOT_IN_OPERATION";
	case BT_HAL_ERROR_CANCEL_BY_USER:
		return "CANCEL_BY_USER";
	case BT_HAL_ERROR_REGISTRATION_FAILED:
		return "REGISTRATION_FAILED";
	case BT_HAL_ERROR_IN_PROGRESS:
		return "IN_PROGRESS";
	case BT_HAL_ERROR_AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED";
	case BT_HAL_ERROR_HOST_DOWN:
		return "HOST_DOWN";
	case BT_HAL_ERROR_END_OF_DEVICE_LIST:
		return "END_OF_DEVICE_LIST";
	case BT_HAL_ERROR_AGENT_ALREADY_EXIST:
		return "AGENT_ALREADY_EXIST";
	case BT_HAL_ERROR_AGENT_DOES_NOT_EXIST:
		return "AGENT_DOES_NOT_EXIST";
	case BT_HAL_ERROR_ALREADY_INITIALIZED:
		return "ALREADY_INITIALIZED";
	case BT_HAL_ERROR_PERMISSION_DEINED:
		return "PERMISSION_DEINED";
	case BT_HAL_ERROR_ALREADY_DEACTIVATED:
		return "ALREADY_DEACTIVATED";
	case BT_HAL_ERROR_NOT_INITIALIZED:
		return "NOT_INITIALIZED";
	default:
		return "UNKNOWN";
	}
}

char * _bt_convert_disc_reason_to_string(int reason)
{
	switch(reason) {
	case 1:
		return "Link loss";
	case 2:
		return "Connection terminated by local host";
	case 3:
		return "Remote user terminated connection";
	case 0:
	default:
		return "Unknown";
	}
}

void _bt_logging_connection(gboolean connect, int addr_type)
{
	static int le_conn = 0;
	static int le_disc = 0;
	static int edr_conn = 0;
	static int edr_disc = 0;

	if (connect) {
		if (addr_type)
			le_conn++;
		else
			edr_conn++;
	} else {
		if (addr_type)
			le_disc++;
		else
			edr_disc++;
	}

	INFO("[PM] Number of LE conn: %d disc: %d, Number of BR/EDR conn: %d disc: %d",
			le_conn, le_disc, edr_conn, edr_disc);
}

void _bt_swap_byte_ordering(char *data, int data_len)
{
	char temp;
	int i, j;

	if (data == NULL)
		return;
	/* Swap to opposite endian */
	for (i = 0, j = data_len - 1; i < data_len; i++, j--) {
		temp = data[i];
		data[i] = data[j];
		data[j] = temp;
	}
}

int _bt_byte_arr_cmp(const char *data1, const char *data2, int data_len)
{
	int i;

	if (data1 == NULL || data2 == NULL)
		return -1;
	for (i = 0; i < data_len; i++) {
		if (data1[i] != data2[i])
			return data1[i] - data2[i];
	}
	return 0;
}
int _bt_byte_arr_cmp_with_mask(const char *data1, const char *data2,
		const char *mask, int data_len)
{
	int i;
	char a, b;

	if (data1 == NULL || data2 == NULL || mask == NULL);
	return -1;
	for (i = 0; i < data_len; i++) {
		a = data1[i] & mask[i];
		b = data2[i] & mask[i];
		if (a != b)
			return (int)(a - b);
	}
	return 0;
}

int _bt_connect_profile(char *address, char *uuid,
		void *cb, gpointer func_data)
{
	char *object_path;
	GDBusProxy *proxy;
	GDBusConnection *conn;
	GDBusProxy *adapter_proxy;
	GError *error = NULL;

	conn = _bt_get_system_gconn();
	if (conn == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	object_path = _bt_get_device_object_path(address);
	if (object_path == NULL) {
		ERR("No searched device");

		adapter_proxy = _bt_get_adapter_proxy();
		if (adapter_proxy == NULL)
			return  BT_HAL_ERROR_INTERNAL;

		g_dbus_proxy_call_sync(adapter_proxy, "CreateDevice",
				g_variant_new("(s)", address),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&error);

		if (error != NULL) {
			ERR("CreateDevice Fail: %s", error->message);
			g_error_free(error);
		}

		object_path = _bt_get_device_object_path(address);
	}
	if (object_path == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			object_path, BT_HAL_DEVICE_INTERFACE,  NULL, NULL);
	g_free(object_path);
	if (proxy == NULL)
		return  BT_HAL_ERROR_INTERNAL;


	g_dbus_proxy_call(proxy, "ConnectProfile",
			g_variant_new("(s)", uuid),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT,
			NULL,
			(GAsyncReadyCallback)cb,
			func_data);

	return BT_HAL_ERROR_NONE;
}

int _bt_disconnect_profile(char *address, char *uuid,
		void *cb, gpointer func_data)
{
	char *object_path;
	GDBusProxy *proxy;
	GDBusConnection *conn;

	conn = _bt_get_system_gconn();
	if (conn == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	object_path = _bt_get_device_object_path(address);
	if (object_path == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
			NULL, BT_HAL_BLUEZ_NAME,
			object_path, BT_HAL_DEVICE_INTERFACE,  NULL, NULL);
	g_free(object_path);
	if (proxy == NULL)
		return  BT_HAL_ERROR_INTERNAL;

	g_dbus_proxy_call(proxy, "DisconnectProfile",
			g_variant_new("(s)", uuid),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT,
			NULL,
			(GAsyncReadyCallback)cb,
			func_data);

	return BT_HAL_ERROR_NONE;
}

int _bt_register_profile(bt_hal_register_profile_info_t *info, gboolean use_default_rfcomm)
{
	GVariantBuilder *option_builder;
	GVariant *ret;
	GDBusProxy *proxy;
	GError *err = NULL;
	int result = BT_STATUS_SUCCESS;

	proxy = _bt_get_profile_proxy();
	if (proxy == NULL) {
		ERR("Getting profile proxy failed");
		return BT_STATUS_FAIL;
	}

	option_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	if (info->authentication)
		g_variant_builder_add(option_builder, "{sv}",
				"RequireAuthentication",
				g_variant_new_boolean(TRUE));
	if (info->authorization)
		g_variant_builder_add(option_builder, "{sv}",
				"RequireAuthorization",
				g_variant_new_boolean(TRUE));
	if (info->role)
		g_variant_builder_add(option_builder, "{sv}",
				"Role",
				g_variant_new_string(info->role));

	/*
	 * Setting RFCOMM channel to default value 0; would allow bluez to assign
	 * RFCOMM channels based on the availability when two services want to use
	 * the RFCOMM along with SPP. Hence bluez makes sure that no two services
	 * use the same SPP RFCOMM channel.
	 */
	if (use_default_rfcomm)
		g_variant_builder_add(option_builder, "{sv}",
				"Channel",
				g_variant_new_uint16(RFCOMM_DEFAULT_PROFILE_CHANNEL));
	if (info->service)
		g_variant_builder_add(option_builder, "{sv}",
				"Service",
				g_variant_new_string(info->service));

	ret = g_dbus_proxy_call_sync(proxy, "RegisterProfile",
			g_variant_new("(osa{sv})", info->obj_path,
				info->uuid,
				option_builder),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &err);
	if (err) {
		ERR("RegisterProfile failed: %s", err->message);

		if (g_strrstr(err->message, BT_HAL_ACCESS_DENIED_MSG))
			result = BT_STATUS_AUTH_REJECTED;
		else
			result = BT_STATUS_FAIL;

		g_clear_error(&err);
	}

	g_variant_builder_unref(option_builder);

	if (ret)
		g_variant_unref(ret);

	return result;
}

void _bt_unregister_profile(char *path)
{
	GVariant *ret;
	GDBusProxy *proxy;
	GError *err = NULL;

	proxy = _bt_get_profile_proxy();
	if (proxy == NULL) {
		ERR("Getting profile proxy failed");
		return;
	}

	ret = g_dbus_proxy_call_sync(proxy, "UnregisterProfile",
			g_variant_new("(o)", path),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &err);
	if (err) {
		ERR("UnregisterProfile failed : %s", err->message);
		g_clear_error(&err);
	}

	if (ret)
		g_variant_unref(ret);

	return;
}

static void __new_connection_method(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	DBG("method %s", method_name);
	if (g_strcmp0(method_name, "NewConnection") == 0) {
		int index;
		int fd;
		GUnixFDList *fd_list;
		GDBusMessage *msg;
		GVariantBuilder *properties;
		char *obj_path;
		bt_bdaddr_t remote_addr1;
		char addr[BT_HAL_ADDRESS_STRING_SIZE];
		bt_hal_new_connection_cb cb = user_data;

		g_variant_get(parameters, "(oha{sv})", &obj_path, &index,
				&properties);

		msg = g_dbus_method_invocation_get_message(invocation);
		fd_list = g_dbus_message_get_unix_fd_list(msg);
		if (fd_list == NULL) {
			GQuark quark = g_quark_from_string("rfcomm-app");
			GError *err = g_error_new(quark, 0, "No fd in message");
			g_dbus_method_invocation_return_gerror(invocation, err);
			g_error_free(err);
			return;
		}


		fd = g_unix_fd_list_get(fd_list, index, NULL);
		if (fd == -1) {
			ERR("Invalid fd return");
			GQuark quark = g_quark_from_string("rfcomm-app");
			GError *err = g_error_new(quark, 0, "Invalid FD return");
			g_dbus_method_invocation_return_gerror(invocation, err);
			g_error_free(err);
			return;
		}
		INFO("Object Path %s", obj_path);

		_bt_convert_device_path_to_address(obj_path, addr);
		_bt_convert_addr_string_to_type(remote_addr1.address, (const char *)addr);
		INFO("fd: %d, address %s", fd, addr);

		g_dbus_method_invocation_return_value(invocation, NULL);

		if (cb)
			cb(object_path, fd, &remote_addr1);
	} else if (g_strcmp0(method_name, "RequestDisconnection") == 0) {
		g_dbus_method_invocation_return_value(invocation, NULL);
	}
}

static GDBusNodeInfo *_bt_get_gdbus_node(const gchar *xml_data)
{
	if (bus_id == 0) {
		char *name = g_strdup_printf("org.bt.frwk%d", getpid());

		bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				name,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				NULL,
				NULL,
				NULL,
				NULL,
				NULL);
		DBG("Got bus id %d", bus_id);
		g_free(name);
	}

	return g_dbus_node_info_new_for_xml(xml_data, NULL);
}

static const GDBusInterfaceVTable method_table = {
	__new_connection_method,
	NULL,
	NULL,
};

int _bt_register_new_gdbus_object(const char *path, bt_hal_new_connection_cb cb)
{
	GDBusConnection *gconn;
	int id;
	GError *error = NULL;

	gconn = _bt_get_system_gconn();
	if (gconn == NULL)
		return -1;

	if (new_conn_node == NULL)
		new_conn_node = _bt_get_gdbus_node(rfcomm_agent_xml);

	if (new_conn_node == NULL)
		return -1;

	id = g_dbus_connection_register_object(gconn, path,
			new_conn_node->interfaces[0],
			&method_table,
			cb, NULL, &error);
	if (id == 0) {
		ERR("Failed to register: %s", error->message);
		g_error_free(error);
		return -1;
	}

	DBG("NEW CONNECTION ID %d", id);

	return id;
}

void _bt_unregister_gdbus_object(int object_id)
{
	GDBusConnection *gconn;

	gconn = _bt_get_system_gconn();
	if (gconn == NULL)
		return;

	g_dbus_connection_unregister_object(gconn, object_id);
}

int _bt_discover_services(char *address, char *uuid, void *cb, gpointer func_data)
{
	char *object_path;
	GDBusProxy *proxy;
	GDBusProxy *adapter_proxy;
	GError *err = NULL;
	GDBusConnection *conn;

	conn = _bt_get_system_gconn();
	if (conn == NULL) {
		ERR("conn == NULL, return");
		return  BT_STATUS_FAIL;
	}

	object_path = _bt_get_device_object_path(address);
	if (object_path == NULL) {
		GVariant *ret = NULL;

		INFO("No searched device");
		adapter_proxy = _bt_get_adapter_proxy();
		if(adapter_proxy == NULL) {
			ERR("adapter_proxy == NULL, return");
			return BT_STATUS_FAIL;
		}

		ret = g_dbus_proxy_call_sync(adapter_proxy, "CreateDevice",
				g_variant_new("(s)", address),
				G_DBUS_CALL_FLAGS_NONE,
				BT_HAL_MAX_DBUS_TIMEOUT, NULL,
				&err);
		if (err != NULL) {
			ERR("CreateDevice Failed: %s", err->message);
			g_clear_error(&err);
		}

		if (ret)
			g_variant_unref(ret);

		g_object_unref(adapter_proxy);
		object_path = _bt_get_device_object_path(address);
		if (object_path == NULL) {
			ERR("object_path == NULL, return");
			return BT_STATUS_FAIL;
		}
	}

	proxy = g_dbus_proxy_new_sync(conn,
			G_DBUS_PROXY_FLAGS_NONE, NULL,
			BT_HAL_BLUEZ_NAME, object_path,
			BT_HAL_DEVICE_INTERFACE,  NULL, NULL);
	g_free(object_path);
	if (proxy == NULL) {
		ERR("Error while getting proxy");
		return BT_STATUS_FAIL;
	}

	g_dbus_proxy_call(proxy, "DiscoverServices",
			g_variant_new("(s)", uuid),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT, NULL,
			(GAsyncReadyCallback)cb,
			func_data);
	DBG("-");
	return BT_STATUS_SUCCESS;
}

int _bt_cancel_discovers(char *address)
{
	char *object_path;
	GDBusProxy *proxy;
	GDBusProxy *adapter_proxy;
	GError *err = NULL;
	GDBusConnection *conn;

	conn = _bt_get_system_gconn();
	if (conn == NULL)
		return  BT_STATUS_FAIL;

	object_path = _bt_get_device_object_path(address);
	if (object_path == NULL) {
		GVariant *ret = NULL;
		INFO("No searched device");
		adapter_proxy = _bt_get_adapter_proxy();
		if(adapter_proxy == NULL) {
			ERR("adapter_proxy == NULL, return");
			return BT_STATUS_FAIL;
		}

		ret = g_dbus_proxy_call_sync(adapter_proxy, "CreateDevice",
				g_variant_new("(s)", address),
				G_DBUS_CALL_FLAGS_NONE,
				BT_HAL_MAX_DBUS_TIMEOUT, NULL,
				&err);
		if (err != NULL) {
			ERR("CreateDevice Failed: %s", err->message);
			g_clear_error(&err);
		}

		if (ret)
			g_variant_unref(ret);

		g_object_unref(adapter_proxy);

		object_path = _bt_get_device_object_path(address);
		if (object_path == NULL)
			return BT_STATUS_FAIL;
	}

	proxy = g_dbus_proxy_new_sync(conn,
			G_DBUS_PROXY_FLAGS_NONE, NULL,
			BT_HAL_BLUEZ_NAME, object_path,
			BT_HAL_DEVICE_INTERFACE,  NULL, NULL);
	g_free(object_path);
	g_dbus_proxy_call_sync(proxy, "CancelDiscovery",
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT, NULL,
			&err);
	if (err) {
		ERR("DBus Error message: [%s]", err->message);
		g_clear_error(&err);
		return BT_STATUS_FAIL;
	}

	if (proxy)
		g_object_unref(proxy);

	return BT_STATUS_SUCCESS;
}

int _bt_discover_service_uuids(char *address, char *remote_uuid)
{
	char *object_path;
	GDBusProxy *proxy;
	GDBusConnection *gconn;
	GError *err = NULL;
	char **uuid_value = NULL;
	gsize size;
	int i =0;
	GVariant *value = NULL;
	GVariant *ret = NULL;
	int result = BT_STATUS_FAIL;

	DBG("+");

	if(remote_uuid == NULL) {
		ERR("remote_uuid == NULL, return");
		return BT_STATUS_FAIL;
	}

	gconn = _bt_get_system_gconn();
	if(gconn == NULL) {
		ERR("gconn == NULL, return");
		return BT_STATUS_FAIL;
	}

	object_path = _bt_get_device_object_path(address);
	if(object_path == NULL) {
		ERR("object_path == NULL, return");
		return BT_STATUS_FAIL;
	}

	proxy = g_dbus_proxy_new_sync(gconn, G_DBUS_PROXY_FLAGS_NONE, NULL,
			BT_HAL_BLUEZ_NAME, object_path, BT_HAL_PROPERTIES_INTERFACE, NULL,
			&err);
	if(proxy == NULL) {
		ERR("proxy == NULL, return");
		return BT_STATUS_FAIL;
	}

	if (err) {
		ERR("DBus Error: [%s]", err->message);
		g_clear_error(&err);
	}

	ret = g_dbus_proxy_call_sync(proxy, "GetAll",
			g_variant_new("(s)", BT_HAL_DEVICE_INTERFACE),
			G_DBUS_CALL_FLAGS_NONE,
			BT_HAL_MAX_DBUS_TIMEOUT, NULL,
			&err);
	if (err) {
		result = BT_STATUS_FAIL;
		ERR("DBus Error : %s", err->message);
		g_clear_error(&err);
		goto done;
	}

	if (ret == NULL) {
		ERR("g_dbus_proxy_call_sync function return NULL");
		result = BT_STATUS_FAIL;
		goto done;
	}

	g_variant_get(ret, "(@a{sv})", &value);
	g_variant_unref(ret);
	if (value) {
		GVariant *temp_value = g_variant_lookup_value(value, "UUIDs",
				G_VARIANT_TYPE_STRING_ARRAY);

		if (temp_value)
			size = g_variant_get_size(temp_value);

		if (size > 0) {
			uuid_value = (char **)g_variant_get_strv(temp_value, &size);
			DBG("Size items %d", size);
		}

		if (temp_value)
			g_variant_unref(temp_value);

		for (i = 0; uuid_value[i] != NULL; i++) {
			DBG("Remote uuids %s, searched uuid: %s",
					uuid_value[i], remote_uuid);
			if (strcasecmp(uuid_value[i], remote_uuid) == 0) {
				result = BT_STATUS_SUCCESS;
				goto done;
			}
		}
	}

done:
	if (proxy)
		g_object_unref(proxy);
	if (value)
		g_variant_unref(value);
	if (uuid_value)
		g_free(uuid_value);

	DBG("-");
	return result;
}

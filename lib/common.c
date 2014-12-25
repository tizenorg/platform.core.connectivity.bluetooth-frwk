/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
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

#include <stdbool.h>
#include <gio/gio.h>
#include <dbus/dbus.h>
#include <gio/gunixfdlist.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include "common.h"

struct error_map_t {
	const gchar *error_key_str;
	enum bluez_error_type type;
} error_map[] = {
	{"Error.DoesNotExist:", 	ERROR_DOES_NOT_EXIST},
	{"Error.InvalidArguments",	ERROR_INVALID_ARGUMENTS},
	{"Error.AlreadyExists", 	ERROR_ALREADY_EXISTS},
	{"Error.Failed", 		ERROR_FAILED},
	{"Error.AuthenticationFailed",	ERROR_AUTH_FAILED},
	{"Error.AuthenticationCanceled",ERROR_AUTH_CANCELED},
	{"Error.AuthenticationRejected",ERROR_AUTH_REJECT},
	{"Error.AuthenticationTimeout",	ERROR_AUTH_TIMEOUT},
	{"Error.ConnectionAttemptFailed",ERROR_AUTH_ATTEMPT_FAILED},
	{NULL, 				ERROR_NONE},
};

static GDBusConnection *conn;

enum bluez_error_type get_error_type(GError *error)
{
	int i = 0;

	while (error_map[i].error_key_str != NULL) {
		const gchar *error_info = error_map[i].error_key_str;

		if (g_strrstr(error->message, error_info))
			return error_map[i].type;

		i++;
	}

	return ERROR_NONE;
}
int property_get_boolean(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				gboolean *value)
{
	GVariant *bool_v, *bool_vv;
	GError *error = NULL;

	bool_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (bool_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(bool_vv, "(v)", &bool_v);

	*value = g_variant_get_boolean(bool_v);

	g_variant_unref(bool_v);

	return 0;
}

char *property_get_string(GDBusProxy *proxy,
				const char *interface_name,
				const char *property)
{
	GVariant *string_v, *string_vv;
	char *string;
	GError *error = NULL;

	string_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (string_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(string_vv, "(v)", &string_v);

	string = g_variant_dup_string(string_v, NULL);

	g_variant_unref(string_v);

	return string;
}

int property_get_int16(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				gint16 *value)
{
	GVariant *int16_v, *int16_vv;
	GError *error = NULL;

	int16_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (int16_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(int16_vv, "(v)", &int16_v);

	*value = g_variant_get_int16(int16_v);

	g_variant_unref(int16_v);

	return 0;
}

int property_get_uint16(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint16 *value)
{
	GVariant *uint16_v, *uint16_vv;
	GError *error = NULL;

	uint16_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (uint16_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(uint16_vv, "(v)", &uint16_v);

	*value = g_variant_get_uint16(uint16_v);

	g_variant_unref(uint16_v);

	return 0;
}

int property_get_uint32(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint32 *u32)
{
	GVariant *u32_v, *u32_vv;
	GError *error = NULL;

	u32_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);
	if (u32_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(u32_vv, "(v)", &u32_v);

	*u32 = g_variant_get_uint32(u32_v);

	g_variant_unref(u32_v);

	return 0;
}

int property_get_uint64(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint64 *u64)
{
	GVariant *u64_v, *u64_vv;
	GError *error = NULL;

	u64_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);
	if (u64_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(u64_vv, "(v)", &u64_v);

	*u64 = g_variant_get_uint64(u64_v);

	g_variant_unref(u64_v);

	return 0;
}

char **property_get_string_list(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *strv_v, *strv_vv;
	char **strv;
	GError *error = NULL;

	strv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (strv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(strv_vv, "(v)", &strv_v);

	strv = g_variant_dup_strv(strv_v, NULL);

	return strv;
}

char **property_get_object_list(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *objv_v, *objv_vv;
	char **objv;
	GError *error = NULL;

	objv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (objv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(objv_vv, "(v)", &objv_v);

	objv = g_variant_dup_objv(objv_v, NULL);

	return objv;
}

GByteArray *property_get_bytestring(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *bytv_v, *bytv_vv;
	GByteArray *gb_array = NULL;
	GError *error = NULL;
	GVariantIter *byt_iter;
	guchar g_value;

	bytv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (bytv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(bytv_vv, "(v)", &bytv_v);

	g_variant_get(bytv_v, "ay", &byt_iter);

	gb_array = g_byte_array_new();

	while (g_variant_iter_loop(byt_iter, "y", &g_value)) {
		g_byte_array_append(gb_array, &g_value,
					sizeof(unsigned char));
	}

	return gb_array;
}

void property_set_string(GDBusProxy *proxy,
					const char *interface_name,
					const char *property,
					const char *str)
{
	GError *error = NULL;
	GVariant *val = g_variant_new("s", str);
	GVariant *parameters = g_variant_new("(ssv)",
		interface_name, property, val);

	g_dbus_proxy_call_sync(
			proxy, "Set", parameters,
			0, -1, NULL, &error);
}

void property_set_uint64(GDBusProxy *proxy,
					const char *interface_name,
					const char *property,
					guint64 u64)
{
	GError *error = NULL;
	GVariant *val = g_variant_new("t", u64);
	GVariant *parameters = g_variant_new("(ssv)",
				interface_name, property, val);

	g_dbus_proxy_call_sync(
			proxy, "Set", parameters,
			0, -1, NULL, &error);
}

void convert_device_path_to_address(const gchar *device_path,
					gchar *device_address)
{
	gchar address[BT_ADDRESS_STRING_SIZE] = { 0 };
	gchar *dev_addr;

	if (device_path == NULL || device_address == NULL)
		return;

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		gchar *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL)
			*pos = ':';

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}

void simple_reply_callback(GObject *source_object, GAsyncResult *res,
							gpointer user_data)
{
	struct simple_reply_data *reply_data = user_data;
	enum bluez_error_type error_type = ERROR_NONE;
	GError *error = NULL;
	GVariant *ret;

	if (!reply_data || !reply_data->proxy)
		goto done;

	ret = g_dbus_proxy_call_finish(reply_data->proxy, res, &error);
	if (ret == NULL) {
		DBG("%s", error->message);
		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	if (!reply_data)
		return;

	if (reply_data->reply_cb)
		reply_data->reply_cb(error_type, reply_data->user_data);

done:
	g_free(reply_data);
}

void device_path_to_address(const char *device_path, char *device_address)
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

		while ((pos = strchr(address, '_')) != NULL)
			*pos = ':';

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}

static int check_address(const char *device_address)
{
	DBG("");

	if (strlen(device_address) != 17)
		return -1;

	while (*device_address) {
		device_address += 2;

		if (*device_address == 0)
			break;

		if (*device_address++ != ':')
			return -1;
	}

	return 0;
}

unsigned char *convert_address_to_baddr(const char *address)
{
	int i, num;
	unsigned char *baddr = g_malloc0(6);

	DBG("address = %s, len = %d", address,
					(int)strlen(address));

	if (baddr == NULL)
		return NULL;

	if (check_address(address) != 0) {
		DBG("check_address != 0");
		return NULL;
	}

	num = 0;

	DBG("address = %s", address);

	for (i = 5; i >= 0; i--, address += 3) {
		baddr[num++] = strtol(address, NULL, 16);
		DBG("0x%2x", baddr[num-1]);
	}

	return baddr;
}

GDBusConnection *get_system_lib_dbus_connect(void)
{
	GError *error = NULL;

	if (conn)
		return conn;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (conn == NULL) {
		DBG("%s", error->message);

		g_error_free(error);
	}

	return conn;
}

unsigned int convert_appearance_to_type(unsigned int appearance)
{
	/*todo support it later*/
	return 0x00;
}

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

#include <string.h>
#include <stdio.h>
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
					const char *property,
					gboolean *value)
{
	GVariant *bool_v;

	bool_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (bool_v == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	*value = g_variant_get_boolean(bool_v);

	g_variant_unref(bool_v);

	return 0;
}

char *property_get_string(GDBusProxy *proxy,
					const char *property)
{
	GVariant *string_v;
	char *string;

	string_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (string_v == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	string = g_variant_dup_string(string_v, NULL);

	g_variant_unref(string_v);

	return string;
}

int property_get_int16(GDBusProxy *proxy,
					const char *property,
					gint16 *value)
{
	GVariant *int16_v;

	int16_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (int16_v == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	*value = g_variant_get_int16(int16_v);

	g_variant_unref(int16_v);

	return 0;
}

int property_get_uint32(GDBusProxy *proxy,
					const char *property,
					guint32 *u32)
{
	GVariant *u32_v;

	u32_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (u32_v == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	*u32 = g_variant_get_uint32(u32_v);

	g_variant_unref(u32_v);

	return 0;
}

int property_get_uint64(GDBusProxy *proxy,
					const char *property,
					guint64 *u64)
{
	GVariant *u64_v;

	u64_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (u64_v == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	*u64 = g_variant_get_uint64(u64_v);

	g_variant_unref(u64_v);

	return 0;
}

char **property_get_string_list(GDBusProxy *proxy,
					const char *property)
{
	GVariant *strv_v;
	char **strv;

	strv_v = g_dbus_proxy_get_cached_property(proxy, property);
	if (strv_v == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	strv = g_variant_dup_strv(strv_v, NULL);

	return strv;
}

void property_set_string(GDBusProxy *proxy,
					const char *property,
					const char *str)
{
	g_dbus_proxy_set_cached_property(proxy, property,
				g_variant_new("s", str));
}

void property_set_uint64(GDBusProxy *proxy,
					const char *property,
					guint64 u64)
{
	g_dbus_proxy_set_cached_property(proxy, property,
				g_variant_new("t", u64));
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

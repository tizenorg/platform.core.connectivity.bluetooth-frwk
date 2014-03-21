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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

#include <gio/gio.h>

#ifndef TIZEN
#define DBG(fmt, arg...) printf("%s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)
#define WARN(fmt, arg...) printf("warning %s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)
#define ERROR(fmt, arg...) printf("error %s:%d %s()" fmt "\n", __FILE__, __LINE__, __func__, ## arg)
#else
#include <dlog.h>
#undef LOG_TAG
#define LOG_TAG "CAPI_NETWORK_BLUETOOTH"

#define WARN(fmt, args...) SLOGI(fmt, ##args)
#define DBG(fmt, args...) SLOGD(fmt, ##args)
#define ERROR(fmt, args...) SLOGE(fmt, ##args)
#endif

#define DEFAULT_ADAPTER_NAME "hci0"
#define BT_ADDRESS_STRING_SIZE 18

enum bluez_error_type {
	ERROR_NONE,
	ERROR_DOES_NOT_EXIST,
	ERROR_INVALID_ARGUMENTS,
	ERROR_ALREADY_EXISTS,
	ERROR_FAILED,
	ERROR_AUTH_CANCELED,
	ERROR_AUTH_REJECT,
	ERROR_AUTH_ATTEMPT_FAILED,
	ERROR_AUTH_TIMEOUT,
	ERROR_AUTH_FAILED
};

typedef void (*simple_reply_cb_t) (
				enum bluez_error_type type,
				void *user_data);

struct simple_reply_data {
	GDBusProxy *proxy;
	simple_reply_cb_t reply_cb;
	void *user_data;
};

enum bluez_error_type get_error_type(GError *error);

int property_get_boolean(GDBusProxy *proxy,
				const char *property,
				gboolean *value);
char *property_get_string(GDBusProxy *proxy,
				const char *property);
int property_get_int16(GDBusProxy *proxy,
				const char *property,
				gint16 *value);
int property_get_uint32(GDBusProxy *proxy,
				const char *property,
				guint32 *u32);
int property_get_uint64(GDBusProxy *proxy,
				const char *property,
				guint64 *u64);

char **property_get_string_list(GDBusProxy *proxy,
				const char *property);

void simple_reply_callback(GObject *source_object,
				GAsyncResult *res,
				gpointer user_data);

int comms_service_plugin_init(void);
void comms_service_plugin_cleanup(void);

void convert_device_path_to_address(const gchar *device_path,
					gchar *device_address);
#endif
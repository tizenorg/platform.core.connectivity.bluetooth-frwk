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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/signalfd.h>
#include <string.h>

#include "common.h"
#include "bluetooth.h"
#include "bluez.h"

#define INPUT_SIZE 255

GMainLoop *loop;
GIOChannel *channel;

static void *handler_user_data;
static void (* handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);

static int show_help(const char *p1, const char *p2);

static int quit(const char *p1, const char *p2)
{
	g_io_channel_unref(channel);
	g_main_loop_quit(loop);

	return 0;
}

static int init_bluez_lib(const char *p1, const char *p2)
{
	int err;

	err = bt_initialize();
	if (err != BT_SUCCESS) {
		ERROR("bt_initialize error: %d", err);
		return 0;
	}

	return 0;
}

static GList *device_list;

static int enable(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_enable();
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_enable error: %d", err);
		return 0;
	}

	return 0;
}

static void device_discovery_cb(int result,
			bt_adapter_device_discovery_state_e state,
			bt_adapter_device_discovery_info_s *discovery_info,
			void *user_data)
{
	if (result != BT_SUCCESS) {
		DBG("Device %s created failed: %d",
					discovery_info->remote_name,
					result);
		return;
	}

	if (state == BT_ADAPTER_DEVICE_DISCOVERY_STARTED)
		DBG("BT_ADAPTER_DEVICE_DISCOVERY_STARTED");
	else if (state == BT_ADAPTER_DEVICE_DISCOVERY_FOUND) {
		int len;
		GList *iter, *next;
		bt_adapter_device_discovery_info_s *device_info;

		device_info = g_new0(bt_adapter_device_discovery_info_s, 1);
		if (device_info == NULL) {
			ERROR("no memory");
			return;
		}

		DBG("Device %s has found, follow is info:",
					discovery_info->remote_name);
		DBG("\tAddress: %s", discovery_info->remote_address);
		DBG("\tRSSI: %d", discovery_info->rssi);
		DBG("\tIs bonded: %d", discovery_info->is_bonded);
		DBG("\tservice_count: %d", discovery_info->service_count);
		DBG("\tappearance: %x", discovery_info->appearance);

		for (len = 0; len < discovery_info->service_count; len++)
			DBG("\t service %d: %s", len,
					discovery_info->service_uuid[len]);

		/* Copy the data to store local */
		for (iter = g_list_first(device_list); iter; iter = next) {
			bt_adapter_device_discovery_info_s *info;

			info = iter->data;

			next = g_list_next(iter);

			if (g_strcmp0(info->remote_address,
					discovery_info->remote_address) == 0)
				return;
		}

		device_info->remote_name =
				g_strdup(discovery_info->remote_name);
		device_info->remote_address =
				g_strdup(discovery_info->remote_address);
		device_info->rssi = discovery_info->rssi;
		device_info->is_bonded = discovery_info->is_bonded;
		device_info->service_count = discovery_info->service_count;

		device_info->service_uuid =
				g_strdupv(discovery_info->service_uuid);

		device_list = g_list_append(device_list, device_info);
/*	} else if (state == BT_ADAPTER_DEVICE_DISCOVERY_REMOVED) {
		GList *iter, *next;

		for (iter = g_list_first(device_list); iter; iter = next) {
			bt_adapter_device_discovery_info_s *info;

			info = iter->data;

			next = g_list_next(iter);

			if (g_strcmp0(info->remote_address,
					discovery_info->remote_address) == 0) {
				device_list = g_list_remove(device_list, info);
				g_free(info->remote_name);
				g_free(info->remote_address);
				g_strfreev(info->service_uuid);
				g_free(info);
			}
		}
*/
	} else if (state == BT_ADAPTER_DEVICE_DISCOVERY_FINISHED)
		DBG("BT_ADAPTER_DEVICE_DISCOVERY_FINISHED");
	else
		DBG("Unknown device discovery state");
}

static int set_discovery_callback(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_set_device_discovery_state_changed_cb(
					device_discovery_cb, NULL);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_set_device_discovery_state_changed_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int start_discovery(const char *p1, const char *p2)
{
	int err;

	if (g_strcmp0(p1, "le") == 0)
		err = bt_adapter_le_start_device_discovery();
	else
		err = bt_adapter_start_device_discovery();

	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_start_device_discovery error: %d", err);
		return 0;
	}

	return 0;
}

static int stop_discovery(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_stop_device_discovery();
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_stop_device_discovery error: %d", err);
		return 0;
	}

	return 0;
}

static bool gatt_primary_service_callback(bt_gatt_attribute_h service,
					void *user_data)
{
	const char *service_handle = service;

	DBG("Primary service found %s", service_handle);

	return TRUE;
}


static int gatt_foreach_primary_services(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt primary service must give the device address");
		return 0;
	}

	ret = bt_gatt_foreach_primary_services(p1,
				gatt_primary_service_callback, NULL);

	DBG("ret = %d", ret);

	return 0;
}

static void bt_gatt_char_changed_cb_test(bt_gatt_attribute_h characteristic,
					unsigned char *value,
					int value_length,
					void *user_data)
{
	char *gatt_char_path = characteristic;
	int i;

	DBG("Characteristic handle %s", gatt_char_path);

	for (i = 0; i < value_length; i++)
		DBG("value %c", value[i]);

	DBG("Value length %d", value_length);
}

static int gatt_set_characteristic_changed_cb(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt set changed cb must give the service handle");
		return 0;
	}

	ret = bt_gatt_set_characteristic_changed_cb(
				(bt_gatt_attribute_h)p1,
				bt_gatt_char_changed_cb_test,
				NULL);

	DBG("ret = %d", ret);

	return 0;
}

static void device_connect_callback(int result, void *user_data)
{
	DBG("device connect callback result is %d", result);
}

static int device_connect_le(const char *p1, const char *p2)
{
	int err;

	err = bt_device_connect_le(device_connect_callback, p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_connect_le error: %d", err);
		return 0;
	}

	return 0;
}

static void device_disconnect_callback(int result, void *user_data)
{
	DBG("device disconnect callback result is %d", result);
}

static int device_disconnect_le(const char *p1, const char *p2)
{
	int err;

	err = bt_device_disconnect_le(device_disconnect_callback, p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_disconnect_le error: %d", err);
		return 0;
	}

	return 0;
}

struct {
	const char *command;
	int (*function)(const char *p1, const char *p2);
	const char *description;
} command_ops[] = {
	{"h", show_help,
		"Usage: h\n\tThis help"},

	{"init_bluez", init_bluez_lib,
		"Usage: init_bluez\n\tInitialize bluez-lib"},

	{"enable", enable,
		"Usage: enable\n\tEnable the local adapter"},

	{"set_discovery_callback", set_discovery_callback,
		"Usage: set_discovery_callback\n\tSet device found callback"},

	{"start_discovery", start_discovery,
		"Usage: start_discovery all/le\n\tStart to discovery devices"},

	{"stop_discovery", stop_discovery,
		"Usage: stop_discovery\n\tStop to discovery devices"},

	{"device_connect_le", device_connect_le,
		"Usage: device_connect_le 70:F9:27:64:DF:65\n\tConnect LE device"},

	{"device_disconnect_le", device_disconnect_le,
		"Usage: device_disconnect_le 70:F9:27:64:DF:65\n\tDisconnect LE device"},

	{"gatt_foreach_primary_services", gatt_foreach_primary_services,
		"Usage: gatt_foreach_primary_services\n\tgatt foreach primary services"},

	{"gatt_set_characteristic_changed_cb", gatt_set_characteristic_changed_cb,
		"Usage: gatt_set_characteristic_changed_cb\n\tgatt set characteristic changed cb"},

	{"q", quit,
		"Usage: q\n\tQuit"},

	{NULL, NULL} };

static int show_help(const char *p1, const char *p2)
{
	int i = 0;

	while (command_ops[i].command != NULL) {
		printf("%s:\n\t%s\n", command_ops[i].command,
				command_ops[i].description);
		i++;
	}

	return 0;
}

static inline void split_input(char *str, const char **s1,
				const char **s2, const char **s3)
{
	*s1 = str;

	*s2 = *s3 = NULL;

	while (*str == ' ' || *str == '\t')
		str++;

	*s1 = str;

	if (*str == '\n') {
		*str = 0;
		*s2 = NULL;
		return;
	}

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	if (*str == '\n') {
		*str = 0;
		*s2 = NULL;
		return;
	} else
		*str = 0;

	str++;

	while (*str == ' ' || *str == '\t')
		str++;

	if (*str == '\n') {
		*s2 = NULL;
		return;
	} else
		*s2 = str;

	str++;

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	if (*str == '\n') {
		*s3 = NULL;
		*str = 0;
		return;
	} else
		*str = 0;

	str++;

	while (*str == ' ' && *str == '\t')
		str++;

	if (*str == '\n')
		return;
	else
		*s3 = str;

	str++;

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	*str = 0;
}

static void cmd_handler(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data)
{
	int i = 0;
	gboolean cmd_found = FALSE;

	if (g_strcmp0(cmd, "") == 0)
		return;

	while (command_ops[i].command != NULL) {
		if (g_strcmp0(command_ops[i].command, cmd) == 0) {
			command_ops[i].function(p1, p2);
			cmd_found = TRUE;
			break;
		}
		i++;
	}

	if (cmd_found == FALSE)
		printf("\nError: unknown command %s\n", cmd);
}

static gboolean handle_command(GIOChannel *src, GIOCondition con, gpointer data)
{
	const char *user_command, *p1, *p2;
	char buf[INPUT_SIZE + 1] = { 0, };

	if (fgets(buf, INPUT_SIZE, stdin) == NULL)
		return TRUE;

	split_input(buf, &user_command, &p1, &p2);

	if (handler)
		handler((const char *) user_command,
				p1, p2, handler_user_data);

	return TRUE;
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	gint fd;
	ssize_t readlen;
	struct signalfd_siginfo si;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	readlen = read(fd, &si, sizeof(struct signalfd_siginfo));
	if (readlen != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		DBG("Terminate.");
		g_io_channel_unref(channel);
		quit(NULL, NULL);
		break;
	default:
		break;
	}

	return TRUE;
}

static guint setup_signal_handle(void)
{
	sigset_t mask;
	int signal_fd;
	guint id;
	GIOChannel *channel;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		ERROR("Error to set signal handle");
		return 0;
	}

	signal_fd = signalfd(-1, &mask, 0);
	if (signal_fd < 0) {
		ERROR("Error to create signal file.");
		return 0;
	}

	channel = g_io_channel_unix_new(signal_fd);

	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);
	g_io_channel_set_close_on_unref(channel, TRUE);

	id = g_io_add_watch(channel,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			signal_handler, NULL);

	return id;
}

int main(int argc, char **argv)
{
#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	loop = g_main_loop_new(NULL, FALSE);

	setup_signal_handle();

	channel = g_io_channel_unix_new(STDIN_FILENO);
	g_io_add_watch(channel, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL),
							handle_command, NULL);

	handler = cmd_handler;
	handler_user_data = NULL;

	g_main_loop_run(loop);

	return 0;
}

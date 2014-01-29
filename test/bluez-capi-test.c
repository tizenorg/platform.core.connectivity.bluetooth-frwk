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

static void _device_free(gpointer data)
{
	bt_adapter_device_discovery_info_s *info = data;

	if (info) {
		g_free(info->remote_name);
		g_free(info->remote_address);
		g_strfreev(info->service_uuid);
		g_free(info);
	}
}

static int deinit_bluez_lib(const char *p1, const char *p2)
{
	int err;

	err = bt_deinitialize();
	if (err != BT_SUCCESS) {
		ERROR("bt_deinitialize error: %d", err);
		return 0;
	}

	g_list_free_full(device_list, _device_free);
	device_list = NULL;

	return 0;
}

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

static int disable(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_disable();
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_disable error: %d", err);
		return 0;
	}

	return 0;
}

static int get_adapter_state(const char *p1, const char *p2)
{
	int err;
	bt_adapter_state_e state;

	err = bt_adapter_get_state(&state);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_get_state error: %d", err);
		return 0;
	}

	DBG("%s", state == BT_ADAPTER_ENABLED ?
				"BT_ADAPTER_ENABLED" :
				"BT_ADAPTER_DISABLED");

	return 0;
}

static int get_adapter_address(const char *p1, const char *p2)
{
	int err;
	char *address = NULL;

	err = bt_adapter_get_address(&address);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_get_address error: %d", err);
		return 0;
	}

	DBG("Local adapter address: %s", address);

	if (address)
		free(address);

	return 0;
}

static int get_adapter_name(const char *p1, const char *p2)
{
	int err;
	char *name = NULL;

	err = bt_adapter_get_name(&name);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_get_name error: %d", err);
		return 0;
	}

	DBG("Local adapter name: %s", name);

	if (name)
		free(name);

	return 0;
}

static int set_adapter_name(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_set_name(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_set_name error: %d", err);
		return 0;
	}

	return 0;
}

static int get_adapter_visibility(const char *p1, const char *p2)
{
	int err, duration;
	bt_adapter_visibility_mode_e mode;

	err = bt_adapter_get_visibility(&mode, &duration);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_get_state error: %d", err);
		return 0;
	}

	switch (mode) {
	case BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE:
		DBG("BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE");
		break;
	case BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE:
		DBG("BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE");
		break;
	case BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE:
		DBG("BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE");
		break;
	default:
		DBG("Unknown mode");
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
		DBG("\tIcon: %s", discovery_info->icon);
		DBG("\tRSSI: %d", discovery_info->rssi);
		DBG("\tIs bonded: %d", discovery_info->is_bonded);
		DBG("\tservice_count: %d", discovery_info->service_count);

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
		device_info->icon = g_strdup(discovery_info->icon);
		device_info->rssi = discovery_info->rssi;
		device_info->is_bonded = discovery_info->is_bonded;
		device_info->service_count = discovery_info->service_count;

		device_info->service_uuid =
				g_strdupv(discovery_info->service_uuid);

		device_list = g_list_append(device_list, device_info);
	} else if (state == BT_ADAPTER_DEVICE_DISCOVERY_REMOVED) {
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
				g_free(info->icon);
				g_strfreev(info->service_uuid);
				g_free(info);
			}
		}
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

static void device_connected_changed(bool connected, const char *remote_address, void *user_data)
{
	DBG("Device %s connected %d", remote_address, connected);
}

static int set_device_connected_callback(const char *p1, const char *p2)
{
	int err;

	err = bt_device_set_connection_state_changed_cb(
					device_connected_changed, NULL);
	if (err != BT_SUCCESS) {
		ERROR("set_device_connected_callback error: %d", err);
		return 0;
	}

	return 0;
}

static int unset_device_connected_callback(const char *p1, const char *p2)
{
	int err;

	err = bt_device_unset_connection_state_changed_cb();
	if (err != BT_SUCCESS) {
		ERROR("unset_device_connected_callback error: %d", err);
		return 0;
	}

	return 0;
}

static int unset_discovery_callback(const char *p1, const char *p2)
{
	int err;
	GList *iter, *next;
	bt_adapter_device_discovery_info_s *device_info;

	err = bt_adapter_unset_device_discovery_state_changed_cb();
	if (err != BT_SUCCESS) {
		ERROR("unset device discovery callback error: %d", err);
		return 0;
	}

	for (iter = g_list_first(device_list); iter; iter = next) {
		next = g_list_next(iter);

		device_info = iter->data;

		device_list = g_list_remove(device_list, device_info);

		g_free(device_info->remote_name);
		g_free(device_info->remote_address);
		g_free(device_info->icon);

		g_strfreev(device_info->service_uuid);
		g_free(device_info);
	}

	g_list_free(device_list);

	device_list = NULL;

	return 0;
}

static int start_discovery(const char *p1, const char *p2)
{
	int err;

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

static void transfer_state_cb(int transfer_id,
				bt_opp_transfer_state_e state,
					const char *file, guint64 size,
					unsigned char percent, void *user_data)
{
	printf("\n\ttransfer %d state %d\n\t", transfer_id, state);
	printf("\n\t%s size %ju transfered %d\n\t", file, size, percent);
}

static void server_push_requested_cb(const char *remote_address,
					const char *file, guint64 size,
							void *user_data)
{
	int id;

	printf("\n\t%s push %s size %ju\n\t", remote_address, file, size);
	printf("\n\tAccept it...\n\t");

	bt_opp_server_accept(NULL, NULL, NULL, &id);

	printf("\n\ttransfer %d accepted\n", id);
}

static int register_opp_server(const char *p1, const char *p2)
{
	bt_opp_init();
	bt_opp_register_server("/tmp", server_push_requested_cb, NULL);
	return 0;
}

static int opp_watch(const char *p1, const char *p2)
{
	if (!g_strcmp0(p1, "on"))
		bt_opp_set_transfers_state_cb(transfer_state_cb, NULL);
	else if (!g_strcmp0(p1, "off"))
		bt_opp_clear_transfers_state_cb();
	else
		ERROR("Unknown parameter %s", (char *) p1);

	return 0;
}

static void push_responded_cb(
			const char *remote_address,
			push_state_e state,
			void *user_data)
{
	printf("\n\t %s connection state %d\n", remote_address, state);
}


static int opp_send(const char *p1, const char *p2)
{
	bt_opp_client_push_file(p1, p2, push_responded_cb, NULL,
					transfer_state_cb, NULL);
	return 0;
}

static int init_opp(const char *p1, const char *p2)
{
	bt_opp_init();

	return 0;
}

static int deinit_opp(const char *p1, const char *p2)
{
	bt_opp_deinit();

	return 0;
}

static void print_bonded_device_info(bt_device_info_s *device_info)
{
	int len;

	if (device_info == NULL)
		return;

	printf("\n\tName: %s", device_info->remote_name);
	printf("\n\t\tAddress: %s", device_info->remote_address);
	printf("\n\t\tIcon: %s", device_info->icon);
	printf("\n\t\tConnected: %d", device_info->is_connected);
	printf("\n\t\tBonded: %d", device_info->is_bonded);
	printf("\n\t\tAuthorized: %d", device_info->is_authorized);
	printf("\n\t\tservice_count: %d", device_info->service_count);

	for (len = 0; len < device_info->service_count; len++)
		printf("\n\t\t service %d: %s", len,
					device_info->service_uuid[len]);
}

bool bonded_devices(bt_device_info_s *device_info, void *user_data)
{
	print_bonded_device_info(device_info);

	return true;
}

static int list_paired_devices(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_foreach_bonded_device(bonded_devices, NULL);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_foreach_bonded_device error: %d", err);
		return 0;
	}

	return 0;
}

static int device_create_bond(const char *p1, const char *p2)
{
	int err;

	if (p1 == NULL) {
		ERROR("Create bond device must give the device address");
		return 0;
	}

	err = bt_device_create_bond(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_create_bond error: %d", err);
		return 0;
	}

	return 0;
}

static int device_destroy_bond(const char *p1, const char *p2)
{
	int err;

	if (p1 == NULL) {
		ERROR("Destroy bond-device must give the device address");
		return 0;
	}

	err = bt_device_destroy_bond(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_destroy_bond error: %d", err);
		return 0;
	}

	return 0;
}

static void device_bond_created_cb(int result,
					bt_device_info_s *device_info,
					void *user_data)
{
	if (result != BT_SUCCESS) {
		DBG("Bond-device created faild: %d", result);
		return;
	}

	printf("Device %s has created, follow is info:",
				device_info->remote_name);

	print_bonded_device_info(device_info);
}

static int device_set_bond_created_cb(const char *p1, const char *p2)
{
	int err;

	err = bt_device_set_bond_created_cb(device_bond_created_cb, NULL);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_set_bond_created_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int device_unset_bond_created_cb(const char *p1, const char *p2)
{
	int err;

	err = bt_device_unset_bond_created_cb();
	if (err != BT_SUCCESS) {
		ERROR("unset_device_connected_callback error: %d", err);
		return 0;
	}

	return 0;
}

static void device_authorization_changed_cb(
				bt_device_authorization_e authorization,
				char *remote_address, void *user_data)
{
	printf("Device %s authorization state changed: %d\n",
					remote_address, authorization);
}

static int device_set_auth_changed_cb(const char *p1, const char *p2)
{
	int err;

	err = bt_device_set_authorization_changed_cb(
				device_authorization_changed_cb, NULL);
	if (err != BT_SUCCESS) {
		ERROR("device_set_auth_changed_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int device_unset_auth_changed_cb(const char *p1, const char *p2)
{
	int err;

	err = bt_device_unset_authorization_changed_cb();
	if (err != BT_SUCCESS) {
		ERROR("bt_device_unset_authorization_changed_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int set_device_authorization(const char *p1, const char *p2)
{
	bt_device_authorization_e authorization;
	int err;

	if (p1 == NULL) {
		ERROR("set alias must give the device address");
		return 0;
	}

	if (p2 == NULL) {
		ERROR("set alias must give the alias");
		return 0;
	}

	if (!g_strcmp0(p2, "1"))
		authorization = BT_DEVICE_UNAUTHORIZED;
	else
		authorization = BT_DEVICE_AUTHORIZED;

	err = bt_device_set_authorization(p1, authorization);
	if (err != BT_SUCCESS) {
		ERROR("set_device_alias error: %d", err);
		return 0;
	}

	return 0;
}

static int set_device_alias(const char *p1, const char *p2)
{
	int err;

	if (p1 == NULL) {
		ERROR("set alias must give the device address");
		return 0;
	}

	if (p2 == NULL) {
		ERROR("set alias must give the alias");
		return 0;
	}

	err = bt_device_set_alias(p1, p2);
	if (err != BT_SUCCESS) {
		ERROR("set_device_alias error: %d", err);
		return 0;
	}

	return 0;
}

static int hid_connect(const char *p1, const char *p2)
{
	int err;

	err = bt_hid_host_connect(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_hid_host_connect error: %d", err);
		return 0;
	}

	return 0;
}

static int audio_connect(const char *p1, const char *p2)
{
	int err;

	DBG("+");
	if (g_strcmp0(p2, "a2dp") == 0) {
		DBG("a2dp");
		err = bt_audio_connect(p1, BT_AUDIO_PROFILE_TYPE_A2DP);
	} else if (g_strcmp0(p2, "all") == 0) {
		DBG("all");
		err = bt_audio_connect(p1, BT_AUDIO_PROFILE_TYPE_ALL);
	} else {
		DBG("please enter type");
		err = BT_ERROR_INVALID_PARAMETER;
		return 0;
	}

	if (err != BT_SUCCESS) {
		ERROR("bt_audio_connect error: %d", err);
		return 0;
	}
	DBG("-");

	return 0;
}

static int get_bonded_device_info(const char *p1, const char *p2)
{
	bt_device_info_s *device_info;
	int err;

	err = bt_adapter_get_bonded_device_info(p1, &device_info);
	if (err != BT_SUCCESS) {
		ERROR("bt_hid_host_connect error: %d", err);
		return 0;
	}

	DBG("Address %s Name %s Icon %s", device_info->remote_address,
						device_info->remote_name,
						device_info->icon);

	bt_adapter_free_device_info(device_info);

	return 0;
}

static int hid_disconnect(const char *p1, const char *p2)
{
	int err;

	err = bt_hid_host_disconnect(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_hid_host_connect error: %d", err);
		return 0;
	}

	return 0;
}

static int audio_disconnect(const char *p1, const char *p2)
{
	int err;

	if (g_strcmp0(p2, "a2dp") == 0) {
		DBG("a2dp");
		err = bt_audio_disconnect(p1, BT_AUDIO_PROFILE_TYPE_A2DP);
	} else if (g_strcmp0(p2, "all") == 0) {
		DBG("all");
		err = bt_audio_disconnect(p1, BT_AUDIO_PROFILE_TYPE_ALL);
	} else {
		DBG("please enter type");
		err = BT_ERROR_INVALID_PARAMETER;
		return 0;
	}

	if (err != BT_SUCCESS) {
		ERROR("bt_audio_disconnect error: %d", err);
		return 0;
	}

	return 0;
}

void audio_connection_state_changed_cb(int result,
				bool connected,
				const char *remote_address,
				bt_audio_profile_type_e type,
				void *user_data)
{
	int connection;

	if (connected == TRUE)
		connection = 1;
	else
		connection = 0;

	DBG("result = %d", result);
	DBG("connected = %d", connection);
	DBG("remote_address = %s", remote_address);
	DBG("type = %d", type);
}

static int audio_set_connection_state_changed()
{
	int err;

	DBG("");

	err = bt_audio_set_connection_state_changed_cb(
		audio_connection_state_changed_cb, NULL);

	DBG("err = %d", err);
	return err;
}

static int audio_unset_connection_state_changed()
{
	int err;

	DBG("");

	err = bt_audio_unset_connection_state_changed_cb();

	DBG("err = %d", err);
	return err;
}

void avrcp_set_shuffle_mode_changed_cb(bt_avrcp_shuffle_mode_e shuffle,
				void *user_data)
{
	if (shuffle == BT_AVRCP_SHUFFLE_MODE_OFF)
		DBG("shuffle mode off");
	else if (shuffle == BT_AVRCP_SHUFFLE_MODE_ALL_TRACK)
		DBG("All tracks shuffle");
	else if (shuffle == BT_AVRCP_SHUFFLE_MODE_GROUP)
		DBG("Group shuffle");
}


static int avrcp_set_shuffle_changed()
{
	int err;

	DBG("");

	err = bt_avrcp_set_shuffle_mode_changed_cb(
		avrcp_set_shuffle_mode_changed_cb, NULL);

	DBG("err = %d", err);
	return err;
}

static int avrcp_unset_shuffle_changed()
{
	int err;

	DBG("");

	err = bt_avrcp_unset_shuffle_mode_changed_cb();

	DBG("err = %d", err);
	return err;
}

void avrcp_set_repeat_mode_changed_cb(bt_avrcp_repeat_mode_e repeat,
					void *user_data)
{
	if (repeat == BT_AVRCP_REPEAT_MODE_OFF)
		DBG(" Repeat Off");
	else if (repeat == BT_AVRCP_REPEAT_MODE_SINGLE_TRACK)
		DBG("Single track repeat");
	else if (repeat == BT_AVRCP_REPEAT_MODE_ALL_TRACK)
		DBG("All track repeat");
	else if (repeat == BT_AVRCP_REPEAT_MODE_GROUP)
		DBG("Group repeat");
}

static int avrcp_set_repeat_changed()
{
	int err;

	DBG("");

	err = bt_avrcp_set_repeat_mode_changed_cb(
		avrcp_set_repeat_mode_changed_cb, NULL);

	DBG("err = %d", err);
	return err;
}

static int avrcp_unset_repeat_changed()
{
	int err;

	DBG("");

	err = bt_avrcp_unset_repeat_mode_changed_cb();

	DBG("err = %d", err);
	return err;
}

void avrcp_target_connection_state_changed_cb(bool connected,
					const char *remote_address,
					void *user_data)
{
	if (connected)
		DBG("connected true");
	else
		DBG("connected false");
	DBG("remote_address = %s", remote_address);
}

static int avrcp_target_initialize()
{
	int err;

	DBG("");

	err = bt_avrcp_target_initialize(
		avrcp_target_connection_state_changed_cb, NULL);

	DBG("err = %d", err);
	return err;
}

static int avrcp_target_deinitialize()
{
	int err;

	DBG("");

	err = bt_avrcp_target_deinitialize();

	DBG("err = %d", err);
	return err;
}

static int list_devices(const char *p1, const char *p2)
{
	int len;
	GList *iter, *next;

	DBG("Count: %d", g_list_length(device_list));

	for (iter = g_list_first(device_list); iter; iter = next) {
		bt_adapter_device_discovery_info_s *discovery_info;

		discovery_info = iter->data;

		next = g_list_next(iter);

		printf("\n\tName: %s", discovery_info->remote_name);
		printf("\n\t\tAddress: %s", discovery_info->remote_address);
		printf("\n\t\tIcon: %s", discovery_info->icon);
		printf("\n\t\tRSSI: %d", discovery_info->rssi);
		printf("\n\t\tBonded: %d", discovery_info->is_bonded);
		printf("\n\t\tservice_count: %d", discovery_info->service_count);

		for (len = 0; len < discovery_info->service_count; len++)
			printf("\n\t\t service %d: %s", len,
					discovery_info->service_uuid[len]);
	}

	return 0;
}

static inline void split_input(char *str, const char **str1,
					const char **s2, const char **s3);

void display_pincode(const char *device_name,
			const char *pincode, void *user_data)
{
	DBG("Device %s display %s", device_name, pincode);
}

void request_pincode(const char *device_name, void *user_data)
{
	const gchar *pin_code, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\tPlease input pincode:(C mean canncel)");

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &pin_code, &p1, &p2);

	if (g_ascii_strncasecmp(pin_code, "C", 1) == 0)
		bt_agent_pincode_cancel(user_data);
	else
		bt_agent_pincode_reply(pin_code, user_data);
}

void request_passkey(const char *device_name, void *user_data)
{
	DBG("");
}

void display_passkey(const char *device_name,
			const char *passkey, void *user_data)
{
	DBG("");
}

void request_confirm(const char *device_name,
			unsigned int confor_num, void *user_data)
{
	const gchar *confirm_info, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\tPlease Confirm(Y/N):\n");

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &confirm_info, &p1, &p2);

	if (g_ascii_strncasecmp(confirm_info, "y", 1))
		bt_agent_confirm_reject(user_data);
	else
		bt_agent_confirm_accept(user_data);
}

void authorize_service(const char *device,
			const char *uuid, void *user_data)
{
	DBG("");
}

/* Should free in unregister_agent */
bt_agent *bt_agent_new;

static int register_agent(const char *p1, const char *p2)
{
	int err;

	bt_agent_new = g_new0(bt_agent, 1);
	if (bt_agent_new == NULL) {
		ERROR("no memroy");
		return 0;
	}

	bt_agent_new->display_pincode = display_pincode;
	bt_agent_new->request_pincode = request_pincode;
	bt_agent_new->request_passkey = request_passkey;
	bt_agent_new->display_passkey = display_passkey;
	bt_agent_new->request_confirm = request_confirm;
	bt_agent_new->authorize_service = authorize_service;

	err = bt_agent_register(bt_agent_new);
	if (err != BT_SUCCESS) {
		ERROR("bt_agent_register error: %d", err);

		g_free(bt_agent_new);
		return 0;
	}

	return 0;
}

static void new_connection(const char *uuid, const char *device_name,
						int fd, void *user_data)
{
	DBG("%s %s comming connect with %d", device_name, uuid, fd);
}

static int spp_create(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("spp create must give the UUID");
		return 0;
	}

	ret = bt_spp_create_rfcomm(p1, new_connection, NULL);
	if (ret != BT_SUCCESS)
		DBG("spp create failed");

	return 0;
}

static int spp_destory(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("spp create must give the UUID");
		return 0;
	}

	ret = bt_spp_destroy_rfcomm(p1);
	if (ret != BT_SUCCESS)
		DBG("destroy spp failed");

	return 0;
}

static void spp_authorize_cb(const char *uuid, const char *device_name,
				bt_req_t *requestion, void *user_data)
{
	const gchar *confirm_info, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\t%s %s requset connect, Please input(Y/N):\n",
						device_name, uuid);

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &confirm_info, &p1, &p2);

	if (g_ascii_strncasecmp(confirm_info, "y", 1))
		bt_spp_reject(requestion);
	else
		bt_spp_accept(requestion);
}

static int spp_set_authorize_cb(const char *p1, const char *p2)
{
	int ret;

	ret = bt_spp_set_connection_requested_cb(spp_authorize_cb, NULL);
	if (ret != BT_SUCCESS)
		DBG("spp set connection requested callback failed");

	return 0;
}

static void spp_data_received(bt_spp_received_data *data, void *user_data)
{
	DBG("received data from %d %s", data->socket_fd, data->data);
}

static int spp_set_data_receive_cb(const char *p1, const char *p2)
{
	int ret;

	ret = bt_spp_set_data_received_cb(spp_data_received, NULL);
	if (ret != BT_SUCCESS)
		DBG("set spp data received callback failed");

	return 0;
}

static int spp_connect(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("spp connect must give the device address");
		return 0;
	}

	if (p2 == NULL) {
		ERROR("spp connect must give the UUID");
		return 0;
	}

	ret = bt_spp_connect_rfcomm(p1, p2);
	if (ret != BT_SUCCESS)
		DBG("spp connect failed");

	return 0;
}

static int spp_disconnect(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("spp disconnect must give the device address");
		return 0;
	}

	if (p2 == NULL) {
		ERROR("spp disconnect must give the UUID");
		return 0;
	}

	ret = bt_spp_disconnect_rfcomm(p1, p2);
	if (ret != BT_SUCCESS)
		DBG("disconnect spp failed");

	return 0;
}

static int spp_send(const char *p1, const char *p2)
{
	int ret, fd;

	fd = g_ascii_strtoll(p1, NULL, 10);
	if (fd < 0) {
		DBG("invalid fd %d", fd);
		return 0;
	}

	ret = bt_spp_send_data(fd, p2, strlen(p2));
	if (ret != BT_SUCCESS)
		DBG("spp send failed");

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

	{"deinit_bluez", deinit_bluez_lib,
		"Usage: deinit\n\tDe-initialize bluez-lib"},

	{"enable", enable,
		"Usage: enable\n\tEnable the local adapter"},

	{"disable", disable,
		"Usage: disable\n\tDisable the local adapter"},

	{"get_adapter_state", get_adapter_state,
		"Usage: get_adapter_state\n\tGet local adapter state(Power on/off)"},

	{"get_adapter_address", get_adapter_address,
		"Usage: get_adapter_address\n\tGet local adapter address"},

	{"get_adapter_name", get_adapter_name,
		"Usage: get_adapter_name\n\tGet local adapter name"},

	{"set_adapter_name", set_adapter_name,
		"Usage: set_adapter_name\n\tSet local adapter name"},

	{"get_adapter_visibility", get_adapter_visibility,
		"Usage: get_adapter_visibility\n\tGet local adapter visibility"},

	{"set_discovery_callback", set_discovery_callback,
		"Usage: set_discovery_callback\n\tSet device found callback"},

	{"unset_discovery_callback", unset_discovery_callback,
		"Usage: unset_discovery_callback\n\tSet device found callback"},

	{"set_device_connected_callback", set_device_connected_callback,
		"Usage: set_device_connected_callback\n\tSet device connected callback"},

	{"unset_device_connected_callback", unset_device_connected_callback,
		"Usage: unset_device_connected_callback\n\tUnSet device connected callback"},

	{"start_discovery", start_discovery,
		"Usage: start_discovery\n\tStart to discovery devices"},

	{"stop_discovery", stop_discovery,
		"Usage: stop_discovery\n\tStop to discovery devices"},

	{"device_create_bond", device_create_bond,
		"Usage: device_create_bond 70:F9:27:64:DF:65\n\tPair the specfic device"},

	{"device_destroy_bond", device_destroy_bond,
		"Usage: device_destroy_bond 70:F9:27:64:DF:65\n\tUnPair the specfic device"},

	{"device_set_bond_created_cb", device_set_bond_created_cb,
		"Usage: device_set_bond_created_cb\n\tSet Device bond state changed callback"},

	{"device_unset_bond_created_cb", device_unset_bond_created_cb,
		"Usage: device_unset_bond_created_cb\n\tUnset Device bond state changed callback"},

	{"device_set_auth_changed_cb", device_set_auth_changed_cb,
		"Usage: device_set_auth_changed_cb\n\tSet Device auth state changed callback"},

	{"device_unset_auth_changed_cb", device_unset_auth_changed_cb,
		"Usage: device_unset_auth_changed_cb\n\tUnset Device auth state changed callback"},

	{"set_device_alias", set_device_alias,
		"Usage: set_device_alias 70:F9:27:64:DF:65 tizen\n\tSet device alias"},

	{"set_device_authorization", set_device_authorization,
		"Usage: set_device_authorization 70:F9:27:64:DF:65 1/0\n\tSet device authorization"},

	{"hid_connect", hid_connect,
		"Usage: hid_connect 70:F9:27:64:DF:65\n\tConnect HID profile"},

	{"hid_disconnect", hid_disconnect,
		"Usage: hid_disconnect 70:F9:27:64:DF:65\n\tDisconnect HID profile"},

	{"audio_connect", audio_connect,
		"Usage: audio_connect address type(a2dp/all)\n\tConnect audio profile"},

	{"audio_disconnect", audio_disconnect,
		"Usage: audio_disconnect address type(a2dp/all)\n\tDisconnect audio profile"},

	{"audio_set_connection_state_changed", audio_set_connection_state_changed,
		"Usage: audio_set_connection_state_changed\n\tset connection state callback"},

	{"audio_unset_connection_state_changed", audio_unset_connection_state_changed,
		"Usage: audio_unset_connection_state_changed\n\tunset connection state callback"},

	{"avrcp_set_shuffle_changed", avrcp_set_shuffle_changed,
		"Usage: avrcp_set_shuffle_changed\n\tset avrcp shuffle changed callback"},

	{"avrcp_unset_shuffle_changed", avrcp_unset_shuffle_changed,
		"Usage: avrcp_unset_shuffle_changed\n\tunset avrcp shuffle changed callback"},

	{"avrcp_set_repeat_changed", avrcp_set_repeat_changed,
		"Usage: avrcp_set_repeat_changed\n\tset avrcp repeat changed callback"},

	{"avrcp_unset_repeat_changed", avrcp_unset_repeat_changed,
		"Usage: avrcp_unset_repeat_changed\n\tunset avrcp repeat changed callback"},

	{"avrcp_target_initialize", avrcp_target_initialize,
		"Usage: avrcp_target_initialize\n\tset avrcp target callback"},

	{"avrcp_target_deinitialize", avrcp_target_deinitialize,
		"Usage: avrcp_target_deinitialize\n\tunset avrcp target callback"},

	{"register_agent", register_agent,
		"Usage: register_agent\n\tRegister agent"},

	{"get_bonded_device_info", get_bonded_device_info,
		"Usage: get_bonded_device_info 70:F9:27:64:DF:65\n\tGet device information"},

	{"list_paired_devices", list_paired_devices,
		"Usage: list_paired_devices\n\tList paired devices"},

	{"list_devices", list_devices,
		"Usage: list_devices\n\tList devices"},

	{"init_opp", init_opp,
		"Usage: init_opp\n\tinitialize obex_lib"},

	{"deinit_opp", deinit_opp,
		"Usage: deinit_opp\n\tdeinitialize obex_lib"},

	{"register_opp_server", register_opp_server,
		"Usage: register_opp_server\n\tregister opp server"},

	{"opp_send", opp_send,
		"Usage: opp_server file_name destination\n\tpush file"},

	{"opp_watch", opp_watch,
		"Usage: opp_watch on/off\n\ton/off opp_watch"},

	{"spp_create", spp_create,
		"Usage: spp_create 00001101-0000-1000-8000-00805f9b34fb\n\tcreate spp with uuid"},

	{"spp_destroy", spp_destory,
		"Usage: spp_destory\n\tdestory spp"},

	{"spp_set_authorize_cb", spp_set_authorize_cb,
		"Usage: spp_set_authorize_cb\n\tset spp authorize callback, accept/reject"},

	{"spp_set_data_receive_cb", spp_set_data_receive_cb,
		"Usage: spp_set_data_receive_cb\n\tset spp data recieved callback"},

	{"spp_connect", spp_connect,
		"Usage: spp_connect 70:F9:27:64:DF:65 00001101-0000-1000-8000-00805f9b34fb\n\tconnect spp"},

	{"spp_disconnect", spp_disconnect,
		"Usage: spp_disconnect 70:F9:27:64:DF:65 00001101-0000-1000-8000-00805f9b34fb\n\tdisconnect spp"},

	{"spp_send", spp_send,
		"Usage: spp_send fd 'data'\n\tsend spp data to fd"},

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

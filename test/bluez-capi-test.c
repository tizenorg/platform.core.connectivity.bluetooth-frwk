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

static int recover(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_recover();
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_enable error: %d", err);
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

static void adapter_name_changed(char *device_name, void *user_data)
{
	DBG("device name changed: %s", device_name);
}

static int set_adapter_name_callback(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_set_name_changed_cb(adapter_name_changed, NULL);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_set_name_changed_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int unset_adapter_name_callback(const char *p1, const char *p2)
{
	int err;

	err = bt_adapter_unset_name_changed_cb();
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_unset_name_changed_cb error: %d", err);
		return 0;
	}

	return 0;
}

static int set_adapter_visibility(const char *p1, const char *p2)
{
	bt_adapter_visibility_mode_e mode;
	unsigned int mode_num, timeout;
	int err;

	if (p1 == NULL) {
		DBG("no visibility mode");
		return 0;
	}

	if (p2 == NULL) {
		DBG("no duration");
		return 0;
	}

	mode_num = atoi(p1);
	timeout = atoi(p2);

	switch(mode_num) {
	case 1:
		mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
		break;
	case 2:
		mode = BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE;
		break;
	case 3:
		mode = BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE;
		break;
	default:
		DBG("Unknown mode");
		return 0;
	}

	err = bt_adapter_set_visibility(mode, timeout);
	if (err != BT_SUCCESS) {
		ERROR("bt_adapter_set_visibility error: %d", err);
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

	DBG("duration %d", duration);

	return 0;
}

static int get_local_oob_data(const char *p1, const char *p2)
{
	int err;
	unsigned char hash[20], randomizer[20];
	int hash_len, randomizer_len;

	DBG("");

	memset(hash, 0, 20);
	memset(randomizer, 0, 20);

	err = bt_adapter_get_local_oob_data((unsigned char **)&hash,
				(unsigned char **)&randomizer,
				&hash_len, &randomizer_len);

	if (err == BT_SUCCESS) {
		DBG("hash = %s, randomizer = %s", hash, randomizer);
		DBG("hash_len = %d, randomizer_len = %d",
					hash_len, randomizer_len);
	} else {
		DBG("bt_adapter_get_local_oob_data err = %d", err);
		return -1;
	}

	return 0;
}

static int set_remote_oob_data(const char *p1, const char *p2)
{
	int err;
	unsigned char hash[20], randomizer[20];
	int hash_len, randomizer_len;

	DBG("");

	if (p1 == NULL) {
		DBG("no remote address");
		return 0;
	}

	DBG("remote address = %s", p1);

	memset(hash, 0, 20);
	memset(randomizer, 0, 20);
	memcpy((unsigned char *)hash, "hash", 4);
	memcpy((unsigned char *)randomizer, "randomizer", 10);
	hash_len = 4;
	randomizer_len = 10;

	err = bt_adapter_set_remote_oob_data(p1, (unsigned char *)hash,
					(unsigned char *)randomizer,
					hash_len, randomizer_len);

	if (err == BT_SUCCESS)
		DBG("Successful");
	else {
		DBG("bt_adapter_set_remote_oob_data err = %d", err);
		return -1;
	}

	return 0;
}

static int remove_remote_oob_data(const char *p1, const char *p2)
{
	int err;

	DBG("");

	if (p1 == NULL) {
		DBG("no remote address");
		return 0;
	}

	DBG("remote address = %s", p1);

	err = bt_adapter_remove_remote_oob_data(p1);

	if (err == BT_SUCCESS)
		DBG("Successful");
	else {
		DBG("bt_adapter_remove_remote_oob_data err = %d", err);
		return -1;
	}

	return 0;
}

static int get_version(const char *p1, const char *p2)
{
	int err;
	char *version;

	DBG("");

	err = bt_adapter_get_version(&version);

	if (err == BT_SUCCESS) {
		DBG("version = %s", version);
		if (version)
			g_free(version);
	} else {
		DBG("bt_adapter_get_version err = %d", err);
		return -1;
	}

	return 0;
}

static int get_local_info(const char *p1, const char *p2)
{
	int err;
	char *chipset;
	char *firmware;
	char *stack_version;
	char *profiles;

	DBG("");

	err = bt_adapter_get_local_info(&chipset, &firmware,
				&stack_version, &profiles);

	if (err == BT_SUCCESS) {
		DBG("chipset = %s", chipset);
		DBG("firmware = %s", firmware);
		DBG("stack_version = %s", stack_version);
		DBG("profiles = %s", profiles);
		if (chipset)
			g_free(chipset);
		if (firmware)
			g_free(firmware);
		if (stack_version)
			g_free(stack_version);
		if (profiles)
			g_free(profiles);
	} else {
		DBG("bt_adapter_get_local_info err = %d", err);
		return -1;
	}

	return 0;
}

static int get_adapter_connectable(const char *p1, const char *p2)
{
	int err;
	bool connectable;

	DBG("");

	err = bt_adapter_get_connectable(&connectable);

	if (err == BT_SUCCESS)
		DBG("connectable = %d", connectable);
	else {
		DBG("bt_adapter_get_connectable err = %d", err);
		return -1;
	}

	return 0;
}

static int set_adapter_connectable(const char *p1, const char *p2)
{
	int err;
	unsigned int connectable;

	DBG("");

	if (p1 == NULL) {
		DBG("no connectable mode");
		return 0;
	}

	connectable = atoi(p1);

	err = bt_adapter_set_connectable((bool)connectable);

	if (err != BT_SUCCESS) {
		DBG("err = %d", err);
		return -1;
	} else
		DBG("successfully");

	return 0;
}

static void adapter_connectable_changed_callback(int result,
						bool connectable,
						void *user_data)
{
	DBG("adapter connectable changed result: %d", result);
	DBG("adapter connectable changed to %d", connectable);
}

static int set_connectable_changed_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_set_connectable_changed_cb(
				adapter_connectable_changed_callback, NULL);
	if (ret != BT_SUCCESS) {
		ERROR("bt_adapter_set_connectable_changed_cb failed %d", ret);
		return 0;
	}

	return 0;
}

static int unset_connectable_changed_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_unset_connectable_changed_cb();
	if (ret != BT_SUCCESS) {
		ERROR("unset_connectable_changed_callback failed %d", ret);
		return 0;
	}

	return 0;
}

static void visibility_duration_changed_callback(int duration,
							void *user_data)
{
	DBG("adapter visibility changed to %d seconds", duration);
}

static int set_visibility_duration_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_set_visibility_duration_changed_cb(
				visibility_duration_changed_callback, NULL);
	if (ret != BT_SUCCESS) {
		ERROR("set_visibility_duration_changed_cb failed %d", ret);
		return 0;
	}

	return 0;
}

static int unset_visibility_duration_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_unset_visibility_duration_changed_cb();
	if (ret != BT_SUCCESS) {
		ERROR("unset_visibility_duration_changed_cb failed %d", ret);
		return 0;
	}

	return 0;
}

static void visibility_mode_changed_callback(int result,
					bt_adapter_visibility_mode_e mode,
					void *user_data)
{
	const char *string;

	if (result != BT_SUCCESS) {
		DBG("visibility mode changed error %d", result);
		return;
	}

	if (mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE)
		string = "BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE";
	else if (mode == BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE)
		string = "BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE";
	else if (mode == BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE)
		string = "BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE";
	else
		string = "Unknown type";

	DBG("visibility mode changed to %s", string);
}

static int set_visibility_mode_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_set_visibility_mode_changed_cb(
				visibility_mode_changed_callback, NULL);
	if (ret != BT_SUCCESS) {
		ERROR("set_visibility_mode_changed_cb failed %d", ret);
		return 0;
	}

	return 0;
}

static int unset_visibility_mode_callback(const char *p1, const char *p2)
{
	int ret = bt_adapter_unset_visibility_mode_changed_cb();
	if (ret != BT_SUCCESS) {
		ERROR("unset_visibility_mode_changed_cb failed %d", ret);
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

static void device_connected_changed(bool connected,
			bt_device_connection_info_s *conn_info, void *user_data)
{
	DBG("Device %s connected %d", conn_info->remote_address, connected);
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

		g_strfreev(device_info->service_uuid);
		g_free(device_info);
	}

	g_list_free(device_list);

	device_list = NULL;

	return 0;
}

static void service_search_cb(int result, bt_device_sdp_info_s *sdp_info,
							void *user_data)
{
	int i;

	if (result != BT_SUCCESS) {
		DBG("device service search failed %d", result);
		return;
	}

	DBG("remote address %s contain services:", sdp_info->remote_address);
	for (i = 0; i < sdp_info->service_count; ++i)
		DBG("\t%s", sdp_info->service_uuid[i]);
}

static int set_device_service_search_callback(const char *p1, const char *p2)
{
	int ret;

	ret = bt_device_set_service_searched_cb(service_search_cb, NULL);
	if (ret != BT_SUCCESS) {
		ERROR("bt_device_set_service_searched_cb error: %d", ret);
		return 0;
	}

	return 0;
}

static int unset_device_service_search_callback(const char *p1,
						const char *p2)
{
	int ret;

	ret = bt_device_unset_service_searched_cb();
	if (ret != BT_SUCCESS) {
		ERROR("bt_device_unset_service_searched_cb error: %d", ret);
		return 0;
	}

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

static void bt_opp_server_transfer_progress_cb_test(const char *file,
							long long size,
							int percent,
							void *user_data)
{
	DBG("file = %s", file);
	DBG("size = %lld", size);
	DBG("percent = %d", percent);
}

static void bt_opp_server_transfer_finished_cb_test(int result,
						const char *file,
						long long size,
						void *user_data)
{
	DBG("file = %s", file);
	DBG("size = %lld", size);
	DBG("result = %d", result);
}

void bt_opp_server_push_requested_cb_test(const char *file, int size,
						void *user_data)
{
	int transfer_id;
	DBG("file = %s", file);
	DBG("size = %d", size);

	bt_opp_server_accept(bt_opp_server_transfer_progress_cb_test,
				bt_opp_server_transfer_finished_cb_test,
				file, NULL, &transfer_id);
}

static int register_opp_server_initialize(const char *p1, const char *p2)
{

	DBG("");

	bt_opp_server_initialize("/tmp",
				bt_opp_server_push_requested_cb_test, NULL);
	return 0;
}

void bt_opp_server_connection_requested_cb_test(
				const char *remote_address, void *user_data)
{
	DBG("remote_address = %s", remote_address);
	bt_opp_server_reject();
}

static int register_opp_server_initialize_by_connection_request(
					const char *p1, const char *p2)
{
	DBG("");

	bt_opp_server_initialize_by_connection_request("/tmp",
				bt_opp_server_connection_requested_cb_test,
				NULL);

	return 0;
}

static int unregister_opp_server(const char *p1, const char *p2)
{
	DBG("");

	bt_opp_server_deinitialize();
	return 0;
}

static int opp_client_init(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_opp_client_initialize();
	if (ret)
		DBG("opp client init error");

	return 0;
}

static int opp_client_add_file(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_opp_client_add_file(p1);
	if (ret != BT_ERROR_NONE)
		DBG("opp client add file fail");

	return ret;
}

void bt_opp_client_push_responded_cb_test(int result,
				const char *remote_address,
				void *user_data)
{
	DBG("result = %d", result);
	DBG("remote_address = %s", remote_address);
}

void bt_opp_client_push_progress_cb_test(const char *file,
				long long size, int percent,
				void *user_data)
{
	DBG("file = %s", file);
	DBG("size = %lld", size);
	DBG("percent = %d", percent);
}

void bt_opp_client_push_finished_cb_test(int result,
				const char *remote_address,
				void *user_data)
{
	DBG("result = %d", result);
	DBG("remote_address = %s", remote_address);
}

static int opp_client_send(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_opp_client_add_file(p1);
	if (ret != BT_ERROR_NONE) {
		DBG("opp client add file fail");
		return ret;
	}

	ret = bt_opp_client_push_files(p2,
			bt_opp_client_push_responded_cb_test,
			bt_opp_client_push_progress_cb_test,
			bt_opp_client_push_finished_cb_test,
			NULL);
	if (ret != BT_ERROR_NONE) {
		DBG("opp client send file fail");
		return ret;
	}

	return ret;
}

static int opp_client_cancel_push(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_opp_client_cancel_push();
	if (ret != BT_ERROR_NONE) {
		DBG("opp client cancel push fail");
		return ret;
	}

	return ret;
}

static void print_bonded_device_info(bt_device_info_s *device_info)
{
	int len;

	if (device_info == NULL)
		return;

	printf("\n\tName: %s", device_info->remote_name);
	printf("\n\t\tAddress: %s", device_info->remote_address);
	printf("\n\t\tConnected: %d", device_info->is_connected);
	printf("\n\t\tBonded: %d", device_info->is_bonded);
	printf("\n\t\tAuthorized: %d", device_info->is_authorized);
	printf("\n\t\tservice_count: %d", device_info->service_count);

	for (len = 0; len < device_info->service_count; len++)
		printf("\n\t\t service %d: %s", len,
					device_info->service_uuid[len]);

	printf("\n");
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

static int device_cancel_bonding(const char *p1, const char *p2)
{
	int ret;

	ret = bt_device_cancel_bonding();
	if (ret != BT_SUCCESS) {
		ERROR("bt_device_cancel_bonding error: %d", ret);
		return 0;
	}

	return 0;
}

static int device_service_search(const char *p1, const char *p2)
{
	int err;

	if (p1 == NULL) {
		ERROR("Search device service must give the device address");
		return 0;
	}

	err = bt_device_start_service_search(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_start_service_search error: %d", err);
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

static void device_bond_destroyed_cb(int result, char *remote_address,
							void *user_data)
{
	GList *iter, *next;

	if (result != BT_SUCCESS) {
		DBG("bonded device destroyed faild: %d", result);
		return;
	}

	printf("Device %s has destroyed, follow is info:",
						remote_address);

	for (iter = g_list_first(device_list); iter; iter = next) {
		bt_adapter_device_discovery_info_s *info;

		info = iter->data;

		next = g_list_next(iter);

		if (g_strcmp0(info->remote_address, remote_address) == 0) {
			device_list = g_list_remove(device_list, info);
			g_free(info->remote_name);
			g_free(info->remote_address);
			g_strfreev(info->service_uuid);
			g_free(info);
		}
	}
}

static int device_set_bond_destroyed_cb(const char *p1, const char *p2)
{
	int err;

	err = bt_device_set_bond_destroyed_cb(device_bond_destroyed_cb, NULL);
	if (err != BT_SUCCESS) {
		ERROR("bt_device_set_bond_destroyed_cb error: %d", err);
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

void connection_cb(int result, bool connected,
			const char *remote_address, void *user_data)
{
	if (connected)
		DBG("connected true");
	else
		DBG("connected false");

	DBG("result = %d", result);

	DBG("remote_address = %s", remote_address);
}

static int hid_host_initialize()
{
	int err;

	err = bt_hid_host_initialize(connection_cb, NULL);

	DBG("err = %d", err);
	return err;
}

static int hid_host_deinitialize()
{
	int err;

	err = bt_hid_host_deinitialize();

	DBG("err = %d", err);
	return err;
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

static int avrcp_target_notify_repeat_mode()
{
	int err;

	DBG("");

	DBG("repeat mode = %d", BT_AVRCP_REPEAT_MODE_SINGLE_TRACK);

	err = bt_avrcp_target_notify_repeat_mode
				(BT_AVRCP_REPEAT_MODE_SINGLE_TRACK);
	if (err != BT_SUCCESS) {
		ERROR("notify_repeat_mode error: %d", err);
		return 0;
	}

	return 0;
}

static int avrcp_target_notify_shuffle_mode()
{
	int err;

	err = bt_avrcp_target_notify_shuffle_mode
				(BT_AVRCP_SHUFFLE_MODE_ALL_TRACK);
	if (err != BT_SUCCESS) {
		ERROR("notify_shuffle_mode error: %d", err);
		return 0;
	}

	return 0;
}

static int avrcp_target_notify_player_state()
{
	int err;

	err = bt_avrcp_target_notify_player_state
				(BT_AVRCP_PLAYER_STATE_PAUSED);

	if (err != BT_SUCCESS) {
		ERROR("notify_player_state error: %d", err);
		return 0;
	}

	return 0;
}

static int avrcp_target_notify_position()
{
	int err;

	err = bt_avrcp_target_notify_position(50);

	if (err != BT_SUCCESS) {
		ERROR("notify_position error: %d", err);
		return 0;
	}

	return 0;
}

static int avrcp_target_notify_track()
{
	int err;

	err = bt_avrcp_target_notify_track("title", "artist",
			"album", "genre", 10, 100, 1);

	if (err != BT_SUCCESS) {
		ERROR("notify_track error: %d", err);
		return 0;
	}

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

	DBG("Address %s Name %s", device_info->remote_address,
						device_info->remote_name);

	bt_adapter_free_device_info(device_info);

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

static int hid_disconnect(const char *p1, const char *p2)
{
	int err;

	err = bt_hid_host_disconnect(p1);
	if (err != BT_SUCCESS) {
		ERROR("bt_hid_host_disconnect error: %d", err);
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
		printf("\n\t\tRSSI: %d", discovery_info->rssi);
		printf("\n\t\tBonded: %d", discovery_info->is_bonded);
		printf("\n\t\tservice_count: %d", discovery_info->service_count);

		for (len = 0; len < discovery_info->service_count; len++)
			printf("\n\t\t service %d: %s", len,
					discovery_info->service_uuid[len]);
	}

	printf("\n");

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
			guint32 passkey, guint16 entered, void *user_data)
{
	DBG("Device %s passkey %d entered %d", device_name, passkey, entered);
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
	const gchar *confirm_info, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\t%s UUID %s requset authorize service, Please input(Y/N):",
							device, uuid);

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &confirm_info, &p1, &p2);

	if (!g_ascii_strncasecmp(confirm_info, "y", 1))
		bt_agent_confirm_accept(user_data);
	else
		bt_agent_confirm_reject(user_data);
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

static int socket_fd;
static int client_fd;
static int socket_create(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	if (p1 == NULL) {
		ERROR("socket create must give the UUID");
		return 0;
	}

	ret = bt_socket_create_rfcomm(p1, &socket_fd);
	if (ret != BT_SUCCESS)
		DBG("socket create failed");

	return 0;
}

static int socket_destroy(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_destroy_rfcomm(socket_fd);
	if (ret != BT_SUCCESS)
		DBG("destroy socket failed");

	socket_fd = 0;

	return 0;
}

void bt_socket_connection_requested_cb_test(int fd,
				const char *remote_address,
				void *user_data)
{
	DBG("socket_fd = %d", socket_fd);
	DBG("remote_address = %s", remote_address);
	DBG("fd = %d", fd);
}

int socket_set_connection_requested_cb(const char *p1, const char *p2)
{
	int ret;
	DBG("");

	ret = bt_socket_set_connection_requested_cb(
			bt_socket_connection_requested_cb_test, NULL);
	if (ret != BT_SUCCESS)
		DBG("listen and accept socket failed");

	return 0;
}

void bt_socket_connection_state_changed_cb_test(int result,
				bt_socket_connection_state_e connection_state,
				bt_socket_connection_s *connection,
				void *user_data)
{
	if (connection_state == BT_SOCKET_CONNECTED)
		client_fd = connection->socket_fd;
	else
		client_fd = 0;

	DBG("result = %d", result);
	DBG("connection_state = %d", connection_state);
	DBG("connection->socket_fd = %d", connection->socket_fd);
	DBG("connection->local_role = %d", connection->local_role);
	DBG("connection->remote_address = %s", connection->remote_address);
	DBG("connection->service_uuid = %s", connection->service_uuid);
}

int socket_set_connection_state_changed_cb(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_set_connection_state_changed_cb(
			bt_socket_connection_state_changed_cb_test, NULL);
	if (ret != BT_SUCCESS)
		DBG("socket unset connection state changed failed");

	return 0;
}

int socket_unset_connection_state_changed_cb(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_unset_connection_requested_cb();
	if (ret != BT_SUCCESS)
		DBG("socket unset connection state changed failed");

	return 0;
}

int socket_unset_connection_requested_cb(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_unset_connection_requested_cb();
	if (ret != BT_SUCCESS)
		DBG("listen and accept socket failed");

	return 0;
}

static int socket_listen_and_accept(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_listen_and_accept_rfcomm(socket_fd, 1);
	if (ret != BT_SUCCESS)
		DBG("listen and accept socket failed");

	return 0;
}

static int socket_connection(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	if (p1 == NULL) {
		ERROR("socket connect must give the device address");
		return 0;
	}

	if (p2 == NULL) {
		ERROR("socket connect must give the UUID");
		return 0;
	}

	ret = bt_socket_connect_rfcomm(p1, p2);
	if (ret != BT_SUCCESS)
		DBG("socket connect failed");

	return 0;
}

static int socket_disconnect(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_disconnect_rfcomm(client_fd);
	if (ret != BT_SUCCESS)
		DBG("disconnect spp failed");

	return 0;
}

static int socket_send(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_send_data(client_fd, "12345", 5);
	if (ret != BT_SUCCESS)
		DBG("send data socket failed");

	return 0;
}

void bt_socket_data_received_cb_test(bt_socket_received_data_s *data, void *user_data)
{
	DBG("data->socket_fd = %d", data->socket_fd);
	DBG("data->data = %s", data->data);
	DBG("data->data_size = %d", data->data_size);
}

static int socket_set_data_received_cb(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_set_data_received_cb(
				bt_socket_data_received_cb_test,
				NULL);
	if (ret != BT_SUCCESS)
		DBG("set received data socket failed");

	return 0;
}

static int socket_unset_data_received_cb(const char *p1, const char *p2)
{
	int ret;

	DBG("");

	ret = bt_socket_unset_data_received_cb();
	if (ret != BT_SUCCESS)
		DBG("unset received data socket failed");

	return 0;
}

static void panu_connected_changed(int result, bool connected,
					const char *remote_address,
					bt_panu_service_type_e type,
					void *user_data)
{
	DBG("Device %s connected %d", remote_address, connected);
}

static int panu_set_state_changed(const char *p1, const char *p2)
{
	int ret;

	ret = bt_panu_set_connection_state_changed_cb(
					panu_connected_changed, NULL);
	if (ret != BT_SUCCESS) {
		ERROR("set_panu_connected_callback error: %d", ret);
		return 0;
	}

	return 0;
}

static int panu_unset_state_changed(const char *p1, const char *p2)
{
	int ret;

	ret = bt_panu_unset_connection_state_changed_cb();
	if (ret != BT_SUCCESS) {
		ERROR("unset_panu_connected_callback error: %d", ret);
		return 0;
	}

	return 0;
}

static int panu_connect(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("panu_connect need remote address");
		return 0;
	}

	ret = bt_panu_connect(p1, BT_PANU_SERVICE_TYPE_NAP);
	if (ret != BT_SUCCESS)
		DBG("bt_panu_connect failed %d", ret);

	return 0;
}

static int panu_disconnect(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("panu_disconnect need remote address");
		return 0;
	}

	ret = bt_panu_disconnect(p1);
	if (ret != BT_SUCCESS)
		DBG("bt_panu_disconnect failed %d", ret);

	return 0;
}

static int nap_activate(const char *p1, const char *p2)
{
	int ret;

	ret = bt_nap_activate();
	if (ret != BT_SUCCESS)
		DBG("bt_nap_activate failed %d", ret);

	return 0;
}

static int nap_deactivate(const char *p1, const char *p2)
{
	int ret;

	ret = bt_nap_deactivate();
	if (ret != BT_SUCCESS)
		DBG("bt_nap_deactivate failed %d", ret);

	return 0;
}

void bt_nap_connection_state_changed_cb_test(bool connected,
					const char *remote_address,
					const char *interface_name,
					void *user_data)
{

	DBG("");
	DBG("connected = %d", connected);
	DBG("remote_address = %s", remote_address);
	DBG("interfaces_name = %s", interface_name);
}

static int nap_set_connection_state_changed_cb(const char *p1,
						const char *p2)
{
	int ret;

	ret = bt_nap_set_connection_state_changed_cb(
			bt_nap_connection_state_changed_cb_test,
			NULL);

	DBG("ret = %d", ret);

	return 0;
}

static int nap_unset_connection_state_changed_cb(const char *p1,
						const char *p2)
{
	int ret;

	ret = bt_nap_unset_connection_state_changed_cb();

	DBG("ret = %d", ret);

	return 0;
}

void bt_hdp_connected_cb_test(int result, const char *remote_address,
			const char *app_id, bt_hdp_channel_type_e type,
			unsigned int channel, void *user_data)
{
	DBG("");
}

void bt_hdp_disconnected_cb_test(int result, const char *remote_address,
				unsigned int channel, void *user_data)
{
	DBG("");
}

static int hdp_set_connection_state_changed_cb(const char *p1,
						const char *p2)
{
	int ret;

	ret = bt_hdp_set_connection_state_changed_cb(
				bt_hdp_connected_cb_test,
				bt_hdp_disconnected_cb_test,
				NULL);

	DBG("ret = %d", ret);

	return 0;
}

static int hdp_unset_connection_state_changed_cb(const char *p1,
						const char *p2)
{
	int ret;

	ret = bt_hdp_unset_connection_state_changed_cb();

	DBG("ret = %d", ret);

	return 0;
}

void bt_hdp_data_received_cb_test(unsigned int channel,
		const char *data, unsigned int size, void *user_data)
{
	DBG("");
}

static int hdp_set_data_received_cb(const char *p1, const char *p2)
{
	int ret;

	ret = bt_hdp_set_data_received_cb(bt_hdp_data_received_cb_test,
						NULL);

	DBG("ret = %d", ret);

	return 0;
}

static int hdp_unset_data_received_cb(const char *p1, const char *p2)
{
	int ret;

	ret = bt_hdp_unset_data_received_cb();

	DBG("ret = %d", ret);

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


static bool gatt_characteristics_callback(int result, int index, int total,
					bt_gatt_attribute_h characteristic,
					void *user_data)
{
	const char *gatt_char_handle = characteristic;

	DBG("CAPI Result is %d", result);

	DBG("The index %d Characteristic found", index);

	DBG("Total characteristic is %d", total);

	DBG("Characteristic found %s", gatt_char_handle);

	return TRUE;
}

static int gatt_discover_characteristics(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt characteristics must give the service_handle");
		return 0;
	}

	ret = bt_gatt_discover_characteristics((bt_gatt_attribute_h)p1,
				gatt_characteristics_callback, NULL);

	DBG("ret = %d", ret);

	return 0;
}

static int gatt_get_service_uuid(const char *p1, const char *p2)
{
	int ret;
	char *uuid;

	if (p1 == NULL) {
		ERROR("gatt service uuid must give the service handle");
		return 0;
	}

	ret = bt_gatt_get_service_uuid((bt_gatt_attribute_h)p1, &uuid);

	DBG("ret = %d", ret);

	DBG("uuid = %s", uuid);

	return 0;
}

static bool gatt_include_service_callback(bt_gatt_attribute_h service,
					void *user_data)
{
	const char *service_handle = service;

	DBG("Include service found %s", service_handle);

	return TRUE;
}

static int gatt_foreach_included_services(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt service includes must give the service handle");
		return 0;
	}

	ret = bt_gatt_foreach_included_services((bt_gatt_attribute_h)p1,
				gatt_include_service_callback, NULL);

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

static int gatt_unset_characteristic_changed_cb(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt unset changed cb must give the service handle");
		return 0;
	}

	ret = bt_gatt_unset_characteristic_changed_cb((bt_gatt_attribute_h)p1);

	DBG("ret = %d", ret);

	return 0;
}

static int gatt_get_characteristic_declaration(const char *p1, const char *p2)
{
	int ret;
	char *uuid = NULL;
	unsigned char *value = NULL;
	int value_length, i;

	if (p1 == NULL) {
		ERROR("gatt declaration must give the charateristic handle");
		return 0;
	}

	ret = bt_gatt_get_characteristic_declaration((bt_gatt_attribute_h)p1,
				&uuid, &value, &value_length);

	DBG("Characteristic uuid %s", uuid);

	for (i = 0; i < value_length; i++)
		DBG("value %c", value[i]);

	DBG("Value length %d", value_length);

	DBG("ret = %d", ret);

	return 0;
}

void gatt_characteristic_write_callback(bt_gatt_attribute_h handle)
{
	char *gatt_char_path = handle;

	DBG("Characteristic handle %s written successfully", gatt_char_path);
}

static int gatt_set_characteristic_value_request(const char *p1, const char *p2)
{
	unsigned char value[4] = { 0, 1, 2, 4};
	int ret;

	if (p1 == NULL) {
		ERROR("gatt set value must give the charateristic handle");
		return 0;
	}

	ret = bt_gatt_set_characteristic_value_request((bt_gatt_attribute_h)p1,
			value, 4, 1, gatt_characteristic_write_callback);

	DBG("ret = %d", ret);

	return 0;
}

static int gatt_clone_and_destroy_attribute_handle(const char *p1, const char *p2)
{
	int ret;
	bt_gatt_attribute_h clone;

	if (p1 == NULL) {
		ERROR("gatt clone must give the attribue handle");
		return 0;
	}

	ret = bt_gatt_clone_attribute_handle(&clone, (bt_gatt_attribute_h)p1);

	DBG("Clone handle %s", (char *)clone);

	ret = bt_gatt_destroy_attribute_handle(clone);

	DBG("destroy handle %s", p1);

	DBG("ret = %d", ret);

	return 0;
}

static void gatt_characteristic_read_callback(unsigned char *value,
			int value_length, void *user_data)
{
	int i;

	for (i = 0; i < value_length; i++)
		DBG("value %c", value[i]);

	DBG("Value length %d", value_length);
}

static int gatt_read_characteristic_value(const char *p1, const char *p2)
{
	int ret;

	if (p1 == NULL) {
		ERROR("gatt read must give the charateristic handle");
		return 0;
	}

	ret = bt_gatt_read_characteristic_value((bt_gatt_attribute_h)p1,
				gatt_characteristic_read_callback);

	DBG("ret = %d", ret);

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

	{"recover", recover,
		"Usage: recover\n\tDisable, then enable the local adapter"},

	{"disable", disable,
		"Usage: disable\n\tDisable the local adapter"},

	{"get_adapter_state", get_adapter_state,
		"Usage: get_adapter_state\n\tGet local adapter state(Power on/off)"},

	{"get_adapter_address", get_adapter_address,
		"Usage: get_adapter_address\n\tGet local adapter address"},

	{"get_adapter_name", get_adapter_name,
		"Usage: get_adapter_name\n\tGet local adapter name"},

	{"set_adapter_name", set_adapter_name,
		"Usage: set_adapter_name BlueZ5.x\n\tSet local adapter name"},

	{"set_adapter_name_callback", set_adapter_name_callback,
		"Usage: set_adapter_name_callback\n\tSet adapter changed callback"},

	{"unset_adapter_name_callback", unset_adapter_name_callback,
		"Usage: unset_adapter_name_callback\n\tUnset adapter changed callback"},

	{"set_adapter_visibility", set_adapter_visibility,
		"Usage: set_adapter_visibility 1 <1-3, No, Limit, Discoverable> duration\n\tSet adapter visibility"},

	{"get_adapter_visibility", get_adapter_visibility,
		"Usage: get_adapter_visibility\n\tGet local adapter visibility"},

	{"set_adapter_connectable", set_adapter_connectable,
		"Usage: set_adapter_connectable 0/1, 0:Off, 1:On\n\tSet adapter connectable"},

	{"get_adapter_connectable", get_adapter_connectable,
		"Usage: get_adapter_connectable\n\tGet local adapter connectable"},

	{"set_connectable_changed_callback", set_connectable_changed_callback,
		"Usage: set_connectable_changed_callback\n\tset connectable callback"},

	{"unset_connectable_changed_callback", unset_connectable_changed_callback,
		"Usage: unset_connectable_changed_callback\n\tunset connectable callback"},

	{"set_visibility_duration_callback", set_visibility_duration_callback,
		"Usage: set_visibility_duration_callback\n\tSet duration callback"},

	{"unset_visibility_duration_callback", unset_visibility_duration_callback,
		"Usage: unset_visibility_duration_callback\n\tunet duration callback"},

	{"set_visibility_mode_callback", set_visibility_mode_callback,
		"Usage: set_visibility_mode_callback\n\tSet mode callback"},

	{"unset_visibility_mode_callback", unset_visibility_mode_callback,
		"Usage: unset_visibility_mode_callback\n\tUnset mode callback"},

	{"set_discovery_callback", set_discovery_callback,
		"Usage: set_discovery_callback\n\tSet device found callback"},

	{"unset_discovery_callback", unset_discovery_callback,
		"Usage: unset_discovery_callback\n\tSet device found callback"},

	{"set_device_connected_callback", set_device_connected_callback,
		"Usage: set_device_connected_callback\n\tSet device connected callback"},

	{"unset_device_connected_callback", unset_device_connected_callback,
		"Usage: unset_device_connected_callback\n\tUnSet device connected callback"},

	{"set_device_service_search_callback", set_device_service_search_callback,
		"Usage: set_device_service_search_callback\n\tSet service search callback"},

	{"unset_device_service_search_callback", unset_device_service_search_callback,
		"Usage: unset_device_service_search_callback\n\tUnset service search callback"},

	{"start_discovery", start_discovery,
		"Usage: start_discovery\n\tStart to discovery devices"},

	{"stop_discovery", stop_discovery,
		"Usage: stop_discovery\n\tStop to discovery devices"},

	{"device_create_bond", device_create_bond,
		"Usage: device_create_bond 70:F9:27:64:DF:65\n\tPair the specfic device"},

	{"device_destroy_bond", device_destroy_bond,
		"Usage: device_destroy_bond 70:F9:27:64:DF:65\n\tUnPair the specfic device"},

	{"device_cancel_bonding", device_cancel_bonding,
		"Usage: device_cancel_bonding\n\tCancel bonding device"},

	{"device_service_search", device_service_search,
		"Usage: device_service_search 70:F9:27:64:DF:65\n\tSearch device service"},

	{"device_set_bond_created_cb", device_set_bond_created_cb,
		"Usage: device_set_bond_created_cb\n\tSet Device bond state changed callback"},

	{"device_set_bond_destroyed_cb", device_set_bond_destroyed_cb,
		"Usage: device_set_bond_destroyed_cb\n\tSet Device bond state changed callback"},

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

	{"device_connect_le", device_connect_le,
		"Usage: device_connect_le 70:F9:27:64:DF:65\n\tConnect LE device"},

	{"device_disconnect_le", device_disconnect_le,
		"Usage: device_disconnect_le 70:F9:27:64:DF:65\n\tDisconnect LE device"},

	{"hid_host_initialize", hid_host_initialize,
		"Usage: hid_host_initialize\n\tInitialize hid host"},

	{"hid_host_deinitialize", hid_host_deinitialize,
		"Usage: hid_host_deinitialize\n\tDe-initialize hid host"},

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

	{"avrcp_target_notify_repeat_mode", avrcp_target_notify_repeat_mode,
		"Usage: avrcp_target_notify_repeat_mode\n\tnotify repeat mode"},

	{"avrcp_target_notify_shuffle_mode", avrcp_target_notify_shuffle_mode,
		"Usage: avrcp_target_notify_shuffle_mode\n\tnotify shuffle mode"},

	{"avrcp_target_notify_player_state", avrcp_target_notify_player_state,
		"Usage: avrcp_target_notify_player_state\n\tnotify player state"},

	{"avrcp_target_notify_position", avrcp_target_notify_position,
		"Usage: avrcp_target_notify_position\n\tnotify position"},

	{"avrcp_target_notify_track", avrcp_target_notify_track,
		"Usage: avrcp_target_notify_track\n\tnotify track"},

	{"register_agent", register_agent,
		"Usage: register_agent\n\tRegister agent"},

	{"get_bonded_device_info", get_bonded_device_info,
		"Usage: get_bonded_device_info 70:F9:27:64:DF:65\n\tGet device information"},

	{"list_paired_devices", list_paired_devices,
		"Usage: list_paired_devices\n\tList paired devices"},

	{"list_devices", list_devices,
		"Usage: list_devices\n\tList devices"},

	{"register_opp_server_initialize", register_opp_server_initialize,
		"Usage: register_opp_server_initialize\n\tregister opp server"},

	{"register_opp_server_init_by_conn_req",
		register_opp_server_initialize_by_connection_request,
		"Usage: register_opp_server_init_by_conn_req"},

	{"unregister_opp_server", unregister_opp_server,
		"Usage: unregister_opp_server\n\tunregister server"},

	{"opp_client_init", opp_client_init,
		"Usage: opp_client_init\n\topp client init"},

	{"opp_client_add_file", opp_client_add_file,
		"Usage: opp_client_add_file file\n\topp client add file"},

	{"opp_client_send", opp_client_send,
		"Usage: opp_client_send file 70:F9:27:64:DF:65\n\topp client send"},

	{"opp_client_cancel_push", opp_client_cancel_push,
		"Usage: opp_client_cancel_push\n\topp client cancel"},

	{"socket_create", socket_create,
		"Usage: socket_create 00001101-0000-1000-8000-00805f9b34fb\n\tcreate socket with uuid"},

	{"socket_destroy", socket_destroy,
		"Usage: socket_destroy\n\tdestroy spp"},

	{"socket_set_connection_state_changed_cb", socket_set_connection_state_changed_cb,
		"Usage: socket_set_connection_state_changed_cb\n\tset connection state changed callback"},

	{"socket_unset_connection_state_changed_cb", socket_unset_connection_state_changed_cb,
		"Usage: socket_unset_connection_state_changed_cb\n\tunset socket connection requested callback"},

	{"socket_listen_and_accept", socket_listen_and_accept,
		"Usage: socket_listen_and_accept\n\tlisten and accept socket"},

	{"socket_connection", socket_connection,
		"Usage: socket_connection 70:F9:27:64:DF:65 00001101-0000-1000-8000-00805f9b34fb\n\tconnect socket"},

	{"socket_disconnect", socket_disconnect,
		"Usage: socket_disconnect 70:F9:27:64:DF:65 00001101-0000-1000-8000-00805f9b34fb\n\tdisconnect socket"},

	{"socket_send", socket_send,
		"Usage: spp_send fd 'data'\n\tsend socket data to fd"},

	{"socket_set_data_receive_cb", socket_set_data_received_cb,
		"Usage: socket_set_data_receive_cb\n\tset socket data recieved callback"},

	{"socket_unset_data_receive_cb", socket_unset_data_received_cb,
		"Usage: socket_unset_data_receive_cb\n\tunset socket data recieved callback"},

	{"socket_set_connection_requested_cb", socket_set_connection_requested_cb,
		"Usage: socket_set_connection_requested_cb\n\tset socket connection requested callback"},

	{"socket_unset_connection_requested_cb", socket_unset_connection_requested_cb,
		"Usage: socket_unset_connection_requested_cb\n\tunset socket connection requested callback"},

	{"panu_set_state_changed", panu_set_state_changed,
		"Usage: panu_set_state_changed\n\tset panu state changed callback"},

	{"panu_unset_state_changed", panu_unset_state_changed,
		"Usage: panu_unset_state_changed\n\tunset panu state changed callback"},

	{"panu_connect", panu_connect,
		"Usage: panu_connect 70:F9:27:64:DF:65\n\tconnect address for panu"},

	{"panu_disconnect", panu_disconnect,
		"Usage: panu_disconnect 70:F9:27:64:DF:65\n\tdisconnect address for panu"},

	{"nap_activate", nap_activate,
		"Usage: nap_activate\n\tactivate NAP"},

	{"nap_deactivate", nap_deactivate,
		"Usage: nap_deactivate\n\tdeactivate NAP"},

	{"nap_set_connection_state_changed_cb", nap_set_connection_state_changed_cb,
		"Usage: nap_set_connection_state_changed_cb\n\tset nap conn cb"},

	{"nap_unset_connection_state_changed_cb", nap_unset_connection_state_changed_cb,
		"Usage: nap_unset_connection_state_changed_cb\n\tunset nap conn cb"},

	{"hdp_set_connect_cb", hdp_set_connection_state_changed_cb,
		"Usage: hdp_set_connect_cb\n\tset hdp conn cb"},

	{"hdp_set_data_rec_cb", hdp_set_data_received_cb,
		"Usage: hdp_set_data_rec_cb\n\tset hdp data rec cb"},

	{"hdp_unset_connect_cb", hdp_unset_connection_state_changed_cb,
		"Usage: hdp_unset_connect_cb\n\tunset hdp conn cb"},

	{"hdp_unset_data_rec_cb", hdp_unset_data_received_cb,
		"Usage: hdp_unset_data_rec_cb\n\tunset hdp data rec cb"},

	{"gatt_foreach_primary_services", gatt_foreach_primary_services,
		"Usage: gatt_foreach_primary_services\n\tgatt foreach primary services"},

	{"gatt_discover_characteristics", gatt_discover_characteristics,
		"Usage: gatt_discover_characteristics\n\tgatt_discover_characteristics"},

	{"gatt_get_service_uuid", gatt_get_service_uuid,
		"Usage: gatt_get_service_uuid\n\tgatt get service uuid"},

	{"gatt_foreach_included_services", gatt_foreach_included_services,
		"Usage: gatt_foreach_included_services\n\tgatt foreach included services"},

	{"gatt_set_characteristic_changed_cb", gatt_set_characteristic_changed_cb,
		"Usage: gatt_set_characteristic_changed_cb\n\tgatt set characteristic changed cb"},

	{"gatt_unset_characteristic_changed_cb", gatt_unset_characteristic_changed_cb,
		"Usage: gatt_unset_characteristic_changed_cb\n\tgatt unset characteristic changed cb"},

	{"gatt_get_characteristic_declaration", gatt_get_characteristic_declaration,
		"Usage: gatt_get_characteristic_declaration\n\tgatt get characteristic declaration"},

	{"gatt_set_characteristic_value_request", gatt_set_characteristic_value_request,
		"Usage: gatt_set_characteristic_value_request\n\tgatt set characteristic value request"},

	{"gatt_clone_and_destroy_attribute_handle", gatt_clone_and_destroy_attribute_handle,
		"Usage: gatt_clone_and_destroy_attribute_handle\n\tgatt clone and destroy attribute handle"},

	{"gatt_read_characteristic_value", gatt_read_characteristic_value,
		"Usage: gatt_read_characteristic_value\n\tgatt read characteristic value"},

	{"get_local_oob_data", get_local_oob_data,
		"Usage: get_local_oob_data\n\tget local oob data value"},

	{"set_remote_oob_data", set_remote_oob_data,
		"Usage: set_remote_oob_data address\n\tset remote oob data value"},

	{"remove_remote_oob_data", remove_remote_oob_data,
		"Usage: remove_remote_oob_data address\n\tremove remote oob data"},

	{"get_version", get_version,
		"Usage: get_version\n\tget adapter version value"},

	{"get_local_info", get_local_info,
		"Usage: get_local_info\n\tget local adapter info"},

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

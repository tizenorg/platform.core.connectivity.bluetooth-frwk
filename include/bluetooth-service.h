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

#ifndef __COMMS_H__
#define __COMMS_H__

#include <glib.h>

#include "common.h"

typedef void (*bluetooth_simple_callback)(
			enum bluez_error_type error,
			void *uer_data);

int comms_lib_init(void);
void comms_lib_deinit(void);
void comms_manager_enable_bluetooth(void);
void comms_manager_disable_bluetooth(void);
int comms_manager_get_bt_adapter_visibale_time(void);

typedef void (*opp_manager_service_watch_t)(
			gchar *address, gchar *name,
			guint64 size, guint transfer_id,
			guint state, double percent,
			void *user_data);

void opp_manager_set_service_watch(
			opp_manager_service_watch_t cb,
			void *user_data);

void opp_manager_remove_service_watch(void);

typedef void (*adapter_connectable_watch_t)(
			int result,
			gboolean connectable,
			void *user_data);

void adapter_connectable_set_service_watch(
			adapter_connectable_watch_t cb,
			void *user_data);

void adapter_connectable_remove_service_watch(void);

typedef void (*comms_manager_bt_in_service_watch_t)(
			uint in_service,
			void *user_data);

void comms_manager_set_bt_in_service_watch(
			comms_manager_bt_in_service_watch_t cb,
			void *user_data);

void comms_manager_remove_bt_in_service_watch(void);

int comms_manager_get_property_bt_in_service(
			int *in_service);

void comms_bluetooth_device_pair(
			const char *address,
			bluetooth_simple_callback cb,
			void *user_data);

enum bluez_error_type comms_bluetooth_device_cancel_pairing_sync();

void comms_bluetooth_register_pairing_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_register_pairing_agent_sync(
					const char *agent_path,
					void *user_data);

void comms_bluetooth_unregister_pairing_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_register_opp_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_register_opp_agent_sync(
			const char *agent_path,
			void *user_data);

void comms_bluetooth_unregister_opp_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_opp_send_file(
			const char *address,
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_opp_remove_Files(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_opp_add_file(const char *filename,
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_opp_cancel_transfer(int transfer_id,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_opp_add_notify(char *path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_opp_cancel_transfers(
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_avrcp_change_property(
			unsigned int type,
			unsigned int value,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_avrcp_change_properties(
			void *properties_data,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_avrcp_change_track(
			void *track_data,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_register_media_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_register_media_agent_sync(
			const char *agent_path,
			void *user_data);

void comms_bluetooth_unregister_media_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

int comms_bluetooth_get_user_privileges_sync(
			const char *address);

int comms_bluetooth_remove_user_privileges_sync(
			const char *address);

int comms_manager_set_connectable(gboolean connectable);

int comms_manager_get_connectable(gboolean *connectable);

#endif

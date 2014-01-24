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

void comms_bluetooth_register_pairing_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_unregister_pairing_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_register_opp_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_unregister_opp_agent(
			const char *agent_path,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_opp_send_file(
			const char *address,
			const char *file_name,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_avrcp_change_property(
			unsigned int type,
			unsigned int value,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_avrcp_change_properties(
			void *properties_data,
			bluetooth_simple_callback cb,
			void *user_data);

void comms_bluetooth_avrcp_change_track(
			void * track_data,
			bluetooth_simple_callback cb,
			void *user_data);
#endif

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

#ifndef __VERTICAL_H__
#define __VERTICAL_H__

enum storage_key {
	STORAGE_KEY_BT_STATE,
	STORAGE_KEY_BT_HEADSET_NAME,
	STORAGE_KEY_BT_PROFILE_STATE,
	STORAGE_KEY_BT_FLIGHT_MODE,
	STORAGE_KEY_TELEPHONE_FLIGHT_MODE
};

typedef void (*bluetooth_flight_cb)(gboolean flight_mode,
					void *user_data);

typedef void (*bluetooth_name_cb)(char *name,
					void *user_data);

struct bluetooth_vertical_driver {
	const char *name;
	int (*probe)(void);
	int (*enabled)(void);
	int (*disabled)(void);
	int (*transfer)(double);
	int (*opp_agent_on)(void*);
	int (*pairing_agent_on)(void*);
	int (*set_value)(enum storage_key, void*);
	int (*get_value)(enum storage_key, void**);
	void (*set_flight_mode_cb)(bluetooth_flight_cb, void*);
	void (*set_name_cb)(bluetooth_name_cb, void*);
};

void comms_service_register_bt_vertical_driver(
			struct bluetooth_vertical_driver *driver);

void comms_service_unregister_bt_vertical_driver(
			struct bluetooth_vertical_driver *driver);

int vertical_notify_bt_enabled(void);

void vertical_notify_bt_disabled(void);

void vertical_notify_bt_transfer(double progress);

void vertical_notify_bt_pairing_agent_on(void *data);

void vertical_notify_bt_opp_agent_on(void *data);

void vertical_notify_bt_set_flight_mode_cb(bluetooth_flight_cb cb,
						void *user_data);

void vertical_notify_bt_set_name_cb(bluetooth_name_cb cb,
						void *user_data);

int vertical_notify_bt_get_flight_mode(
				enum storage_key key, void **value);

int vertical_notify_bt_set_flight_mode(
				enum storage_key key, void *value);
#endif

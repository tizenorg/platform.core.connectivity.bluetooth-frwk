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

struct bluetooth_vertical_driver {
	const char *name;
	int (*probe)(void);
	int (*enabled)(void);
	int (*disabled)(void);
	int (*transfer)(char *, char *,
		unsigned long long, unsigned int, double);
	int (*opp_agent_on)(void);
	int (*pairing_agent_on)(void*);
};

void comms_service_register_bt_vertical_driver(
			struct bluetooth_vertical_driver *driver);

void comms_service_unregister_bt_vertical_driver(
			struct bluetooth_vertical_driver *driver);

int vertical_notify_bt_enabled(void);

void vertical_notify_bt_disabled(void);

void vertical_notify_bt_transfer(char *address, char *name,
		unsigned long long size, unsigned int transfer_id,
						double progress);

void vertical_notify_bt_pairing_agent_on(void* data);

void vertical_notify_bt_opp_agent_on(void);
#endif

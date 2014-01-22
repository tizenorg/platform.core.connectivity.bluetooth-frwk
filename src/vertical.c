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

#include <glib.h>
#include "common.h"
#include "vertical.h"

#define VERTICAL "Mobile"

static struct bluetooth_vertical_driver *bluetooth_driver;

static int match_bt_driver(const char *vertical, const char *driver_name)
{
	return !g_strcmp0(vertical, driver_name);
}

void comms_service_register_bt_vertical_driver(
		struct bluetooth_vertical_driver *driver)
{
	if (bluetooth_driver) 
		return;

	if (!match_bt_driver(VERTICAL, driver->name))
		return;

	if (driver->probe())
		return;

	bluetooth_driver = driver;

	DBG("Bluetooth driver %s registered", driver->name);
}

void comms_service_unregister_bt_vertical_driver(
		struct bluetooth_vertical_driver *driver)
{
	if (!bluetooth_driver)
		return;

	if (driver != bluetooth_driver)
		return;

	bluetooth_driver = NULL;
}

int vertical_notify_bt_enabled(void)
{
	if (!bluetooth_driver)
		return 0;

	if (!bluetooth_driver->enabled)
		return 0;

	return bluetooth_driver->enabled();
}

void vertical_notify_bt_disabled(void)
{
	if (!bluetooth_driver)
		return;

	if (bluetooth_driver->disabled)
		bluetooth_driver->disabled();
}

void vertical_notify_bt_register_pairing_agent(void)
{
	if (!bluetooth_driver)
		return;

	if (bluetooth_driver->register_pairing_agent)
		bluetooth_driver->register_pairing_agent();
}

void vertical_notify_bt_register_opp_agent(void)
{
	if (!bluetooth_driver)
		return;

	if (bluetooth_driver->register_opp_agent)
		bluetooth_driver->register_opp_agent();
}

void vertical_notify_bt_transfer(double progress)
{
	if (!bluetooth_driver)
		return;

	if (bluetooth_driver->transfer)
		bluetooth_driver->transfer(progress);
}
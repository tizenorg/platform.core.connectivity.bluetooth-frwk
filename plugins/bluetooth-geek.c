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

#include "common.h"
#include "plugin.h"
#include "vertical.h"

static int bt_probe(void)
{
	DBG("");

	return 0;
}

static int bt_enabled(void)
{
	return 0;
}

static int bt_disabled(void)
{
	DBG("");

	return 0;
}

static int bt_transfer(double progress)
{
	DBG("\tprogress: %f", progress);

	return 0;
}

static int bt_pairing_agent_on(void)
{
	return 0;
}

static int bt_opp_agent_on(void)
{
	return 0;
}

static struct bluetooth_vertical_driver bt_driver = {
	.name = "Mobile",
	.probe = bt_probe,
	.enabled = bt_enabled,
	.disabled = bt_disabled,
	.transfer = bt_transfer,
	.pairing_agent_on = bt_pairing_agent_on,
	.opp_agent_on = bt_opp_agent_on,
};

static int bt_init(void)
{
	DBG("");

	comms_service_register_bt_vertical_driver(&bt_driver);
	return 0;
}

static void bt_exit(void)
{
	DBG("");

	comms_service_unregister_bt_vertical_driver(&bt_driver);
}

COMMS_SERVICE_PLUGIN_DEFINE(bluetooth, "Bleutooth service plugin for Geek",
				COMMS_SERVICE_VERSION, bt_init, bt_exit);

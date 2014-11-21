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

#include <stdint.h>
#include <fcntl.h>
#include <string.h>

#include "common.h"
#include "plugin.h"
#include "vertical.h"
#include "brcm_patchram_plus.h"

enum rfkill_type {
	RFKILL_TYPE_ALL = 0,
	RFKILL_TYPE_WLAN,
	RFKILL_TYPE_BLUETOOTH,
	RFKILL_TYPE_UWB,
	RFKILL_TYPE_WIMAX,
	RFKILL_TYPE_WWAN,
	RFKILL_TYPE_GPS,
	RFKILL_TYPE_FM,
	RFKILL_TYPE_NFC,
	NUM_RFKILL_TYPES,
};

enum rfkill_operation {
	RFKILL_OP_ADD = 0,
	RFKILL_OP_DEL,
	RFKILL_OP_CHANGE,
	RFKILL_OP_CHANGE_ALL,
};

struct rfkill_event {
	uint32_t idx;
	uint8_t  type;
	uint8_t  op;
	uint8_t  soft, hard;
};

static int set_bt_rfkill_block(int block)
{
	struct rfkill_event event;
	int rfkill_fd;
	ssize_t len;

	DBG("");

	rfkill_fd = open("/dev/rfkill", O_RDWR | O_CLOEXEC);
	if (rfkill_fd < 0) {
		ERROR("open rfkill failed");
		return -1;
	}

	memset(&event, 0, sizeof(struct rfkill_event));
	event.op = RFKILL_OP_CHANGE_ALL;
	event.type = RFKILL_TYPE_BLUETOOTH;
	event.soft = block;

	len = write(rfkill_fd, &event, sizeof(event));
	if (len < 0) {
		ERROR("failed to change rfkill state");

		return -1;
	}

	close(rfkill_fd);

	return 0;
}

static int bt_probe(void)
{
	DBG("");

	return 0;
}

static int bt_enabled(void)
{
	char *brcm_args[] = { NULL, "--enable_lpm", "--enable_hci",
			"--patchram", "/lib/firmware/BCM43341B0_0008_ZTE.hcd",
			"--baudrate", "3000000", "/dev/ttyMFD0", "--no2bytes"};
	int ret, arg_count;

	ret = set_bt_rfkill_block(0);
	if (ret != 0)
		return -1;

	arg_count = sizeof(brcm_args) / sizeof(char *);
	init_brcm_bluetooth(arg_count, brcm_args);

	return 0;
}

static int bt_disabled(void)
{
	int ret;

	DBG("");

	deinit_brcm_patchram();

	ret = set_bt_rfkill_block(1);
	if (ret != 0)
		return -1;

	return 0;
}

static int bt_transfer(double progress)
{
	DBG("\tprogress: %f", progress);

	return 0;
}

static int bt_pairing_agent_on(void *data)
{
	/*TODO:
	 * In Geek, it should startup Application that using
	 * CAPI bt_agent_register to register agent handler
	 */
	DBG("Please startup bluetooth-agent to register agent");

	return 0;
}

static int bt_opp_agent_on(void *data)
{
	/*TODO:
	 * In Geek, it should startup Application that using
	 * CAPI bt_agent_register to register agent handler
	 */
	DBG("Please startup bluetooth-agent to register agent");

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

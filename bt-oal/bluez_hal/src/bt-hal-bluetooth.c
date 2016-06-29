/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlog.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"

#define enum_prop_to_hal(prop, hal_prop, type) do { \
	static type e; \
	prop.val = &e; \
	prop.len = sizeof(e); \
	e = *((uint8_t *) (hal_prop->val)); \
} while (0)

static const bt_callbacks_t *bt_hal_cbacks = NULL;

static bool interface_ready(void)
{
	return bt_hal_cbacks != NULL;
}

static int init(bt_callbacks_t *callbacks)
{
	DBG("HAL library Initialization..");

	if (interface_ready())
		return BT_STATUS_DONE;
	else {
		bt_hal_cbacks = callbacks;
		DBG("Store HAL stack msg handler callback");
	}
	return BT_STATUS_SUCCESS;
}

/* Enable Adapter */
static int enable(void)
{
	return BT_STATUS_UNSUPPORTED;
}

/* Disable Adapter */
static int disable(void)
{
	return BT_STATUS_UNSUPPORTED;
}

static void cleanup(void)
{
	return;
}

static int get_adapter_properties(void)
{
	return BT_STATUS_UNSUPPORTED;
}


static int get_adapter_property(bt_property_type_t type)
{
	return BT_STATUS_UNSUPPORTED;
}

static int set_adapter_property(const bt_property_t *property)
{
	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_properties(bt_bdaddr_t *remote_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_device_property(bt_bdaddr_t *remote_addr,
		bt_property_type_t type)
{
	return BT_STATUS_UNSUPPORTED;
}

static int set_remote_device_property(bt_bdaddr_t *remote_addr,
		const bt_property_t *property)
{
	return BT_STATUS_UNSUPPORTED;
}

static int get_remote_service_record(bt_bdaddr_t *remote_addr, bt_uuid_t *uuid)
{
	return BT_STATUS_UNSUPPORTED;

}

static int get_remote_services(bt_bdaddr_t *remote_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int start_discovery(void)
{
	return BT_STATUS_UNSUPPORTED;
}

static int cancel_discovery(void)
{
	return BT_STATUS_UNSUPPORTED;
}

static int create_bond(const bt_bdaddr_t *bd_addr, int transport)
{
	return BT_STATUS_UNSUPPORTED;
}

static int cancel_bond(const bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int remove_bond(const bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int pin_reply(const bt_bdaddr_t *bd_addr, uint8_t accept,
		uint8_t pin_len, bt_pin_code_t *pin_code)
{
	return BT_STATUS_UNSUPPORTED;
}

static int ssp_reply(const bt_bdaddr_t *bd_addr, bt_ssp_variant_t variant,
		uint8_t accept, uint32_t passkey)
{
	return BT_STATUS_UNSUPPORTED;
}

static const void *get_profile_interface(const char *profile_id)
{
	/*TODO: Profile interfaces to be included later*/
	DBG("%s", profile_id);

	if (!interface_ready())
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_PAN_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_ADVANCED_AUDIO_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_AV_RC_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_HANDSFREE_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_GATT_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_HEALTH_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_AV_RC_CTRL_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_HANDSFREE_CLIENT_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_MAP_CLIENT_ID))
		return NULL;

	if (!strcmp(profile_id, BT_PROFILE_ADVANCED_AUDIO_SINK_ID))
		return NULL;

	return NULL;
}

static int dut_mode_configure(uint8_t enable)
{
	return BT_STATUS_UNSUPPORTED;
}

static int dut_mode_send(uint16_t opcode, uint8_t *buf, uint8_t buf_len)
{
	return BT_STATUS_UNSUPPORTED;
}

static int le_test_mode(uint16_t opcode, uint8_t *buf, uint8_t buf_len)
{
	return BT_STATUS_UNSUPPORTED;
}

static int config_hci_snoop_log(uint8_t enable)
{
	return BT_STATUS_UNSUPPORTED;
}

static int get_connection_state(const bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static int set_os_callouts(bt_os_callouts_t *callouts)
{
	DBG("callouts: %p", callouts);

	/* TODO: implement */

	return BT_STATUS_UNSUPPORTED;
}

static int read_energy_info(void)
{
	return BT_STATUS_UNSUPPORTED;
}

static const bt_interface_t bluetooth_if = {
	.size = sizeof(bt_interface_t),
	.init = init,
	.enable = enable,
	.disable = disable,
	.cleanup = cleanup,
	.get_adapter_properties = get_adapter_properties,
	.get_adapter_property = get_adapter_property,
	.set_adapter_property = set_adapter_property,
	.get_remote_device_properties = get_remote_device_properties,
	.get_remote_device_property = get_remote_device_property,
	.set_remote_device_property = set_remote_device_property,
	.get_remote_service_record = get_remote_service_record,
	.get_remote_services = get_remote_services,
	.start_discovery = start_discovery,
	.cancel_discovery = cancel_discovery,
	.create_bond = create_bond,
	.remove_bond = remove_bond,
	.cancel_bond = cancel_bond,
	.pin_reply = pin_reply,
	.ssp_reply = ssp_reply,
	.get_profile_interface = get_profile_interface,
	.dut_mode_configure = dut_mode_configure,
	.dut_mode_send = dut_mode_send,
	.le_test_mode = le_test_mode,
	.config_hci_snoop_log = config_hci_snoop_log,
	.get_connection_state = get_connection_state,
	.set_os_callouts = set_os_callouts,
	.read_energy_info = read_energy_info,
};

static const bt_interface_t *get_bluetooth_interface(void)
{
	DBG("");
	return &bluetooth_if;
}

static int close_bluetooth(struct hw_device_t *device)
{
	DBG("");
	cleanup();
	free(device);
	return 0;
}

static int open_bluetooth(const struct hw_module_t *module, char const *name,
		struct hw_device_t **device)
{
	bluetooth_device_t *dev = malloc(sizeof(bluetooth_device_t));

	DBG("");

	memset(dev, 0, sizeof(bluetooth_device_t));
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = (struct hw_module_t *) module;
	dev->common.close = close_bluetooth;
	dev->get_bluetooth_interface = get_bluetooth_interface;

	*device = (struct hw_device_t *) dev;

	return 0;
}

static struct hw_module_methods_t bluetooth_module_methods = {
	.open = open_bluetooth,
};

struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = BT_HARDWARE_MODULE_ID,
	.name = "Bluetooth stack",
	.author = "Intel Corporation",
	.methods = &bluetooth_module_methods
};

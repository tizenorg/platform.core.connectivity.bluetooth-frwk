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

#include <bt-hal-adapter-dbus-handler.h>

#define enum_prop_to_hal(prop, hal_prop, type) do { \
	static type e; \
	prop.val = &e; \
	prop.len = sizeof(e); \
	e = *((uint8_t *) (hal_prop->val)); \
} while (0)

static const bt_callbacks_t *bt_hal_cbacks = NULL;


/* Forward declarations */
static void __bt_adapter_props_to_hal(bt_property_t *send_props, struct hal_property *prop, uint8_t num_props, uint16_t len);
static void __bt_device_props_to_hal(bt_property_t *send_props,
                struct hal_property *prop, uint8_t num_props,
                uint16_t len);
static void __bt_hal_handle_adapter_state_changed(void *buf, uint16_t len);
static void __bt_hal_handle_adapter_property_changed(void *buf, uint16_t len);
static void __bt_hal_handle_stack_messages(int message, void *buf, uint16_t len);
static void __bt_hal_handle_adapter_discovery_state_changed(void *buf, uint16_t len);
static void __bt_hal_handle_device_found_event(void *buf, uint16_t len);

static bool interface_ready(void)
{
	return bt_hal_cbacks != NULL;
}

static int init(bt_callbacks_t *callbacks)
{
	int ret;
	DBG("HAL library Initialization..");

	if (interface_ready())
		return BT_STATUS_DONE;
	else {
		bt_hal_cbacks = callbacks;
		DBG("Store HAL stack msg handler callback");
		_bt_hal_dbus_store_stack_msg_cb(__bt_hal_handle_stack_messages);
		ret = _bt_hal_initialize_event_receiver(__bt_hal_handle_stack_messages);

		if (ret == BT_STATUS_SUCCESS)
			return BT_STATUS_SUCCESS;
		else
			return BT_STATUS_FAIL;

	}
	return BT_STATUS_SUCCESS;
}

/* Enable Adapter */
static int enable(void)
{
	return _bt_hal_dbus_enable_adapter();
}

/* Disable Adapter */
static int disable(void)
{
	return _bt_hal_dbus_disable_adapter();
}

static void cleanup(void)
{
	return;
}

static int get_adapter_properties(void)
{
	return _bt_hal_dbus_get_adapter_properties();
}

static int get_adapter_property(bt_property_type_t type)
{
	return _bt_hal_dbus_get_adapter_property(type);
}

static int set_adapter_property(const bt_property_t *property)
{
	if (!property) {
		ERR("Invalid param");
		return BT_STATUS_PARM_INVALID;
	}

	return _bt_hal_dbus_set_adapter_property(property);
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
	return _bt_hal_dbus_start_discovery();
}

static int cancel_discovery(void)
{
	return _bt_hal_dbus_stop_discovery();
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

static void __bt_hal_handle_adapter_state_changed(void *buf, uint16_t len)
{
	struct hal_ev_adapter_state_changed *ev = buf;

	DBG("Adapter State: %d", ev->state);

	if (bt_hal_cbacks->adapter_state_changed_cb)
		bt_hal_cbacks->adapter_state_changed_cb(ev->state);
}

static void __bt_adapter_props_to_hal(bt_property_t *send_props, struct hal_property *prop,
		uint8_t num_props, uint16_t len)
{
	void *buf = prop;
	uint8_t i;

	for (i = 0; i < num_props; i++) {
		if (sizeof(*prop) + prop->len > len) {
			ERR("invalid adapter properties(%zu > %u), cant process further properties!!!",
					sizeof(*prop) + prop->len, len);
			return;
		}

		send_props[i].type = prop->type;

		switch (prop->type) {
			/* TODO: Add Adapter Properties */
			default:
				send_props[i].len = prop->len;
				send_props[i].val = prop->val;
				break;
		}

		DBG("prop[%d]: %s", i, btproperty2str(&send_props[i]));

		len -= sizeof(*prop) + prop->len;
		buf += sizeof(*prop) + prop->len;
		prop = buf;
	}

	if (!len)
		return;
}

static void __bt_device_props_to_hal(bt_property_t *send_props,
                struct hal_property *prop, uint8_t num_props,
                uint16_t len)
{
	void *buf = prop;
	uint8_t i;

	DBG("+");

	for (i = 0; i < num_props; i++) {

		if (sizeof(*prop) + prop->len > len) {
			ERR("invalid device properties (%zu > %u), cant process further properties!!!",
					sizeof(*prop) + prop->len, len);
			return;
		}

		send_props[i].type = prop->type;

		DBG("HAL prop Type [%d]", prop->type);

		switch (prop->type) {
		case HAL_PROP_DEVICE_TYPE:
		{
			DBG("Device property:HAL_PROP_DEVICE_TYPE:");
			enum_prop_to_hal(send_props[i], prop,
					bt_device_type_t);
			break;
		}
		case HAL_PROP_DEVICE_VERSION_INFO:
		{
			DBG("Device property: HAL_PROP_DEVICE_VERSION_INFO");
			static bt_remote_version_t e;
			const struct hal_prop_device_info *p;
			send_props[i].val = &e;
			send_props[i].len = sizeof(e);
				p = (struct hal_prop_device_info *) prop->val;
				e.manufacturer = p->manufacturer;
			e.sub_ver = p->sub_version;
			e.version = p->version;
			break;
		}
		case HAL_PROP_DEVICE_SERVICE_REC:
		{
			DBG("Device property: HAL_PROP_DEVICE_SERVICE_REC");
			static bt_service_record_t e;
			const struct hal_prop_device_service_rec *p;
			send_props[i].val = &e;
			send_props[i].len = sizeof(e);
				p = (struct hal_prop_device_service_rec *) prop->val;
					memset(&e, 0, sizeof(e));
			memcpy(&e.channel, &p->channel, sizeof(e.channel));
			memcpy(e.uuid.uu, p->uuid, sizeof(e.uuid.uu));
			memcpy(e.name, p->name, p->name_len);
			break;
		}
		default:
			send_props[i].len = prop->len;
			send_props[i].val = prop->val;
			break;
		}

		DBG("prop[%d]: %s", i, btproperty2str(&send_props[i]));
		len -= sizeof(*prop) + prop->len;
		buf += sizeof(*prop) + prop->len;
		prop = buf;

	}

	if (!len) {
		DBG("-");
		return;
	}

	ERR("invalid device properties (%u bytes left), ", len);
}

static void __bt_hal_handle_adapter_property_changed(void *buf, uint16_t len)
{
	struct hal_ev_adapter_props_changed *ev = (struct hal_ev_adapter_props_changed *)buf;
	bt_property_t props[ev->num_props];
	DBG("+");

	if (!bt_hal_cbacks->adapter_properties_cb)
		return;

	len -= sizeof(*ev);
	__bt_adapter_props_to_hal(props, ev->props, ev->num_props, len);

	if (bt_hal_cbacks->adapter_properties_cb)
		bt_hal_cbacks->adapter_properties_cb(ev->status, ev->num_props, props);
}

static void __bt_hal_handle_adapter_discovery_state_changed(void *buf, uint16_t len)
{
	struct hal_ev_discovery_state_changed *ev = (struct hal_ev_discovery_state_changed *)buf;

	DBG("+");

	if (bt_hal_cbacks->discovery_state_changed_cb)
		bt_hal_cbacks->discovery_state_changed_cb(ev->state);
}

static void __bt_hal_handle_device_found_event(void *buf, uint16_t len)
{
	struct hal_ev_device_found *ev =  (struct hal_ev_device_found *) buf;
	bt_property_t props[ev->num_props];
	DBG("+");

	if (!bt_hal_cbacks->device_found_cb)
		return;

	len -= sizeof(*ev);
	__bt_device_props_to_hal(props, ev->props, ev->num_props, len);

	bt_hal_cbacks->device_found_cb(ev->num_props, props);
}

static void __bt_hal_handle_stack_messages(int message, void *buf, uint16_t len)
{
	DBG("+");
	switch(message) {
		case HAL_EV_ADAPTER_STATE_CHANGED:
			DBG("Event: HAL_EV_ADAPTER_STATE_CHANGED");
			__bt_hal_handle_adapter_state_changed(buf, len);
			break;
		case HAL_EV_ADAPTER_PROPS_CHANGED:
			DBG("Event: HAL_EV_ADAPTER_PROPS_CHANGED");
			__bt_hal_handle_adapter_property_changed(buf, len);
			break;
		case HAL_EV_DISCOVERY_STATE_CHANGED:
			DBG("Event: HAL_EV_DISCOVERY_STATE_CHANGED");
			__bt_hal_handle_adapter_discovery_state_changed(buf, len);
			break;
		case HAL_EV_DEVICE_FOUND:
			DBG("Event: HAL_EV_DEVICE_FOUND");
			__bt_hal_handle_device_found_event(buf, len);
		default:
			DBG("Event Currently not handled!!");
			break;
	}
	DBG("-");
}

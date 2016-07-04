/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <sys/wait.h>

#include <bluetooth.h>

#include "oal-event.h"
#include "oal-internal.h"
#include "oal-manager.h"
#include "oal-hardware.h"
#include "oal-common.h"
#include "oal-utils.h"

#define CHECK_MAX(max, x) (((max) > (x)) ? (x) : (max))

static const bt_interface_t * blued_api;

static bt_address_t local_address;
static char local_name[BT_DEVICE_NAME_LENGTH_MAX + 1] = {'O', 'A', 'L', 0};
static char local_version[BT_VERSION_STR_LEN_MAX + 1];
static bt_scan_mode_t scan_mode = BT_SCAN_MODE_NONE;
static int discoverable_timeout = 0;

/* Forward declarations */
oal_status_t convert_to_oal_status(bt_status_t status);
static gboolean retry_enable_adapter(gpointer data);
oal_status_t oal_mgr_init_internal(void);


/* Callback registered with Stack */
static void cb_adapter_state_change(bt_state_t status);
static void cb_adapter_discovery_state_changed(bt_discovery_state_t state);
static void cb_adapter_device_found(int num_properties, bt_property_t *properties);
static void cb_adapter_properties (bt_status_t status,
		int num_properties, bt_property_t *properties);

static bt_callbacks_t callbacks = {
	sizeof(callbacks),
	cb_adapter_state_change,
	cb_adapter_properties,
	NULL, /* remote_device_properties_callback */
	cb_adapter_device_found,
	cb_adapter_discovery_state_changed,
	NULL, /* pin_request_callback */
	NULL, /* ssp_request_callback */
	NULL, /* bond_state_changed_callback */
	NULL, /* acl_state_changed_callback */
	NULL, /* callback_thread_event */
	NULL, /* dut_mode_recv_callback */
	NULL, /* le_test_mode_callback*/
	NULL, /* energy_info_callback */
};

oal_status_t adapter_mgr_init(const bt_interface_t * stack_if)
{
	int ret;
	blued_api = stack_if;

	ret = blued_api->init(&callbacks);

	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("Adapter callback registration failed: [%s]", status2string(ret));
		blued_api->cleanup();
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

const bt_interface_t* adapter_get_stack_interface(void)
{
	return blued_api;
}

void adapter_mgr_cleanup(void)
{
	/* Nothing to clean yet , do not set blued_api NULL as it will be used to clean Bluedroid states */
	BT_DBG();
}

oal_status_t adapter_enable(void)
{
	int ret = BT_STATUS_SUCCESS;

	API_TRACE();
	CHECK_OAL_INITIALIZED();
	if (OAL_STATUS_SUCCESS != hw_is_module_ready()) {
		g_timeout_add(200, retry_enable_adapter, NULL);
		return OAL_STATUS_PENDING;
	}

	ret = blued_api->enable();

	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("Enable failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_disable(void)
{
	int ret;

	API_TRACE();

	CHECK_OAL_INITIALIZED();

	ret = blued_api->disable();

	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("Disable failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_start_inquiry(void)
{
	int ret;

	API_TRACE();

	CHECK_OAL_INITIALIZED();

	ret = blued_api->start_discovery();
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("start_discovery failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_stop_inquiry(void)
{
	int ret;

	API_TRACE();

	CHECK_OAL_INITIALIZED();

	ret = blued_api->cancel_discovery();
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("cancel_discovery failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

/* Callbacks from Stack */
static void cb_adapter_state_change(bt_state_t status)
{
	BT_DBG("+");
	oal_event_t event;

	event = (BT_STATE_ON == status)?OAL_EVENT_ADAPTER_ENABLED:OAL_EVENT_ADAPTER_DISABLED;

	send_event(event, NULL, 0);
}

static gboolean retry_enable_adapter(gpointer data)
{
	adapter_enable();
	return FALSE;
}

oal_status_t adapter_get_address(void)
{
	int ret;

	API_TRACE();
	CHECK_OAL_INITIALIZED();

	ret = blued_api->get_adapter_property(BT_PROPERTY_BDADDR);
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("get_adapter_property failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_get_version(void)
{
	int ret;

	API_TRACE();
	CHECK_OAL_INITIALIZED();

	ret = blued_api->get_adapter_property(BT_PROPERTY_VERSION);
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("get_adapter_property failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_get_name(void)
{
	int ret;

	CHECK_OAL_INITIALIZED();

	API_TRACE();

	ret = blued_api->get_adapter_property(BT_PROPERTY_BDNAME);
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("get_adapter_property failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_set_name(char * name)
{
	int ret;
	bt_property_t prop;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(name, return);
	API_TRACE("Name: %s", name);

	prop.type = BT_PROPERTY_BDNAME;
	prop.len = strlen(name);
	prop.val = name;

	ret = blued_api->set_adapter_property(&prop);
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("set_adapter_property: [%s]", status2string(ret));
		ret = OAL_STATUS_INTERNAL_ERROR;
	} else
		ret = OAL_STATUS_SUCCESS;

	return ret;
}

oal_status_t adapter_is_discoverable(int *p_discoverable)
{
	OAL_CHECK_PARAMETER(p_discoverable, return);

	*p_discoverable = (scan_mode == BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE);

	API_TRACE("%d", *p_discoverable);

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_is_connectable(int *p_connectable)
{
	OAL_CHECK_PARAMETER(p_connectable, return);

	*p_connectable = (scan_mode == BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE)
		||(scan_mode == BT_SCAN_MODE_CONNECTABLE);

	API_TRACE("%d", *p_connectable);

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_get_discoverable_timeout(int *p_timeout)
{
	API_TRACE("%d", discoverable_timeout);

	*p_timeout = discoverable_timeout;

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_get_service_uuids(void)
{
	int ret;

	CHECK_OAL_INITIALIZED();

	API_TRACE();

	ret = blued_api->get_adapter_property(BT_PROPERTY_UUIDS);
	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("get_adapter_property failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

static oal_status_t set_scan_mode(bt_scan_mode_t mode)
{
	bt_property_t prop;
	int res;

	BT_DBG("+");

	CHECK_OAL_INITIALIZED();

	prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE;
	prop.len = sizeof(bt_scan_mode_t);
	prop.val = &mode;
	res = blued_api->set_adapter_property(&prop);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("set scan mode failed [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	BT_DBG("-");
	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_set_connectable(int connectable)
{
	bt_scan_mode_t mode;

	API_TRACE("%d", connectable);

	CHECK_OAL_INITIALIZED();

	mode = connectable ? BT_SCAN_MODE_CONNECTABLE : BT_SCAN_MODE_NONE;

	return set_scan_mode(mode);
}

static void cb_adapter_properties(bt_status_t status,
                                               int num_properties,
                                               bt_property_t *properties)
{
	int i;

	BT_DBG("status: %d, count: %d", status, num_properties);

	if (status != BT_STATUS_SUCCESS) {
		if (num_properties == 1) {
			BT_ERR("Adapter Prop failed: status: [%s], count: %d, prop: %d",
				status2string(status), num_properties, properties[num_properties-1].type);
		} else {
			BT_ERR("Adapter Prop failed: status: [%s], count: %d", status2string(status), num_properties);
		}
		return;
	}

	for (i = 0; i < num_properties; i++) {
		BT_DBG("prop type %d, len %d", properties[i].type, properties[i].len);
		switch (properties[i].type) {
		case BT_PROPERTY_VERSION: {
			g_strlcpy(local_version, properties[i].val, BT_VERSION_STR_LEN_MAX);
			local_version[properties[i].len] = '\0';

			BT_DBG("Version: %s", local_version);
			/* Send event to application */
			if (num_properties == 1) {
				char *adapter_ver = g_strdup(local_version);

				/* Application has requested this property SET/GET hence send EVENT */
				send_event(OAL_EVENT_ADAPTER_PROPERTY_VERSION, adapter_ver, strlen(adapter_ver));
			}
			break;
		}
		case BT_PROPERTY_BDNAME: {
			g_strlcpy(local_name, properties[i].val, BT_DEVICE_NAME_LENGTH_MAX);
			local_name[properties[i].len] = '\0';

			BT_DBG("Name: %s", local_name);
			/* Send event to application */
			if (num_properties == 1) {
				char * adap_name = g_strdup(local_name);

				/* Application has requested this property SET/GET hence send EVENT */
				send_event(OAL_EVENT_ADAPTER_PROPERTY_NAME, adap_name, strlen(adap_name));
			}
			break;
		}
		case BT_PROPERTY_BDADDR: {
			bt_bdaddr_t * addr;

			addr =  properties[i].val;
			memcpy(local_address.addr, addr->address, 6);
			if (num_properties == 1) {
				/* Application has requested this property SET/GET hence send EVENT */
				send_event(OAL_EVENT_ADAPTER_PROPERTY_ADDRESS,
						g_memdup(&local_address, sizeof(local_address)),
						sizeof(local_address));
			}
			break;
		}
		case BT_PROPERTY_UUIDS: {
			int num_uuid;

			num_uuid = properties[i].len/sizeof(bt_uuid_t);

			BT_DBG("num_uuid: %d", num_uuid);

			/* Send event to application */
			if (num_properties == 1) {
				event_adapter_services_t *uuids_event;

				uuids_event = g_malloc(sizeof(event_adapter_services_t) + properties[i].len);
				memcpy(uuids_event->service_list, properties[i].val, properties[i].len);
				uuids_event->num = num_uuid;

				/* Application has requested this property SET/GET hence send EVENT */
				send_event(OAL_EVENT_ADAPTER_PROPERTY_SERVICES,
						uuids_event, (num_uuid * sizeof(bt_uuid_t)));
			}
			break;
		}
		case BT_PROPERTY_ADAPTER_SCAN_MODE: {
			bt_scan_mode_t cur_mode = *((bt_scan_mode_t *)properties[i].val);

			BT_INFO("Scan mode (%d)", cur_mode);

			scan_mode = cur_mode;

			/* Send event to application */
			if (num_properties == 1) {
				oal_event_t event = OAL_EVENT_ADAPTER_MODE_NON_CONNECTABLE;

				if (BT_SCAN_MODE_CONNECTABLE == cur_mode)
					event = OAL_EVENT_ADAPTER_MODE_CONNECTABLE;
				else if (BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE == cur_mode)
					event = OAL_EVENT_ADAPTER_MODE_DISCOVERABLE;

				/* Application has requested this property SET/GET hence send EVENT */
				send_event(event, NULL, 0);
			}
			break;
		}
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT: {
			int timeout;

			timeout = *((uint32_t*)properties[i].val);

			BT_INFO("Discoverability timeout: %d", timeout);
			discoverable_timeout = timeout;

			send_event(OAL_EVENT_ADAPTER_MODE_DISCOVERABLE_TIMEOUT,
					g_memdup(properties[i].val, sizeof(uint32_t)),
					sizeof(uint32_t));
			break;
		}
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES: {
			int j;
			int num_bonded;
			bt_bdaddr_t *bonded_addr_list;
			event_device_list_t *event_data;

			num_bonded = properties[i].len/sizeof(bt_bdaddr_t);
			BT_DBG("num_bonded %d", num_bonded);

			if (num_properties > 1)	/* No explicit req for this prop, ignore */
				break;

			bonded_addr_list = properties[i].val;
			event_data = g_malloc(sizeof(event_device_list_t) + num_bonded*sizeof(bt_address_t));
			event_data->num = num_bonded;

			for (j = 0; j < num_bonded; j++)
				memcpy(event_data->devices[j].addr, bonded_addr_list[j].address, 6);

			send_event(OAL_EVENT_ADAPTER_BONDED_DEVICE_LIST,
					event_data, (num_bonded * sizeof(bt_bdaddr_t)));
			break;
		}
		default:
			 BT_WARN("Unhandled property: %d", properties[i].type);
			 break;
		}
	}
}

static void cb_adapter_discovery_state_changed(bt_discovery_state_t state)
{
	oal_event_t event;

	event = (BT_DISCOVERY_STARTED == state)?OAL_EVENT_ADAPTER_INQUIRY_STARTED:OAL_EVENT_ADAPTER_INQUIRY_FINISHED;

	BT_DBG("%d", state);
	send_event(event, NULL, 0);
}

static void cb_adapter_device_found(int num_properties, bt_property_t *properties)
{
	remote_device_t dev_info;
	ble_adv_data_t adv_info;
	oal_event_t event;
	gpointer event_data;
	gsize properties_size = 0;
	BT_DBG("+");

	if (num_properties == 0) {
		BT_ERR("Unexpected, properties count is zero!!");
		return;
	}

	memset(&dev_info, 0x00, sizeof(remote_device_t));
	memset(&adv_info, 0x00, sizeof(ble_adv_data_t));

	print_bt_properties(num_properties, properties);
	parse_device_properties(num_properties, properties, &dev_info, &adv_info, &properties_size);

	BT_INFO("number of properties= [%d] total size [%u]", num_properties, properties_size);

	if (dev_info.type != DEV_TYPE_BREDR) {
		/* BLE Single or DUAL mode found, so it should have Adv data */
		event_ble_dev_found_t * ble_dev_event = g_new0(event_ble_dev_found_t, 1);

		ble_dev_event->adv_len = adv_info.len;

		if (adv_info.len > 0 && adv_info.adv_data) {
			memcpy(ble_dev_event->adv_data, adv_info.adv_data, adv_info.len);
			ble_dev_event->adv_len = adv_info.len;
		} else
			ble_dev_event->adv_len = 0;

		ble_dev_event->device_info = dev_info;

		event_data = ble_dev_event;
		event = OAL_EVENT_ADAPTER_INQUIRY_RESULT_BLE;
	} else {
		/* BREDR device, so No Adv data */
		event_dev_found_t * dev_event = g_new0(event_dev_found_t, 1);

		memcpy(dev_event, &dev_info, sizeof(remote_device_t));
		event_data = dev_event;
		event = OAL_EVENT_ADAPTER_INQUIRY_RESULT_BREDR_ONLY;
	}

	send_event(event, event_data, properties_size);

	BT_DBG("-");
}

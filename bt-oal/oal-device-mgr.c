/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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
#include <dlog.h>
#include <string.h>

#include <bluetooth.h>

#include "oal-event.h"
#include "oal-internal.h"
#include "oal-common.h"
#include "oal-manager.h"
#include "oal-utils.h"

static const bt_interface_t * blued_api;

void device_mgr_init(const bt_interface_t * stack_if)
{
	blued_api = stack_if;
}

void device_mgr_cleanup(void)
{
	BT_DBG();
	blued_api = NULL;
}

oal_status_t device_query_attributes(bt_address_t *addr)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s]", bdt_bd2str(addr, &bdstr));

	res = blued_api->get_remote_device_properties((bt_bdaddr_t *)addr);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("get_remote_device_properties error: [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

void cb_device_properties(bt_status_t status, bt_bdaddr_t *bd_addr,
		int num_properties, bt_property_t *properties)
{
	oal_event_t event;
	gpointer event_data = NULL;
	remote_device_t *dev_info;
	ble_adv_data_t adv_info;
	gsize size = 0;
	bdstr_t bdstr;

	if(BT_STATUS_SUCCESS != status) {
		BT_ERR("[%s]status: %d", bdt_bd2str((bt_address_t*)bd_addr, &bdstr), status);
		return;
	}

	BT_DBG("[%s]", bdt_bd2str((bt_address_t*)bd_addr, &bdstr));
	dev_info = g_new0(remote_device_t, 1);
	memcpy(dev_info->address.addr, bd_addr->address, 6);
	parse_device_properties(num_properties, properties, dev_info, &adv_info);

	if(num_properties == 1) {
		/* For one particular property a dedicated event to be sent */
		switch(properties[0].type) {
		case BT_PROPERTY_BDNAME:
			event = OAL_EVENT_DEVICE_NAME;
			event_data = dev_info;
			send_event_trace(event, event_data, sizeof(remote_device_t),
				(bt_address_t*)bd_addr, "Name: %s", dev_info->name);
			return;
		case BT_PROPERTY_UUIDS: {
			event_dev_services_t *services_info;
			bt_uuid_t *uuids = (bt_uuid_t *) properties[0].val;

			services_info = g_malloc(sizeof(event_dev_services_t) + properties[0].len);
			services_info->address = dev_info->address;
			memcpy(services_info->service_list, uuids, properties[0].len);
			services_info->num = properties[0].len/sizeof(bt_uuid_t);
			event = OAL_EVENT_DEVICE_SERVICES;
			event_data = services_info;
			size = sizeof(event_dev_services_t) + properties[0].len;
			g_free(dev_info);
			break;
		}
		default:
			BT_ERR("Single Property [%d] not handled", properties[0].type);
			g_free(dev_info);
			return;
		}
	} else {
		event_dev_properties_t *dev_props_event = g_new0(event_dev_properties_t, 1);
		if (dev_info->type != DEV_TYPE_BREDR) {
			int i;

			BT_INFO("BLE Device");
			/* BLE Single or DUAL mode found, so it should have Adv data */
			dev_props_event->adv_len = adv_info.len;
			if(dev_props_event->adv_len > 0)
				memcpy(dev_props_event->adv_data,
					adv_info.adv_data, adv_info.len);

			for (i = 0; i < dev_props_event->adv_len; i++)
				BT_INFO("Adv Data[%d] = [0x%x]",
					i, dev_props_event->adv_data[i]);
			memcpy(&dev_props_event->device_info,
				dev_info, sizeof(remote_device_t));
		} else {
			BT_INFO("BREDR type Device");
			memcpy(&dev_props_event->device_info,
				dev_info, sizeof(remote_device_t));
		}

		event_data = dev_props_event;
		event = OAL_EVENT_DEVICE_PROPERTIES;
		size = sizeof(event_dev_properties_t);
	}

	send_event_bda_trace(event, event_data, size, (bt_address_t*)bd_addr);
}

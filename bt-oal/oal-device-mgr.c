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
#include "oal-device-mgr.h"

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

oal_status_t device_set_alias(bt_address_t * addr, char * alias)
{
	int res;
	bt_property_t prop;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();
	OAL_CHECK_PARAMETER(addr, return);
	OAL_CHECK_PARAMETER(alias, return);

	API_TRACE("%s ->Alias: %s", bdt_bd2str(addr, &bdstr), alias);

	prop.type = BT_PROPERTY_REMOTE_FRIENDLY_NAME;
	prop.len = strlen(alias);
	prop.val = alias;
	res = blued_api->set_remote_device_property((bt_bdaddr_t*)addr, &prop);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("set_remote_device_property error: [%s]", status2string(res));
		BT_ERR("Alias: %s", alias);
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_create_bond(bt_address_t *addr, connection_type_e transport)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s]", bdt_bd2str(addr, &bdstr));

	res = blued_api->create_bond((bt_bdaddr_t *)addr, transport);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("create_bond error: [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_destroy_bond(bt_address_t * addr)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s]", bdt_bd2str(addr, &bdstr));

	res = blued_api->remove_bond((bt_bdaddr_t *)addr);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("remove_bond error: [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_accept_pin_request(bt_address_t * addr, char * pin)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);
	OAL_CHECK_PARAMETER(pin, return);

	API_TRACE("[%s] PIN: %s", bdt_bd2str(addr, &bdstr), pin);

	res = blued_api->pin_reply((bt_bdaddr_t *)addr, TRUE, strlen(pin), (bt_pin_code_t *)pin);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("pin_reply error: [%s]", status2string(res));
		BT_ERR("PIN: %s", pin);
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_reject_pin_request(bt_address_t * addr)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s]", bdt_bd2str(addr, &bdstr));

	res = blued_api->pin_reply((bt_bdaddr_t *)addr, FALSE, 0, NULL);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("pin_reply error: [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_accept_passkey_entry(bt_address_t * addr, uint32_t passkey)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s] Passkey: %d", bdt_bd2str(addr, &bdstr), passkey);

	res = blued_api->ssp_reply((bt_bdaddr_t *)addr, BT_SSP_VARIANT_PASSKEY_ENTRY, TRUE, passkey);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("ssp_reply error: [%s]", status2string(res));
		BT_ERR("Passkey: %d", passkey);
		return convert_to_oal_status(res);

	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_reject_passkey_entry(bt_address_t * addr)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s]", bdt_bd2str(addr, &bdstr));

	res = blued_api->ssp_reply((bt_bdaddr_t *)addr, BT_SSP_VARIANT_PASSKEY_ENTRY, FALSE, 0);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("ssp_reply error: [%s]", status2string(res));
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t device_reply_passkey_confirmation(bt_address_t * addr, int accept)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s] accept: %d", bdt_bd2str(addr, &bdstr), accept);

	res = blued_api->ssp_reply((bt_bdaddr_t *)addr, BT_SSP_VARIANT_PASSKEY_CONFIRMATION, accept, 0);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("ssp_reply error: [%s]", status2string(res));
		BT_ERR("%d", accept);
		return convert_to_oal_status(res);
	}

	return OAL_STATUS_SUCCESS;

}

oal_status_t device_reply_ssp_consent(bt_address_t * addr, int accept)
{
	int res;
	bdstr_t bdstr;

	CHECK_OAL_INITIALIZED();

	OAL_CHECK_PARAMETER(addr, return);

	API_TRACE("[%s] %d", bdt_bd2str(addr, &bdstr), accept);

	res = blued_api->ssp_reply((bt_bdaddr_t *)addr, BT_SSP_VARIANT_CONSENT, accept, 0);
	if (res != BT_STATUS_SUCCESS) {
		BT_ERR("ssp_reply error: [%s]", status2string(res));
		BT_ERR("%d", accept);
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

	/*Below code is commented out for handling Get Bonded devices for BLuez case.
	GetALl properties on a particular device interface can reyurn properties of
	an unpaired or untrusted device. If We block the below event, Application
	request (BT_GET_BONDED_DEVICES) will timeout on DBUS */
#if 0
	if(BT_STATUS_SUCCESS != status) {
		BT_ERR("[%s]status: %d", bdt_bd2str((bt_address_t*)bd_addr, &bdstr), status);
		return;
	}
#endif
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

void cb_device_bond_state_changed(bt_status_t status, bt_bdaddr_t *bd_addr,
                                        bt_bond_state_t state)
{
	bt_address_t * address = g_new0(bt_address_t, 1);
	oal_event_t event;
	gsize size = 0;

	BT_DBG("status: %d, state: %d", status, state);

	memcpy(address->addr, bd_addr->address, 6);

	switch(state) {
		case BT_BOND_STATE_BONDED:
			event = OAL_EVENT_DEVICE_BONDING_SUCCESS;
			break;
		case BT_BOND_STATE_NONE:
			/* Reaches both when bonding removed or bonding cancelled */
			if (BT_STATUS_SUCCESS != status) {
				event_dev_bond_failed_t * bond_fail_info = g_new0(event_dev_bond_failed_t, 1);
				bond_fail_info->status = convert_to_oal_status(status);
				bond_fail_info->address = *address;
				size = sizeof(event_dev_bond_failed_t);
				send_event_bda_trace(OAL_EVENT_DEVICE_BONDING_FAILED, bond_fail_info, size, (bt_address_t*)bd_addr);
				g_free(address);
				return;
			} else
				event = OAL_EVENT_DEVICE_BONDING_REMOVED;
			break;
		case BT_BOND_STATE_BONDING:
			g_free(address);
			return;
		default:
			BT_ERR("Unexpected Bond state %d", state);
			g_free(address);
			return;
	}
	send_event_bda_trace(event, address, size, (bt_address_t*)bd_addr);
}

void cb_device_acl_state_changed(bt_status_t status, bt_bdaddr_t *bd_addr,
		bt_acl_state_t state)
{
	event_dev_conn_status_t * conn_status = g_new0(event_dev_conn_status_t, 1);
	//bt_address_t * address = g_new0(bt_address_t, 1);
	oal_event_t event;
	gsize size = 0;

	BT_DBG("ACL State:%d, state: %d", status, state);

	memcpy(conn_status->address.addr, bd_addr->address, 6);

	if (BT_STATUS_SUCCESS != status) {
		/* At present only timeout will cause non-success status, later we can add more */
		conn_status->status = OAL_STATUS_CONN_TIMEOUT;
		BT_ERR("ACL State Error:%d, state: %d", status, state);
	} else
		conn_status->status = OAL_STATUS_SUCCESS;

	memcpy(conn_status->address.addr, bd_addr->address, 6);
	switch(state) {
	case BT_ACL_STATE_CONNECTED:
		event = OAL_EVENT_DEVICE_ACL_CONNECTED;
		conn_status->status = OAL_STATUS_SUCCESS;
		break;
	case BT_ACL_STATE_DISCONNECTED:
		event = OAL_EVENT_DEVICE_ACL_DISCONNECTED;
		break;
	default:
		BT_ERR("Unexpected ACL state %d", state);
		g_free(conn_status);
		return;
	}

	size = sizeof(event_dev_conn_status_t);
	send_event_bda_trace(event, conn_status, size, (bt_address_t*)bd_addr);
}

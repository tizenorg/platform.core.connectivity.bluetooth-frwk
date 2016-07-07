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
#include <bt_hh.h>

#include "oal-event.h"
#include "oal-internal.h"
#include "oal-common.h"
#include "oal-manager.h"
#include "oal-hid-host.h"
#include "oal-utils.h"

#define CHECK_OAL_HID_ENABLED() \
	do { \
		if (hid_api == NULL) { \
			BT_ERR("HID Not Enabled"); \
			return OAL_STATUS_NOT_READY; \
		} \
	} while (0)

static void connection_state_callback(bt_bdaddr_t *bd_addr, bthh_connection_state_t state);
static void hid_info_callback(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info);
static void get_protocol_mode_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status, bthh_protocol_mode_t mode);
static void idle_time_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status, int idle_rate);
static void get_report_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status, uint8_t* rpt_data, int rpt_size);
static void virtual_unplug_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status);
static void handshake_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status);

static const bthh_interface_t * hid_api;

static bthh_callbacks_t sBluetoothHidCallbacks = {
	sizeof(sBluetoothHidCallbacks),
	connection_state_callback,
	hid_info_callback,
	get_protocol_mode_callback,
	idle_time_callback,
	get_report_callback,
	virtual_unplug_callback,
	handshake_callback,
};

oal_status_t hid_enable(void)
{
	const bt_interface_t * blued_api;
	int ret;

	API_TRACE();
	blued_api = adapter_get_stack_interface();

	if(blued_api == NULL) {
		BT_ERR("Stack is not initialized");
		return OAL_STATUS_NOT_READY;
	}
	if(hid_api != NULL){
		BT_WARN("HID Interface is already initialized...");
		return OAL_STATUS_ALREADY_DONE;
	}

	hid_api = (const bthh_interface_t *)blued_api->get_profile_interface(BT_PROFILE_HIDHOST_ID);

	if(hid_api == NULL) {
		BT_ERR("HID interface failed");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	if((ret = hid_api->init(&sBluetoothHidCallbacks)) != BT_STATUS_SUCCESS) {
		BT_ERR("HID Init failed: %s", status2string(ret));
		hid_api->cleanup();
		hid_api = NULL;
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

oal_status_t hid_disable(void)
{
	API_TRACE();

	CHECK_OAL_HID_ENABLED();

	hid_api->cleanup();

	hid_api = NULL;
	return OAL_STATUS_SUCCESS;
}

void hid_cleanup(void)
{
	BT_DBG();
	hid_api = NULL;
}

oal_status_t hid_connect(bt_address_t * address)
{
	int ret;
	bdstr_t bdstr;

	API_TRACE();
	CHECK_OAL_HID_ENABLED();
	BT_INFO("[%s]", bdt_bd2str(address, &bdstr));

	ret = hid_api->connect((bt_bdaddr_t*)address);
	if(ret != BT_STATUS_SUCCESS) {
		BT_ERR("ret: %s", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

oal_status_t hid_disconnect(bt_address_t * address)
{
	int ret;
	bdstr_t bdstr;

	API_TRACE();
	CHECK_OAL_HID_ENABLED();

	BT_INFO("[%s]", bdt_bd2str(address, &bdstr));

	ret = hid_api->disconnect((bt_bdaddr_t*)address);
	if(ret != BT_STATUS_SUCCESS) {
		BT_ERR("ret: %s", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

oal_status_t hid_set_report(bt_address_t *address,
		bthh_report_type_t reportType, char *report)
{
	int ret;
	bdstr_t bdstr;

	API_TRACE("len: %d", strlen(report));
	CHECK_OAL_HID_ENABLED();
	OAL_CHECK_PARAMETER(address, return);
	OAL_CHECK_PARAMETER(report, return);
	BT_INFO("[%s]", bdt_bd2str(address, &bdstr));
	BT_INFO("[data:%s]", report);

	ret = hid_api->set_report((bt_bdaddr_t*)address, reportType, report);
	if(ret != BT_STATUS_SUCCESS) {
		BT_ERR("ret: %s", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

oal_status_t hid_send_data(bt_address_t *address, uint8_t *buf, uint16_t len)
{
	int ret;
	bdstr_t bdstr;

	API_TRACE("len: %d", len);
	CHECK_OAL_HID_ENABLED();
	OAL_CHECK_PARAMETER(address, return);
	OAL_CHECK_PARAMETER(buf, return);

	BT_INFO("[%s]", bdt_bd2str(address, &bdstr));

	ret = hid_api->send_data((bt_bdaddr_t*)address, (char *)buf);
	if(ret != BT_STATUS_SUCCESS) {
		BT_ERR("ret: %s", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

static void connection_state_callback(bt_bdaddr_t *bd_addr, bthh_connection_state_t state)
{
	event_hid_conn_t *event = g_new0(event_hid_conn_t, 1);
	int event_type;

	BT_DBG("%d", state);

	memcpy(event->address.addr, bd_addr->address, BT_ADDRESS_BYTES_NUM);

	event->status = OAL_STATUS_SUCCESS;

	switch(state) {
	case BTHH_CONN_STATE_CONNECTED:
		event_type = OAL_EVENT_HID_CONNECTED;
		break;
	case BTHH_CONN_STATE_DISCONNECTED:
		event_type = OAL_EVENT_HID_DISCONNECTED;
		break;
	case BTHH_CONN_STATE_CONNECTING:
	case BTHH_CONN_STATE_DISCONNECTING:
		return;
	case BTHH_CONN_STATE_FAILED_MOUSE_FROM_HOST:
		event_type = OAL_EVENT_HID_DISCONNECTED;
		event->status = OAL_STATUS_HID_FAILED_MOUSE;
		break;
	case BTHH_CONN_STATE_FAILED_KBD_FROM_HOST:
	case BTHH_CONN_STATE_FAILED_TOO_MANY_DEVICES:
	case BTHH_CONN_STATE_FAILED_NO_BTHID_DRIVER:
	case BTHH_CONN_STATE_FAILED_GENERIC:
		BT_ERR("HID Connection SPECIAL state(%d)", state);
		event_type = OAL_EVENT_HID_DISCONNECTED;
		event->status = OAL_STATUS_INTERNAL_ERROR;
		break;
	case BTHH_CONN_STATE_UNKNOWN:
	default:
		BT_ERR("Unhandled Connection state %d", state);
		return;
	}

	send_event_bda_trace(event_type, event, sizeof (event_hid_conn_t), (bt_address_t*)bd_addr);
}

static void hid_info_callback(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info)
{
	BT_INFO("");
}

static void get_protocol_mode_callback(bt_bdaddr_t *bd_addr,
		bthh_status_t hh_status,bthh_protocol_mode_t mode)
{
	BT_INFO("status: %d, mode: %d", hh_status, mode);
}

static void idle_time_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status, int idle_rate)
{
	BT_INFO("status: %d", hh_status);
}

static void get_report_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status, uint8_t* rpt_data, int rpt_size)
{
	BT_INFO("status: %d", hh_status);
}

static void virtual_unplug_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status)
{
	BT_INFO("status: %d", hh_status);
}

static void handshake_callback(bt_bdaddr_t *bd_addr, bthh_status_t hh_status)
{
	BT_INFO("status: %d", hh_status);
}

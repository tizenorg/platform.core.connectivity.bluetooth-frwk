/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Kumar Rai <a.rai@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <dlog.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"

#include "bt-hal-hid-dbus-handler.h"
#include "bt-hal-event-receiver.h"

static const bthh_callbacks_t *bt_hal_hid_cbacks;

static bool interface_ready(void)
{
	return bt_hal_hid_cbacks != NULL;
}

static void __bt_hal_handle_conn_state(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_conn_state *ev = buf;

	if (bt_hal_hid_cbacks->connection_state_cb)
		bt_hal_hid_cbacks->connection_state_cb((bt_bdaddr_t *) ev->bdaddr,
				ev->state);
}

static void __bt_hal_handle_hidhost_info(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_info *ev = buf;
	bthh_hid_info_t info;

	info.attr_mask = ev->attr;
	info.sub_class = ev->subclass;
	info.app_id = ev->app_id;
	info.vendor_id = ev->vendor;
	info.product_id = ev->product;
	info.version = ev->version;
	info.ctry_code = ev->country;
	info.dl_len = ev->descr_len;
	memcpy(info.dsc_list, ev->descr, info.dl_len);

	if (bt_hal_hid_cbacks->hid_info_cb)
		bt_hal_hid_cbacks->hid_info_cb((bt_bdaddr_t *) ev->bdaddr, info);
}

static void __bt_hal_handle_proto_mode(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_proto_mode *ev = buf;

	if (bt_hal_hid_cbacks->protocol_mode_cb)
		bt_hal_hid_cbacks->protocol_mode_cb((bt_bdaddr_t *) ev->bdaddr,
				ev->status, ev->mode);
}

static void __bt_hal_handle_idle_time(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_idle_time *ev = buf;

	if (bt_hal_hid_cbacks->idle_time_cb)
		bt_hal_hid_cbacks->idle_time_cb((bt_bdaddr_t *) ev->bdaddr, ev->status,
				ev->idle_rate);
}

static void __bt_hal_handle_get_report(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_get_report *ev = buf;

	if (len != sizeof(*ev) + ev->len) {
		ERR("invalid get report event");
		return;
	}

	if (bt_hal_hid_cbacks->get_report_cb)
		bt_hal_hid_cbacks->get_report_cb((bt_bdaddr_t *) ev->bdaddr, ev->status,
				ev->data, ev->len);
}

static void __bt_hal_handle_virtual_unplug(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_virtual_unplug *ev = buf;

	if (bt_hal_hid_cbacks->virtual_unplug_cb)
		bt_hal_hid_cbacks->virtual_unplug_cb((bt_bdaddr_t *) ev->bdaddr,
				ev->status);
}

static void __bt_hal_handle_handshake(void *buf, uint16_t len)
{
	struct hal_ev_hidhost_handshake *ev = buf;

	if (bt_hal_hid_cbacks->handshake_cb)
		bt_hal_hid_cbacks->handshake_cb((bt_bdaddr_t *) ev->bdaddr, ev->status);
}

static bt_status_t hidhost_connect(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return _bt_hal_dbus_handler_hidhost_connect(bd_addr);
}

static bt_status_t hidhost_disconnect(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return _bt_hal_dbus_handler_hidhost_disconnect(bd_addr);
}

static bt_status_t virtual_unplug(bt_bdaddr_t *bd_addr)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t hidhost_set_info(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid_info)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_protocol(bt_bdaddr_t *bd_addr,
		bthh_protocol_mode_t protocol_mode)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t set_protocol(bt_bdaddr_t *bd_addr,
		bthh_protocol_mode_t protocol_mode)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t get_report(bt_bdaddr_t *bd_addr,
		bthh_report_type_t report_type,
		uint8_t report_id,
		int buffer_size)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t set_report(bt_bdaddr_t *bd_addr,
		bthh_report_type_t report_type,
		char *report)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t hidhost_send_data(bt_bdaddr_t *bd_addr, char *data)
{
	DBG("");
	return BT_STATUS_UNSUPPORTED;
}

static void __bt_hal_handle_hid_events(int message, void *buf, uint16_t len)
{
	DBG("+");

	if (!interface_ready())
		return;

	switch(message) {
	case HAL_EV_HIDHOST_CONN_STATE:
		DBG("Event: HAL_EV_HIDHOST_CONN_STATE");
		__bt_hal_handle_conn_state(buf, len);
		break;
	case HAL_EV_HIDHOST_INFO:
		DBG("Event: HAL_EV_HIDHOST_INFO");
		__bt_hal_handle_hidhost_info(buf, len);
		break;
	case HAL_EV_HIDHOST_PROTO_MODE:
		DBG("Event: HAL_EV_HIDHOST_PROTO_MODE");
		__bt_hal_handle_proto_mode(buf, len);
		break;
	case HAL_EV_HIDHOST_IDLE_TIME:
		DBG("Event: HAL_EV_HIDHOST_IDLE_TIME");
		__bt_hal_handle_idle_time(buf, len);
		break;
	case HAL_EV_HIDHOST_GET_REPORT:
		DBG("Event: HAL_EV_HIDHOST_GET_REPORT");
		__bt_hal_handle_get_report(buf, len);
		break;
	case HAL_EV_HIDHOST_VIRTUAL_UNPLUG:
		DBG("Event: HAL_EV_HIDHOST_VIRTUAL_UNPLUG");
		__bt_hal_handle_virtual_unplug(buf, len);
		break;
	case HAL_EV_HIDHOST_HANDSHAKE:
		DBG("Event: HAL_EV_HIDHOST_HANDSHAKE");
		__bt_hal_handle_handshake(buf, len);
		break;
	default:
		DBG("Event Currently not handled!!");
		break;
	}

	DBG("-");
}

static bt_status_t init(bthh_callbacks_t *callbacks)
{
	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	bt_hal_hid_cbacks = callbacks;
	DBG("Register HID events callback function");
	_bt_hal_register_hid_dbus_handler_cb(__bt_hal_handle_hid_events);
	_bt_hal_register_hid_event_handler_cb(__bt_hal_handle_hid_events);

	return BT_STATUS_SUCCESS;
}

static void cleanup(void)
{
	DBG("");

	if (!interface_ready())
		return;

	_bt_hal_unregister_hid_dbus_handler_cb();
	_bt_hal_unregister_hid_event_handler_cb();

	bt_hal_hid_cbacks = NULL;
}

static bthh_interface_t hidhost_if = {
	.size = sizeof(hidhost_if),
	.init = init,
	.connect = hidhost_connect,
	.disconnect = hidhost_disconnect,
	.virtual_unplug = virtual_unplug,
	.set_info = hidhost_set_info,
	.get_protocol = get_protocol,
	.set_protocol = set_protocol,
	.get_report = get_report,
	.set_report = set_report,
	.send_data = hidhost_send_data,
	.cleanup = cleanup
};

bthh_interface_t *bt_get_hidhost_interface(void)
{
	return &hidhost_if;
}

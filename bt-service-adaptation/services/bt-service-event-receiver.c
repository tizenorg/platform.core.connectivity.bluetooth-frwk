/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <string.h>
#include <dlog.h>
#include <vconf.h>
#include <vconf-internal-bt-keys.h>

#include <oal-event.h>

#include "bt-service-common.h"
#include "bt-service-event-receiver.h"

_bt_service_event_handler_callback adapter_cb;
_bt_service_event_handler_callback device_cb;

void _bt_service_register_event_handler_callback(
		bt_service_module_t module, _bt_service_event_handler_callback cb)
{
	switch(module) {
	case BT_ADAPTER_MODULE:
		BT_INFO("Register BT_ADAPTER_MODULE Callback");
		adapter_cb = cb;
		break;
	case BT_DEVICE_MODULE:
                BT_INFO("Register BT_DEVICE_MODULE Callback");
                device_cb = cb;
                break;
	default:
		BT_INFO("Unknown module");
	}
}

void _bt_service_unregister_event_handler_callback(bt_service_module_t module)
{
	switch(module) {
	case BT_ADAPTER_MODULE:
		BT_INFO("Un-Register BT_ADAPTER_MODULE Callback");
		adapter_cb = NULL;
		break;
	default:
		BT_INFO("Unknown module");
	}
}

void _bt_service_oal_event_receiver(int event_type, gpointer event_data, gsize len)
{
	BT_INFO("event_type: [%d], data size: [%d]", event_type, len);

	switch (event_type) {
	case OAL_EVENT_OAL_INITIALISED_SUCCESS:
	case OAL_EVENT_OAL_INITIALISED_FAILED:
	case OAL_EVENT_ADAPTER_ENABLED:
	case OAL_EVENT_ADAPTER_DISABLED:
	case OAL_EVENT_ADAPTER_PROPERTY_ADDRESS:
	case OAL_EVENT_ADAPTER_PROPERTY_NAME:
	case OAL_EVENT_ADAPTER_PROPERTY_VERSION:
	case OAL_EVENT_ADAPTER_PROPERTY_SERVICES:
	case OAL_EVENT_ADAPTER_BONDED_DEVICE_LIST:
	case OAL_EVENT_ADAPTER_MODE_NON_CONNECTABLE:
	case OAL_EVENT_ADAPTER_MODE_CONNECTABLE:
	case OAL_EVENT_ADAPTER_MODE_DISCOVERABLE:
	case OAL_EVENT_ADAPTER_MODE_DISCOVERABLE_TIMEOUT:
	case OAL_EVENT_ADAPTER_INQUIRY_STARTED:
	case OAL_EVENT_ADAPTER_INQUIRY_FINISHED:
		if (adapter_cb)
			adapter_cb(event_type, event_data);
		break;
        case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BREDR_ONLY:
        case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BLE:
	case OAL_EVENT_DEVICE_PROPERTIES:
		if (device_cb)
                        device_cb(event_type, event_data);
		break;
	default:
		BT_ERR("Unhandled Event: %d", event_type);
		break;
	}
}

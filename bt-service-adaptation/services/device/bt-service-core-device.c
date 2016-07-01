/*
 * Copyright (c) 2015 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <gio/gio.h>
#include <glib.h>
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <vconf-internal-keys.h>
#include <syspopup_caller.h>
#include <aul.h>
#include <eventsystem.h>
#include <bundle_internal.h>

/*bt-service headers */
#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-util.h"
#include "bt-service-main.h"
#include "bt-service-core-device.h"
#include "bt-service-core-adapter.h"
#include "bt-service-event-receiver.h"
#include "bt-request-handler.h"
#include "bt-service-event.h"

/* OAL headers */
#include <oal-event.h>
#include <oal-manager.h>
#include <oal-adapter-mgr.h>

/* Forward declaration */
static void __bt_device_event_handler(int event_type, gpointer event_data);
static void __bt_device_remote_device_found_callback(gpointer event_data, gboolean is_ble);


void _bt_device_state_handle_callback_set_request(void)
{
	_bt_service_register_event_handler_callback(
			BT_DEVICE_MODULE, __bt_device_event_handler);
}

static void __bt_device_event_handler(int event_type, gpointer event_data)
{
        int eventcheck = OAL_EVENT_DEVICE_PROPERTIES;
        BT_INFO("event [%d] Event check = [%d]", event_type, eventcheck);

        switch(event_type) {
                case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BREDR_ONLY:
                {
                        BT_INFO("BREDR Device Found");
                        __bt_device_remote_device_found_callback(event_data, FALSE);
                        break;
                }
		case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BLE:
                {
                        BT_INFO("Dual Device Found");
                        __bt_device_remote_device_found_callback(event_data, FALSE);
                        break;
                }
		default:
		BT_INFO("Unhandled event..");
	}
}

static void __bt_device_remote_device_found_callback(gpointer event_data, gboolean is_ble)
{
	BT_INFO("+");
	bt_remote_dev_info_t *dev_info = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	ret_if(_bt_is_discovering() == FALSE);
	ret_if(event_data == NULL);

	dev_info = g_malloc0(sizeof(bt_remote_dev_info_t));
	memset(dev_info, 0x00, sizeof(bt_remote_dev_info_t));

	if(is_ble) {
		event_ble_dev_found_t * oal_ble_dev = event_data;
		BT_INFO("Device type [%d]",oal_ble_dev->device_info.type);

		_bt_copy_remote_dev(dev_info, &oal_ble_dev->device_info);

		dev_info->manufacturer_data_len = oal_ble_dev->adv_len;
		if(dev_info->manufacturer_data_len)
			dev_info->manufacturer_data = g_memdup(oal_ble_dev->adv_data, dev_info->manufacturer_data_len);
		else
			dev_info->manufacturer_data = NULL;
		BT_DBG("----Advertising Data Length: %d",dev_info->manufacturer_data_len);
	} else {
		event_dev_found_t * oal_dev = event_data;
		_bt_copy_remote_dev(dev_info, &oal_dev->device_info);
	}

	if (dev_info) {
		GVariant *param = NULL;
		if (dev_info->name == NULL)
			/* If Remote device name is NULL or still RNR is not done
			 * then display address as name.
			 */
			dev_info->name = g_strdup(dev_info->address);
		BT_DBG("Name %s", dev_info->name);
		GVariant *uuids = NULL;
		GVariantBuilder *builder = NULL;
		int i = 0;
		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		for (i=0; i < dev_info->uuid_count; i++) {
			g_variant_builder_add(builder, "s",
					dev_info->uuids[i]);
		}
		uuids = g_variant_new("as", builder);
		g_variant_builder_unref(builder);
		GVariant *manufacturer_data =  NULL;
		manufacturer_data = g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
				dev_info->manufacturer_data,
				dev_info->manufacturer_data_len,
				TRUE,
				NULL, NULL);
		param = g_variant_new("(isunsbub@asn@ay)", result,
				dev_info->address,
				dev_info->class,
				dev_info->rssi,
				dev_info->name,
				dev_info->paired,
				dev_info->connected,
				dev_info->trust,
				uuids,
				dev_info->manufacturer_data_len,
				manufacturer_data);

		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND,
				param);
	}
	BT_DBG("-");
}

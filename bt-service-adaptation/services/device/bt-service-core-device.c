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
#include <oal-device-mgr.h>

/* Forward declaration */
static void __bt_device_event_handler(int event_type, gpointer event_data);
static void __bt_device_remote_device_found_callback(gpointer event_data, gboolean is_ble);


void _bt_device_state_handle_callback_set_request(void)
{
	_bt_service_register_event_handler_callback(
			BT_DEVICE_MODULE, __bt_device_event_handler);
}

void __bt_device_handle_pending_requests(int result, int service_function,
		void *user_data, unsigned int size)
{
	GSList *l;
	GArray *out_param;
	invocation_info_t *req_info = NULL;

	BT_DBG("+");

	/* Get method invocation context */
	for (l = _bt_get_invocation_list(); l != NULL; l = g_slist_next(l)) {
		req_info = l->data;
		if (req_info == NULL || req_info->service_function != service_function)
			continue;

		switch (service_function) {
		case BT_GET_BONDED_DEVICE: {
			char rem_addr[BT_ADDRESS_STRING_SIZE];
			char *address = req_info->user_data;
			bluetooth_device_info_t *dev_info = user_data;

			ret_if(dev_info == NULL);

			_bt_convert_addr_type_to_string(rem_addr, dev_info->device_address.addr);
			if (strncasecmp(address, rem_addr, BT_ADDRESS_STRING_SIZE))
				break;

			out_param = g_array_new(FALSE, FALSE, sizeof(gchar));
			g_array_append_vals(out_param, dev_info,
					sizeof(bluetooth_device_info_t));

			_bt_service_method_return(req_info->context, out_param, result);
			_bt_free_info_from_invocation_list(req_info);
			g_array_free(out_param, TRUE);
			break;
		}
		case BT_GET_BONDED_DEVICES: {
			char rem_addr[BT_ADDRESS_STRING_SIZE];
			char req_addr[BT_ADDRESS_STRING_SIZE];
			bluetooth_device_address_t *addr_list;
			bluetooth_device_info_t *dev_info = user_data;
			bonded_devices_req_info_t *list_info = req_info->user_data;

			ret_if (list_info == NULL);
			ret_if(dev_info == NULL);

			addr_list = list_info->addr_list;
			_bt_convert_addr_type_to_string(rem_addr, dev_info->device_address.addr);
			_bt_convert_addr_type_to_string(req_addr, addr_list[list_info->count].addr);

			BT_DBG("rem_addr: [%s]", rem_addr);
			BT_DBG("req_addr: [%s]", req_addr);
			if (strncasecmp(req_addr, rem_addr, BT_ADDRESS_STRING_SIZE))
				break;

			if (dev_info->paired == TRUE)
				g_array_append_vals(list_info->out_param,
						dev_info, sizeof(bluetooth_device_info_t));

			if (list_info->count == 0) {
				BT_DBG("Device info for all the paired devices is received");
				/*
				 * Device info for all the paired devices is received,
				 * Send reply to get_bonded_devices request.
				 */
				_bt_service_method_return(req_info->context,
						list_info->out_param, req_info->result);

				g_free(list_info->addr_list);
				g_array_free(list_info->out_param, TRUE);
				g_free(list_info);
				req_info->user_data = NULL;
				_bt_free_info_from_invocation_list(req_info);
				break;
			}

			while (list_info->count > 0) {
				BT_DBG("list_info->count: %d", list_info->count);
				list_info->count -= 1;
				result = _bt_device_get_bonded_device_info(&addr_list[list_info->count]);
				if (BLUETOOTH_ERROR_NONE == result)
					break;
				else if (list_info->count == 0) {
					BT_DBG("Send reply to get_bonded_devices request");
					/* Send reply to get_bonded_devices request */
					_bt_service_method_return(req_info->context,
							list_info->out_param, req_info->result);

					g_free(list_info->addr_list);
					g_array_free(list_info->out_param, TRUE);
					g_free(list_info);
					req_info->user_data = NULL;
					_bt_free_info_from_invocation_list(req_info);
				}
			}
			break;
		}
		default:
			BT_ERR("Unhandled case");
			break;
		}
	}
	BT_INFO("-");
}

/*
 * Remote device properties are received on all following conditions
 * a. When Bonding in on-going
 * b. When device properties are updated\changed for a connected device
 *    (due to SDP or any other reason)
 * c. When app requests for GET_BONDED_DEVICE\GET_BONDED_DEVICES info
 */
static void __bt_device_remote_properties_callback(event_dev_properties_t *oal_dev_props)
{
	bluetooth_device_info_t dev_info;
	bt_remote_dev_info_t *rem_info = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");
	rem_info = g_malloc0(sizeof(bt_remote_dev_info_t));
	memset(rem_info, 0x00, sizeof(bt_remote_dev_info_t));
	_bt_copy_remote_dev(rem_info, &(oal_dev_props->device_info));

	if (oal_dev_props->adv_len > 0) {
		int k;

		rem_info->manufacturer_data_len = oal_dev_props->adv_len;
		rem_info->manufacturer_data =
			g_memdup(oal_dev_props->adv_data,
					oal_dev_props->adv_len);
		BT_DBG("----Advertising Data Length: %d",
				rem_info->manufacturer_data_len);

		for(k=0; k < rem_info->manufacturer_data_len; k++) {
			BT_INFO("Check data[%d] = [[0x%x]",
					k, oal_dev_props->adv_data[k]);
		}
	} else {
		rem_info->manufacturer_data = NULL;
		rem_info->manufacturer_data_len = 0;
	}

	_bt_copy_remote_device(rem_info, &dev_info);
	_bt_service_print_dev_info(&dev_info);

	/* Check if app has requested for device info for already bonded devices */
	__bt_device_handle_pending_requests(result, BT_GET_BONDED_DEVICES,
			(void *)&dev_info, sizeof(bluetooth_device_info_t));
	__bt_device_handle_pending_requests(result, BT_GET_BONDED_DEVICE,
			(void *)&dev_info, sizeof(bluetooth_device_info_t));

	BT_DBG("-");
}

static void __bt_device_event_handler(int event_type, gpointer event_data)
{
        int eventcheck = OAL_EVENT_DEVICE_PROPERTIES;
        BT_INFO("event [%d] Event check = [%d]", event_type, eventcheck);

	switch(event_type) {
	case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BREDR_ONLY: {
		BT_INFO("BREDR Device Found");
		__bt_device_remote_device_found_callback(event_data, FALSE);
		break;
	}
	case OAL_EVENT_ADAPTER_INQUIRY_RESULT_BLE: {
		BT_INFO("Dual Device Found");
		__bt_device_remote_device_found_callback(event_data, FALSE);
		break;
	}
	case OAL_EVENT_DEVICE_PROPERTIES: {
		BT_INFO("Remote Device properties Received");
		__bt_device_remote_properties_callback((event_dev_properties_t *)event_data);
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

int _bt_device_get_bonded_device_info(bluetooth_device_address_t *addr)
{
	int result;
	bt_address_t bd_addr;

	BT_DBG("+");

	retv_if(!addr, BLUETOOTH_ERROR_INVALID_PARAM);

	memcpy(bd_addr.addr, addr, BLUETOOTH_ADDRESS_LENGTH);
	result = device_query_attributes(&bd_addr);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("device_query_attributes error: [%d]", result);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_alias(bluetooth_device_address_t *device_address, const char *alias)
{
	int ret;

	BT_DBG("+");
	BT_CHECK_PARAMETER(alias, return);

	ret = device_set_alias((bt_address_t *)device_address, (char *)alias);
	if (ret != OAL_STATUS_SUCCESS) {
		BT_ERR("device_set_alias: %d", ret);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

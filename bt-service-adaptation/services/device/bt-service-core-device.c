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
#include "bt-service-agent-util.h"

/* OAL headers */
#include <oal-event.h>
#include <oal-manager.h>
#include <oal-adapter-mgr.h>
#include <oal-device-mgr.h>

#define MAX_BOND_RETRY_COUNT 3
#define BT_PASSKEY_MAX_LENGTH 4

/* Bonding Info structure */
typedef struct {
        int result;
        char *addr;
        gboolean is_autopair;
        unsigned short conn_type;
        gboolean is_cancelled_by_user;
        gboolean is_device_creating;
        bluetooth_device_address_t *dev_addr;
        bt_remote_dev_info_t *dev_info;
} bt_bond_data_t;

/* Pairing Info structure */
typedef struct {
        char *addr;
        gboolean is_autopair;
        int is_ssp;
} bt_pairing_data_t;

/* Bonding and Pairing Informations */
bt_bond_data_t *trigger_bond_info;
bt_bond_data_t *trigger_unbond_info;
bt_pairing_data_t *trigger_pairing_info;

typedef enum {
  BT_DEVICE_BOND_STATE_NONE,
  BT_DEVICE_BOND_STATE_CANCEL_DISCOVERY,
  BT_DEVICE_BOND_STATE_DISCOVERY_CANCELLED,
  BT_DEVICE_BOND_STATE_REMOVE_BONDING,
  BT_DEVICE_BOND_STATE_REMOVED_BONDING,
  BT_DEVICE_BOND_STATE_STARTED,
  BT_DEVICE_BOND_STATE_WAIT_PROP,
  BT_DEVICE_BOND_STATE_WAIT_DID
} bt_bond_state_e;

typedef enum {
   BT_DEVICE_BOND_INFO,
   BT_DEVICE_UNBOND_INFO
} bt_bond_info_e;

/* BT device bond state variable */
static bt_bond_state_e bt_device_bond_state;
static int bond_retry_count;

/* Forward declaration */
static void __bt_device_event_handler(int event_type, gpointer event_data);
static void __bt_device_remote_device_found_callback(gpointer event_data, gboolean is_ble);


static int __bt_device_handle_bond_state(void);
static void __bt_free_bond_info(uint8_t type);
static void __bt_device_handle_bond_completion_event(bt_address_t *bd_addr);
static void __bt_device_handle_bond_removal_event(bt_address_t *bd_addr);
static void __bt_device_handle_bond_failed_event(event_dev_bond_failed_t* bond_fail_event);
static void __bt_handle_ongoing_bond(bt_remote_dev_info_t *remote_dev_info);
static void __bt_device_acl_state_changed_callback(event_dev_conn_status_t * acl_event,
				gboolean connected);
static void __bt_free_pairing_info(bt_pairing_data_t **p_info);

static void __bt_device_ssp_consent_callback(remote_device_t* dev_info);
static void __bt_device_pin_request_callback(remote_device_t* pin_req_event);
static void __bt_device_ssp_passkey_display_callback(event_dev_passkey_t *dev_info);
static void __bt_device_ssp_passkey_confirmation_callback(event_dev_passkey_t *dev_info);
static void __bt_device_ssp_passkey_entry_callback(remote_device_t* dev_info);

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
		case BT_BOND_DEVICE:
		case BT_UNBOND_DEVICE: {
			char *address = (char *)user_data;
			if (strncmp((char*)req_info->user_data, address, BT_ADDRESS_STRING_SIZE)) {
				BT_ERR("Unexpected: Info request pending for a different address!!");
				return;
			} else {
				BT_INFO("Found info request addr [%s]", (char*)req_info->user_data);
				bluetooth_device_info_t dev_info;
				memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));
				_bt_convert_addr_string_to_type(dev_info.device_address.addr,
						address);
					out_param = g_array_new(FALSE, FALSE, sizeof(gchar));
				g_array_append_vals(out_param, &dev_info,
						sizeof(bluetooth_device_info_t));
					_bt_service_method_return(req_info->context, out_param, result);
				_bt_free_info_from_invocation_list(req_info);
				g_array_free(out_param, TRUE);
			}
			break;
		}
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

	/* a. Check if bonding is on-going, if yes, we MUST update the bonding device properties */
	if (trigger_bond_info  && !strcmp(trigger_bond_info->addr, rem_info->address)) {
		BT_INFO("Bonding is ongoing, try update properties");
		if (!trigger_bond_info->dev_info ||
				!trigger_bond_info->dev_info->name ||
					!trigger_bond_info->dev_info->address ||
						!trigger_bond_info->dev_info->uuid_count == 0) {
			BT_INFO("Complete data is not present, Assigning rem_info");
			trigger_bond_info->dev_info = rem_info;
		}
	}

	_bt_copy_remote_device(rem_info, &dev_info);
	_bt_service_print_dev_info(&dev_info);

	/* Check if app has requested for device info for already bonded devices */
	__bt_device_handle_pending_requests(result, BT_GET_BONDED_DEVICES,
			(void *)&dev_info, sizeof(bluetooth_device_info_t));
	__bt_device_handle_pending_requests(result, BT_GET_BONDED_DEVICE,
			(void *)&dev_info, sizeof(bluetooth_device_info_t));

	if (trigger_bond_info  && !strcmp(trigger_bond_info->addr, rem_info->address)) {
		BT_DBG("Bonding dev addr has matched with remote dev properties address [%s]", rem_info->address);
		__bt_handle_ongoing_bond(trigger_bond_info->dev_info);
	}

	BT_DBG("-");
}

static void __bt_handle_ongoing_bond(bt_remote_dev_info_t *remote_dev_info)
{
	GVariant *param = NULL;
	BT_DBG("+");

	if (remote_dev_info->name
			&& remote_dev_info->address
			&& remote_dev_info->uuids) {
		BT_INFO("All properties updated,  time to send bonding finished event");
		GVariant *uuids = NULL;
		GVariantBuilder *builder = NULL;
		GVariant *manufacturer_data;
		int i = 0;
		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		for (i=0; i < remote_dev_info->uuid_count; i++) {
			g_variant_builder_add(builder, "s",
					remote_dev_info->uuids[i]);
		}
		uuids = g_variant_new("as", builder);
		g_variant_builder_unref(builder);
		manufacturer_data = g_variant_new_from_data((const GVariantType *)"ay",
				remote_dev_info->manufacturer_data, remote_dev_info->manufacturer_data_len,
				TRUE, NULL, NULL);

		param = g_variant_new("(isunsbub@asn@ay)",
				BLUETOOTH_ERROR_NONE,
				remote_dev_info->address,
				remote_dev_info->class,
				remote_dev_info->rssi,
				remote_dev_info->name,
				remote_dev_info->paired,
				remote_dev_info->connected,
				remote_dev_info->trust,
				uuids,
				remote_dev_info->manufacturer_data_len,
				manufacturer_data);
		/* Send the event to application */
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_BONDING_FINISHED,
				param);
		__bt_free_bond_info(BT_DEVICE_BOND_INFO);
		__bt_free_pairing_info(&trigger_pairing_info);
	} else {
		BT_INFO("Lets wait for more remote device properties");
	}
}

static void __bt_device_handle_bond_completion_event(bt_address_t *bd_addr)
{
	gchar address[BT_ADDRESS_STR_LEN];
	bluetooth_device_address_t dev_addr;
	BT_INFO("+");
	/* Tizen does not propagate incoming bond complete event to app */
	if (trigger_bond_info == NULL) {
		/* Send reply */
		BT_DBG("trigger_bond_info == NULL");
		return;
	}

	_bt_convert_addr_type_to_string(address, bd_addr->addr);
	if (g_strcmp0(trigger_bond_info->addr, address)) {
		BT_DBG("Bonding address= [%s] is different from requested address =[%s]",
				address, trigger_bond_info->addr);
		return;
	}

	BT_INFO("Bonding successfully completed");
	/* TODO: Bonding state will be cleaned up & BONDING FINISHED EVENT
	   will be sent only when Properties are fetched from stack
	   Till that time lets not free trigger_bond_info */
	__bt_device_handle_pending_requests(BLUETOOTH_ERROR_NONE, BT_BOND_DEVICE,
			trigger_bond_info->addr, BT_ADDRESS_STRING_SIZE);

	_bt_convert_addr_string_to_type(dev_addr.addr,
                        trigger_bond_info->addr);
	_bt_device_get_bonded_device_info(&dev_addr);
	BT_INFO("-");
}

/**********************************************************************************************
*  Bond removal event can be triggered for following reasons -
*  a. If Bonding procedure if failed (for Auth failed, Page timeout, cancelled by user etc)
*  b. If Application requests for explicitly removing the bond
*  c. When application attempt to create bond,bond is removed first which triggers this event
*     c. is in-line with Bluedroid bond create\emoval architecture
*********************************************************************************************/
static void __bt_device_handle_bond_removal_event(bt_address_t *bd_addr)
{
	BT_INFO("+");
	if (trigger_unbond_info) {
		BT_INFO("Bond removal request successfully handled, return DBUS and send event");
		GVariant *param = NULL;
		__bt_device_handle_pending_requests(BLUETOOTH_ERROR_NONE, BT_UNBOND_DEVICE,
				trigger_unbond_info->addr, BT_ADDRESS_STRING_SIZE);
		param = g_variant_new("(is)", BLUETOOTH_ERROR_NONE, trigger_unbond_info->addr);
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
				param);
		__bt_free_bond_info(BT_DEVICE_UNBOND_INFO);
		__bt_free_pairing_info(&trigger_pairing_info);
	} else if (trigger_bond_info) {
		__bt_device_handle_bond_state();
	}
	BT_INFO("-");
}

static void __bt_device_handle_bond_failed_event(event_dev_bond_failed_t* bond_fail_event)
{
	BT_INFO("+");
	oal_status_t status = bond_fail_event->status;
	BT_INFO("Bonding failed, reason: %d", status);

	switch(status) {
	case OAL_STATUS_RMT_DEVICE_DOWN:
	{
		if (trigger_bond_info) {
			BT_INFO("OAL_STATUS_RMT_DEVICE_DOWN:Lets retry bonding!! retry count [%d]",
					bond_retry_count);
			int ret = OAL_STATUS_SUCCESS;
			if (bond_retry_count < MAX_BOND_RETRY_COUNT) {
				ret = device_create_bond((bt_address_t *)trigger_bond_info->dev_addr, BLUETOOTH_DEV_CONN_DEFAULT);
				bond_retry_count++;
			} else {
				BT_ERR("Create Bond failed MAX_BOND_RETRY_COUNT TIMES!!");
			}
			if (ret != OAL_STATUS_SUCCESS || bond_retry_count >= MAX_BOND_RETRY_COUNT) {
				BT_ERR("Create Bond procedure could not suceed");
				__bt_device_handle_pending_requests(BLUETOOTH_ERROR_INTERNAL, BT_BOND_DEVICE,
						trigger_bond_info->addr, BT_ADDRESS_STRING_SIZE);
				__bt_free_bond_info(BT_DEVICE_BOND_INFO);
				__bt_free_pairing_info(&trigger_pairing_info);
				bond_retry_count = 0;
			}
		}
		break;
	}
	case OAL_STATUS_AUTH_FAILED:
	{
		/*TODO Auto pairing status set & ignore auto pairing logics can be done at this point.
		  To be considered later*/
		int result = BLUETOOTH_ERROR_INTERNAL;
		BT_INFO("BT_OPERATION_STATUS_AUTH_FAILED");
		if (trigger_bond_info) {
			BT_ERR("Create Bond procedure could not suceed, check if cancelled by User");
			if (trigger_bond_info->is_cancelled_by_user) {
				BT_ERR("Bonding is cancelled by user");
				result = BLUETOOTH_ERROR_CANCEL_BY_USER;
			}
			__bt_device_handle_pending_requests(result, BT_BOND_DEVICE,
					trigger_bond_info->addr, BT_ADDRESS_STRING_SIZE);
			__bt_free_bond_info(BT_DEVICE_BOND_INFO);
			__bt_free_pairing_info(&trigger_pairing_info);
		}
		break;
	}
	case OAL_STATUS_INTERNAL_ERROR:
	{
		BT_INFO("OAL_STATUS_INTERNAL_ERROR");
		if (trigger_unbond_info) {
			BT_INFO("Bond removal request failed, return DBUS and send event");
			GVariant *param = NULL;
			__bt_device_handle_pending_requests(BLUETOOTH_ERROR_INTERNAL, BT_UNBOND_DEVICE,
					trigger_unbond_info->addr, BT_ADDRESS_STRING_SIZE);
			param = g_variant_new("(is)", BLUETOOTH_ERROR_INTERNAL, trigger_unbond_info->addr);
			_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
					param);
			__bt_free_bond_info(BT_DEVICE_UNBOND_INFO);
			__bt_free_pairing_info(&trigger_pairing_info);
		} else if (trigger_bond_info) {
			if (__bt_device_handle_bond_state()!= BLUETOOTH_ERROR_NONE) {
				__bt_device_handle_pending_requests(BLUETOOTH_ERROR_INTERNAL, BT_BOND_DEVICE,
						trigger_bond_info->addr, BT_ADDRESS_STRING_SIZE);
				__bt_free_bond_info(BT_DEVICE_BOND_INFO);
				__bt_free_pairing_info(&trigger_pairing_info);
			}
		}
		break;
	}
	default:
	{
		BT_ERR("Unknown status of Bond failed event status [%d]", status);
		break;
	}

	}
	BT_INFO("-");
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
	case OAL_EVENT_DEVICE_BONDING_SUCCESS: {
	       BT_INFO("Bonding Success event Received");
	       __bt_device_handle_bond_completion_event((bt_address_t *)event_data);
	       break;
       }
	case OAL_EVENT_DEVICE_BONDING_REMOVED: {
	       BT_INFO("Bonding Removed event Received");
	       __bt_device_handle_bond_removal_event((bt_address_t *)event_data);
	       break;
	}
	case OAL_EVENT_DEVICE_BONDING_FAILED: {
	      BT_INFO("Bonding Failed event Received");
	      __bt_device_handle_bond_failed_event((event_dev_bond_failed_t*) event_data);
	      break;
	}
	case OAL_EVENT_DEVICE_ACL_CONNECTED: {
	     BT_INFO("ACL Connected event Received");
	     event_dev_conn_status_t* param = event_data;
	     __bt_device_acl_state_changed_callback(param, TRUE);
	     __bt_device_handle_bond_removal_event(&(param->address));
	     break;
	}
	case OAL_EVENT_DEVICE_ACL_DISCONNECTED: {
		BT_INFO("ACL Disconnected event Received");
		__bt_device_acl_state_changed_callback((event_dev_conn_status_t *)event_data, FALSE);
		break;
	}
	case OAL_EVENT_DEVICE_PIN_REQUEST: {
		   BT_INFO("PIN Request Received");
		   __bt_device_pin_request_callback((remote_device_t*)event_data);
		   break;
	}
	case OAL_EVENT_DEVICE_PASSKEY_ENTRY_REQUEST: {
		BT_INFO("Passkey Entry request Received");
		__bt_device_ssp_passkey_entry_callback((remote_device_t*)event_data);
		break;
	}
	case OAL_EVENT_DEVICE_PASSKEY_CONFIRMATION_REQUEST:{
		   BT_INFO("Passkey Confirmation Request Received");
		   __bt_device_ssp_passkey_confirmation_callback((event_dev_passkey_t *)event_data);
		   break;
	}
	case OAL_EVENT_DEVICE_PASSKEY_DISPLAY: {
	      BT_INFO("Passkey Display Request Received");
	      __bt_device_ssp_passkey_display_callback((event_dev_passkey_t *)event_data);
	      break;
	}
	case OAL_EVENT_DEVICE_SSP_CONSENT_REQUEST: {
		BT_INFO("SSP Consent Request Received");
		 __bt_device_ssp_consent_callback((remote_device_t*)event_data);
		break;
	}
	default:
		BT_INFO("Unhandled event..");
	}
}

/* Legacy Pairing event handler */
static void __bt_device_pin_request_callback(remote_device_t* pin_req_event)
{
	GVariant *param;
	gchar address[BT_ADDRESS_STR_LEN];
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, pin_req_event->address.addr);

	BT_INFO("Address[%s]", address);
	BT_INFO("Name[%s]", pin_req_event->name);
	BT_INFO("COD[%d]", pin_req_event->cod);

	if (trigger_pairing_info) {
		/* BTAPI support only one pairing at a time */
		BT_ERR("Already Pairing address [%s]", trigger_pairing_info->addr);
		BT_ERR("New PIN request address [%s]", address);
		device_reject_pin_request(&pin_req_event->address);
		return;
	}

	/* If user initiated bonding and auto response is possible, just reply with default 0000*/
	if (_bt_is_bonding_device_address(address) == TRUE &&
			_bt_agent_is_auto_response(pin_req_event->cod, address, pin_req_event->name)) {
		/* Note: Currently even if SYSPOPUP is supported, we use Fixed PIN "0000" for basic pairing
		   as BT SYSPOPUP is currently not working for PIN KEY entry in Tizen platform. This needs
		   to be checked and fixed apropriately */
		_bt_set_autopair_status_in_bonding_info(TRUE);
		device_accept_pin_request(&pin_req_event->address, "0000");
	} else if (_bt_agent_is_hid_keyboard(pin_req_event->cod)) {
		char str_passkey[BT_PASSKEY_MAX_LENGTH + 1] = { 0 };

		if (_bt_agent_generate_passkey(str_passkey,
					BT_PASSKEY_MAX_LENGTH) != 0) {
			device_reject_pin_request(&pin_req_event->address);
			goto done;
		}
		device_accept_pin_request(&pin_req_event->address, str_passkey);

		BT_DBG("Send BLUETOOTH_EVENT_KEYBOARD_PASSKEY_DISPLAY");
		param = g_variant_new("(isss)", BLUETOOTH_ERROR_NONE, address, pin_req_event->name, str_passkey);
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_KEYBOARD_PASSKEY_DISPLAY, param);
		BT_DBG("Key board pairing in process");
	} else {
		if (_bt_is_bonding_device_address(address) == TRUE) {
			BT_DBG("Show Pin entry");
			trigger_pairing_info = g_malloc0(sizeof(bt_pairing_data_t));
			trigger_pairing_info->addr = g_strdup(address);
			trigger_pairing_info->is_ssp = FALSE;

			BT_DBG("Send BLUETOOTH_EVENT_PIN_REQUEST");
			param = g_variant_new("(iss)", BLUETOOTH_ERROR_NONE, address, pin_req_event->name);
			_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_PIN_REQUEST, param);
		}
	}

done:
	_bt_agent_release_memory();
	BT_DBG("-");
}


static void __bt_device_ssp_passkey_entry_callback(remote_device_t* dev_info)
{
	GVariant *param;
	gchar address[BT_ADDRESS_STR_LEN];
	char *p_addr;
	gchar *name;
	int result = BLUETOOTH_ERROR_NONE;
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, dev_info->address.addr);
	p_addr = address;
	name = dev_info->name;

	BT_INFO("Address[%s]", address);
	BT_INFO("Name[%s]", name);
	BT_INFO("COD[%d]", dev_info->cod);

	if (trigger_pairing_info) {
		/* BTAPI support only one pairing at a time */
		BT_ERR("Already Pairing address [%s]", trigger_pairing_info->addr);
		BT_ERR("New PIN request address [%s]", address);
		device_reject_pin_request(&dev_info->address);
		BT_DBG("-");
		return;
	}

	/* Set pairing data */
	trigger_pairing_info = g_malloc0(sizeof(bt_pairing_data_t));
	trigger_pairing_info->addr = g_strdup(address);
	trigger_pairing_info->is_ssp = TRUE;

	param = g_variant_new("(iss)", result, p_addr, name);
	_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_PASSKEY_REQUEST, param);
	BT_DBG("-");
}

static void __bt_device_ssp_passkey_confirmation_callback(event_dev_passkey_t *dev_info)
{
	GVariant *param;
	gchar address[BT_ADDRESS_STR_LEN];
	char *p_addr;
	gchar *name;
	char str_passkey[7];
	int result = BLUETOOTH_ERROR_NONE;
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, dev_info->device_info.address.addr);
	p_addr = address;
	name = dev_info->device_info.name;

	BT_INFO("Address[%s]", address);
	BT_INFO("Name[%s]", name);
	BT_INFO("COD[%d]", dev_info->device_info.cod);

	if (trigger_pairing_info) {
		/* BTAPI support only one pairing at a time */
		BT_ERR("Already Pairing address [%s]", trigger_pairing_info->addr);
		BT_ERR("New PIN request address [%s]", address);
		device_reject_pin_request(&dev_info->device_info.address);
		BT_DBG("-");
		return;
	}

	/* Set pairing data */
	trigger_pairing_info = g_malloc0(sizeof(bt_pairing_data_t));
	trigger_pairing_info->addr = g_strdup(address);
	trigger_pairing_info->is_ssp = TRUE;

	BT_DBG("Send BLUETOOTH_EVENT_PASSKEY_CONFIRMATION");
	snprintf(str_passkey, sizeof(str_passkey), "%.6d", dev_info->pass_key);

	param = g_variant_new("(isss)", result, p_addr, name, str_passkey);
	_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_PASSKEY_CONFIRM_REQUEST, param);
	BT_DBG("-");
}

static void __bt_device_ssp_passkey_display_callback(event_dev_passkey_t *dev_info)
{
	GVariant *param;
	gchar address[BT_ADDRESS_STR_LEN];
	char *p_addr;
	gchar *name;
	char str_passkey[7];
	int result = BLUETOOTH_ERROR_NONE;
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, dev_info->device_info.address.addr);
	p_addr = address;
	name = dev_info->device_info.name;

	BT_INFO("Address[%s]", address);
	BT_INFO("Name[%s]", name);
	BT_INFO("COD[%d]", dev_info->device_info.cod);

	if (trigger_pairing_info) {
		/* BTAPI support only one pairing at a time */
		BT_ERR("Already Pairing address [%s]", trigger_pairing_info->addr);
		BT_ERR("New PIN request address [%s]", address);
		device_reject_pin_request(&dev_info->device_info.address);
		BT_DBG("-");
		return;
	}

	/* Set pairing data */
	trigger_pairing_info = g_malloc0(sizeof(bt_pairing_data_t));
	trigger_pairing_info->addr = g_strdup(address);
	trigger_pairing_info->is_ssp = TRUE;

	BT_DBG("Send BLUETOOTH_EVENT_KEYBOARD_PASSKEY_DISPLAY");
	snprintf(str_passkey, sizeof(str_passkey), "%.6d", dev_info->pass_key);

	param = g_variant_new("(isss)", result, p_addr, name, str_passkey);
	_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_KEYBOARD_PASSKEY_DISPLAY, param);
	BT_DBG("-");

}

static void __bt_device_ssp_consent_callback(remote_device_t* dev_info)
{
	gchar address[BT_ADDRESS_STR_LEN];
	gchar *name;
	int local_major;
	int local_minor;
	int cod;
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, dev_info->address.addr);
	name = dev_info->name;
	cod = dev_info->cod;

	BT_INFO("Address[%s]", address);
	BT_INFO("Name[%s]", name);
	BT_INFO("COD[%d]", cod);

	if (trigger_pairing_info) {
		/* BTAPI support only one pairing at a time */
		BT_ERR("Already Pairing address [%s]", trigger_pairing_info->addr);
		BT_ERR("New PIN request address [%s]", address);
		device_reject_pin_request(&dev_info->address);
		BT_DBG("-");
		return;
	}

	/* Set pairing data */
	trigger_pairing_info = g_malloc0(sizeof(bt_pairing_data_t));
	trigger_pairing_info->addr = g_strdup(address);
	trigger_pairing_info->is_ssp = TRUE;

	local_major = ((cod >> 8) & 0x001f);
	local_minor = (cod & 0x00fc);
	BT_DBG("SSP_CONSENT: Major type=[0x%x] and Minor type=[0x%x]",local_major, local_minor);

	/*TODO: BLUETOOTH_EVENT_SSP_CONSENT_REQUEST to be handled in Tizen */
	BT_DBG("-");
}

static void __bt_device_acl_state_changed_callback(event_dev_conn_status_t * acl_event, gboolean connected)
{
	gchar address[BT_ADDRESS_STR_LEN];
	int result = BLUETOOTH_ERROR_NONE;
	GVariant *param = NULL;
	unsigned char addr_type = 0;
	BT_DBG("+");

	_bt_convert_addr_type_to_string(address, acl_event->address.addr);

	if (connected) {
		param = g_variant_new("(isy)", result, address, addr_type);
		_bt_send_event(BT_DEVICE_EVENT,
				BLUETOOTH_EVENT_DEVICE_CONNECTED,
				param);
	} else {
		param = g_variant_new("(isy)", result, address, addr_type);
		_bt_send_event(BT_DEVICE_EVENT,
				BLUETOOTH_EVENT_DEVICE_DISCONNECTED,
				param);
	}
	BT_DBG("-");
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

static void __bt_free_pairing_info(bt_pairing_data_t **p_info)
{
	bt_pairing_data_t * info = *p_info;
	if (info) {
		if(info->addr) {
			g_free(info->addr);
		}

		g_free(info);
	}
	*p_info = NULL;
}

static void __bt_free_bond_info(uint8_t type)
{
	BT_INFO("+");
	if (type == BT_DEVICE_BOND_INFO) {
		if (trigger_bond_info) {
			if (trigger_bond_info->addr)
				g_free(trigger_bond_info->addr);
			if (trigger_bond_info->dev_addr)
				g_free(trigger_bond_info->dev_addr);
			if (trigger_bond_info->dev_info) {
				if (trigger_bond_info->dev_info->address)
					g_free(trigger_bond_info->dev_info->address);
				if (trigger_bond_info->dev_info->name)
					g_free(trigger_bond_info->dev_info->name);
				if (trigger_bond_info->dev_info->manufacturer_data)
					g_free(trigger_bond_info->dev_info->manufacturer_data);
				g_free(trigger_bond_info->dev_info);
			}
			g_free(trigger_bond_info);
			trigger_bond_info = NULL;
		}
	} else {
		if (trigger_unbond_info) {
			if (trigger_unbond_info->addr)
				g_free(trigger_unbond_info->addr);
			if (trigger_unbond_info->dev_addr)
				g_free(trigger_unbond_info->dev_addr);
			if (trigger_unbond_info->dev_info) {
				if (trigger_unbond_info->dev_info->address)
					g_free(trigger_unbond_info->dev_info->address);
				if (trigger_unbond_info->dev_info->name)
					g_free(trigger_unbond_info->dev_info->name);
				if (trigger_unbond_info->dev_info->manufacturer_data)
					g_free(trigger_unbond_info->dev_info->manufacturer_data);
				g_free(trigger_unbond_info->dev_info);
			}
			g_free(trigger_unbond_info);
			trigger_unbond_info = NULL;
		}
	}
}

static int __bt_device_handle_bond_state(void)
{
	BT_INFO("Current Bond state: %d", bt_device_bond_state);
	int ret = OAL_STATUS_INTERNAL_ERROR;

	switch (bt_device_bond_state) {
	case BT_DEVICE_BOND_STATE_CANCEL_DISCOVERY:
		/*TODO:Bonding during discovery: Unhandled!!*/
		BT_INFO("Bonding during discovery: Unhandled!!");
		break;
	case BT_DEVICE_BOND_STATE_DISCOVERY_CANCELLED:
		/*TODO:Bonding during discovery: Unhandled!!*/
		BT_INFO("Bonding during discovery: Unhandled!!");
		break;
	case BT_DEVICE_BOND_STATE_REMOVE_BONDING:
		bt_device_bond_state = BT_DEVICE_BOND_STATE_REMOVED_BONDING;
		ret = device_destroy_bond((bt_address_t *)trigger_bond_info->dev_addr);
		if (ret != OAL_STATUS_SUCCESS) {
			ret = __bt_device_handle_bond_state();
		}
		break;
	case BT_DEVICE_BOND_STATE_REMOVED_BONDING:
		bt_device_bond_state = BT_DEVICE_BOND_STATE_NONE;
		ret = device_create_bond((bt_address_t *)trigger_bond_info->dev_addr, BLUETOOTH_DEV_CONN_DEFAULT);
		/* Bonding procedure was started but unfortunately could not complete.
		   Basically removed bonding was success, but create bond request could not proceed
		   So lets cleanup the context */
		if (ret != OAL_STATUS_SUCCESS) {
			BT_ERR("Create Bond procedure could not suceed");
			__bt_device_handle_pending_requests(BLUETOOTH_ERROR_INTERNAL, BT_BOND_DEVICE,
					trigger_bond_info->addr, BT_ADDRESS_STRING_SIZE);
			__bt_free_bond_info(BT_DEVICE_BOND_INFO);
			__bt_free_pairing_info(&trigger_pairing_info);
		}
		break;
	case BT_DEVICE_BOND_STATE_NONE:
		BT_INFO("Create Bond failed!!");
		break;
	default:
		break;
	}

	if (ret != OAL_STATUS_SUCCESS)
		return BLUETOOTH_ERROR_INTERNAL;
	else
		return BLUETOOTH_ERROR_NONE;
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

int _bt_bond_device(bluetooth_device_address_t *device_address,
                unsigned short conn_type, GArray **out_param1)
{
	int result = BLUETOOTH_ERROR_NONE;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	bluetooth_device_info_t dev_info;
	BT_DBG("+");

	retv_if(device_address == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	/* If bonding or discovery already going on */
	if (trigger_bond_info || _bt_is_discovering()) {
		BT_ERR("Device is buzy, bonding can not proceed now..");
		result = BLUETOOTH_ERROR_DEVICE_BUSY;
		goto fail;
	}

	/*TODO: If unbonding with same device going on */
	_bt_convert_addr_type_to_string(address, device_address->addr);

	trigger_bond_info = g_malloc0(sizeof(bt_bond_data_t));
	trigger_bond_info->addr = g_strdup(address);
	trigger_bond_info->conn_type = conn_type;
	trigger_bond_info->is_device_creating = TRUE;
	trigger_bond_info->dev_addr = g_memdup(device_address, sizeof(bluetooth_device_address_t));
	trigger_bond_info->dev_info = NULL;

	/* Ready to initiate bonding */

	/* In Tizen, we will first remove bond and then attempt to create bond to keep
	   consistency with bluedroid. Even if remove bond fails due to device not already
	   bonded, then straight away create bond is triggered. This is because, remove bond
	   is handled differently in bluedroid and bluez. In Bluez, if device is
	   already removed, remove bond call fails.
	   However in bluedroid, remove bond on already removed device returns success. So we will
	   handle the cases transparently*/
	bt_device_bond_state = BT_DEVICE_BOND_STATE_REMOVE_BONDING;
	bond_retry_count = 0;
	result = __bt_device_handle_bond_state();

	if (result != BLUETOOTH_ERROR_NONE)
		goto fail;

	BT_DBG("-");
	return result;

fail:
	memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));
	memcpy(dev_info.device_address.addr, device_address->addr,
			BLUETOOTH_ADDRESS_LENGTH);

	g_array_append_vals(*out_param1, &dev_info,
			sizeof(bluetooth_device_info_t));
	__bt_free_bond_info(BT_DEVICE_BOND_INFO);

	BT_DBG("-");
	return result;
}

int _bt_unbond_device(bluetooth_device_address_t *device_address,
                GArray **out_param1)
{
	int result = OAL_STATUS_SUCCESS;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	bluetooth_device_info_t dev_info;
	BT_INFO("+");

	retv_if(device_address == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	_bt_convert_addr_type_to_string(address, device_address->addr);

	trigger_unbond_info = g_malloc0(sizeof(bt_bond_data_t));
	trigger_unbond_info->addr = g_malloc0(BT_ADDRESS_STRING_SIZE);
	trigger_unbond_info->addr = g_strdup(address);
	trigger_unbond_info->dev_addr = g_memdup(device_address, sizeof(bluetooth_device_address_t));

	/* Check if Bonding is already going on, we should not abruptly remove bonding*/
	if (trigger_bond_info && strncmp(trigger_bond_info->addr, trigger_unbond_info->addr, BT_ADDRESS_STRING_SIZE) == 0) {
		BT_ERR("Bonding with same device already ongoing");
		result = BLUETOOTH_ERROR_PERMISSION_DEINED;
		goto fail;
	}

	result = device_destroy_bond((bt_address_t *)device_address);
	if (result != OAL_STATUS_SUCCESS)
		goto fail;

	return result;

fail:
	memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));
	_bt_convert_addr_string_to_type(dev_info.device_address.addr,
			trigger_unbond_info->addr);

	g_array_append_vals(*out_param1, &dev_info,
			sizeof(bluetooth_device_info_t));
	__bt_free_bond_info(BT_DEVICE_UNBOND_INFO);

	return result;
}

gboolean _bt_device_is_pairing(void)
{
        return (trigger_pairing_info) ? TRUE : FALSE;
}

gboolean _bt_device_is_bonding(void)
{
        return (trigger_bond_info) ? TRUE : FALSE;
}

gboolean _bt_is_bonding_device_address(const char *address)
{
	if (trigger_bond_info == NULL || trigger_bond_info->addr == NULL)
		return FALSE;

	if (g_strcmp0(trigger_bond_info->addr, address) == 0) {
		BT_DBG("[%s]  is bonding device", address);
		return TRUE;
	}

	BT_DBG("[%s]  is NOT bonding device", address);
	return FALSE;
}

void _bt_set_autopair_status_in_bonding_info(gboolean is_autopair)
{
        ret_if (trigger_bond_info == NULL);
        trigger_bond_info->is_autopair = is_autopair;
}

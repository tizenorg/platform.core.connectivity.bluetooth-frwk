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

#include "alarm.h"

/*bt-service headers */
#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-util.h"
#include "bt-service-main.h"
#include "bt-service-core-adapter.h"
#include "bt-service-core-device.h"
#include "bt-service-event-receiver.h"
#include "bt-request-handler.h"
#include "bt-service-event.h"
#ifdef TIZEN_DPM_ENABLE
#include "bt-service-dpm.h"
#endif
#include "bt-service-hidhost.h"

/* OAL headers */
#include <oal-event.h>
#include <oal-manager.h>
#include <oal-adapter-mgr.h>

#define BT_ENABLE_TIMEOUT 20000 /* 20 seconds */

/*This file will contain state machines related to adapter and remote device */

/* Global variables */
typedef struct {
	guint event_id;
	int timeout;
	time_t start_time;
	gboolean alarm_init;
	int alarm_id;
} bt_adapter_timer_t;

static bt_adapter_timer_t visible_timer;

static guint timer_id = 0;

/* Adapter default states */
static bt_status_t adapter_state = BT_DEACTIVATED;
static bt_adapter_discovery_state_t adapter_discovery_state = ADAPTER_DISCOVERY_STOPPED;

/* Forward declarations */
static void __bt_adapter_event_handler(int event_type, gpointer event_data);
static void __bt_post_oal_init(void);
static void __bt_handle_oal_initialisation(oal_event_t event);
static void __bt_adapter_handle_pending_requests(int service_function, void *user_data, unsigned int size);
static gboolean __bt_adapter_post_set_enabled(gpointer user_data);
static gboolean __bt_adapter_post_set_disabled(gpointer user_data);
static void __bt_adapter_update_bt_enabled(void);
static void __bt_adapter_update_bt_disabled(void);
static void __bt_adapter_state_set_status(bt_status_t status);
static void __bt_adapter_update_discovery_status(bt_adapter_discovery_state_t status);
static void __bt_adapter_state_change_callback(int bt_status);
static int __bt_adapter_state_handle_request(gboolean enable);
static int __bt_adapter_state_discovery_request(gboolean enable);
static void __bt_adapter_discovery_state_change_callback(int bt_discovery_status);
static gboolean __bt_is_service_request_present(int service_function);

/* Initialize BT stack (Initialize OAL layer) */
int _bt_stack_init(void)
{
	int ret;

	BT_INFO("[bt-service] Start to initialize BT stack");
	/* Adapter enable request is successful, setup event handlers */
	_bt_service_register_event_handler_callback(
			BT_ADAPTER_MODULE, __bt_adapter_event_handler);

	ret = oal_bt_init(_bt_service_oal_event_receiver);

	if (OAL_STATUS_PENDING == ret) {
		BT_INFO("OAL Initialisation Pending, Profiles Init will be done once oal initialised...");
		return BLUETOOTH_ERROR_NONE;
	} else if (OAL_STATUS_SUCCESS != ret) {
		_bt_service_unregister_event_handler_callback(BT_ADAPTER_MODULE);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__bt_post_oal_init();
	return BLUETOOTH_ERROR_NONE;
}

int _bt_enable_adapter(void)
{
	return __bt_adapter_state_handle_request(TRUE);
}

int _bt_disable_adapter(void)
{
	return __bt_adapter_state_handle_request(FALSE);
}


int _bt_start_discovery(void)
{
	return __bt_adapter_state_discovery_request(TRUE);
}

int _bt_cancel_discovery(void)
{
	return __bt_adapter_state_discovery_request(FALSE);
}

gboolean _bt_is_discovering(void)
{
	if (adapter_discovery_state == ADAPTER_DISCOVERY_STARTED
			|| adapter_discovery_state == ADAPTER_DISCOVERY_STARTING)
		return TRUE;
	else
		return FALSE;
}

int _bt_get_local_address(void)
{
	int result;

	BT_DBG("+");

	result =  adapter_get_address();
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_address failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

int _bt_get_local_version(void)
{
	int result;
	BT_DBG("+");

	result =  adapter_get_version();
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_address failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

int _bt_get_local_name(void)
{
	int result;

	BT_DBG("+");

	result =  adapter_get_name();
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_name failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

int _bt_set_local_name(char *local_name)
{
	int result = BLUETOOTH_ERROR_NONE;
	BT_DBG("+");

	retv_if(NULL == local_name, BLUETOOTH_ERROR_INVALID_PARAM);

	result =  adapter_set_name(local_name);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_set_name failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

int _bt_get_discoverable_mode(int *mode)
{
	int scan_mode = 0;
	int timeout = 0;

	BT_DBG("+");

	retv_if(NULL == mode, BLUETOOTH_ERROR_INVALID_PARAM);

	adapter_is_discoverable(&scan_mode);
	if (TRUE == scan_mode) {
		adapter_get_discoverable_timeout(&timeout);
		if (timeout > 0)
			*mode = BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
		else
			*mode = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
	} else {
		adapter_is_connectable(&scan_mode);
		if(scan_mode == TRUE)
			*mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		else {
			/*
			 * TODO: NON CONNECTABLE is not defined in bluetooth_discoverable_mode_t.
			 * After adding BLUETOOTH_DISCOVERABLE_MODE_NON_CONNECTABLE, set mode as
			 * BLUETOOTH_DISCOVERABLE_MODE_NON_CONNECTABLE. Until then return -1.
			 */
			return -1;
		}
	}

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_timeout_value(int *timeout)
{
	time_t current_time;
	int time_diff;

	/* Take current time */
	time(&current_time);
	time_diff = difftime(current_time, visible_timer.start_time);

	BT_DBG("Time diff = %d\n", time_diff);
	*timeout = visible_timer.timeout - time_diff;

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_visibility_alarm_remove()
{
	if (visible_timer.event_id > 0) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
	}

	if (visible_timer.alarm_id > 0) {
		alarmmgr_remove_alarm(visible_timer.alarm_id);
		visible_timer.alarm_id = 0;
	}
}

static int __bt_visibility_alarm_cb(alarm_id_t alarm_id, void* user_param)
{
	int result = BLUETOOTH_ERROR_NONE;
	int timeout = 0;

	BT_DBG("__bt_visibility_alarm_cb - alram id = [%d] \n", alarm_id);

	if (alarm_id != visible_timer.alarm_id)
		return 0;

	if (visible_timer.event_id) {
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_CHANGED,
				g_variant_new("(in)", result, timeout));
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
		visible_timer.timeout = 0;

#ifndef TIZEN_WEARABLE
		if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			BT_ERR("Set vconf failed\n");
#endif
	}
	/* Switch Off visibility in Bluez */
	_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
	visible_timer.alarm_id = 0;
	return 0;
}

static gboolean __bt_timeout_handler(gpointer user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	time_t current_time;
	int time_diff;

	/* Take current time */
	time(&current_time);
	time_diff = difftime(current_time, visible_timer.start_time);

	/* Send event to application */
	_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_CHANGED,
			g_variant_new("(in)", result, time_diff));

	if (visible_timer.timeout <= time_diff) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
		visible_timer.timeout = 0;

#ifndef TIZEN_WEARABLE
		if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			BT_ERR("Set vconf failed\n");
#endif
		return FALSE;
	}

	return TRUE;
}

static void __bt_visibility_alarm_create()
{
	alarm_id_t alarm_id;
	int result;

	result = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, visible_timer.timeout,
			0, NULL, &alarm_id);
	if (result < 0) {
		BT_ERR("Failed to create alarm error = %d\n", result);
	} else {
		BT_DBG("Alarm created = %d\n", alarm_id);
		visible_timer.alarm_id = alarm_id;
	}
}

static int __bt_set_visible_time(int timeout)
{
	int result;

	__bt_visibility_alarm_remove();

	visible_timer.timeout = timeout;

#ifndef TIZEN_WEARABLE
#ifdef TIZEN_DPM_ENABLE
	if (_bt_dpm_get_bluetooth_limited_discoverable_state() != DPM_RESTRICTED) {
#endif
		if (vconf_set_int(BT_FILE_VISIBLE_TIME, timeout) != 0)
			BT_ERR("Set vconf failed");
#ifdef TIZEN_DPM_ENABLE
	}
#endif
#endif

	if (timeout <= 0)
		return BLUETOOTH_ERROR_NONE;

	if (!visible_timer.alarm_init) {
		/* Set Alarm timer to switch off BT */
		result = alarmmgr_init("bt-service");
		if (result != 0)
			return BLUETOOTH_ERROR_INTERNAL;

		visible_timer.alarm_init = TRUE;
	}

	result = alarmmgr_set_cb(__bt_visibility_alarm_cb, NULL);
	if (result != 0)
		return BLUETOOTH_ERROR_INTERNAL;

	/* Take start time */
	time(&(visible_timer.start_time));
	visible_timer.event_id = g_timeout_add_seconds(1,
			__bt_timeout_handler, NULL);

	__bt_visibility_alarm_create();

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_discoverable_mode(int discoverable_mode, int timeout)
{
	int result;

	BT_DBG("+");

	BT_INFO("discoverable_mode: %d, timeout: %d", discoverable_mode, timeout);

#ifdef TIZEN_DPM_ENABLE
	if (discoverable_mode != BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE &&
			_bt_dpm_get_bluetooth_limited_discoverable_state() == DPM_RESTRICTED) {
		_bt_launch_dpm_popup("DPM_POLICY_DISABLE_BT_HANDSFREE");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}
	if (discoverable_mode != BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE &&
			_bt_dpm_get_bluetooth_limited_discoverable_state() == DPM_RESTRICTED) {
		_bt_launch_dpm_popup("DPM_POLICY_DISABLE_BT");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}
#endif

	switch (discoverable_mode) {
	case BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE:
		result = adapter_set_connectable(TRUE);
		timeout = 0;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE:
		result = adapter_set_discoverable();
		timeout = 0;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE:
		result = adapter_set_discoverable();
		break;
	default:
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("set scan mode failed %d", result);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	result = adapter_set_discoverable_timeout(timeout);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_set_discoverable_timeout failed %d", result);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (discoverable_mode == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE)
		timeout = -1;

	result = __bt_set_visible_time(timeout);

	BT_DBG("-");
	return result;
}

gboolean _bt_is_connectable(void)
{
	int connectable = 0;
	int result;

	BT_DBG("+");

	adapter_is_connectable(&connectable);
	if (connectable)
		result = TRUE;
	else
		result = FALSE;

	BT_DBG("Connectable: [%s]", result ? "TRUE":"FALSE");
	BT_DBG("-");
	return result;
}

int _bt_set_connectable(gboolean connectable)
{
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");
	result =  adapter_set_connectable(connectable);
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_address failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

int _bt_is_service_used(void)
{
	int result;

	BT_DBG("+");

	result =  adapter_get_service_uuids();
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_service_uuids failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		result = BLUETOOTH_ERROR_NONE;
	}

	BT_DBG("-");
	return result;
}

int _bt_adapter_get_bonded_devices(void)
{
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");
	result =  adapter_get_bonded_devices();
	if (result != OAL_STATUS_SUCCESS) {
		BT_ERR("adapter_get_bonded_devices failed: %d", result);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else
		result = BLUETOOTH_ERROR_NONE;

	BT_DBG("-");
	return result;
}

static void __bt_adapter_event_handler(int event_type, gpointer event_data)
{
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");

	switch(event_type) {
	case OAL_EVENT_OAL_INITIALISED_SUCCESS:
	case OAL_EVENT_OAL_INITIALISED_FAILED:
		__bt_handle_oal_initialisation(event_type);
		break;
	case OAL_EVENT_ADAPTER_ENABLED:
		__bt_adapter_state_change_callback(BT_ACTIVATED);
		break;
	case OAL_EVENT_ADAPTER_DISABLED:
		__bt_adapter_state_change_callback(BT_DEACTIVATED);
		break;
	case OAL_EVENT_ADAPTER_INQUIRY_STARTED:
		__bt_adapter_discovery_state_change_callback(ADAPTER_DISCOVERY_STARTED);
		break;
	case OAL_EVENT_ADAPTER_INQUIRY_FINISHED:
		__bt_adapter_discovery_state_change_callback(ADAPTER_DISCOVERY_STOPPED);
		break;
	case OAL_EVENT_ADAPTER_PROPERTY_ADDRESS: {
		bt_address_t *bd_addr = event_data;
		bluetooth_device_address_t local_address;

		/* Copy data */
		memcpy(local_address.addr, bd_addr->addr, BT_ADDRESS_LENGTH_MAX);
		BT_DBG("Adapter address: [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]",
				local_address.addr[0], local_address.addr[1], local_address.addr[2],
				local_address.addr[3], local_address.addr[4], local_address.addr[5]);

		__bt_adapter_handle_pending_requests(BT_GET_LOCAL_ADDRESS,
				(void *) &local_address, sizeof(bluetooth_device_address_t));
		break;
	}
	case OAL_EVENT_ADAPTER_PROPERTY_NAME: {
		char *name = event_data;
		BT_DBG("Adapter Name: %s", name);

		if (__bt_is_service_request_present(BT_GET_LOCAL_NAME)) {
			bluetooth_device_name_t local_name;

			memset(&local_name, 0x00, sizeof(bluetooth_device_name_t));
			g_strlcpy(local_name.name,
				(const gchar *)name, BLUETOOTH_DEVICE_NAME_LENGTH_MAX);
			__bt_adapter_handle_pending_requests(BT_GET_LOCAL_NAME,
				(void *) &local_name, sizeof(bluetooth_device_name_t));
		} else {
			/* Send event to application */
			_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_LOCAL_NAME_CHANGED,
					g_variant_new("(is)", result, name));
		}
		break;
	}
	case OAL_EVENT_ADAPTER_PROPERTY_VERSION: {
		char *ver = event_data;
		bluetooth_version_t local_version;

		memset(&local_version, 0x00, sizeof(bluetooth_version_t));
		g_strlcpy(local_version.version,
				(const gchar *)ver, BLUETOOTH_VERSION_LENGTH_MAX);
		BT_DBG("BT Version: %s", local_version.version);

		__bt_adapter_handle_pending_requests(BT_GET_LOCAL_VERSION,
				(void *) &local_version, sizeof(bluetooth_version_t));
		break;
	}
	case OAL_EVENT_ADAPTER_MODE_NON_CONNECTABLE: {
		int mode = -1;
		gboolean connectable = FALSE;

		BT_INFO("Adapter discoverable mode:"
				" BLUETOOTH_DISCOVERABLE_MODE_NON_CONNECTABLE");
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_CONNECTABLE_CHANGED,
				g_variant_new("(b)", connectable));

		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				g_variant_new("(in)", result, mode));
		break;
	}
	case OAL_EVENT_ADAPTER_MODE_CONNECTABLE: {
		int mode;
		gboolean connectable = TRUE;

		BT_INFO("Adapter discoverable mode:"
				" BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE");
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_CONNECTABLE_CHANGED,
				g_variant_new("(b)", connectable));

		mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				g_variant_new("(in)", result, mode));
		break;
	}
	case OAL_EVENT_ADAPTER_MODE_DISCOVERABLE: {
		int mode;

		BT_INFO("Adapter discoverable mode:"
				" BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE");

		/* Send event to application */
		mode = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				g_variant_new("(in)", result, mode));

		break;
	}
	case OAL_EVENT_ADAPTER_MODE_DISCOVERABLE_TIMEOUT: {
		int *timeout = event_data;
		int mode;

		BT_INFO("Discoverable timeout: [%d]", *timeout);

		/* Send event to application */
		_bt_get_discoverable_mode(&mode);
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				g_variant_new("(in)", result, mode));
		break;
	}
	case OAL_EVENT_ADAPTER_PROPERTY_SERVICES: {
		int count;
		service_uuid_t *service_list;
		event_adapter_services_t *list = event_data;

		count = list->num;
		service_list = list->service_list;
		__bt_adapter_handle_pending_requests(BT_IS_SERVICE_USED, service_list, count);
		break;
	}
	case OAL_EVENT_ADAPTER_BONDED_DEVICE_LIST: {
		int i;
		int count;
		bluetooth_device_address_t *addr_list;

		event_device_list_t *bonded_device_list = event_data;
		count = bonded_device_list->num;

		addr_list = g_malloc0(count * sizeof(bluetooth_device_address_t));
		for (i = 0; i < count; i++) {
			memcpy(addr_list[i].addr,
					bonded_device_list->devices[i].addr,
					BLUETOOTH_ADDRESS_LENGTH);
		}

		__bt_adapter_handle_pending_requests(BT_GET_BONDED_DEVICES,
				(void *)addr_list, bonded_device_list->num);
		break;
	}
	default:
		BT_ERR("Unhandled event..");
		break;
	}

	BT_DBG("-");
}

static int __bt_init_profiles()
{
	int ret;

	/*TODO: Init bluetooth profiles */
	ret = _bt_hidhost_initialize();
	if (ret != BLUETOOTH_ERROR_NONE) {
		BT_ERR("_bt_hidhost_initialize Failed");
		return ret;
	}

	return BLUETOOTH_ERROR_NONE;
}

/* OAL post initialization handler */
static void __bt_post_oal_init(void)
{
	int ret;

	BT_DBG("OAL initialized, Init profiles..");
	ret = __bt_init_profiles();
	if (ret != BLUETOOTH_ERROR_NONE)
		BT_ERR("Bluetooth profile init error: %d", ret);

	return;
}

/* OAL initialization handler */
static void __bt_handle_oal_initialisation(oal_event_t event)
{
	BT_DBG("");

	switch(event) {
	case OAL_EVENT_OAL_INITIALISED_SUCCESS:
		__bt_post_oal_init();
		break;
	case OAL_EVENT_OAL_INITIALISED_FAILED:
		BT_ERR("OAL Initialisation Failed, terminate bt-service daemon..");
		g_idle_add(_bt_terminate_service, NULL);
		break;
	default:
		BT_ERR("Unknown Event");
		break;
	}
}

static gboolean __bt_is_service_request_present(int service_function)
{
	GSList *l;
	invocation_info_t *req_info;

	BT_DBG("+");

	/* Get method invocation context */
	for (l = _bt_get_invocation_list(); l != NULL; l = g_slist_next(l)) {
		req_info = l->data;
		if (req_info && req_info->service_function == service_function)
			return TRUE;
	}

	BT_DBG("-");
	return FALSE;
}

/* Internal functions of core adapter service */
static void __bt_adapter_handle_pending_requests(int service_function, void *user_data, unsigned int size)
{
	GSList *l;
	GArray *out_param;
	invocation_info_t *req_info;
	BT_INFO("+");

	/* Get method invocation context */
	for (l = _bt_get_invocation_list(); l != NULL; l = g_slist_next(l)) {
		req_info = l->data;
		if (req_info == NULL || req_info->service_function != service_function)
			continue;

		/* Create out param */
		out_param = g_array_new(FALSE, FALSE, sizeof(gchar));

		switch(service_function) {
		case BT_ENABLE_ADAPTER:
		case BT_DISABLE_ADAPTER: {
			gboolean done = TRUE;
			g_array_append_vals(out_param, &done, sizeof(gboolean));
			break;
		}
		case BT_GET_LOCAL_NAME:
		case BT_GET_LOCAL_ADDRESS:
		case BT_GET_LOCAL_VERSION:
			g_array_append_vals(out_param, user_data, size);
			break;
		case BT_IS_SERVICE_USED: {
			int i;
			gboolean used = FALSE;
			unsigned char *uuid;
			char uuid_str[BT_UUID_STRING_SIZE];
			char *request_uuid = req_info->user_data;
			service_uuid_t *service_list = user_data;

			BT_INFO("Check for service uuid: %s", request_uuid);
			for (i = 0; i < size; i++) {
				uuid = service_list[i].uuid;
				_bt_service_convert_uuid_type_to_string(uuid_str, uuid);
				BT_INFO("Adapter Service: [%s]", uuid_str);
				if (strcasecmp(uuid_str, request_uuid) == 0) {
					BT_INFO("UUID matched!!");
					used = TRUE;
					break;
				}
			}

			g_array_append_vals(out_param, &used, sizeof(gboolean));
			break;
		}
		case BT_GET_BONDED_DEVICES: {
			bluetooth_device_address_t *addr_list = user_data;
			bonded_devices_req_info_t *bonded_devices_req_info;
			char address[BT_ADDRESS_STRING_SIZE];
			int count = size;
			int res = BLUETOOTH_ERROR_NONE;

			/*
			 * BT_GET_BONDED_DEVICES is already processed for this request,
			 * continue for next BT_GET_BONDED_DEVICES request if any
			 */
			if (NULL != req_info->user_data)
				continue;

			BT_DBG("BT_GET_BONDED_DEVICES: count = [%d]", count);
			/* No bonded devices, return method invocation */
			if (0 == count || !addr_list)
				break;

			/* Save address list in user data  for futur reference. */
			bonded_devices_req_info = g_malloc0(sizeof(bonded_devices_req_info));
			if (!bonded_devices_req_info) {
				BT_ERR("Memory allocation failed");
				req_info->result = BLUETOOTH_ERROR_MEMORY_ALLOCATION;
				g_free(addr_list);
				break;
			}

			bonded_devices_req_info->count = count;
			bonded_devices_req_info->addr_list = addr_list;
			bonded_devices_req_info->out_param = out_param;
			req_info->user_data = bonded_devices_req_info;

			while (bonded_devices_req_info->count > 0) {
				bonded_devices_req_info->count -= 1;
				res = _bt_device_get_bonded_device_info(
						&addr_list[bonded_devices_req_info->count]);
				if (BLUETOOTH_ERROR_NONE == res)
					return;
				else {
					_bt_convert_addr_type_to_string((char *)address,
							addr_list[bonded_devices_req_info->count].addr);
					BT_ERR("_bt_device_get_bonded_device_info Failed for [%s]", address);
					if (bonded_devices_req_info->count == 0) {
						g_free(bonded_devices_req_info->addr_list);
						g_free(bonded_devices_req_info);
						req_info->user_data = NULL;
					}
				}
			}
			break;
		}
		default:
			BT_ERR("Unknown service function[%d]", service_function);
		}

		_bt_service_method_return(req_info->context, out_param, req_info->result);
		g_array_free(out_param, TRUE);
		/* Now free invocation info for this request*/
		_bt_free_info_from_invocation_list(req_info);
	}
}

/* Request return handlings */
static gboolean __bt_adapter_post_set_enabled(gpointer user_data)
{
	BT_INFO("__bt_adapter_post_set_enabled>>");
	/*TODO Get All properties */
	/* Add Adapter enabled post processing codes */
	return FALSE;
}

static gboolean __bt_adapter_post_set_disabled(gpointer user_data)
{
	BT_INFO("_bt_adapter_post_set_disabled>>");
	/* Add Adapter disabled post processing codes */
	return FALSE;
}

static void __bt_adapter_update_bt_enabled(void)
{
	int result = BLUETOOTH_ERROR_NONE;
	BT_INFO("_bt_adapter_update_bt_enabled>>");
	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_ON) != 0)
		BT_ERR("Set vconf failed\n");

	/* TODO:Add timer function to handle any further post processing */
	g_idle_add((GSourceFunc)__bt_adapter_post_set_enabled, NULL);

	/*Return BT_ADAPTER_ENABLE Method invocation context */
	__bt_adapter_handle_pending_requests(BT_ENABLE_ADAPTER, NULL, 0);
	/*Send BT Enabled event to application */
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_ENABLED,
			g_variant_new("(i)", result));
}

static void __bt_adapter_update_bt_disabled(void)
{
	int result = BLUETOOTH_ERROR_NONE;
	BT_INFO("_bt_adapter_update_bt_disabled>>");

	int power_off_status = 0;
	int ret;

	/* Update the vconf BT status in normal Deactivation case only */
	ret = vconf_get_int(VCONFKEY_SYSMAN_POWER_OFF_STATUS, &power_off_status);
	BT_DBG("ret : %d, power_off_status : %d", ret, power_off_status);

	/* TODO:Add timer function to handle any further post processing */
	g_idle_add((GSourceFunc)__bt_adapter_post_set_disabled, NULL);

	/* Return BT_ADAPTER_DISABLE Method invocation context */
	__bt_adapter_handle_pending_requests(BT_DISABLE_ADAPTER, NULL, 0);

	/* Send BT Disabled event to application */
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_DISABLED,
			g_variant_new("(i)", result));
}


static void __bt_adapter_state_set_status(bt_status_t status)
{
        BT_INFO("adapter_status changed [%d] -> [%d]", adapter_state, status);
        adapter_state = status;
}

static void __bt_adapter_update_discovery_status(bt_adapter_discovery_state_t status)
{
        BT_INFO("adapter_discovery_status changed [%d] -> [%d]", adapter_discovery_state, status);
        adapter_discovery_state = status;
}

static void __bt_adapter_state_change_callback(int bt_status)
{
	BT_INFO("__bt_adapter_state_change_callback: status [%d]", bt_status);

	switch (bt_status) {
	case BT_DEACTIVATED:
		__bt_adapter_state_set_status(bt_status);

		/* Adapter is disabled, unregister event handlers */
		_bt_service_unregister_event_handler_callback(BT_ADAPTER_MODULE);
		//_bt_deinit_device_event_handler();

		/* Add Adapter disabled post processing codes */
		__bt_adapter_update_bt_disabled();
		break;
	case BT_ACTIVATED:
		__bt_adapter_state_set_status(bt_status);
		/* Add Adapter enabled post processing codes */
		if (timer_id > 0) {
			BT_DBG("g_source is removed");
			g_source_remove(timer_id);
			timer_id = 0;
		}
		__bt_adapter_update_bt_enabled();
		break;
	default:
		BT_ERR("Incorrect Bluetooth adapter state changed status");

	}
}

static int __bt_adapter_state_handle_request(gboolean enable)
{
	int result = BLUETOOTH_ERROR_NONE;
	BT_DBG("");

	switch (adapter_state) {
	case BT_ACTIVATING:
	{
		BT_INFO("Adapter is currently in activating state, state [%d]",
				adapter_state);
		if (enable) {
			return BLUETOOTH_ERROR_IN_PROGRESS;
		} else {
			if (adapter_discovery_state == ADAPTER_DISCOVERY_STARTED ||
					adapter_discovery_state == ADAPTER_DISCOVERY_STARTING) {
				/*TODO Stop Discovery*/
				if (result != OAL_STATUS_SUCCESS)
					BT_ERR("Discover stop failed: %d", result);
				__bt_adapter_update_discovery_status(FALSE);
			}
			result = adapter_disable();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("adapter_enable failed: [%d]", result);
				result = BLUETOOTH_ERROR_INTERNAL;
				/*TODO: perform if anything more needs to be done to handle failure */
			} else {
				/* TODO: To be handled */
				__bt_adapter_state_set_status(BT_DEACTIVATING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case BT_ACTIVATED:
	{
		BT_INFO("Adapter is currently in activated state, state [%d]",
				adapter_state);
		if (enable) {
			return BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
		} else {
			if (adapter_discovery_state == ADAPTER_DISCOVERY_STARTED ||
					adapter_discovery_state == ADAPTER_DISCOVERY_STARTING) {
				/*TODO Stop Discovery*/
				if (result != OAL_STATUS_SUCCESS)
					BT_ERR("Discover stop failed: %d", result);
				__bt_adapter_update_discovery_status(FALSE);
			}
			result = adapter_disable();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("adapter_enable failed: [%d]", result);
				result = BLUETOOTH_ERROR_INTERNAL;
				/*TODO: perform if anything more needs to be done to handle failure */
			} else {
				/* TODO: To be handled */
				__bt_adapter_state_set_status(BT_DEACTIVATING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case BT_DEACTIVATING:
	{
		BT_INFO("Adapter is currently in deactivating state, state [%d]",
				adapter_state);
		if (!enable) {
			return BLUETOOTH_ERROR_IN_PROGRESS;

		} else {
			result = adapter_enable();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("adapter_enable failed: [%d]", result);
				adapter_disable();
				result = BLUETOOTH_ERROR_INTERNAL;
				/*TODO: perform if anything more needs to be done to handle failure */
			} else {
				/* TODO: To be handled */
				__bt_adapter_state_set_status(BT_ACTIVATING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case BT_DEACTIVATED:
	{
		BT_INFO("Adapter is currently in deactivated state, state [%d]",
				adapter_state);
		if (!enable) {
			return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
		} else {
			result = adapter_enable();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("adapter_enable failed: [%d]", result);
				adapter_disable();
				result = BLUETOOTH_ERROR_INTERNAL;
				/*TODO: perform if anything more needs to be done to handle failure */
			} else {
				/* TODO: To be handled */
				__bt_adapter_state_set_status(BT_ACTIVATING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	}
	if (enable && result == BLUETOOTH_ERROR_NONE) {
		/* Adapter enable request is successful, setup event handlers */
		_bt_service_register_event_handler_callback(
				BT_ADAPTER_MODULE, __bt_adapter_event_handler);
		_bt_device_state_handle_callback_set_request();
	}
	return result;
}

static int __bt_adapter_state_discovery_request(gboolean enable)
{
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");
	switch (adapter_discovery_state) {
	case ADAPTER_DISCOVERY_STARTED: {
		BT_INFO("Adapter is currently in discovery started state, state [%d]",
				adapter_discovery_state);
		if (enable) {
			return BLUETOOTH_ERROR_IN_PROGRESS;
		} else {
			result = adapter_stop_inquiry();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("Discover stop failed: %d", result);
				result = BLUETOOTH_ERROR_INTERNAL;
			} else {
				BT_ERR("Stop Discovery Triggered successfully");
				__bt_adapter_update_discovery_status(ADAPTER_DISCOVERY_STOPPING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case ADAPTER_DISCOVERY_STARTING: {
		BT_INFO("Adapter is currently in discovery starting state, state [%d]",
				adapter_discovery_state);
		if (enable) {
			return BLUETOOTH_ERROR_IN_PROGRESS;
		} else {
			result = adapter_stop_inquiry();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("Discover stop failed: %d", result);
				result = BLUETOOTH_ERROR_INTERNAL;
			} else {
				BT_ERR("Stop Discovery Triggered successfully");
				__bt_adapter_update_discovery_status(ADAPTER_DISCOVERY_STOPPING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case ADAPTER_DISCOVERY_STOPPED: {
		BT_INFO("Adapter is currently in discovery stopped state, state [%d]",
				adapter_discovery_state);
		if (!enable)
			return BLUETOOTH_ERROR_NOT_IN_OPERATION;
		else {
			result = adapter_start_inquiry();
		if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("Start Discovery failed: %d", result);
				result = BLUETOOTH_ERROR_INTERNAL;
			} else {
				BT_ERR("Start Discovery Triggered successfully");
			__bt_adapter_update_discovery_status(ADAPTER_DISCOVERY_STARTING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	case ADAPTER_DISCOVERY_STOPPING: {
		BT_INFO("Adapter is currently in discovery stopping state, state [%d]",
				adapter_discovery_state);
		if (!enable)
			return BLUETOOTH_ERROR_NOT_IN_OPERATION;
		else {
			result = adapter_start_inquiry();
			if (result != OAL_STATUS_SUCCESS) {
				BT_ERR("Start Discovery failed: %d", result);
				result = BLUETOOTH_ERROR_INTERNAL;
			} else {
				BT_ERR("Start Discovery Triggered successfully");
			__bt_adapter_update_discovery_status(ADAPTER_DISCOVERY_STARTING);
				result = BLUETOOTH_ERROR_NONE;
			}
		}
		break;
	}
	}

	BT_DBG("-");
	return result;
}

static void __bt_adapter_discovery_state_change_callback(int bt_discovery_status)
{
	BT_INFO("__bt_adapter_discovery_state_change_callback: status [%d]", bt_discovery_status);
	GVariant *param = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	switch (bt_discovery_status) {
	case ADAPTER_DISCOVERY_STOPPED:
	{
		__bt_adapter_update_discovery_status(bt_discovery_status);
		param = g_variant_new("(i)", result);
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERY_FINISHED,
				param);
		break;
	}
	case ADAPTER_DISCOVERY_STARTED:
	{
		__bt_adapter_update_discovery_status(bt_discovery_status);
		param = g_variant_new("(i)", result);
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERY_STARTED,
				param);
		break;
	}
	default:
		BT_ERR("Incorrect Bluetooth adapter Discovery state changed status");
	}
}

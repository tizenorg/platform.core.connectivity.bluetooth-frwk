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
#include "bt-service-core-adapter.h"
#include "bt-service-event-receiver.h"
#include "bt-request-handler.h"
#include "bt-service-event.h"

/* OAL headers */
#include <oal-event.h>
#include <oal-manager.h>
#include <oal-adapter-mgr.h>

#define BT_ENABLE_TIMEOUT 20000 /* 20 seconds */

/*This file will contain state machines related to adapter and remote device */

/* Global variables */
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

static void __bt_adapter_event_handler(int event_type, gpointer event_data)
{
        BT_DBG("");

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
	default:
		BT_ERR("Unhandled event..");
		break;
	}
}

/* OAL post initialization handler */
static void __bt_post_oal_init(void)
{
	BT_DBG("OAL initialized, Init profiles..");
	/*TODO */
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
			case BT_DISABLE_ADAPTER:
			{
				gboolean done = TRUE;
				g_array_append_vals(out_param, &done, sizeof(gboolean));
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
		/*TODO Set Device Core Callbacks*/
	}
	return result;
}


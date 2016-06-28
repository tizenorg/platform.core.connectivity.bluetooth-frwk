/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <sys/wait.h>

#include <bluetooth.h>

#include "oal-event.h"
#include "oal-internal.h"
#include "oal-manager.h"
#include "oal-hardware.h"

#define CHECK_MAX(max, x) (((max) > (x)) ? (x) : (max))

static const bt_interface_t * blued_api;

/* Forward declarations */
const char * status2string(bt_status_t status);
oal_status_t convert_to_oal_status(bt_status_t status);
void parse_device_properties(int num_properties, bt_property_t *properties,
		remote_device_t *dev_info, ble_adv_data_t * adv_info);
static gboolean retry_enable_adapter(gpointer data);
oal_status_t oal_mgr_init_internal(void);


/* Callback registered with Stack */
static void cb_adapter_state_change(bt_state_t status);

static bt_callbacks_t callbacks = {
	sizeof(callbacks),
	cb_adapter_state_change,
	NULL, /* adapter_properties_callback */
	NULL, /* remote_device_properties_callback */
	NULL, /* device_found_callback */
	NULL, /* discovery_state_changed_callback */
	NULL, /* pin_request_callback */
	NULL, /* ssp_request_callback */
	NULL, /* bond_state_changed_callback */
	NULL, /* acl_state_changed_callback */
	NULL, /* callback_thread_event */
	NULL, /* dut_mode_recv_callback */
	NULL, /* le_test_mode_callback*/
	NULL, /* energy_info_callback */
};

oal_status_t adapter_mgr_init(const bt_interface_t * stack_if)
{
	int ret;
	blued_api = stack_if;

	ret = blued_api->init(&callbacks);

	if(ret != BT_STATUS_SUCCESS) {
		BT_ERR("Adapter callback registration failed: [%s]", status2string(ret));
		blued_api->cleanup();
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

const bt_interface_t* adapter_get_stack_interface(void)
{
	return blued_api;
}

void adapter_mgr_cleanup(void)
{
	/* Nothing to clean yet , do not set blued_api NULL as it will be used to clean Bluedroid states */
	BT_DBG();
}

oal_status_t adapter_enable(void)
{
	int ret = BT_STATUS_SUCCESS;

	API_TRACE();
	CHECK_OAL_INITIALIZED();
	if (OAL_STATUS_SUCCESS != hw_is_module_ready()) {
		g_timeout_add(200, retry_enable_adapter, NULL);
		return OAL_STATUS_PENDING;
	}

	ret = blued_api->enable();

	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("Enable failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}

	return OAL_STATUS_SUCCESS;
}

oal_status_t adapter_disable(void)
{
	int ret;

	API_TRACE();

	CHECK_OAL_INITIALIZED();

	ret = blued_api->disable();

	if (ret != BT_STATUS_SUCCESS) {
		BT_ERR("Disable failed: [%s]", status2string(ret));
		return convert_to_oal_status(ret);
	}
	return OAL_STATUS_SUCCESS;
}

/* Callbacks from Stack */
static void cb_adapter_state_change(bt_state_t status)
{
	BT_DBG("+");
	oal_event_t event;

	event = (BT_STATE_ON == status)?OAL_EVENT_ADAPTER_ENABLED:OAL_EVENT_ADAPTER_DISABLED;

	send_event(event, NULL);
}

static gboolean retry_enable_adapter(gpointer data)
{
	adapter_enable();
	return FALSE;
}


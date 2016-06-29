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

/* Forward declarations */
static void __bt_adapter_event_handler(int event_type, gpointer event_data);
static void __bt_post_oal_init(void);
static void __bt_handle_oal_initialisation(oal_event_t event);

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

static void __bt_adapter_event_handler(int event_type, gpointer event_data)
{
        BT_DBG("");

        switch(event_type) {
        case OAL_EVENT_OAL_INITIALISED_SUCCESS:
        case OAL_EVENT_OAL_INITIALISED_FAILED:
                __bt_handle_oal_initialisation(event_type);
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

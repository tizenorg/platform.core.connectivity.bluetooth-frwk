/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
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

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <syspopup_caller.h>
#include <vconf.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <eventsystem.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <vconf.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

/* BT HAL Headers */
#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-internal.h"
#include "bt-hal-event-receiver.h"
#include "bt-hal-dbus-common-utils.h"

#include "bt-hal-adapter-dbus-handler.h"
#include "bt-hal-event-receiver.h"

#include <bt-hal-agent.h>
#include <bt-hal-gap-agent1.h>
#include <bt-hal-dbus-common-utils.h>

static void *adapter_agent = NULL;

void* _bt_hal_create_agent(const char *path, gboolean adapter)
{
	GAP_AGENT_FUNC_CB func_cb;
	GDBusProxy *adapter_proxy;
	GapAgentPrivate *agent;

	DBG("+");
	adapter_proxy = _bt_get_adapter_proxy();
	if (!adapter_proxy)
		return NULL;

	func_cb.pincode_func = NULL;
	func_cb.display_func = NULL;
	func_cb.passkey_func = NULL;
	func_cb.confirm_func = NULL;
	func_cb.authorize_func = NULL;
	func_cb.pairing_cancel_func = NULL;
	func_cb.authorization_cancel_func = NULL;

	/* Allocate memory*/
	agent = g_new0(GapAgentPrivate, 1);

	_gap_agent_setup_dbus(agent, &func_cb, path, adapter_proxy);

	if (adapter) {
		if (!_gap_agent_register(agent)) {
			ERR("gap agent registration failed!");
			_bt_hal_destroy_agent(agent);
			agent = NULL;
		}
	}
	DBG("-");
	return agent;
}

void _bt_hal_destroy_agent(void *agent)
{
	DBG("+");
	if (!agent)
		return;

	_gap_agent_reset_dbus((GapAgentPrivate *)agent);

	g_free(agent);
	DBG("-");
}

gboolean _bt_hal_agent_is_canceled(void)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return FALSE;

	return _gap_agent_is_canceled(agent);
}

int _bt_hal_agent_reply_cancellation(void)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return BT_STATUS_FAIL;
	/* TODO Handle GAP Agent Cancel */
	return BT_STATUS_SUCCESS;
}

void _bt_hal_agent_set_canceled(gboolean value)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return;

	return _gap_agent_set_canceled(agent, value);
}

void _bt_hal_initialize_adapter_agent(void)
{
	adapter_agent = _bt_hal_create_agent(BT_HAL_ADAPTER_AGENT_PATH, TRUE);
	if (!adapter_agent) {
		ERR("Fail to register agent");
		return;
	}
}

void _bt_hal_destroy_adapter_agent(void)
{
	if (adapter_agent)
		_bt_hal_destroy_agent(adapter_agent);
	adapter_agent = NULL;
}

void* _bt_hal_get_adapter_agent(void)
{
	return adapter_agent;
}

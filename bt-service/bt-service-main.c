/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#include <dbus/dbus-glib.h>
#include <glib.h>
#include <dlog.h>
#include <string.h>
#include <privilege-control.h>
#include <vconf.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-main.h"
#include "bt-service-util.h"
#include "bt-request-handler.h"
#include "bt-service-adapter.h"

static GMainLoop *main_loop;
static gboolean terminated;

static void __bt_release_service(void)
{
	_bt_deinit_service_event_sender();
	_bt_deinit_service_event_reciever();

	_bt_service_unregister();

	_bt_deinit_proxys();

	_bt_clear_request_list();

	BT_DBG("Terminating the bt-service daemon");
}

static void __bt_sigterm_handler(int signo)
{
	BT_DBG("Get the signal: %d", signo);

	_bt_terminate_service(NULL);
}

gboolean _bt_terminate_service(gpointer user_data)
{
	int value;

	if (vconf_get_int(BT_OFF_DUE_TO_FLIGHT_MODE, &value) != 0)
		BT_ERR("Fail to get the flight_mode_deactivated value");

	if (value == 1) {
		BT_DBG("Bt service not terminated");

		_bt_deinit_bluez_proxy();

		return FALSE;
	}

	if (main_loop != NULL) {
		g_main_loop_quit(main_loop);
	} else {
		BT_DBG("main_loop == NULL");
		__bt_release_service();
		terminated = TRUE;
		exit(0);
	}

	return FALSE;
}

static gboolean __bt_check_bt_service(void *data)
{
	int bt_status = VCONFKEY_BT_STATUS_OFF;
	int flight_mode_deactivation = 0;

	if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_status) < 0) {
		BT_DBG("no bluetooth device info, so BT was disabled at previous session");
	}

	if (vconf_get_int(BT_OFF_DUE_TO_FLIGHT_MODE, &flight_mode_deactivation) != 0)
			BT_ERR("Fail to get the flight_mode_deactivated value");

	if (bt_status != VCONFKEY_BT_STATUS_OFF) {
		BT_DBG("Previous session was enabled.");

		/* Enable the BT */
		_bt_enable_adapter();
	} else if (bt_status == VCONFKEY_BT_STATUS_OFF &&
					flight_mode_deactivation == 1) {
		_bt_handle_flight_mode_noti();
	} else {
		bt_status_t status = _bt_adapter_get_status();
		int adapter_enabled = 0;

		_bt_check_adapter(&adapter_enabled);

		BT_DBG("State: %d", status);
		BT_DBG("Adapter enabled: %d", adapter_enabled);

		if (adapter_enabled == 1) {
			_bt_handle_adapter_added();
			return FALSE;
		}

		if (status != BT_ACTIVATING && status != BT_ACTIVATED) {
			_bt_terminate_service(NULL);
		}
	}

	return FALSE;
}

int main(void)
{
	struct sigaction sa;
	BT_DBG("Starting the bt-service daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __bt_sigterm_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_type_init();

	if (set_app_privilege("bluetooth-frwk-service", NULL, NULL) !=
								PC_OPERATION_SUCCESS)
		BT_ERR("Failed to set app privilege.\n");

	/* Event reciever Init */
	if (_bt_init_service_event_receiver() != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to init event reciever");
		return 0;
	}

	/* Event sender Init */
	if (_bt_init_service_event_sender() != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to init event sender");
		return 0;
	}

	if (_bt_service_register() != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to register service");
		return 0;
	}

	_bt_init_request_id();

	_bt_init_request_list();

	g_idle_add((GSourceFunc)__bt_check_bt_service, NULL);

	if (terminated == TRUE) {
		__bt_release_service();
		return 0;
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	if (main_loop != NULL) {
		g_main_loop_unref(main_loop);
	}

	__bt_release_service();

	return 0;
}


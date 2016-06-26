/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <glib.h>
#include <dlog.h>
#include <string.h>

#include <bundle.h>
#include <eventsystem.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-request-handler.h"
#include "bt-service-event.h"
#include "bt-service-util.h"

static GMainLoop *main_loop;
static gboolean terminated = FALSE;

gboolean _bt_terminate_service(gpointer user_data)
{
	/* TODO*/
        return FALSE;
}

gboolean _bt_reliable_terminate_service(gpointer user_data)
{
	/* TODO*/
        return FALSE;
}

static gboolean __bt_check_bt_service(void *data)
{
	/* TODO*/
        return FALSE;
}

static void __bt_release_service(void)
{
	/* TODO*/
}

static void __bt_sigterm_handler(int signo, siginfo_t *info, void *data)
{
	/* TODO*/
}

static int __bt_service_load_hal_lib(void)
{
	int ret = BLUETOOTH_ERROR_NONE;
	BT_INFO("+");
	/* TODO: Pass oal event receiver handler */
	return  ret;
}

int main(void)
{
	struct sigaction sa;
	BT_INFO_C("Starting the bt-service daemon!!!");

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = __bt_sigterm_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Security Initialization */
	if (_bt_service_cynara_init() != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to init cynara");
		return EXIT_FAILURE;
	}

	/* Event sender Init */
        if (_bt_init_service_event_sender() != BLUETOOTH_ERROR_NONE) {
                BT_ERR("Fail to init event sender");
                return 0;
        }

        if (_bt_init_hf_local_term_event_sender() != BLUETOOTH_ERROR_NONE) {
                BT_ERR("Fail to init core event sender");
                return 0;
        }

        if (_bt_service_register() != BLUETOOTH_ERROR_NONE) {
                BT_ERR("Fail to register service");
                return 0;
        }

	_bt_init_request_id();

        _bt_init_request_list();

	/* BT HAL library Load */
	BT_ERR("Attempt to load BT HAL lib");
	if (__bt_service_load_hal_lib() != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to initialize BT HAL");
		return 0;
	}

	g_timeout_add(500, (GSourceFunc)__bt_check_bt_service, NULL);

        if (terminated == TRUE) {
                __bt_release_service();
                return 0;
        }

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);
	BT_DBG("g_main_loop_quit called!");

	if (main_loop != NULL) {
		g_main_loop_unref(main_loop);
	}

	if (terminated == FALSE)
		__bt_release_service();

	return 0;
}

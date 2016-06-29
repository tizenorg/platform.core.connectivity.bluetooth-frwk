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
#define _OAL_EVENT_DISPATCHER_C_

#include <stdio.h>
#include <glib.h>
#include <dlog.h>
#include <string.h>
#include <unistd.h>

#include "oal-hardware.h"
#include "oal-event.h"
#include "oal-utils.h"
#include "oal-manager.h"

#define EVENT_TRACE(fmt, args...) {LOG_(LOG_ID_SYSTEM, DLOG_INFO, "OAL_EVENT", GREEN(fmt), ##args); \
	LOG_(LOG_ID_MAIN, DLOG_INFO, LOG_TAG, GREEN("[OAL_EVENT]"fmt), ##args);}

typedef struct {
	int event;
	gpointer event_data;
} event_t;

static GMainContext *event_thread_context;
static oal_event_callback event_handler_cb;

static gpointer __event_handler_loop(gpointer user_data)
{
	gboolean ret = FALSE;
	GMainLoop *event_loop;

	/* Set up the thread�s context and run it forever. */
	g_main_context_push_thread_default (event_thread_context);

	event_loop = g_main_loop_new (event_thread_context, FALSE);
	do {
		ret = oal_lib_init(NULL);
		if(ret == FALSE)
			BT_WARN("oal_lib_init failed, trying again...");
	} while(ret == FALSE);

	g_main_loop_run (event_loop);
	g_main_loop_unref (event_loop);

	g_main_context_pop_thread_default (event_thread_context);
	g_main_context_unref (event_thread_context);

	return NULL;
}

static void event_data_free(event_t *event_info)
{
	if(event_info->event_data)
		g_free (event_info->event_data);
	g_slice_free (event_t, event_info);
}

/* Convert an idle callback into a call to dispatch_idle(). */
static gboolean dispatch_idle (gpointer user_data)
{
	event_t *event_info = user_data;
	BT_DBG("+");

	if (!event_handler_cb) {
		BT_ERR("Upstream handler not registered");
	} else
		(*event_handler_cb) (event_info->event, event_info->event_data);

	BT_DBG("-");
	return G_SOURCE_REMOVE;
}

static gboolean need_same_context(oal_event_t event)
{
	gboolean ret;

	switch(event) {
		default:
			ret = FALSE;
			break;
	}
	return ret;
}

void _bt_event_dispatcher_init(oal_event_callback cb)
{
	event_handler_cb = cb;
	BT_DBG("+");
	/* Spawn a background thread and pass it a reference to its
	 * GMainContext. Retain a reference for use in this thread
	 * too. */
	event_thread_context = g_main_context_new ();
	g_thread_new ("OALEventScheduler", __event_handler_loop, NULL);
}

void send_event_no_trace(oal_event_t event, gpointer event_data)
{
	event_t *event_info;

	/* Create a data closure to pass all the desired variables
	 * between threads. */
	event_info = g_slice_new0 (event_t);
	event_info->event = event;
	event_info->event_data = event_data;
	/* Invoke the function. */

	if (need_same_context(event)) {
		BT_INFO("Without context change");
		dispatch_idle(event_info);
		event_data_free(event_info);
	} else
		g_main_context_invoke_full (event_thread_context,
				G_PRIORITY_DEFAULT, dispatch_idle,
				event_info,
				(GDestroyNotify) event_data_free);
}

void send_event_bda_trace(oal_event_t event, gpointer event_data, bt_address_t *address)
{
	send_event_no_trace(event, event_data);
}

void send_event(oal_event_t event, gpointer event_data)
{
	send_event_bda_trace(event, event_data, NULL);
}
#undef _OAL_EVENT_DISPATCHER_C_

/*
 * bluetooth-frwk
 *
 * Copyright (c) 2013 Intel Corporation.
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

#include <libnotify/notify.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <bundle.h>
#include "bt-service-common.h"

#define BT_PIN_MLEN 	16	/* Pin key max length */
#define BT_PK_MLEN 	6	/* Passkey max length */
#define NOTIFY_ICON 	DATA_DIR_ICON"/icons/default/bt-icon.png"
#define BT_SUCCESS 	0
#define BT_FAILED 	1

typedef enum {
	BT_AGENT_ACCEPT,
	BT_AGENT_REJECT,
	BT_AGENT_CANCEL,
	BT_CORE_AGENT_TIMEOUT,
} bt_agent_accept_type_t;

struct bt_popup_appdata {
	DBusGProxy *agent_proxy;
	DBusGProxy *obex_proxy;
	GtkWidget *window;
	GtkWidget *entry;
};

int notify_launch(bundle *user_data);

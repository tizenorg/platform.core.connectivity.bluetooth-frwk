/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
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

#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "vertical.h"

#define BT_MAP_AGENT_NAME "org.bluez.map_agent"
#define BT_MAP_AGENT_INTERFACE "org.bluez.MapAgent"
#define BT_MAP_AGENT_OBJECT_PATH "/org/bluez/map_agent"

GDBusConnection *conn;
guint bus_id;

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
	"<node>"
	"</node>";

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");

	conn = connection;
}

static void name_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");
}

static void name_lost(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("Name Lost");

	bus_id = 0;
}

void bt_map_agent_init(void)
{
	DBG("");

	introspection_data =
		g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	if (conn == NULL)
		bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
			BT_MAP_AGENT_NAME,
			G_BUS_NAME_OWNER_FLAGS_NONE,
			bus_acquired,
			name_acquired,
			name_lost,
			NULL,
			NULL);
}

void bt_map_agent_deinit(void)
{
	DBG("");
}

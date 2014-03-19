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
#include "map_agent.h"
#include "bluetooth_map_agent.h"

#define BT_MAP_AGENT_NAME "org.bluez.map_agent"
#define BT_MAP_AGENT_INTERFACE "org.bluez.MapAgent"
#define BT_MAP_AGENT_OBJECT_PATH "/org/bluez/map_agent"

GDBusConnection *conn;
guint bus_id;
guint agent_registration_id;

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
"<node name='/'>"
" <interface name='org.bluez.MapAgent'>"
"  <method name='GetFolderTree'>"
"    <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='a(s)' name='folder_list' direction='out'/>"
"  </method>"
"  <method name='GetMessageList'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='s' name='folder_name'/>"
"    <arg type='q' name='max'/>"
"    <arg type='b' name='newmessage' direction='out'/>"
"    <arg type='t' name='count' direction='out'/>"
"    <arg type='a(ssssssssssbsbbbbs)' name='msg_list' direction='out'/>"
"  </method>"
"  <method name='GetMessage'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='s' name='messgae_name'/>"
"    <arg type='b' name='attach'/>"
"    <arg type='b' name='transcode'/>"
"    <arg type='b' name='first_request'/>"
"    <arg type='b' name='fraction_deliver' direction='out'/>"
"    <arg type='s' name='msg_body' direction='out'/>"
"  </method>"
"  <method name='PushMessage'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='b' name='save_copy'/>"
"    <arg type='b' name='retry_send'/>"
"    <arg type='b' name='native'/>"
"    <arg type='s' name='folder_name'/>"
"    <arg type='t' name='handle' direction='out'/>"
"  </method>"
"  <method name='PushMessageData'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='s' name='bmsg'/>"
"  </method>"
"  <method name='UpdateMessage'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='u' name='update_err' direction='out'/>"
"  </method>"
"  <method name='SetReadStatus'>"
"  <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"   <arg type='s' name='handle'/>"
"   <arg type='b' name='read_status'/>"
"   <arg type='u' name='update_err' direction='out'/>"
"  </method>"
"  <method name='SetDeleteStatus'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='s' name='handle'/>"
"    <arg type='b' name='delete_status'/>"
"    <arg type='u' name='update_err' direction='out'/>"
"  </method>"
"  <method name='NotiRegistration'>"
"   <annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"    <arg type='s' name='remote_addr'/>"
"    <arg type='b' name='status'/>"
"    <arg type='u' name='update_err' direction='out'/>"
"  </method>"
" </interface>"
"</node>";

static void handle_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "GetFolderTree") == 0)
		bluetooth_map_get_folder_tree(invocation);
	else if (g_strcmp0(method_name, "GetMessageList") == 0) {
		gchar *folder_name;
		guint16 max;

		g_variant_get(parameters, "(sq)",
					&folder_name, &max);
		bluetooth_map_get_message_list(folder_name,
					max, invocation);
	} else if (g_strcmp0(method_name, "GetMessage") == 0) {
		gchar *message_name;
		gboolean attach, transcode, first_request;

		g_variant_get(parameters, "(sbbb)", &message_name,
			&attach, &transcode, &first_request);
		bluetooth_map_get_message(message_name, attach,
			transcode, first_request, invocation);
	} else if (g_strcmp0(method_name, "PushMessage") == 0) {
		gboolean save_copy, retry_send, native;
		gchar *folder_name;

		g_variant_get(parameters, "(bbbs)", &save_copy,
			&retry_send, &native, &folder_name);
		bluetooth_map_push_message(save_copy, retry_send,
			native, folder_name, invocation);
	} else if (g_strcmp0(method_name, "PushMessageData") == 0) {
		gchar *bmsg;

		g_variant_get(parameters, "(s)", &bmsg);
		bluetooth_map_push_message_data(bmsg, invocation);
	} else if (g_strcmp0(method_name, "UpdateMessage") == 0) {
		bluetooth_map_update_message(invocation);
	} else if (g_strcmp0(method_name, "SetReadStatus") == 0) {
		gchar *handle;
		gboolean read_status;

		g_variant_get(parameters, "(sb)", &handle,
						&read_status);
		bluetooth_map_set_read_status(handle, read_status,
							invocation);
	} else if (g_strcmp0(method_name, "SetDeleteStatus") == 0) {
		gchar *handle;
		gboolean delete_status;

		g_variant_get(parameters, "(sb)", &handle,
						&delete_status);
		bluetooth_map_set_delete_status(handle, delete_status,
							invocation);
	} else if (g_strcmp0(method_name, "NotiRegistration") == 0) {
		gchar *remote_addr;
		gboolean status;

		g_variant_get(parameters, "(sb)", &remote_addr,
							&status);
		bluetooth_map_noti_registration(remote_addr, status,
							invocation);
	} else
		WARN("Unknown method");
}

static const GDBusInterfaceVTable interface_handle = {
	handle_method_call,
	NULL,
	NULL
};

static void register_agent_object(GDBusConnection *connection)
{

	agent_registration_id = g_dbus_connection_register_object(
				connection,
				BT_MAP_AGENT_OBJECT_PATH,
				introspection_data->
					interfaces[0],
				&interface_handle,
				NULL,
				NULL,
				NULL);

	g_assert(agent_registration_id > 0);
}

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");

	register_agent_object(connection);

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

	if (agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			connection,
			agent_registration_id);
		agent_registration_id = 0;
	}

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

	if (agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			conn,
			agent_registration_id);
		agent_registration_id = 0;
	}

	g_bus_unown_name(bus_id);

	g_dbus_node_info_unref(introspection_data);
	bus_id = 0;
}

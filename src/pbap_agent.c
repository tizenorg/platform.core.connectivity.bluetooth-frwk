/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Samsung Electronics Co., Ltd.
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

#ifdef TIZEN_2_MOBILE

#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "vertical.h"
#include "pbap_agent.h"
#include "bluetooth_pb_agent.h"

#define BT_PBAP_AGENT_NAME "org.bluez.pb_agent"
#define BT_PBAP_AGENT_OBJECT_PATH "/org/bluez/pb_agent"

GDBusConnection *conn;
guint bus_id;
guint pb_agent_registration_id;
guint pb_at_agent_registration_id;


static GDBusNodeInfo *pbap_introspection_data;

/*Below Inrospection data is exposed to bluez from agent*/
static const gchar pbap_introspection_xml[] =
"<node name='/'>"
"	<interface name='org.bluez.PbAgent'>"
"		<method name='GetPhonebookFolderList'>"
"			<arg type='as' name='folder_list' direction='out'/>"
"		</method>"
"		<method name='GetPhonebook'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='t' name='filter'/>"
"			<arg type='y' name='format'/>"
"			<arg type='q' name='max_list_count'/>"
"			<arg type='q' name='list_start_offset'/>"
"			<arg type='as' name='phonebook' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookSize'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookList'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='name'/>"
"			<arg type='a(ssu)' name='phonebook_list' direction='out'/>"
"			<arg type='u' name='new_missed_call' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntry'>"
"			<anno-tation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='folder'/>"
"			<arg type='s' name='id'/>"
"			<arg type='t' name='filter'/>"
"			<arg type='y' name='format'/>"
"			<arg type='s' name='phonebook_entry' direction='out'/>"
"		</method>"
"		<method name='GetTotalObjectCount'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='path'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"		</method>"
"		<method name='AddContact'>"
"			<arg type='s' name='filename'/>"
"		</method>"
"	</interface>"
"	<interface name='org.bluez.PbAgent.At'>"
"		<method name='GetPhonebookSizeAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='u' name='phonebook_size' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntriesAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='i' name='start_index'/>"
"			<arg type='i' name='end_index'/>"
"			<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
"		</method>"
"		<method name='GetPhonebookEntriesFindAt'>"
"			<annotation name='org.freedesktop.DBus.GLib.Async' value=''/>"
"			<arg type='s' name='command'/>"
"			<arg type='s' name='find_text'/>"
"			<arg type='a(ssu)' name='phonebook_entries' direction='out'/>"
"		</method>"
"	</interface>"
"</node>";

static void handle_pbap_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "GetPhonebookFolderList") == 0) {
		bluetooth_pb_get_phonebook_folder_list(invocation);
	} else if (g_strcmp0(method_name, "GetPhonebook") == 0) {
		gchar *name;
		guint64 filter;
		guint8 format;
		guint16 max_list_count;
		guint16 list_start_offset;

		g_variant_get(parameters, "styqq", &name, &filter, &format,
					&max_list_count, &list_start_offset);
		bluetooth_pb_get_phonebook(name, filter, format,
					max_list_count, list_start_offset, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookSize") == 0) {
		gchar *name;

		g_variant_get(parameters, "s", &name);
		bluetooth_pb_get_phonebook_size(name, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookList") == 0) {
		gchar *name;

		g_variant_get(parameters, "s", &name);
		bluetooth_pb_get_phonebook_list(name, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntry") == 0) {
		gchar *folder;
		gchar *id;
		guint64 filter;
		guint8 format;

		g_variant_get(parameters, "ssty", &folder, &id, &filter, &format);

		bluetooth_pb_get_phonebook_entry(folder, id, filter, format, invocation);
	} else if (g_strcmp0(method_name, "GetTotalObjectCount") == 0) {
		gchar *path;

		g_variant_get(parameters, "s", &path);
		bluetooth_pb_get_total_object_count(path, invocation);
	} else if (g_strcmp0(method_name, "AddContact") == 0) {
		gchar *filename;

		g_variant_get(parameters, "s", &filename);
		bluetooth_pb_add_contact(filename, invocation);
	} else if (g_strcmp0(method_name, "DestroyAgent") == 0) {
		DBG("DestroyAgent");
		/* TODO: */
	} else {
		DBG("Unknown Method");
	}
}

static void handle_pbap_at_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "GetPhonebookSizeAt") == 0) {
		gchar *command;

		g_variant_get(parameters, "s", &command);
		bluetooth_pb_get_phonebook_size_at(command, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntriesAt") == 0) {
		gchar *command;
		int start_idx;
		int end_idx;

		g_variant_get(parameters, "sii", &command, &start_idx, &end_idx);
		bluetooth_pb_get_phonebook_entries_at(command, start_idx, end_idx, invocation);
	} else if (g_strcmp0(method_name, "GetPhonebookEntriesFindAt") == 0) {
		gchar *command;
		gchar *find_text;

		g_variant_get(parameters, "ss", &command, &find_text);
		bluetooth_pb_get_phonebook_entries_find_at(command, find_text, invocation);
	} else {
		DBG("Unknown Method");
	}
}


static const GDBusInterfaceVTable pbap_interface_handle = {
	handle_pbap_method_call,
	NULL,
	NULL
};

static const GDBusInterfaceVTable pbap_st_interface_handle = {
	handle_pbap_at_method_call,
	NULL,
	NULL
};


static void register_agent_object(GDBusConnection *connection)
{
	DBG("");
	pb_agent_registration_id = g_dbus_connection_register_object(
				connection,
				BT_PBAP_AGENT_OBJECT_PATH,
				pbap_introspection_data->
					interfaces[0],
				&pbap_interface_handle,
				NULL,
				NULL,
				NULL);

	g_assert(pb_agent_registration_id > 0);

	pb_at_agent_registration_id = g_dbus_connection_register_object(
			connection,
			BT_PBAP_AGENT_OBJECT_PATH,
			pbap_introspection_data->
				interfaces[1],
			&pbap_st_interface_handle,
			NULL,
			NULL,
			NULL);

	g_assert(pb_at_agent_registration_id > 0);
}

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");

	/* Register Pbap object */
	register_agent_object(connection);

	conn = connection;
}

static void name_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");
	pb_agent_init();
}

static void name_lost(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("Name Lost");

	if (pb_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			connection,
			pb_agent_registration_id);
		pb_agent_registration_id = 0;
	}

	if (pb_at_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			connection,
			pb_at_agent_registration_id);
		pb_at_agent_registration_id = 0;
	}

	bus_id = 0;
}

void bt_pbap_agent_init(void)
{
	DBG("");

	pbap_introspection_data =
		g_dbus_node_info_new_for_xml(pbap_introspection_xml, NULL);

	if (conn == NULL)
		bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
			BT_PBAP_AGENT_NAME,
			G_BUS_NAME_OWNER_FLAGS_NONE,
			bus_acquired,
			name_acquired,
			name_lost,
			NULL,
			NULL);
}

void bt_pbap_agent_deinit(void)
{
	DBG("");

	if (pb_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			conn,
			pb_agent_registration_id);
		pb_agent_registration_id = 0;
	}

	if (pb_at_agent_registration_id > 0) {
		g_dbus_connection_unregister_object(
			conn,
			pb_at_agent_registration_id);
		pb_at_agent_registration_id = 0;
	}

	g_bus_unown_name(bus_id);

	g_dbus_node_info_unref(pbap_introspection_data);
	bus_id = 0;
}
#endif /* #ifdef TIZEN_2_MOBILE */

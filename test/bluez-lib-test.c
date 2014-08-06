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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>
#include <sys/signalfd.h>
#include <gio/gunixfdlist.h>
#include "common.h"
#include "bluez.h"

#define INPUT_SIZE 255

#define BLUEZ_LIB_TEST_SERVICE "org.bluezlib.test"
#define AGENT_INTERFACE "org.bluez.Agent1"
#define AGENT_OBJECT_PATH "/org/bluezlib/test"
#define PROFILE_OBJECT_PATH "/org/bluezlib/profile"

GMainLoop *loop;
GIOChannel *channel;

bluez_adapter_t *adapter;

static int start_scan(void *parameter)
{
	bluez_adapter_start_discovery(adapter);
	return 1;
}

static int stop_scan(void *parameter)
{
	bluez_adapter_stop_discovery(adapter);
	return 1;
}

static int show_help(void *parameter);

static int quit(void *parameter)
{
	g_io_channel_unref(channel);
	g_main_loop_quit(loop);

	return 0;
}

static int list_devices(void *parameter)
{
	GList *list, *next;
	const GList *path_list = bluez_adapter_get_devices_path(adapter);

	if (path_list == NULL)
		return 0;

	for (list = g_list_first((GList *)path_list); list; list = next) {
		next = g_list_next(list);
		printf("%s\n", (gchar *)list->data);
	}

	return 0;
}

static void transfer_address(char *address)
{
	while (*address != 0) {
		if (*address == '_')
			*address = ':';
		++address;
	}
}

static void device_pair_cb(enum bluez_error_type type,
				void *user_data)
{
	DBG("Pair type: %d", type);
}

static int pair(void *parameter)
{
	bluez_device_t *device;
	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	bluez_device_pair(device, device_pair_cb, NULL);

	return 0;
}

static int unpair(void *parameter)
{
	bluez_device_t *device;
	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	bluez_adapter_remove_device(adapter, device);

	return 0;
}

static int remove_device(void *parameter)
{
	bluez_device_t *device;
	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	bluez_adapter_remove_device(adapter, device);

	return 0;
}

static int power_on(void *parameter)
{
	bluez_adapter_set_powered(adapter, TRUE);

	return 0;
}

static int power_off(void *parameter)
{
	bluez_adapter_set_powered(adapter, FALSE);

	return 0;
}

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.Agent1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='RequestPinCode'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' direction='out'/>"
	"    </method>"
	"    <method name='DisplayPinCode'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' name='pincode' direction='in'/>"
	"    </method>"
	"    <method name='RequestPasskey'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' direction='out'/>"
	"    </method>"
	"    <method name='RequestConfirmation'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' name='passkey' direction='in'/>"
	"    </method>"
	"    <method name='AuthorizeService'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' name='uuid' direction='in'/>"
	"    </method>"
	"  </interface>"
	"</node>";

static void *handler_user_data, *pre_handler_user_data;
static void (* handler)(const char *cmd,
			const char *parameter,
			void *user_data);
static void (* pre_handler)(const char *cmd,
			const char *parameter,
			void *user_data);

static void handle_display_pincode(const char *device_path,
			const char *pincode,
			GDBusMethodInvocation *invocation)
{
	printf("\n\tdevice %s\n\tpingcode %s", device_path, pincode);
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static inline void switch_handler(void *new_handler, void *new_data)
{
	pre_handler = handler;

	handler = new_handler;

	pre_handler_user_data = handler_user_data;
	handler_user_data = new_data;
}

static inline void restore_handler(void)
{
	handler = pre_handler;
	handler_user_data = pre_handler_user_data;
}

static void request_confirmation_handler(const char *cmd,
					const char *parameter,
					void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;

	if (g_strcmp0(cmd, "Y") ||
			g_strcmp0(cmd, "y") ||
					g_strcmp0(cmd, ""))
		g_dbus_method_invocation_return_value(invocation, NULL);

	restore_handler();
}

static void handle_release(GDBusMethodInvocation *invocation)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void request_passkey_handler(const char *cmd,
					const char *parameter,
					void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;
	/* We do not test the digital type here */
	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(u)", atoi(cmd)));
	restore_handler();
}

static void request_pincode_handler(const char *cmd,
					const char *parameter,
					void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;
	/* We do not test the digital type here */
	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", g_strdup(cmd)));
	restore_handler();
}

static void authorize_service(const char *cmd,
				const char *parameter,
				void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;

	if (!g_ascii_strcasecmp(cmd, "Y"))
		g_dbus_method_invocation_return_value(invocation, NULL);

	restore_handler();
}

static void handle_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0) {
		handle_release(invocation);

		return;
	}

	if (g_strcmp0(method_name, "DisplayPinCode") == 0) {
		gchar *device_path = NULL, *pincode =  NULL;
		g_variant_get(parameters, "(os)", &device_path, &pincode);

		handle_display_pincode(device_path, pincode, invocation);

		g_free(device_path);
		g_free(pincode);

		return;
	}

	if (g_strcmp0(method_name, "RequestPinCode") == 0) {
		gchar *device_path = NULL;
		g_variant_get(parameters, "(o)", &device_path);

		switch_handler(request_pincode_handler, invocation);
		printf("\n\tdevice %s initial paring", device_path);
		printf("\n\tPlease input pin code:\n");

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "RequestPasskey") == 0) {
		gchar *device_path = NULL;
		g_variant_get(parameters, "(o)", &device_path);

		switch_handler(request_passkey_handler, invocation);
		printf("\n\tdevice %s initial paring", device_path);
		printf("\n\tPlease input passkey:\n");

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "RequestConfirmation") == 0) {
		gchar *device_path = NULL;
		gint32 passkey = 0;
		g_variant_get(parameters, "(ou)", &device_path, &passkey);

		printf("\n\tdevice %s\n\tpasskey %d\n\tPlease Confirm(Y/N)\n",
						device_path, passkey);

		switch_handler(request_confirmation_handler, invocation);

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "AuthorizeService") == 0) {
		gchar *device_path, *uuid;
		gint32 fd_index;
		g_variant_get(parameters, "(osh)", &device_path,
					&uuid, &fd_index);

		printf("\n\tdevice %s uuid %s", device_path, uuid);
		printf("\n\tAuthorize connection (yes/no):\n");

		switch_handler(authorize_service, invocation);

		g_free(device_path);
		g_free(uuid);
	}
}

static const GDBusInterfaceVTable interface_handle = {
	handle_method_call,
	NULL,
	NULL
};

guint bus_id;
guint agent_registration_id;
guint profile_registration_id;
GDBusConnection *conn;

static void deteach_connection()
{
	if (agent_registration_id == 0 &&
			profile_registration_id == 0) {
		g_bus_unown_name(bus_id);
		bus_id = 0;

		g_object_unref(conn);
		conn = NULL;
	}
}

static void register_agent_object(GDBusConnection *connection)
{
	agent_registration_id = g_dbus_connection_register_object(
						connection,
						AGENT_OBJECT_PATH,
						introspection_data->
							interfaces[0],
						&interface_handle,
						NULL,
						NULL,
						NULL);
	g_assert(agent_registration_id > 0);

	bluez_agent_register_agent(AGENT_OBJECT_PATH,
				DISPLAY_YES_NO, NULL, NULL);

	bluez_agent_request_default_agent(AGENT_OBJECT_PATH);
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

	if (agent_registration_id) {
		g_dbus_connection_unregister_object(connection,
					agent_registration_id);
		agent_registration_id = 0;
	}

	bus_id = 0;
}

static int agent_on(void *parameter)
{
	DBG("");

	introspection_data =
			g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	if (conn == NULL)
		bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				BLUEZ_LIB_TEST_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				bus_acquired,
				name_acquired,
				name_lost,
				parameter,
				NULL);
	else
		register_agent_object(conn);

	return 0;
}

static int agent_off(void *parameter)
{
	if (agent_registration_id)
		g_dbus_connection_unregister_object(conn,
					agent_registration_id);

	agent_registration_id = 0;

	bluez_agent_unregister_agent(AGENT_OBJECT_PATH, NULL, NULL);

	deteach_connection();

	return 0;
}

static char *app_id;

static int hdp_activate(void *parameter)
{
	int result = 0;

	DBG("");

	result = bluez_hdp_activate(1,
		HDP_ROLE_SINK, HDP_CHANNEL_ANY, &app_id);

	DBG("result = %d app_id = %s", result, app_id);

	return result;
}

static int hdp_deactivate(void *parameter)
{
	int result = 0;

	DBG("app_id = %s", app_id);

	result = bluez_hdp_deactivate((const char *)(app_id));

	DBG("result = %d", result);

	return result;
}

static int default_agent(void *parameter)
{
	bluez_agent_request_default_agent((const gchar*)parameter);

	return 0;
}

static int list_uuid(void *parameter)
{
	char **uuids;
	guint length, index;

	uuids = bluez_adapter_get_property_uuids(adapter);
	length = g_strv_length(uuids);

	printf("\n\tUUIDs:\n");
	for (index = 0; index < length; ++index)
		printf("\t%s\n", uuids[index]);

	g_strfreev(uuids);

	return 0;
}

static int device_uuids(void *parameter)
{
	char **uuids;
	guint length, index;
	bluez_device_t *device;

	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	uuids = bluez_device_get_property_uuids(device);
	length = g_strv_length(uuids);

	printf("\n\tDevice %s UUIDs:", (char *)parameter);
	for (index = 0; index < length; ++index)
		printf("\t%s\n", uuids[index]);

	g_strfreev(uuids);

	return 0;
}

static GDBusNodeInfo *profile_introspection_data;

static const gchar profile_xml[] =
	"<node>"
	"  <interface name='org.bluez.Profile1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='NewConnection'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='h' name='fd' direction='in'/>"
	"      <arg type='a{sv}' name='opts' direction='in'/>"
	"    </method>"
	"    <method name='RequestDisconnection'>"
	"      <arg type='o' name='device' direction='in'/>"
	"    </method>"
	"  </interface>"
	"</node>";

static gboolean received_data(GIOChannel *channel, GIOCondition con,
							gpointer user_data)
{
	gchar buf[128] = {0};
	GError *error = NULL;
	GIOStatus status;
	gsize rbytes;

	status = g_io_channel_read_chars(channel, buf, 128, &rbytes, &error);
	if (status == G_IO_STATUS_ERROR) {
		DBG("Channel read error %s", error->message);
		g_error_free(error);

		return FALSE;
	}

	printf("\n\tReceived: %s\n", buf);

	return TRUE;
}

static void handle_new_connection(gchar *device_path, gint fd,
					GDBusMethodInvocation *invocation)
{
	GIOChannel *channel;
	gchar *local_address;
	gchar *reply_buf;

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL) {
		ERROR("Create connection channel error");
		g_dbus_method_invocation_return_value(invocation, NULL);
		goto done;
	}

	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_add_watch(channel, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							received_data, NULL);

	local_address = bluez_adapter_get_property_address(adapter);
	reply_buf = g_strdup_printf("%s say: %s", local_address, "Hello!");

	g_io_channel_write_chars(channel, reply_buf,
					strlen(reply_buf), NULL, NULL);

	g_free(local_address);
	g_free(reply_buf);

done:
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_request_disconnection(gchar *device_path,
					GDBusMethodInvocation *invocation)
{
	DBG("device path %s", device_path);

	/* TODO: We should close the fd */

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_profile_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0)
		handle_release(invocation);
	else if (g_strcmp0(method_name, "NewConnection") == 0) {
		GDBusMessage *msg;
		GUnixFDList *fd_list;
		GVariantIter *opts;
		gchar *device_path;
		gint32 fd_index;
		gint fd;

		g_variant_get(parameters, "(oha{sv})", &device_path, &fd_index, &opts);

		msg = g_dbus_method_invocation_get_message(invocation);
		fd_list = g_dbus_message_get_unix_fd_list(msg);

		fd = g_unix_fd_list_get(fd_list, fd_index, NULL);

		handle_new_connection(device_path, fd, invocation);

		g_free(device_path);
		g_variant_iter_free(opts);
	} else if (g_strcmp0(method_name, "RequestDisconnection") == 0) {
		gchar *device_path;

		g_variant_get(parameters, "(o)", &device_path);

		handle_request_disconnection(device_path, invocation);

		g_free(device_path);
	} else
		DBG("Unknown method name %s", method_name);
}

static const GDBusInterfaceVTable profile_interface = {
	handle_profile_method_call,
	NULL,
	NULL
};

static void register_profile_object(GDBusConnection *connection, gchar *uuid)
{
	profile_registration_id = g_dbus_connection_register_object(
						connection,
						PROFILE_OBJECT_PATH,
						profile_introspection_data->
							interfaces[0],
						&profile_interface,
						NULL,
						NULL,
						NULL);
	g_assert(profile_registration_id > 0);

	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(builder, "{sv}", "Name",
				g_variant_new("s", "RFcomm"));
	g_variant_builder_add(builder, "{sv}", "Service",
				g_variant_new("s", "spp-server"));
	g_variant_builder_add(builder, "{sv}", "RequireAuthentication",
				g_variant_new("b", "true"));
	g_variant_builder_add(builder, "{sv}", "RequireAuthorization",
				g_variant_new("b", "true"));
	g_variant_builder_add(builder, "{sv}", "Version",
				g_variant_new("q", "1"));
	g_variant_builder_add(builder, "{sv}", "Features",
				g_variant_new("q", "1"));

	bluez_profile_register_profile(PROFILE_OBJECT_PATH, uuid,
					builder, NULL, NULL);
}

static void profile_bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	gchar *uuid = user_data;

	DBG("uuid %s", uuid);

	register_profile_object(connection, uuid);

	conn = connection;

	g_free(uuid);
}

static void profile_name_acquired(GDBusConnection *connection,
			const gchar *name,
			gpointer user_data)
{
	DBG("");
}

static void profile_name_lost(GDBusConnection *connection,
			const gchar *name,
			gpointer user_data)
{
	DBG("Name Lost");

	if (profile_registration_id) {
		g_dbus_connection_unregister_object(connection,
					profile_registration_id);

		profile_registration_id = 0;
	}

	bus_id = 0;
}

static int register_profile(void *parameter)
{
	gchar *uuid;

	if (parameter == NULL) {
		ERROR("no uuid specified");
		return -1;
	}

	uuid = g_strdup(parameter);

	profile_introspection_data =
			g_dbus_node_info_new_for_xml(profile_xml, NULL);

	if (conn) {
		register_profile_object(conn, uuid);

		g_free(uuid);
	} else
		bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				BLUEZ_LIB_TEST_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				profile_bus_acquired,
				profile_name_acquired,
				profile_name_lost,
				uuid,
				NULL);

	return 0;
}

static int unregister_profile(void *parameter)
{
	bluez_profile_unregister_profile(PROFILE_OBJECT_PATH, NULL, NULL);

	if (profile_registration_id)
		g_dbus_connection_unregister_object(conn,
					profile_registration_id);

	profile_registration_id = 0;

	deteach_connection();

	return 0;
}

static void profile_connect_cb(struct _bluez_device *device,
				enum device_profile_state state)
{
	DBG("%d", state);
}

static int connect_spp(void *parameter)
{
	const gchar *spp_uuid = "00001101-0000-1000-8000-00805f9b34fb";
	bluez_device_t *device;

	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	bluez_device_connect_profile(device, spp_uuid, profile_connect_cb);

	return 0;
}
/*
static int icon(void *parameter)
{
	gchar *icon;
	bluez_device_t *device;

	if (parameter == NULL) {
		ERROR("no device specified");
		return -1;
	}

	transfer_address(parameter);

	device = bluez_adapter_get_device_by_address(adapter, (const char *)parameter);
	if (device == NULL) {
		ERROR("Can't find device %s", (char *) parameter);
		return -1;
	}

	icon = bluez_device_get_property_icon(device);

	printf("\nDevice Icon: %s\n", icon);

	g_free(icon);

	return 0;
}
*/
struct {
	const char *command;
	int (*function)(void *parameter);
	const char *description;
} command_ops[] = {
	{"h", show_help,
		"Usage: h\n\tThis help"},

	{"on", power_on,
		"Usage: on\n\tPower on adapter"},

	{"off", power_off,
		"Usage: scan\n\tPower off adapter"},

	{"scan", start_scan,
		"Usage: scan\n\tKick adapter to start discovery"},

	{"stop", stop_scan,
		"Usage: stop\n\tKick adapter to stop discovery"},

	{"list", list_devices,
		"Usage: list\n\tList devices object path"},

	{"agent_on", agent_on,
		"Usage: agent_on agent_type\n\tRegister agent"},

	{"agent_off", agent_off,
		"Usage: agent_off\n\tUnregister agent"},

	{"hdp_activate", hdp_activate,
		"Usage: hdp_activate\n\thdp activate"},

	{"hdp_deactivate", hdp_deactivate,
		"Usage: hdp_activate\n\thdp deactivate"},

	{"default_agent", default_agent,
		"Usage: default_agent /path/to/agent\n\tSet default agent"},

	{"pair", pair,
		"Usage: pair F0_DC_E2_7F_41_3D\n\tPair device"},

	{"unpair", unpair,
		"Usage: unpair F0_DC_E2_7F_41_3D\n\tUnPair device"},

	{"remove", remove_device,
		"Usage: remove F0_DC_E2_7F_41_3D\n\tRemove device"},

//	{"icon", icon,
//		"Usage: icon F0_DC_E2_7F_41_3D\n\tGet device Icon"},

	{"l_a_uuid", list_uuid,
		"Usage: list_uuid\n\tList adapter UUIDs"},

	{"l_d_uuids", device_uuids,
		"Usage: l_d_uuids F0_DC_E2_7F_41_3D\n\tList device UUIDs"},

	{"r_profile", register_profile,
		"Usage: r_profile 00001101-0000-1000-8000-00805F9B34FB\n\tRegister client Profile"},

	{"unr_profile", unregister_profile,
		"Usage: r_profile\n\tRegister client Profile"},

	{"c_spp", connect_spp,
		"Usage: c_spp F0_DC_E2_7F_41_3D\n\tConnect device with SPP UUID"},

	{"q", quit,
		"Usage: q\n\tQuit"},

	{NULL, NULL}};

static int show_help(void *parameter)
{
	int i = 0;

	while (command_ops[i].command != NULL) {
		printf("%s:\n\t%s\n", command_ops[i].command,
				command_ops[i].description);
		i++;
	}

	return 0;
}

static inline void split_input(char *str, char **s1, char **s2)
{
	*s1 = str;

	while (*str == ' ' || *str == '\t')
		str++;

	*s1 = str;

	if (*str == '\n') {
		*str = 0;
		*s2 = NULL;
		return;
	}

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	if (*str == '\n') {
		*str = 0;
		*s2 = NULL;
		return;
	} else
		*str = 0;

	str++;

	while (*str == ' ' || *str == '\t')
		str++;

	if (*str == '\n') {
		*s2 = NULL;
		return;
	} else
		*s2 = str;

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	*str = 0;
}

static void cmd_handler(const char *cmd,
			const char *parameter,
			void *user_data)
{
	int i = 0;
	gboolean cmd_found = FALSE;

	if (g_strcmp0(cmd, "") == 0)
		return;

	while (command_ops[i].command != NULL) {
		if (g_strcmp0(command_ops[i].command, cmd) == 0) {
			command_ops[i].function((void *) parameter);
			cmd_found = TRUE;
			break;
		}
		i++;
	}

	if (cmd_found == FALSE)
		printf("\nError: unknown command %s\n", cmd);
}

gboolean handle_command(GIOChannel *src, GIOCondition con, gpointer data)
{
	gchar *user_command, *user_parameter;
	char buf[INPUT_SIZE + 1] = { 0, };

	if (fgets(buf, INPUT_SIZE, stdin) == NULL)
		return TRUE;

	split_input(buf, &user_command, &user_parameter);

	if (handler)
		handler((const char *) user_command,
				(const char *) user_parameter,
				handler_user_data);

	return TRUE;
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	gint fd;
	ssize_t readlen;
	struct signalfd_siginfo si;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	readlen = read(fd, &si, sizeof(struct signalfd_siginfo));
	if (readlen != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		DBG("Terminate.");
		quit(NULL);
		break;
	default:
		break;
	}

	return TRUE;
}

static guint setup_signal_handle(void)
{
	sigset_t mask;
	int signal_fd;
	guint id;
	GIOChannel *channel;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		ERROR("Error to set signal handle");
		return 0;
	}

	signal_fd = signalfd(-1, &mask, 0);
	if (signal_fd < 0) {
		ERROR("Error to create signal file.");
		return 0;
	}

	channel = g_io_channel_unix_new(signal_fd);

	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);
	g_io_channel_set_close_on_unref(channel, TRUE);

	id = g_io_add_watch(channel,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			signal_handler, NULL);

	return id;
}

int main(int argc, char **argv)
{

	if (argv[1] == NULL) {
		ERROR("Please specify adatper name");
		return -1;
	}

#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	setup_signal_handle();

	bluez_lib_init();

	adapter = bluez_adapter_get_adapter(argv[1]);
	if (adapter == NULL) {
		ERROR("Can't Find adapter %s", argv[1]);
		return -1;
	}

	loop = g_main_loop_new(NULL, FALSE);

	channel = g_io_channel_unix_new(STDIN_FILENO);
	g_io_add_watch(channel, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL),
							handle_command, NULL);

	handler = cmd_handler;
	handler_user_data = NULL;

	g_main_loop_run(loop);

	bluez_lib_deinit();

	return 0;
}

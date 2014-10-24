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
#include "common.h"
#include "obex.h"
#include "bluetooth-service.h"

#define PAIRING_AGENT_ERROR "org.bluetooth.pairing.error"

#define BLUEZ_LIB_TEST_SERVICE "org.bluezlib.agent"
#define PAIRING_AGENT_PATH "/org/service/pairing"
#define OPP_AGENT_PATH "/org/service/opp"

#define INPUT_SIZE 255

GMainLoop *loop;
GIOChannel *channel;

static int show_help(void *p1, void *p2);

static int quit(void *p1, void *p2)
{
	g_io_channel_unref(channel);
	g_main_loop_quit(loop);

	return 0;
}

static void *handler_user_data, *pre_handler_user_data;

static void (* handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);

static void (* pre_handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);

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

static void *handler_user_data, *pre_handler_user_data;

static void (* handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);
static void (* pre_handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);


static int enable_bluetooth(void *p1, void *p2)
{
	comms_manager_enable_bluetooth();

	return 0;
}

static int disable_bluetooth(void *p1, void *p2)
{
	comms_manager_disable_bluetooth();

	return 0;
}

static void bt_simple_result_cb(enum bluez_error_type error_type,
						void *user_data)
{
	DBG("error type: %d", error_type);
}

static int bt_pair(void *p1, void *p2)
{
	DBG("");

	comms_bluetooth_device_pair(p1, bt_simple_result_cb, NULL);

	return 0;
}

GDBusNodeInfo *pairing_introspection_data;
GDBusNodeInfo *opp_introspection_data;
guint pairing_agent_id;
guint opp_agent_id;
guint bus_id;
GDBusConnection *conn;

static const gchar pairing_agent_xml[] =
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
	"  </interface>"
	"</node>";

static inline void split_input(char *str, char **s1, char **s2, char **s3);

static void handle_release(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_request_pincode(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	gchar *pin_code, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\tPlease input pincode:(C mean canncel)");

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &pin_code, &p1, &p2);

	if (g_ascii_strncasecmp(pin_code, "C", 1) == 0)
		g_dbus_method_invocation_return_dbus_error(
					invocation,
					PAIRING_AGENT_ERROR ".PinCode",
					"CancelByUser");
	else
		g_dbus_method_invocation_return_value(
					invocation,
					g_variant_new("(s)", pin_code));
}

static void handle_display_pincode(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	gchar *pincode, *device_name;

	g_variant_get(parameters, "(os)", &device_name, &pincode);

	DBG("PinCode: %s %s", device_name, pincode);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_request_passkey(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("");
}

static void handle_request_confirmation(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	gchar *confirm_info, *p1, *p2;
	gchar input_value[32] = { 0 };

	DBG("\n\tPlease Confirm(Y/N):\n");

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &confirm_info, &p1, &p2);

	if (g_ascii_strncasecmp(confirm_info, "y", 1) == 0)
		g_dbus_method_invocation_return_value(
						invocation,
						NULL);
	else
		g_dbus_method_invocation_return_dbus_error(
						invocation,
						PAIRING_AGENT_ERROR ".PinCode",
						"RejectByUser");
}

static void pairing_agent_method_call_handler(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	DBG("Method_name: %s", method_name);

	if (g_strcmp0(method_name, "Release") == 0)
		handle_release(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "RequestPinCode") == 0)
		handle_request_pincode(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "DisplayPinCode") == 0)
		handle_display_pincode(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "RequestPasskey") == 0)
		handle_request_passkey(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "RequestConfirmation") == 0)
		handle_request_confirmation(parameters, invocation,
								user_data);
	else
		WARN("Unknown method %s", method_name);
}

static const GDBusInterfaceVTable pairing_agent_interface_vtable =
{
	pairing_agent_method_call_handler,
	NULL,
	NULL
};

static const gchar opp_agent_xml[] =
	"<node>"
	"  <interface name='org.bluez.obex.Agent1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='AuthorizePush'>"
	"      <arg type='o' name='transfer' direction='in'/>"
	"      <arg type='s' direction='out'/>"
	"    </method>"
	"    <method name='Cancel'>"
	"    </method>"
	"  </interface>"
	"</node>";

static void opp_agent_release_handler(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void opp_server_accept_file(GVariant *parameters,
				GDBusMethodInvocation *invocation)
{
	gchar *transfer_path, *file_name;

	g_variant_get(parameters, "(o)", &transfer_path);

	file_name = g_build_filename("/tmp/", "test", NULL);

	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", file_name));
}

static void opp_server_reject_file(GVariant *parameters,
				GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", NULL));
}

static void opp_agent_authorize_push_handler(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	gchar *pin_code, *p1, *p2;
	gchar input_value[32] = { 0 };

	printf("\n\tPlease input accept/reject:(Y mean accept)");

	if (fgets(input_value, 32, stdin) == NULL) {
		ERROR("fgets error.");
		return;
	}

	split_input(input_value, &pin_code, &p1, &p2);

	if (g_ascii_strncasecmp(pin_code, "Y", 1) == 0)
		opp_server_accept_file(parameters, invocation);
	else
		opp_server_reject_file(parameters, invocation);
}

static void opp_agent_cancel_handler(GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void obex_agent_method_call_handler(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0)
		opp_agent_release_handler(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "AuthorizePush") == 0)
		opp_agent_authorize_push_handler(parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "Cancel") == 0)
		opp_agent_cancel_handler(parameters, invocation, user_data);
	else
		WARN("Unknown method %s", method_name);
}
static const GDBusInterfaceVTable opp_agent_interface_vtable =
{
	obex_agent_method_call_handler,
	NULL,
	NULL
};

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");

	pairing_introspection_data = g_dbus_node_info_new_for_xml(
						pairing_agent_xml, NULL);
	g_assert(pairing_introspection_data != NULL);

	pairing_agent_id = g_dbus_connection_register_object(connection,
						PAIRING_AGENT_PATH,
						pairing_introspection_data->interfaces[0],
						&pairing_agent_interface_vtable,
						NULL, NULL, NULL);

	g_assert(pairing_agent_id > 0);

	opp_introspection_data = g_dbus_node_info_new_for_xml(
						opp_agent_xml, NULL);
	g_assert(opp_introspection_data != NULL);

	opp_agent_id = g_dbus_connection_register_object(connection,
						OPP_AGENT_PATH,
						opp_introspection_data->interfaces[0],
						&opp_agent_interface_vtable,
						NULL, NULL, NULL);

	g_assert(opp_agent_id > 0);

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

	if (pairing_agent_id > 0) {
		g_dbus_connection_unregister_object(connection,
						pairing_agent_id);

		comms_bluetooth_unregister_pairing_agent(PAIRING_AGENT_PATH,
						bt_simple_result_cb, NULL);
	}

	if (opp_agent_id > 0) {
		g_dbus_connection_unregister_object(connection,
							opp_agent_id);

		comms_bluetooth_unregister_opp_agent(OPP_AGENT_PATH,
						bt_simple_result_cb, NULL);
	}

	bus_id = 0;
}

static gboolean create_simple_agent(void)
{
	if (bus_id > 0)
		return TRUE;

	bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				BLUEZ_LIB_TEST_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				bus_acquired,
				name_acquired,
				name_lost,
				NULL,
				NULL);

	g_assert(bus_id > 0);

	return TRUE;
}

static int bt_agent(void *p1, void *p2)
{
	create_simple_agent();

	return TRUE;
}

static int bt_pairing_agent_on(void *p1, void *p2)
{
	if (bus_id < 0) {
		DBG("Run bt_agent first");
		return 0;
	}

	comms_bluetooth_register_pairing_agent(PAIRING_AGENT_PATH,
						bt_simple_result_cb, NULL);

	return 0;
}

static int bt_pairing_agent_off(void *p1, void *p2)
{
	comms_bluetooth_unregister_pairing_agent(PAIRING_AGENT_PATH,
						bt_simple_result_cb, NULL);

	return 0;
}

static int bt_opp_agent_on(void *p1, void *p2)
{
	if (bus_id < 0) {
		DBG("Run bt_agent first");
		return 0;
	}

	comms_bluetooth_register_opp_agent(OPP_AGENT_PATH,
						bt_simple_result_cb, NULL);

	return 0;
}

static int bt_opp_agent_off(void *p1, void *p2)
{
	comms_bluetooth_unregister_opp_agent(OPP_AGENT_PATH,
						bt_simple_result_cb, NULL);

	return 0;
}

static int bt_send_file(void *p1, void *p2)
{
	comms_bluetooth_opp_send_file(p1, p2, bt_simple_result_cb, NULL);

	return 0;
}

struct {
	const char *command;
	int (*function)(void *p1, void *p2);
	const char *description;
} command_ops[] = {
	{"h", show_help,
		"Usage: h\n\tThis help"},

	{"bt_on", enable_bluetooth,
		"Usage: bt_on \n\tEnable Bluetooth service"},

	{"bt_off", disable_bluetooth,
		"Usage: bt_off\n\tDisable Bluetooth service"},

	{"bt_agent", bt_agent,
		"Usage: bt_agent\n\tCreate Bluetooth agent"},

	{"bt_pairing_agent_on", bt_pairing_agent_on,
		"Usage: bt_pairing_agent_on\n\tRegister pairing agent"},

	{"bt_pairing_agent_off", bt_pairing_agent_off,
		"Usage: bt_pairing_agent_off\n\tUnregister pairing agent"},

	{"bt_opp_agent_on", bt_opp_agent_on,
		"Usage: bt_opp_agent_on\n\tRegister opp agent"},

	{"bt_opp_agent_off", bt_opp_agent_off,
		"Usage: bt_opp_agent_off\n\tUnregister opp agent"},

	{"bt_pair", bt_pair,
		"Usage: bt_pair <device address>\n\tPair the <device address>"},

	{"bt_send_file", bt_send_file,
		"Usage: bt_send_file <device address> <file name>\n\tSend <file name> to <device address>"},

	{"q", quit,
		"Usage: q\n\tQuit"},

	{NULL, NULL} };

static int show_help(void *p1, void *p2)
{
	int i = 0;

	while (command_ops[i].command != NULL) {
		printf("%s:\n\t%s\n", command_ops[i].command,
				command_ops[i].description);
		i++;
	}

	return 0;
}

static inline void split_input(char *str, char **s1, char **s2, char **s3)
{
	*s1 = str;

	*s2 = *s3 = NULL;

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

	str++;

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	if (*str == '\n') {
		*s3 = NULL;
		*str = 0;
		return;
	} else
		*str = 0;

	str++;

	while (*str == ' ' && *str == '\t')
		str++;

	if (*str == '\n')
		return;
	else
		*s3 = str;

	str++;

	while (*str != ' ' && *str != '\t' && *str != '\n')
		str++;

	*str = 0;
}

static void cmd_handler(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data)
{
	int i = 0;
	gboolean cmd_found = FALSE;

	if (g_strcmp0(cmd, "") == 0)
		return;

	while (command_ops[i].command != NULL) {
		if (g_strcmp0(command_ops[i].command, cmd) == 0) {
			command_ops[i].function((void *) p1, (void *) p2);
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
	gchar *user_command, *p1, *p2;
	char buf[INPUT_SIZE + 1] = { 0, };

	if (fgets(buf, INPUT_SIZE, stdin) == NULL)
		return TRUE;

	split_input(buf, &user_command, &p1, &p2);

	if (handler)
		handler((const char *) user_command,
				(const char *) p1,
				(const char *) p2,
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
		quit(NULL, NULL);
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
#if (GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 36)
	g_type_init();
#endif

	setup_signal_handle();

	comms_lib_init();

	loop = g_main_loop_new(NULL, FALSE);

	channel = g_io_channel_unix_new(STDIN_FILENO);
	g_io_add_watch(channel, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL),
							handle_command, NULL);

	handler = cmd_handler;
	handler_user_data = NULL;

	g_main_loop_run(loop);

	comms_lib_deinit();

	return 0;
}

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

#define INPUT_SIZE 255

#define OBEX_LIB_TEST_SERVICE "org.obexlib.test"
#define AGENT_OBJECT_PATH "/org/obexlib/test"

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

static void transfer_address(char *address)
{
	while (*address != 0) {
		if (*address == '_')
			*address = ':';
		address++;
	}
}

static int create_session(void *p1, void *p2)
{
	transfer_address(p1);
	return 0;
}

static int opp_send(void *p1, void *p2)
{
	return 0;
}

static int list_transfer(void *p1, void *p2)
{
	return 0;
}

static int list_active_transfer(void *p1, void *p2)
{
	return 0;
}


static int stop_transfer(void *p1, void *p2)
{
	return 0;
}

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
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

static void *handler_user_data, *pre_handler_user_data;

static void (* handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);
static void (* pre_handler)(const char *cmd,
			const char *p1,
			const char *p2,
			void *user_data);

static void handle_release(GDBusMethodInvocation *invocation)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_cancel(GDBusMethodInvocation *invocation)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
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

	DBG("%s", method_name);

	if (g_strcmp0(method_name, "Release") == 0) {
		handle_release(invocation);

		return;
	}

	if (g_strcmp0(method_name, "AuthorizePush") == 0) {
		return;
	}

	if (g_strcmp0(method_name, "Cancel") == 0) {
		handle_cancel(invocation);

		return;
	}
}

static const GDBusInterfaceVTable interface_handle = {
	handle_method_call,
	NULL,
	NULL
};

guint bus_id;
GDBusConnection *conn;

static void obex_agent_register_agent_cb(enum bluez_error_type type,
						void *user_data)
{
	DBG("error type: %d", type);
}

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	DBG("");

	bus_id = g_dbus_connection_register_object(
						connection,
						AGENT_OBJECT_PATH,
						introspection_data->
							interfaces[0],
						&interface_handle,
						NULL,
						NULL,
						NULL);
	g_assert(bus_id > 0);

	conn = connection;

	obex_agent_register_agent(AGENT_OBJECT_PATH,
			obex_agent_register_agent_cb, NULL);
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

	if (bus_id) {
		g_dbus_connection_unregister_object(connection, bus_id);
		bus_id = 0;
	}
}

static int transfer_watch(void *p1, void *p2)
{
	return 0;
}

static int agent_on(void *p1, void *p2)
{
	DBG("");

	introspection_data =
			g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	bus_id = g_bus_own_name(G_BUS_TYPE_SESSION,
				OBEX_LIB_TEST_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				bus_acquired,
				name_acquired,
				name_lost,
				NULL,
				NULL);

	return 0;
}

struct {
	const char *command;
	int (*function)(void *p1, void *p2);
	const char *description;
} command_ops[] = {
	{"h", show_help,
		"Usage: h\n\tThis help"},

	{"cs", create_session,
		"Usage: cs 70_F9_27_64_DF_65\n\tCreate OPP Session"},

	{"opp_send", opp_send,
		"Usage: opp_send session_id file_name\n\tSend file through OPP"},

	{"t_watch", transfer_watch,
		"Usage: t_watch on/off\n\topen/close transfer watch"},

	{"lt", list_transfer,
		"Usage: lt\n\tlist all the transfer path"},

	{"lat", list_active_transfer,
		"Usage: lat\n\tlist the active transfer path"},

	{"cancel_t", stop_transfer,
		"Usage: cancel_t /org/bluez/obex/client/session9/transfer41\n\tCancel the transfer"},

	{"agent_on", agent_on,
		"Usage: agent_on agent_type\n\tRegister agent"},

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

	obex_lib_init();

	loop = g_main_loop_new(NULL, FALSE);

	channel = g_io_channel_unix_new(STDIN_FILENO);
	g_io_add_watch(channel, (G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL),
							handle_command, NULL);

	handler = cmd_handler;
	handler_user_data = NULL;

	g_main_loop_run(loop);

	obex_lib_deinit();

	return 0;
}

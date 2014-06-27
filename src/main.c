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
#include <gio/gunixsocketaddress.h>
#include <glib-object.h>
#include <sys/signalfd.h>
#include "common.h"
#include "manager.h"

#define COMMS_SERVICE "org.tizen.comms"
#define COMMS_SERVICE_MANAGER "/org/tizen/comms"
#define MANAGER_OBJECT "/org/tizen/comms/manager"
#define BLUETOOTH_OBJECT "/org/tizen/comms/bluetooth"

GMainLoop *loop;
GIOChannel *channel;

static guint bus_id;
static GDBusObjectManagerServer *comms_server_manager;
static GDBusObjectSkeleton *manager_object;

static void bus_acquired(GDBusConnection *connection,
				const gchar *name,
				gpointer user_data)
{
	GDBusInterfaceSkeleton *manager_interface;
	CommsManagerSkeleton *comms_manager;

	DBG("");

	comms_server_manager = g_dbus_object_manager_server_new(
						COMMS_SERVICE_MANAGER);

	g_dbus_object_manager_server_set_connection(comms_server_manager,
								connection);

	comms_manager = comms_service_manager_new(comms_server_manager);

	manager_interface = G_DBUS_INTERFACE_SKELETON(comms_manager);

	manager_object = g_dbus_object_skeleton_new(MANAGER_OBJECT);
	g_dbus_object_skeleton_add_interface(manager_object, manager_interface);

	g_dbus_object_manager_server_export(comms_server_manager,
							manager_object);
}

static void name_acquired(GDBusConnection *connection,
					const gchar *name,
					gpointer user_data)
{
	DBG("");
}

static void deinit_manager(void)
{
	DBG("");

	g_dbus_object_manager_server_unexport(comms_server_manager,
							MANAGER_OBJECT);

	g_object_unref(manager_object);
}

static void name_lost(GDBusConnection *connection,
			const gchar *name,
			gpointer user_data)
{
	DBG("Name Lost");

	deinit_manager();

	exit(-1);
}

static int init_manager(void)
{
	DBG("");

	bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
					COMMS_SERVICE,
					G_BUS_NAME_OWNER_FLAGS_NONE,
					bus_acquired,
					name_acquired,
					name_lost,
					NULL,
					NULL);

	return 0;
}

static gboolean socket_handler(GIOChannel *channel, GIOCondition condition,
                                                        gpointer user_data)
{
	GString *s;
	GIOStatus status;
	GError *error = NULL;

	s = g_string_new(NULL);
	status = g_io_channel_read_line_string(channel, s, NULL, &error);

	if (status == G_IO_STATUS_ERROR) {
		ERROR("Unable to receive from listening socket");
		g_object_unref(user_data);
		return FALSE;
	}

	g_printerr ("RECEIVED : %s\n", s->str);

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
		g_main_loop_quit(loop);
		break;
	default:
		break;
	}

	return TRUE;
}

static void cleanup_listening_socket(void)
{
//	GError *error = NULL;

//	g_socket_close(socket, &error);

}

static guint setup_listening_socket(void)
{
	GSocket *socket;
#if 0
	GSocket *opened_socket;
#endif
	GSocketFamily socket_family;
	GSocketType socket_type;
	GSocketAddress *socket_address;
#if 0
	GIOStream *connection;
	GInputStream *istream;
#endif
	GIOChannel *channel;
	gint fd;
	guint id;
	GError *error = NULL;

	socket_family = G_SOCKET_FAMILY_UNIX;
	socket_type = G_SOCKET_TYPE_STREAM;
	socket = g_socket_new(socket_family, socket_type, 0, &error);

	if (socket == NULL) { g_print("NEW\n");
		ERROR("Error to set listening socket");
		return 0;
	}

	g_socket_set_blocking(socket, FALSE);
	socket_address = g_unix_socket_address_new("/tmp/.bluetooth.service");
	g_socket_bind(socket, socket_address, FALSE, &error);

	if (error) { g_print("BIND\n");
		ERROR("Error to bind listening socket");
		return 0;
	}
g_print("APRES BIND\n");
	g_socket_listen(socket, &error);

	if (error) { g_print("LISTEN\n");
		ERROR("Error to listen on socket");
		return 0;
	}
g_print("APRES LISTEN\n");

	g_object_unref(socket_address);
#if 0
	opened_socket = g_socket_accept(socket, NULL, &error);

	if (opened_socket == NULL) {g_print("ACCEPT\n");
		ERROR("Error to accept connections on listening socket");
		return 0;
	}
#endif
g_print("AVANT GET_FD\n");
	fd = g_socket_get_fd(socket);
	channel = g_io_channel_unix_new(fd);

g_print("AVANT SET_ENCODING\n");
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);
	g_io_channel_set_close_on_unref(channel, TRUE);

	id = g_io_add_watch(channel,
			G_IO_IN,
			socket_handler, NULL);
g_print("APRES ADD_WATCH\n");

	//g_io_channel_unref(channel);
#if 0
	connection = G_IO_STREAM (g_socket_connection_factory_create_connection(opened_socket));

	if (!connection) {
		ERROR("Unable to establish connections on listening socket");
		return 0;
	}

	istream = g_io_stream_get_input_stream(connection);

	//while (1) {
	gchar buffer[4096];
	gssize size;
	size = g_input_stream_read (istream, buffer, sizeof buffer, NULL, &error);

	if (size < 0) {
		ERROR("Unable to receive from listening socket");
		return 0;
	}

	// if (size == 0) break;

	g_print ("received %" G_GSSIZE_FORMAT "bytes of data : %s\n", size, buffer);

	//}
#endif

	return id;
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

	setup_listening_socket();

	setup_signal_handle();

	comms_service_plugin_init();

	init_manager();

	loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(loop);

	comms_service_plugin_cleanup();

	cleanup_listening_socket();

	deinit_manager();

	g_bus_unown_name(bus_id);
	
	return 0;
}

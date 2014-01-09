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

	comms_service_plugin_init();

	init_manager();

	loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(loop);

	comms_service_plugin_cleanup();

	deinit_manager();

	g_bus_unown_name(bus_id);
	
	return 0;
}

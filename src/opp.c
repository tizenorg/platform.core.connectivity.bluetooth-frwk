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

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gunixfdlist.h>
#include <string.h>
#include "obex.h"
#include "comms_error.h"
#include "gdbus.h"
#include "opp.h"
#include "vertical.h"

#define OPP_OBJECT "/org/tizen/comms/bluetooth"
#define AGENT_INTERFACE "org.bluez.obex.Agent1"
#define OPP_AGENT_PATH OPP_OBJECT "/agent/opp"

#define FILENAME_LEN 100
#define ADDRESS_LEN 18
#define UID_LEN 8
#define CONTEXT_LEN 28

static gboolean g_connectable;

struct user_privileges {
	char address[ADDRESS_LEN];
	char uid[UID_LEN];
};

G_DEFINE_TYPE(OppSkeleton, opp_skeleton,
				G_TYPE_DBUS_INTERFACE_SKELETON);

static void opp_skeleton_init(OppSkeleton *skeleton)
{
	DBG("");

	obex_lib_init();
}

static void opp_skeleton_finalize(GObject *object)
{
	DBG("");

	obex_lib_deinit();
}

static const GDBusMethodInfo * const _method_info_pointers[] =
{
	GDBUS_METHOD("RegisterObexAgent", GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("UnregisterObexAgent", GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("AddFile", GDBUS_ARGS(_ARG("sourcefile", "s"),
						_ARG("agent", "o")), NULL),
	GDBUS_METHOD("SendFile", GDBUS_ARGS(_ARG("address", "s"),
						_ARG("agent", "o")), NULL),
	GDBUS_METHOD("CancelTransfer", GDBUS_ARGS(_ARG("transfer_id", "i")), NULL),
	GDBUS_METHOD("CancelAllTransfer", NULL, NULL),
	GDBUS_METHOD("AddNotify", GDBUS_ARGS(_ARG("path", "s")), NULL),
	GDBUS_METHOD("RemoveFiles", GDBUS_ARGS(_ARG("agent", "o")), NULL),
	NULL
};

static const GDBusPropertyInfo * const _opp_property_info_pointers[] = {
	GDBUS_PROPERTY("address", "s",
		G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("name", "s",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("size", "t",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("transfer_id", "i",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("state", "i",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("percent", "d",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	GDBUS_PROPERTY("pid", "u",
			G_DBUS_PROPERTY_INFO_FLAGS_READABLE),
	NULL
};

static const GDBusInterfaceInfo _opp_interface_info =
{
	-1,
	(gchar *) "org.tizen.comms.opp",
	(GDBusMethodInfo **) &_method_info_pointers,
	NULL,
	(GDBusPropertyInfo **) &_opp_property_info_pointers,
	NULL
};

static GDBusInterfaceInfo *opp_skeleton_get_info(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceInfo *) &_opp_interface_info;
}

struct agent {
	gchar *owner;
	gchar *object_path;
	gchar *session;
	gchar *transfer_path;
	gchar *address;
	guint32 pid;
	guint32 uid;
	gint number;
	guint watch_id;
};

struct pending_files {
	gchar *owner;
	gchar *object_path;
	gchar *path;
	gchar *file_name;
};

struct opp_context {
	gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
	gpointer user_data;
};

struct opp_push_data {
	gchar *address;
	GDBusMethodInvocation *invocation;
	gboolean invocation_useable;
};

struct agent_reply_data {
	GDBusConnection *connection;
	GDBusMethodInvocation *invocation;
};

static GDBusObjectSkeleton *bt_object_skeleton;
static OppSkeleton *bt_opp;
static GDBusNodeInfo *opp_introspection_data;
static struct opp_context *opp_context;
static guint relay_agent_timeout_id;
static guint opp_agent_dbus_id;
static struct agent *relay_agent;
static struct agent *relay_client_agent;
static GDBusConnection *session_connection;

static GList *agent_list;
static GList *agent_server_list;
static GList *pending_push_data;
static GList *pending_p_list;

#define OBEX_ERROR_INTERFACE "org.bluez.obex.Error"

static void free_remove_relay_agent(void);
static void free_pending_files(struct pending_files *p_file);
static void free_relay_agent(struct agent *agent);
static void session_state_cb(const gchar *session_id,
				const gchar *session,
				enum session_state state,
				void *user_data,
				char *error_msg);
static struct agent *find_agent(GList *agent_l,
			const char *sender, const char *path);

static void bt_opp_register_dbus_interface(OppSkeleton *skeleton,
					GDBusConnection *connection)
{
	GDBusInterfaceSkeleton *opp_interface;

	opp_interface = G_DBUS_INTERFACE_SKELETON(skeleton);

	g_dbus_object_skeleton_add_interface(bt_object_skeleton,
							opp_interface);
}

static void bt_opp_unregister_dbus_interface()
{
	GDBusInterfaceSkeleton *opp_interface;

	opp_interface = G_DBUS_INTERFACE_SKELETON(bt_opp);
	g_dbus_object_skeleton_remove_interface(bt_object_skeleton,
							opp_interface);
}

static void destruct_opp_agent(GDBusConnection *connection)
{
	if (opp_agent_dbus_id > 0)
		g_dbus_connection_unregister_object(connection,
						opp_agent_dbus_id);

	g_dbus_node_info_unref(opp_introspection_data);
}

static guint32 get_connection_p_id(GDBusConnection *connection,
						const gchar *sender)
{
	GError *error = NULL;
	GVariant *pidvalue;
	guint32 pid;

	DBG("");

	pidvalue = g_dbus_connection_call_sync(connection,
				"org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus",
				"GetConnectionUnixProcessID",
				g_variant_new("(s)", sender),
				NULL, 0, -1, NULL, &error);

	if (pidvalue == NULL) {
		DBG("GetConnectionUnixUser: %s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_get(pidvalue, "(u)", &pid);
	g_variant_unref(pidvalue);

	return pid;
}

static guint32 get_connection_user_id(GDBusConnection *connection,
						const gchar *sender)
{
	GError *error = NULL;
	GVariant *uidvalue;
	guint32 uid;

	DBG("");

	uidvalue = g_dbus_connection_call_sync(connection,
				"org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus",
				"GetConnectionUnixUser",
				g_variant_new("(s)", sender),
				NULL, 0, -1, NULL, &error);

	if (uidvalue == NULL) {
		DBG("GetConnectionUnixUser: %s", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_get(uidvalue, "(u)", &uid);
	g_variant_unref(uidvalue);

	return uid;
}

static void handle_pushstatus(GVariant *parameters)
{
	GDBusConnection *connection;
	DBG("");

	connection = g_dbus_interface_skeleton_get_connection(
				G_DBUS_INTERFACE_SKELETON(bt_opp));

	g_dbus_connection_emit_signal(connection, NULL,
				"/org/tizen/comms/bluetooth",
				"org.freedesktop.DBus.Properties",
				"PropertiesChanged",
				parameters,
				NULL);

	return;
}

void send_pushstatus(char *destination, const char *name, guint64 size,
			guint transfer_id, enum transfer_state state,
					double percent, guint32 pid)
{
	GVariant *parameters;
	GVariantBuilder *builder;
	GVariant *val;

	DBG("");

	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	if (destination)
		val = g_variant_new("s", destination);
	else
		val = g_variant_new("s", "");
	g_variant_builder_add(builder, "{sv}", "address", val);
	if (name)
		val = g_variant_new("s", name);
	else
		val = g_variant_new("s", "");
	g_variant_builder_add(builder, "{sv}", "name", val);
	val = g_variant_new("t", size);
	g_variant_builder_add(builder, "{sv}", "size", val);
	val = g_variant_new("i", transfer_id);
	g_variant_builder_add(builder, "{sv}", "transfer_id", val);
	val = g_variant_new("i", state);
	g_variant_builder_add(builder, "{sv}", "state", val);
	val = g_variant_new("d", percent);
	g_variant_builder_add(builder, "{sv}", "percent", val);
	val = g_variant_new("u", pid);
	g_variant_builder_add(builder, "{sv}", "pid", val);

	parameters = g_variant_ref_sink(g_variant_new("(sa{sv}as)",
					"org.tizen.comms.opp",
					builder, NULL));

	handle_pushstatus(parameters);
}

static void transfer_watched_cb(
			const char *transfer_path,
			enum transfer_state state,
			const char *name,
			guint64 size,
			guint64 transferred,
			void *data,
			char *error_msg)
{
	struct pending_files *p_file = data;
	guint transfer_id;

	DBG("");

	transfer_id = obex_get_transfer_id(transfer_path, OBEX_CLIENT);

	DBG("state: %d, %d, %s, %ju", state, transfer_id,
						name, size);
	if (state == OBEX_TRANSFER_ERROR) {
		vertical_notify_bt_transfer(0);
		if (relay_client_agent)
			send_pushstatus(relay_client_agent->address,
				name, size, transfer_id, state, 0,
				relay_client_agent->pid);
		relay_client_agent->number = 0;
		goto done;
	}

	if (state == OBEX_TRANSFER_QUEUED) {
		vertical_notify_bt_transfer(0);
		if (relay_client_agent)
			send_pushstatus(relay_client_agent->address,
				name, size, transfer_id, state, 0,
				relay_client_agent->pid);
		return;
	}

	if (state == OBEX_TRANSFER_COMPLETE) {
		vertical_notify_bt_transfer(100);
		relay_client_agent->number--;
		goto done;
	}

	if (state == OBEX_TRANSFER_ACTIVE) {
		double percent = 0;

		DBG("transferred %ju, size %ju", transferred, size);
		percent = (double) transferred * 100 / size;

		vertical_notify_bt_transfer(percent);
		if (relay_client_agent)
			send_pushstatus(relay_client_agent->address,
				name, size, transfer_id, state, percent,
				relay_client_agent->pid);
		return;
	}
done:
	if (relay_client_agent) {
		if (state == OBEX_TRANSFER_COMPLETE)
			send_pushstatus(relay_client_agent->address,
					name, size, transfer_id, state,
					100, relay_client_agent->pid);
		if (!relay_client_agent->number)
			free_remove_relay_agent();
	}

	if (p_file) {
		pending_p_list = g_list_remove(pending_p_list, p_file);
		free_pending_files(p_file);
	}
}

static void transfer_server_watched_cb(
			const char *transfer_path,
			enum transfer_state state,
			const char *name,
			guint64 size,
			guint64 transferred,
			void *data,
			char *error_msg)
{
	guint transfer_id;

	DBG("");

	transfer_id = obex_get_transfer_id(transfer_path, OBEX_SERVER);

	if (relay_agent && !relay_agent->transfer_path)
		relay_agent->transfer_path = g_strdup(transfer_path);

	DBG("state: %d, %d, %s, %ju", state, transfer_id,
						name, size);

	if (state == OBEX_TRANSFER_ERROR) {
		vertical_notify_bt_transfer(0);
		if (relay_agent) {
			send_pushstatus(relay_agent->address,
				name, size, transfer_id, state, 0,
				relay_agent->pid);
			g_free(relay_agent->transfer_path);
			relay_agent->transfer_path = NULL;
		}
		return;
	}

	if (state == OBEX_TRANSFER_QUEUED) {
		vertical_notify_bt_transfer(0);
		if (relay_agent)
			send_pushstatus(relay_agent->address,
				name, size, transfer_id, state, 0,
				relay_agent->pid);
		return;
	}

	if (state == OBEX_TRANSFER_COMPLETE) {
		vertical_notify_bt_transfer(100);
		if (relay_agent) {
			send_pushstatus(relay_agent->address,
				name, size, transfer_id, state, 100,
				relay_agent->pid);
			g_free(relay_agent->transfer_path);
			relay_agent->transfer_path = NULL;
		}
		return;
	}

	if (state == OBEX_TRANSFER_ACTIVE) {
		double percent = 0;

		DBG("transferred %ju, size %ju", transferred, size);
		percent = (double) transferred * 100 / size;

		vertical_notify_bt_transfer(percent);
		if (relay_agent)
			send_pushstatus(relay_agent->address,
				name, size, transfer_id, state, percent,
				relay_agent->pid);
		return;
	}
}

static void register_obex_agent_cb(enum bluez_error_type type, void *user_data)
{
	GDBusConnection *connection = user_data;

	if (type != ERROR_NONE) {
		destruct_opp_agent(session_connection);

		g_object_unref(session_connection);

		g_object_unref(bt_opp);
		bt_opp = NULL;

		return;
	}

	bt_opp_register_dbus_interface(bt_opp, connection);
}

static void unregister_obex_agent_cb(enum bluez_error_type type, void *user_data)
{
	DBG("");

	if (type != ERROR_NONE)
		ERROR("unregister obex agent failed :%d", type);

	destruct_opp_agent(session_connection);

	bt_opp_unregister_dbus_interface();

	g_object_unref(session_connection);
	g_object_unref(bt_opp);
	bt_opp = NULL;
}

static void agent_request_release_reply(GObject *source_object,
					GAsyncResult *result,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	struct agent_reply_data *reply_data = user_data;

	ret = g_dbus_connection_call_finish(reply_data->connection,
							result, &error);

	g_dbus_method_invocation_return_value(reply_data->invocation, ret);

	g_free(reply_data);
}

static void authorize_push_reply(GObject *source_object,
					GAsyncResult *result,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	struct agent_reply_data *reply_data = user_data;

	ret = g_dbus_connection_call_finish(reply_data->connection,
							result, &error);

	if (ret == NULL) {
		WARN("%s", error->message);

		if (g_strrstr(error->message, "org.bluez.Error.Rejected"))
			g_dbus_method_invocation_return_dbus_error(
						reply_data->invocation,
						OBEX_ERROR_INTERFACE ".Rejected",
						"RejectByUser");
		else if (g_strrstr(error->message, "org.bluez.Error.Canceled"))
			g_dbus_method_invocation_return_dbus_error(
						reply_data->invocation,
						OBEX_ERROR_INTERFACE ".Cancel",
						"CancelByUser");
		else
			comms_error_failed(reply_data->invocation, "Failed");

		g_free(reply_data);
		return;
	}

	g_dbus_method_invocation_return_value(reply_data->invocation, ret);

	g_free(reply_data);
}

static void agent_request_cancel_reply(GObject *source_object,
					GAsyncResult *result,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	struct agent_reply_data *reply_data = user_data;

	ret = g_dbus_connection_call_finish(reply_data->connection,
							result, &error);

	g_dbus_method_invocation_return_value(reply_data->invocation, ret);

	g_free(reply_data);
}

static const gchar opp_introspection_xml[] =
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

static void handle_release(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	DBG("");

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_dbus_connection_call(connection,
				relay_agent->owner,
				relay_agent->object_path,
				AGENT_INTERFACE,
				"Release",
				NULL,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				agent_request_release_reply,
				reply_data);
}

static int get_privileges_uid(gchar *address)
{
	char file[FILENAME_LEN];
	char context[CONTEXT_LEN];
	char *path = getenv("HOME");
	int fd;
	struct user_privileges *privileges = NULL;
	int len;
	struct stat st;
	int privileges_uid;
	int ret;

	DBG("");

	sprintf(file, "%s/.bt_userprivileges", path);

	fd = open(file, O_RDONLY, S_IRUSR | S_IWUSR);

	if (fd < 0) {
		DBG("fd = %d", fd);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		DBG("privileges context error");
		return -1;
	}

	len = st.st_size;
	lseek(fd, 0, SEEK_SET);

	while (len >= CONTEXT_LEN) {
		memset(context, 0, CONTEXT_LEN);
		ret = read(fd, context, CONTEXT_LEN-2);
		if (ret <= 0) {
			DBG("read error");
			close(fd);
			return -1;
		}
		privileges = (struct user_privileges *)context;
		privileges->address[ADDRESS_LEN-1] = 0;
		privileges_uid = atoi(privileges->uid);
		if (!strcasecmp(address, privileges->address)) {
			DBG("find privileges matched user");
			close(fd);
			return privileges_uid;
		}
		len -= CONTEXT_LEN;
		lseek(fd, 2, SEEK_CUR);
	}

	close(fd);

	return -1;
}

static struct agent *find_server_agent(guint32 uid)
{
	struct agent *agent;
	GList *list, *next;

	DBG("uid = %d", uid);

	if (agent_server_list == NULL)
		return NULL;

	for (list = g_list_first(agent_server_list);
				list; list = next) {
		next = g_list_next(list);
		agent = list->data;

		if (agent && (agent->uid == uid))
			return agent;
	}

	return NULL;
}

void opp_set_adapter_connectable(gboolean connectable)
{
	DBG("");
	g_connectable = connectable;
}

static void handle_authorize_push(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;
	gchar *transfer_path = NULL;
	gchar *destination = NULL;
	gchar *name = NULL;
	guint64 size = 0;
	guint transfer_id = 0;
	int uid;
	GVariant *param;
	struct agent *agent = NULL;

	DBG("g_connectable = %d", g_connectable);

	if (!g_connectable) {
		g_dbus_method_invocation_return_dbus_error(
					invocation,
					OBEX_ERROR_INTERFACE ".Rejected",
					"RejectByUser");
		return;
	}

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_variant_get(parameters, "(o)", &transfer_path);

	obex_transfer_get_property_size(transfer_path, &size);
	name = obex_transfer_get_property_name(transfer_path);
	if (!name)
		name = "";
	destination = obex_transfer_get_property_destination(transfer_path);
	if (!destination)
		destination = "";
	transfer_id = obex_get_transfer_id(transfer_path, OBEX_SERVER);

	uid = get_privileges_uid(destination);
	DBG("destination = %s, uid = %d", destination, uid);

	if (uid > -1)
		agent = find_server_agent(uid);

	if (agent)
		relay_agent = agent;

	param = g_variant_new("(sssti)",
			destination, name, transfer_path, size, transfer_id);

	g_dbus_connection_call(connection,
				relay_agent->owner,
				relay_agent->object_path,
				AGENT_INTERFACE,
				"AuthorizePush",
				param,
				g_variant_type_new("(s)"),
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				authorize_push_reply,
				reply_data);
}

static void handle_cancel(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	DBG("");

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_dbus_connection_call(connection,
				relay_agent->owner,
				relay_agent->object_path,
				AGENT_INTERFACE,
				"Cancel",
				NULL,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				agent_request_cancel_reply,
				reply_data);
}

static void handle_opp_context(GDBusConnection *connection,
				struct opp_context *context)
{
	gchar *method_name = context->method_name;
	if (g_strcmp0(method_name, "Release") == 0)
		handle_release(connection,
				context->parameters,
				context->invocation,
				context->user_data);
	else if (g_strcmp0(method_name, "AuthorizePush") == 0)
		handle_authorize_push(connection,
				context->parameters,
				context->invocation,
				context->user_data);
	else if (g_strcmp0(method_name, "Cancel") == 0)
		handle_cancel(connection,
				context->parameters,
				context->invocation,
				context->user_data);
	else
		WARN("Unknown method %s", method_name);
}

static struct opp_context *create_opp_context(const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	struct opp_context *context;

	context = g_new0(struct opp_context, 1);
	if (context == NULL) {
		ERROR("no memroy");

		return NULL;
	}

	context->method_name = g_strdup(method_name);
	context->parameters = g_variant_ref_sink(parameters);
	context->invocation = invocation;
	context->user_data = user_data;

	return context;
}

static void free_opp_context(gpointer user_data)
{
	struct opp_context *context = user_data;

	g_free(context->method_name);
	g_variant_unref(context->parameters);

	g_free(context);
}

static gboolean relay_agent_timeout_cb(gpointer user_data)
{
	DBG("");

	comms_error_failed(opp_context->invocation, "Relay agent timeout");

	free_opp_context(opp_context);

	opp_context = NULL;

	return FALSE;
}

static void handle_opp_agent_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	opp_context = create_opp_context(method_name, parameters,
					invocation, user_data);

	if (relay_agent) {
		GDBusConnection *system_connection;

		system_connection = g_dbus_interface_skeleton_get_connection(
					G_DBUS_INTERFACE_SKELETON(bt_opp));

		handle_opp_context(system_connection, opp_context);

		free_opp_context(opp_context);

		opp_context = NULL;

		return;
	}

	vertical_notify_bt_opp_agent_on(NULL);

	relay_agent_timeout_id = g_timeout_add(500,
					relay_agent_timeout_cb, NULL);
}

static const GDBusInterfaceVTable opp_agent_vtable =
{
	handle_opp_agent_method_call,
	NULL,
	NULL
};

static gboolean create_opp_agent(GDBusConnection *connection)
{
	opp_introspection_data = g_dbus_node_info_new_for_xml(
						opp_introspection_xml, NULL);
	if (opp_introspection_data == NULL)
		return FALSE;

	opp_agent_dbus_id = g_dbus_connection_register_object(connection,
						OPP_AGENT_PATH,
						opp_introspection_data->interfaces[0],
						&opp_agent_vtable,
						NULL, NULL, NULL);
	if (opp_agent_dbus_id < 0) {
		ERROR("Register OPP Agent Failed");
		return FALSE;
	}

	return TRUE;
}

static struct pending_files *create_pending_files(const gchar *sender,
				const gchar *path, const gchar *file_name)
{
	struct pending_files *p_file;

	DBG("");

	p_file = g_new0(struct pending_files, 1);
	if (p_file == NULL) {
		ERROR("no memory");
		return NULL;
	}

	p_file->owner = g_strdup(sender);
	p_file->object_path = g_strdup(path);
	p_file->file_name = g_strdup(file_name);

	return p_file;
}

static void free_pending_files(struct pending_files *p_file)
{
	DBG("+");

	if (!p_file)
		return;

	if (p_file->owner)
		g_free(p_file->owner);
	if (p_file->object_path)
		g_free(p_file->object_path);
	if (p_file->file_name)
		g_free(p_file->file_name);
	if (p_file->path)
		g_free(p_file->path);
	g_free(p_file);
	p_file = NULL;

	DBG("-");
}

static void free_all_pending_files(void)
{
	GList *list, *next;
	struct pending_files *p_file;

	DBG("+");

	if (!pending_p_list ||
		g_list_length(pending_p_list) == 0)
		return;

	for (list = g_list_first(pending_p_list); list; list = next) {
		next = g_list_next(list);
		p_file = list->data;
		pending_p_list = g_list_remove(pending_p_list, p_file);
		if (p_file)
			free_pending_files(p_file);
	}

	pending_p_list = NULL;

	DBG("-");
}

static void free_remove_relay_agent(void)
{
	GList *list;

	DBG("");

	if (relay_client_agent) {
		if (relay_client_agent->session)
			obex_session_remove_session(
				relay_client_agent->session);
		free_relay_agent(relay_client_agent);
		relay_client_agent = NULL;
	}

	if (!agent_list)
		return;

	if (g_list_length(agent_list) > 0) {
		list = g_list_first(agent_list);
		relay_client_agent = list->data;
		agent_list = g_list_remove(
			agent_list, relay_client_agent);
		obex_create_session(relay_client_agent->address,
			OBEX_OPP, session_state_cb, NULL);
	}
}

static struct agent *create_relay_agent(const gchar *sender,
				const gchar *path, const gchar *address,
				guint32 pid, guint32 uid, guint watch_id)
{
	struct agent *agent;

	agent = g_new0(struct agent, 1);
	if (agent == NULL) {
		ERROR("no memory");
		return NULL;
	}

	agent->owner = g_strdup(sender);
	agent->object_path = g_strdup(path);
	agent->address = g_strdup(address);
	agent->watch_id = watch_id;
	agent->pid = pid;
	agent->uid = uid;

	return agent;
}

static void free_relay_agent(struct agent *agent)
{
	if (!agent)
		return;

	if (agent->owner)
		g_free(agent->owner);
	if (agent->object_path)
		g_free(agent->object_path);
	if (agent->session)
		g_free(agent->session);
	if (agent->transfer_path)
		g_free(agent->transfer_path);

	g_free(agent);
}

static void relay_agent_disconnected(GDBusConnection *connection,
					const gchar *name, gpointer user_data)
{
	struct agent *agent = (struct agent *)user_data;

	DBG("");

	if (agent == NULL || relay_agent == NULL)
		return;

	agent_server_list = g_list_remove(agent_server_list, agent);

	if (!g_strcmp0(agent->object_path, relay_agent->object_path) &&
			!g_strcmp0(agent->owner, relay_agent->owner)) {
		GList *next;
		next = g_list_last(agent_server_list);
		if (next)
			relay_agent = next->data;
		else
			relay_agent = NULL;
	}

	free_relay_agent(agent);

	agent = NULL;
}

static void relay_client_agent_disconnected(GDBusConnection *connection,
					const gchar *name, gpointer user_data)
{
	DBG("");

	if (!relay_client_agent)
		return;

	free_relay_agent(relay_client_agent);

	relay_client_agent = NULL;
}

static void register_relay_agent_handler(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	const gchar *sender;
	gchar *agent_path;
	guint relay_agent_watch_id = 0;
	guint32 uid, pid;
	struct agent *agent = NULL;

	DBG("");

	g_variant_get(parameters, "(o)", &agent_path);
	if (agent_path == NULL)
		return comms_error_invalid_args(invocation);

	sender = g_dbus_method_invocation_get_sender(invocation);
	uid = get_connection_user_id(connection, sender);

	agent = find_server_agent(uid);
	if (agent != NULL)
		return comms_error_already_done(invocation);

	pid = get_connection_p_id(connection, sender);

	relay_agent = create_relay_agent(sender, agent_path, NULL, pid,
					uid, relay_agent_watch_id);

	agent_server_list = g_list_append(agent_server_list, relay_agent);

	relay_agent_watch_id =
			g_bus_watch_name_on_connection(connection, sender,
					G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
					NULL, relay_agent_disconnected,
					(gpointer)relay_agent, NULL);

	relay_agent->watch_id = relay_agent_watch_id;

	if (relay_agent_timeout_id > 0) {
		g_source_remove(relay_agent_timeout_id);

		relay_agent_timeout_id = 0;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);

	if (!opp_context)
		return;

	handle_opp_context(connection, opp_context);

	free_opp_context(opp_context);

	opp_context = NULL;
}

static void unregister_relay_agent_handler(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	gchar *agent_path;
	const gchar *sender;
	struct agent *agent;

	DBG("");

	if (relay_agent == NULL)
		return comms_error_does_not_exist(invocation);

	sender = g_dbus_method_invocation_get_sender(invocation);

	g_variant_get(parameters, "(o)", &agent_path);
	if (agent_path == NULL)
		return comms_error_invalid_args(invocation);

	agent = find_agent(agent_server_list, sender, agent_path);
	if (agent == NULL) {
		DBG("can not find agent");
		return comms_error_does_not_exist(invocation);
	}

	agent_server_list = g_list_remove(agent_server_list, agent);

	if (!g_strcmp0(agent_path, relay_agent->object_path) &&
		!g_strcmp0(sender, relay_agent->owner)) {
		GList *next;
		g_bus_unwatch_name(relay_agent->watch_id);
		next = g_list_last(agent_server_list);
		if (next)
			relay_agent = next->data;
		else
			relay_agent = NULL;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);

	g_free(agent_path);

	free_relay_agent(agent);

	agent = NULL;
}

char *get_failed_content(const gchar *error_message)
{
	const gchar *title = "org.bluez.obex.Error.Failed: ";
	gchar *error_str = g_strrstr(error_message, title);

	if (error_str == NULL)
		return NULL;

	return error_str + strlen(title);
}

static void handle_error_message(GDBusMethodInvocation *invocation,
							char *error_msg)
{
	if (g_strrstr(error_msg, "org.bluez.obex.Error.InvalidArguments"))
		return comms_error_invalid_args(invocation);
	else if (g_strrstr(error_msg, "org.bluez.obex.Error.Failed")) {
		gchar *info = get_failed_content(error_msg);

		return comms_error_failed(invocation, info);
	} else
		WARN("Unknown error %s", error_msg);
}

static void transfer_state_cb(
			const char *transfer_path,
			enum transfer_state state,
			const char *name,
			guint64 size,
			guint64 transferred,
			void *data,
			char *error_msg)
{
	struct pending_files *p_file = data;

	DBG("transfer path %s", transfer_path);
	DBG("state %d", state);

	if (error_msg) {
		DBG("error = %s", error_msg);
		if (relay_client_agent)
			send_pushstatus(relay_client_agent->address,
				"", 0, 0, OBEX_TRANSFER_ERROR, 0,
				relay_client_agent->pid);
		free_all_pending_files();
		free_remove_relay_agent();
		return;
	}

	if (state == OBEX_TRANSFER_QUEUED) {
		if (p_file) {
			p_file->path = g_strdup(transfer_path);
			pending_p_list = g_list_append(pending_p_list, p_file);
		}
		obex_transfer_set_notify((char *)transfer_path,
						transfer_watched_cb, p_file);
	}
}

static void send_pending_push_data(void)
{
	struct pending_files *p_file;
	gboolean is_send = FALSE;
	GList *list, *next;

	DBG("");

	if (g_list_length(pending_push_data) == 0)
		return;

	for (list = g_list_first(pending_push_data); list; list = next) {
		next = g_list_next(list);
		p_file = list->data;

		if (!g_strcmp0(p_file->owner, relay_client_agent->owner) &&
					!g_strcmp0(p_file->object_path,
					relay_client_agent->object_path)) {
			DBG("send p_file->file_name = %s", p_file->file_name);
			relay_client_agent->number++;
			obex_session_opp_send_file(relay_client_agent->session,
						p_file->file_name,
						transfer_state_cb, p_file);
			pending_push_data =
				g_list_remove(pending_push_data, p_file);
			is_send = TRUE;
		}
	}

	if (is_send == FALSE)
		free_remove_relay_agent();
}

static void session_state_cb(const gchar *session_id,
				const gchar *session,
				enum session_state state,
				void *user_data,
				char *error_msg)
{
	gchar *name = "OBEX_TRANSFER_QUEUED";
	guint64 size = 0;
	guint transfer_id = 0;
	struct opp_push_data *push_data = user_data;

	DBG("%s", error_msg);

	if (error_msg) {
		DBG("error = %s", error_msg);
		if (push_data) {
			handle_error_message(
				push_data->invocation, error_msg);
			g_free(push_data);
		}
		if (relay_client_agent)
			send_pushstatus(relay_client_agent->address,
				"", 0, 0, OBEX_TRANSFER_ERROR, 0,
				relay_client_agent->pid);
		free_remove_relay_agent();
		return;
	}

	if (relay_client_agent) {
		send_pushstatus(relay_client_agent->address, name, size,
					transfer_id, OBEX_TRANSFER_QUEUED, 0,
					relay_client_agent->pid);

		DBG("session = %s", session);
		relay_client_agent->session = g_strdup(session);

		if (g_list_length(pending_push_data) > 0)
			send_pending_push_data();
	}

	if (push_data) {
		g_dbus_method_invocation_return_value(
					push_data->invocation, NULL);
		g_free(push_data);
	}
}

static struct agent *find_agent(GList *agent_l,
			const char *sender, const char *path)
{
	struct agent *agent;
	GList *list, *next;

	DBG("sender = %s, path = %s", sender, path);

	if (agent_l == NULL)
		return NULL;

	for (list = g_list_first(agent_l); list; list = next) {
		next = g_list_next(list);

		agent = list->data;

		if (agent && !g_strcmp0(agent->owner, sender)
				&& !g_strcmp0(agent->object_path, path))
			return agent;
	}

	return NULL;
}

static gboolean find_pending_files(const char *sender, const char *path)
{
	struct pending_files *p_file;
	GList *list, *next;

	DBG("sender = %s, path = %s", sender, path);

	if (pending_push_data == NULL)
		return FALSE;

	for (list = g_list_first(pending_push_data); list; list = next) {
		next = g_list_next(list);

		p_file = list->data;

		if (p_file && !g_strcmp0(p_file->owner, sender)
				&& !g_strcmp0(p_file->object_path, path))
			return TRUE;
	}

	return FALSE;
}

static struct agent *create_relay_client_agent(GDBusConnection *connection,
				const gchar *sender, const gchar *address,
				const gchar *agent, guint32 pid)
{
	guint relay_agent_watch_id;
	struct agent *client_agent;

	relay_agent_watch_id =
			g_bus_watch_name_on_connection(connection, sender,
					G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
					NULL, relay_client_agent_disconnected,
					NULL, NULL);

	client_agent = create_relay_agent(sender, agent, address, pid, 0,
							relay_agent_watch_id);

	return client_agent;
}


static void remove_file_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent *agent;
	const gchar *sender, *path;
	struct pending_files *p_file;
	GList *list, *next;

	sender = g_dbus_method_invocation_get_sender(invocation);

	DBG("sender = %s", sender);

	if (agent_list == NULL)
		return comms_error_failed(invocation, "Failed");

	g_variant_get(parameters, "(o)", &path);

	for (list = g_list_first(agent_list); list; list = next) {
		next = g_list_next(list);
		agent = list->data;

		if (agent && !g_strcmp0(agent->owner, sender)
			&& !g_strcmp0(agent->object_path, path)) {
			agent_list = g_list_remove(agent_list, agent);
			free_relay_agent(agent);
			agent = NULL;
			break;
		}
	}

	for (list = g_list_first(pending_push_data); list; list = next) {
		next = g_list_next(list);

		p_file = list->data;
		if (p_file && !g_strcmp0(p_file->owner, sender)
				&& !g_strcmp0(p_file->object_path, path)) {
			pending_push_data =
				g_list_remove(pending_push_data, p_file);
			free_pending_files(p_file);
		}
	}

	return g_dbus_method_invocation_return_value(invocation, NULL);
}

static void add_file_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	const gchar *file_name;
	const gchar *agent;
	const gchar *sender;
	struct pending_files *p_file;

	DBG("");

	sender = g_dbus_method_invocation_get_sender(invocation);

	g_variant_get(parameters, "(so)", &file_name, &agent);

	DBG("file_name = %s, agent = %s", file_name, agent);

	if (agent == NULL || file_name == NULL) {
		comms_error_invalid_args(invocation);
		return;
	}

	p_file = create_pending_files(sender, agent, file_name);
	if (p_file)
		pending_push_data = g_list_append(pending_push_data, p_file);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void send_file_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct opp_push_data *data;
	gchar *address;
	const gchar *agent;
	const gchar *sender;
	struct agent *client_agent;
	guint32 pid = 0;

	DBG("");

	sender = g_dbus_method_invocation_get_sender(invocation);
	g_variant_get(parameters, "(so)", &address, &agent);

	DBG("sender = %s", sender);

	pid = get_connection_p_id(connection, sender);

	if (address == NULL) {
		comms_error_invalid_args(invocation);
		return;
	}

	if (find_pending_files(sender, agent) == FALSE)
		return comms_error_not_available(invocation);

	if (relay_client_agent == NULL) {
		relay_client_agent =
			create_relay_client_agent(connection, sender,
						address, agent, pid);
		if (!relay_client_agent)
			return comms_error_not_available(invocation);
	} else if (g_strcmp0(relay_client_agent->owner, sender) != 0) {
		client_agent = find_agent(agent_list, sender, agent);
		if (!client_agent) {
			client_agent =
				create_relay_client_agent(connection, sender,
							address, agent, pid);
			if (!client_agent)
				return comms_error_not_available(invocation);
			agent_list = g_list_append(agent_list, client_agent);
		}
		return comms_error_in_progress(invocation);
	} else
		return comms_error_in_progress(invocation);

	data = g_new0(struct opp_push_data, 1);
	if (data == NULL) {
		ERROR("no memory");
		return;
	}

	data->address = address;
	data->invocation = invocation;
	data->invocation_useable = TRUE;

	obex_create_session(address, OBEX_OPP, session_state_cb, data);
}

static void add_notify(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	const gchar *sender;
	gchar *path;

	DBG("+");

	if (!relay_agent) {
		comms_error_not_available(invocation);
		return;
	}

	sender = g_dbus_method_invocation_get_sender(invocation);

	if (g_strcmp0(relay_agent->owner, sender) != 0) {
		comms_error_not_available(invocation);
		return;
	}

	g_variant_get(parameters, "(s)", &path);

	obex_transfer_set_notify(path, transfer_server_watched_cb, NULL);

	g_dbus_method_invocation_return_value(invocation, NULL);

	DBG("-");
}

static void cancel_transfer_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	const gchar *sender;
	gchar *name;
	guint transfer_id, agent_id = 0;

	DBG("");

	if (!relay_agent) {
		comms_error_not_available(invocation);
		return;
	}

	sender = g_dbus_method_invocation_get_sender(invocation);

	if (g_strcmp0(relay_agent->owner, sender) != 0) {
		comms_error_not_available(invocation);
		return;
	}

	g_variant_get(parameters, "(i)", &transfer_id);

	if (relay_agent && relay_agent->transfer_path)
		agent_id = obex_get_transfer_id(
			relay_agent->transfer_path, OBEX_SERVER);
	else {
		comms_error_not_available(invocation);
		return;
	}

	if (transfer_id == agent_id) {
		name = obex_transfer_get_property_name(
					relay_agent->transfer_path);
		if (!name)
			name = "";
		obex_transfer_cancel(relay_agent->transfer_path);
		send_pushstatus(relay_agent->address,
			name, 0, transfer_id, OBEX_TRANSFER_CANCELED,
			0, relay_agent->pid);
		obex_transfer_clear_notify(relay_agent->transfer_path);
	} else {
		comms_error_not_available(invocation);
		return;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void cancel_all_transfer_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	const gchar *sender;
	struct pending_files *p_file;
	guint transfer_id;
	GList *list, *next;

	DBG("+");

	if (!relay_client_agent) {
		comms_error_not_available(invocation);
		return;
	}

	sender = g_dbus_method_invocation_get_sender(invocation);

	if (g_strcmp0(relay_client_agent->owner, sender) != 0) {
		comms_error_not_available(invocation);
		return;
	}

	if (!pending_p_list || !g_list_length(pending_p_list))
		return g_dbus_method_invocation_return_value(
						invocation, NULL);

	for (list = g_list_first(pending_p_list); list; list = next) {
		p_file = list->data;
		next = g_list_next(list);

		if (p_file == NULL)
			continue;

		if (p_file->path)
			obex_transfer_cancel(p_file->path);
	}

	if (relay_client_agent) {
		obex_session_remove_session(
					relay_client_agent->session);

		for (list = g_list_first(pending_p_list); list; list = next) {
			p_file = list->data;
			next = g_list_next(list);

			if (p_file == NULL)
				continue;

			if (p_file->path) {
				transfer_id = obex_get_transfer_id(
						p_file->path, OBEX_CLIENT);
				send_pushstatus(relay_client_agent->address,
					p_file->file_name, 0, transfer_id,
					OBEX_TRANSFER_CANCELED, 0,
					relay_client_agent->pid);
				obex_transfer_clear_notify(p_file->path);
			}
			free_pending_files(p_file);
		}

		free_relay_agent(relay_client_agent);
		relay_client_agent = NULL;
	}

	if (g_list_length(agent_list) > 0) {
		list = g_list_first(agent_list);
		relay_client_agent = list->data;
		agent_list = g_list_remove(agent_list, relay_client_agent);
		obex_create_session(relay_client_agent->address,
					OBEX_OPP, session_state_cb, NULL);
	}

	g_dbus_method_invocation_return_value(invocation, NULL);

	DBG("-");
}

static void _opp_skeleton_handle_method_call(
				GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	if (g_strcmp0(method_name, "RegisterObexAgent") == 0)
		register_relay_agent_handler(connection,
						parameters,
						invocation,
						user_data);
	else if (g_strcmp0(method_name, "UnregisterObexAgent") == 0)
		unregister_relay_agent_handler(connection,
						parameters,
						invocation,
						user_data);
	else if (g_strcmp0(method_name, "SendFile") == 0)
		send_file_handler(connection, parameters,
					invocation, user_data);
	else if (g_strcmp0(method_name, "AddFile") == 0)
		add_file_handler(connection, parameters,
					invocation, user_data);
	else if (g_strcmp0(method_name, "RemoveFiles") == 0)
		remove_file_handler(connection, parameters,
					invocation, user_data);
	else if (g_strcmp0(method_name, "CancelTransfer") == 0)
		cancel_transfer_handler(connection, parameters,
					invocation, user_data);
	else if (g_strcmp0(method_name, "CancelAllTransfer") == 0)
		cancel_all_transfer_handler(connection, parameters,
					invocation, user_data);
	else if (g_strcmp0(method_name, "AddNotify") == 0)
		add_notify(connection, parameters,
					invocation, user_data);
	else
		ERROR("Unknown method");
} 

static const GDBusInterfaceVTable _opp_skeleton_vtable =
{
	_opp_skeleton_handle_method_call,
	NULL,
	NULL
};

static GDBusInterfaceVTable *opp_skeleton_get_vtable(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceVTable *) &_opp_skeleton_vtable;
}

static GVariant *opp_skeleton_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	GVariantBuilder builder;

	DBG("");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	return g_variant_builder_end (&builder);
}

static void opp_skeleton_class_init(OppSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *skeleton_class;

	DBG("");

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = opp_skeleton_finalize;

	skeleton_class = G_DBUS_INTERFACE_SKELETON_CLASS(klass);

	skeleton_class->get_info = opp_skeleton_get_info;
	skeleton_class->get_vtable = opp_skeleton_get_vtable;
	skeleton_class->get_properties = opp_skeleton_get_properties;
}

OppSkeleton *bt_service_opp_new(void)
{
	DBG("");
	return g_object_new(TYPE_OPP_SKELETON, NULL);
}

static void obex_agent_added_cb(void *user_data)
{
	GDBusConnection *connection = user_data;

	obex_agent_unset_agent_added();

	if (create_opp_agent(session_connection) == FALSE) {
		g_object_unref(session_connection);
		g_object_unref(bt_opp);
		bt_opp = NULL;

		return;
	}

	obex_agent_register_agent(OPP_AGENT_PATH,
				register_obex_agent_cb,
				connection);
}

void bt_service_opp_init(GDBusObjectSkeleton *gdbus_object_skeleton,
						GDBusConnection *connection)
{
	GError *error = NULL;
	int opp_startup;

	DBG("");

	if (bt_opp)
		return;

	bt_object_skeleton = gdbus_object_skeleton;

	g_connectable = TRUE;

	session_connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (session_connection == NULL) {
		ERROR("%s", error->message);

		g_error_free(error);
		return;
	}

	bt_opp = bt_service_opp_new();

	opp_startup = obex_agent_get_agent();
	if (!opp_startup) {
		obex_agent_set_agent_added(obex_agent_added_cb,
						connection);

		return;
	}

	if (create_opp_agent(session_connection) == FALSE) {
		g_object_unref(session_connection);
		g_object_unref(bt_opp);
		bt_opp = NULL;

		return;
	}

	obex_agent_register_agent(OPP_AGENT_PATH,
				register_obex_agent_cb,
				connection);

#ifdef TIZEN_3
	ERROR("popups app registers the opp agent here");
	struct opp_context *context;

	context = g_new0(struct opp_context, 1);
	if (context == NULL) {
		ERROR("no memroy");
		return;
	}
	context->method_name = "RegisterOppAgent";

	vertical_notify_bt_opp_agent_on(context);

	g_free(context);
#endif
}

void bt_service_opp_deinit(void)
{
	GDBusConnection *connection;

	DBG("");

	if (bt_opp == NULL)
		return;

	connection = g_dbus_interface_skeleton_get_connection(
				G_DBUS_INTERFACE_SKELETON(bt_opp));

	obex_agent_unregister_agent(OPP_AGENT_PATH,
				unregister_obex_agent_cb,
				connection);
}

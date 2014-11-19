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

#include <string.h>
#include "obex.h"
#include "comms_error.h"
#include "gdbus.h"
#include "opp.h"
#include "vertical.h"

#define OPP_OBJECT "/org/tizen/comms/bluetooth"
#define AGENT_INTERFACE "org.bluez.obex.Agent1"
#define OPP_AGENT_PATH OPP_OBJECT "/agent/opp"

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
	GDBUS_METHOD("SendFile", GDBUS_ARGS(_ARG("remote_address", "s"),
						_ARG("sourcefile", "s"),
						_ARG("agent", "o")),
				GDBUS_ARGS(_ARG("transfer_id", "i"))),
	GDBUS_METHOD("CancelTransfer", GDBUS_ARGS(_ARG("transfer_id", "i")), NULL),
	GDBUS_METHOD("CancelAllTransfer", NULL, NULL),
	GDBUS_METHOD("AddNotify", GDBUS_ARGS(_ARG("path", "s")), NULL),
	NULL
};

static const GDBusInterfaceInfo _opp_interface_info =
{
	-1,
	(gchar *) "org.tizen.comms.opp",
	(GDBusMethodInfo **) &_method_info_pointers,
	NULL,
	NULL,
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
	guint watch_id;
};

struct opp_context {
	gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
	gpointer user_data;
};

struct agent_reply_data {
	GDBusConnection *connection;
	GDBusMethodInvocation *invocation;
};

struct opp_push_data {
	struct _obex_session *session;
	gchar *address;
	gchar *file_name;
	GDBusMethodInvocation *invocation;
	gboolean invocation_useable;
};

static GDBusObjectSkeleton *bt_object_skeleton;
static OppSkeleton *bt_opp;
static GDBusNodeInfo *opp_introspection_data;
static struct opp_context *opp_context;
static guint relay_agent_timeout_id;
static guint opp_agent_dbus_id;
static struct agent *relay_agent;
static struct agent *relay_client_agent;
static obex_agent_t *obex_agent;
static GDBusConnection *session_connection;

#define OBEX_ERROR_INTERFACE "org.bluez.obex.Error"

static void free_relay_agent(struct agent *agent);

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

static void handle_pushstatus(GVariant *parameters,
						gboolean is_server)
{
	GDBusConnection *conn = get_system_lib_dbus_connect();

	if (conn == NULL)
		return;

	if (is_server) {
		g_dbus_connection_call(conn,
				relay_agent->owner,
				relay_agent->object_path,
				AGENT_INTERFACE,
				"PushStatus",
				parameters, NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL, NULL, NULL);
	} else {
		g_dbus_connection_call(conn,
				relay_client_agent->owner,
				relay_client_agent->object_path,
				AGENT_INTERFACE,
				"PushStatus",
				parameters, NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL, NULL, NULL);
	}
}

void send_pushstatus(char *destination, char *name, guint64 size,
	guint transfer_id, enum transfer_state state, double percent)
{
	GVariant *parameters;

	DBG("");

	parameters = g_variant_new("(sstiid)", destination,
				name, size, transfer_id, state, percent);

	if (transfer_id < 10000) {
		if (relay_client_agent)
			handle_pushstatus(parameters, FALSE);
		else
			return;
	} else {
		if (relay_agent)
			handle_pushstatus(parameters, TRUE);
		else
			return;
	}
}

static void transfer_watched_cb(
			const char *transfer_path,
			struct _obex_transfer *transfer,
			enum transfer_state state,
			guint64 transferred,
			void *data,
			char *error_msg)
{
	gchar *name = "", *dest = "";
	guint64 size = 0;
	guint transfer_id;

	transfer_id = obex_transfer_get_id(transfer);
	dest = obex_transfer_get_property_destination(transfer);

	if (state == OBEX_TRANSFER_QUEUED ||
				state == OBEX_TRANSFER_ACTIVE) {
		name = obex_transfer_get_name(transfer);
		obex_transfer_get_size(transfer, &size);
	}

	DBG("state: %d, %d, %s, %s, %ju", state, transfer_id,
						name, dest, size);
	if (state == OBEX_TRANSFER_ERROR ||
		state == OBEX_TRANSFER_CANCELED ||
				state == OBEX_TRANSFER_UNKNOWN) {
		vertical_notify_bt_transfer(dest, name,
						size, transfer_id, -1);
		send_pushstatus(dest, name, size, transfer_id, state, 0);
		goto done;
	}

	if (state == OBEX_TRANSFER_QUEUED) {
		vertical_notify_bt_transfer(dest, name,
						size, transfer_id, 0);
		if (transfer_id >= 10000)
			send_pushstatus(dest, name,
					size, transfer_id, state, 0);
		return;
	}

	if (state == OBEX_TRANSFER_COMPLETE) {
		vertical_notify_bt_transfer(dest, name,
					size, transfer_id, 100);
		if (transfer_id >= 10000)
			send_pushstatus(dest, name,
					size, transfer_id, state, 0);
		goto done;
	}

	if (state == OBEX_TRANSFER_ACTIVE && transfer) {
		double percent = 0;

		DBG("transferred %ju, size %ju", transferred, size);
		percent = (double) transferred * 100 / size;

		vertical_notify_bt_transfer(dest, name,
					size, transfer_id, percent);
		send_pushstatus(dest, name,
					size, transfer_id, state, percent);
		return;
	}
done:

	if (transfer_id < 10000) {
		struct opp_push_data *push_data = data;
		int client_num = 0;

		client_num = obex_transfer_client_number();

		if (client_num <= 1) {
			obex_session_remove_session(push_data->session);
			if (relay_client_agent)
				free_relay_agent(relay_client_agent);
			relay_client_agent = NULL;
			if (state == OBEX_TRANSFER_COMPLETE)
				send_pushstatus(dest, name, size,
						transfer_id, state, 100);
		}
		g_free(push_data);
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

static void handle_authorize_push(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;
	gchar *transfer_path = NULL;
	obex_transfer_t *transfer;
	gchar *destination = NULL;
	gchar *name = NULL;
	guint64 size = 0;
	guint transfer_id = 0;
	GVariant *param;

	DBG("");

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_variant_get(parameters, "(o)", &transfer_path);

	transfer = obex_transfer_get_transfer_from_path(
					(const gchar *) transfer_path);

	if (transfer != NULL) {

		obex_transfer_get_size(transfer, &size);
		name = obex_transfer_get_name(transfer);
		destination = obex_transfer_get_property_destination(transfer);
		transfer_id = obex_transfer_get_id(transfer);
	}

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

	vertical_notify_bt_opp_agent_on();

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

static struct agent *create_relay_agent(const gchar *sender,
					const gchar *path, guint watch_id)
{
	struct agent *agent;

	agent = g_new0(struct agent, 1);
	if (agent == NULL) {
		ERROR("no memory");
		return NULL;
	}

	agent->owner = g_strdup(sender);
	agent->object_path = g_strdup(path);
	agent->watch_id = watch_id;

	return agent;
}

static void free_relay_agent(struct agent *agent)
{
	g_free(agent->owner);
	g_free(agent->object_path);

	g_free(agent);
}

static void relay_agent_disconnected(GDBusConnection *connection,
					const gchar *name, gpointer user_data)
{
	DBG("");

	if (!relay_agent)
		return;

	free_relay_agent(relay_agent);

	relay_agent = NULL;
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
	guint relay_agent_watch_id;

	DBG("");

	if (relay_agent)
		return comms_error_already_exists(invocation);

	g_variant_get(parameters, "(o)", &agent_path);
	if (agent_path == NULL)
		return comms_error_invalid_args(invocation);

	sender = g_dbus_method_invocation_get_sender(invocation);

	relay_agent_watch_id =
			g_bus_watch_name_on_connection(connection, sender,
					G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
					NULL, relay_agent_disconnected,
					NULL, NULL);

	relay_agent = create_relay_agent(sender, agent_path,
						relay_agent_watch_id);

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

	DBG("");

	if (relay_agent == NULL)
		return comms_error_does_not_exist(invocation);

	g_variant_get(parameters, "(o)", &agent_path);
	if (agent_path == NULL)
		return comms_error_invalid_args(invocation);

	if (g_strcmp0(relay_agent->object_path, agent_path))
		return comms_error_invalid_args(invocation);

	g_dbus_method_invocation_return_value(invocation, NULL);

	g_free(agent_path);

	free_relay_agent(relay_agent);
	relay_agent = NULL;
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

static void transfer_state_cb(const gchar *transfer_path,
				obex_transfer_t *transfer,
				enum transfer_state state,
				guint64 transferred,
				void *data,
				char *error_msg)
{
	GVariant *ret;
	guint transfer_id;
	struct opp_push_data *push_data = data;

	DBG("transfer path %s", transfer_path);
	DBG("transfer %p", transfer);
	DBG("state %d", state);

	if (state == OBEX_TRANSFER_QUEUED) {
		transfer_id = -1;

		obex_transfer_set_notify((char *)transfer_path,
					transfer_watched_cb, push_data);
		transfer_id =
			obex_get_transferid_from_path(OBEX_CLIENT,
						transfer_path);

		ret = g_variant_new("(i)", transfer_id);

		DBG("transfer_id = %d", transfer_id);

		g_dbus_method_invocation_return_value(
					push_data->invocation, ret);

		DBG("");
		return;

	} else {
		comms_error_failed(push_data->invocation, "Failed");
	}
}

static GList *pending_push_data;

static void send_pending_push_data(struct _obex_session *session)
{
	struct opp_push_data *push_data;
	GList *list, *next;

	for (list = g_list_first(pending_push_data); list; list = next) {
		next = g_list_next(list);

		push_data = list->data;

		push_data->session = session;

		obex_session_opp_send_file(session, push_data->file_name,
						transfer_state_cb, push_data);
	}

	g_list_free(pending_push_data);
	pending_push_data = NULL;
}

static void reply_pending_push_data(char *error_msg)
{
	struct opp_push_data *push_data;
	GList *list, *next;

	for (list = g_list_first(pending_push_data); list; list = next) {
		next = g_list_next(list);

		push_data = list->data;

		handle_error_message(push_data->invocation, error_msg);

		g_free(push_data);
	}

	g_list_free(pending_push_data);
	pending_push_data = NULL;
}

static void session_state_cb(const gchar *session_id,
				struct _obex_session *session,
				enum session_state state,
				void *user_data,
				char *error_msg)
{
	GVariant *parameters;
	gchar *name = "OBEX_TRANSFER_QUEUED";
	guint64 size = 0;
	guint transfer_id = 0;
	struct opp_push_data *push_data = user_data;

	DBG("%s", error_msg);
	if (error_msg) {
		handle_error_message(push_data->invocation, error_msg);

		reply_pending_push_data(error_msg);

		return;
	}

	if (state == OBEX_SESSION_RETRY) {
		pending_push_data = g_list_append(pending_push_data,
							push_data);

		return;
	}

	push_data->session = session;

	if (relay_client_agent) {
		parameters = g_variant_new("(sstiid)", push_data->address,
			name, size, transfer_id, OBEX_TRANSFER_QUEUED, 0);
		handle_pushstatus(parameters, FALSE);
	}

	obex_session_opp_send_file(session, push_data->file_name,
					transfer_state_cb, push_data);

	if (g_list_length(pending_push_data) > 0)
		send_pending_push_data(session);
}

static void send_file_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct opp_push_data *data;
	gchar *address, *file_name;
	const gchar *agent;
	const gchar *sender;
	guint relay_agent_watch_id;

	DBG("");

	sender = g_dbus_method_invocation_get_sender(invocation);

	g_variant_get(parameters, "(sso)", &address, &file_name, &agent);

	DBG("sender = %s", sender);

	if (relay_client_agent) {
		if (g_strcmp0(relay_client_agent->owner, sender) != 0)
			return comms_error_already_exists(invocation);
	} else {
		relay_agent_watch_id =
			g_bus_watch_name_on_connection(connection, sender,
					G_BUS_NAME_WATCHER_FLAGS_AUTO_START,
					NULL, relay_client_agent_disconnected,
					NULL, NULL);

		relay_client_agent = create_relay_agent(sender, agent,
							relay_agent_watch_id);
		if (!relay_client_agent)
			return comms_error_not_available(invocation);
	}

	if (address == NULL || file_name == NULL) {
		comms_error_invalid_args(invocation);

		return;
	}

	data = g_new0(struct opp_push_data, 1);
	if (data == NULL) {
		ERROR("no memory");
		return;
	}

	data->address = address;
	data->file_name = file_name;
	data->invocation = invocation;
	data->invocation_useable = TRUE;

	obex_create_session(address, OBEX_OPP,
				session_state_cb, data);
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

	obex_transfer_set_notify(path, transfer_watched_cb, NULL);

	g_dbus_method_invocation_return_value(invocation, NULL);

	DBG("-");
}

static void cancel_transfer_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	const gchar *sender;
	obex_transfer_t *transfer;
	guint transfer_id;

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

	transfer = obex_transfer_get_transfer_from_id(transfer_id);
	if (transfer == NULL)
		comms_error_does_not_exist(invocation);

	obex_transfer_cancel(transfer);

	g_dbus_method_invocation_return_value(invocation, NULL);

	DBG("");
}

static void cancel_all_transfer_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	obex_transfer_t *transfer;
	guint transfer_id;
	GList *transfer_list;
	GList *list, *next;

	DBG("");

	transfer_list = (GList *)obex_transfer_get_pathes();

	for (list = g_list_first(transfer_list); list; list = next) {
		transfer = list->data;
		next = g_list_next(list);

		if (transfer == NULL)
			continue;

		transfer_id = obex_transfer_get_id(transfer);

		if (transfer_id < 10000)
			obex_transfer_cancel(transfer);
	}

	g_dbus_method_invocation_return_value(invocation, NULL);
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

static void obex_agent_added_cb(obex_agent_t *agent, void *user_data)
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

	DBG("");

	if (bt_opp)
		return;

	bt_object_skeleton = gdbus_object_skeleton;

	session_connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (session_connection == NULL) {
		ERROR("%s", error->message);

		g_error_free(error);
		return;
	}

	bt_opp = bt_service_opp_new();

	obex_agent = obex_agent_get_agent();
	if (obex_agent == NULL) {
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

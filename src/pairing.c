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

#include <gio/gunixfdlist.h>
#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "pairing.h"
#include "vertical.h"

#define BLUETOOTH_OBJECT "/org/tizen/comms/bluetooth"

#define AGENT_INTERFACE "org.bluez.Agent1"

#define PAIRING_AGENT_PATH BLUETOOTH_OBJECT "/agent/pairing"

static const GDBusMethodInfo *_pairing_method_info_pointers[] =
{
	GDBUS_METHOD("RegisterPairingAgent",
				GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("UnregisterPairingAgent",
				GDBUS_ARGS(_ARG("agent", "o")), NULL),
	GDBUS_METHOD("Pair", GDBUS_ARGS(_ARG("address", "s")), NULL),
	GDBUS_METHOD("CancelPairing", NULL, NULL),
	NULL
};

static const GDBusInterfaceInfo _pairing_interface_info =
{
	-1,
	"org.tizen.comms.pairing",
	(GDBusMethodInfo **) &_pairing_method_info_pointers,
	NULL,
	NULL,
	NULL
};

G_DEFINE_TYPE(PairingSkeleton, pairing_skeleton,
			G_TYPE_DBUS_INTERFACE_SKELETON);

static GDBusInterfaceInfo *pairing_skeleton_dbus_interface_get_info(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceInfo *) &_pairing_interface_info;
}

struct agent {
	gchar *owner;
	gchar *object_path;
	guint watch_id;
};

struct pairing_context {
	gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
	gpointer user_data;
};

struct agent_reply_data {
	GDBusConnection *connection;
	GDBusMethodInvocation *invocation;
};

static GDBusObjectSkeleton *bt_object_skeleton;
static bluez_adapter_t *default_adapter;
static struct agent *relay_agent;
static struct pairing_context *pairing_context;
static guint relay_agent_timeout_id;
static PairingSkeleton *bt_pairing;
static bluez_agent_t *bluez_agent;
static guint pairing_agent_dbus_id;
static GDBusNodeInfo *pairing_introspection_data;
static gchar *pairing_device_address;

static void bt_pairing_register_dbus_interface(PairingSkeleton *skeleton,
						GDBusConnection *connection)
{
	GDBusInterfaceSkeleton *pairing_interface;

	DBG("");

	pairing_interface = G_DBUS_INTERFACE_SKELETON(skeleton);

	g_dbus_object_skeleton_add_interface(bt_object_skeleton,
						pairing_interface);
}

static void bt_pairing_unregister_dbus_interface()
{
	GDBusInterfaceSkeleton *pairing_interface;

	pairing_interface = G_DBUS_INTERFACE_SKELETON(bt_pairing);

	g_dbus_object_skeleton_remove_interface(bt_object_skeleton,
							pairing_interface);
}

static void destruct_pairing_agent(GDBusConnection *connection)
{
	if (pairing_agent_dbus_id) {
		g_dbus_connection_unregister_object(connection,
						pairing_agent_dbus_id);
		pairing_agent_dbus_id = 0;
	}

	g_dbus_node_info_unref(pairing_introspection_data);
}

static void handle_error_message(GDBusMethodInvocation *invocation,
						enum bluez_error_type type)
{
	switch (type) {
	case ERROR_DOES_NOT_EXIST:
		comms_error_does_not_exist(invocation);
		break;
	case ERROR_INVALID_ARGUMENTS:
		comms_error_invalid_args(invocation);
		break;
	case ERROR_ALREADY_EXISTS:
		comms_error_already_exists(invocation);
		break;
	case ERROR_AUTH_CANCELED:
		g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AuthenticationCanceled",
				"Authentication Canceled");
		break;
	case ERROR_AUTH_REJECT:
		g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AuthenticationRejected",
				"Authentication Canceled");
		break;
	case ERROR_AUTH_ATTEMPT_FAILED:
		g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				"Page Timeout");
		break;
	case ERROR_AUTH_TIMEOUT:
		g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AuthenticationTimeout",
				"Authentication Timeout");
		break;
	case ERROR_AUTH_FAILED:
		g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AuthenticationFailed",
				"Authentication Failed");
		break;
	default:
		WARN("Unknown error type %d", type);
		break;
	}
}

static void register_pairing_agent_cb(enum bluez_error_type type, void *user_data)
{
	GDBusConnection *connection = user_data;

	DBG("");
	if (type != ERROR_NONE) {
		ERROR("Register pairing agent failed %d", type);

		destruct_pairing_agent(connection);

		g_object_unref(bt_pairing);
		bt_pairing = NULL;

		return;
	}

	bluez_agent_request_default_agent(PAIRING_AGENT_PATH);

	bt_pairing_register_dbus_interface(bt_pairing, connection);
}

static void unregister_pairing_agent_cb(enum bluez_error_type type, void *user_data)
{
	GDBusConnection *connection = user_data;

	if (type != ERROR_NONE)
		DBG("%d", type);

	destruct_pairing_agent(connection);

	bt_pairing_unregister_dbus_interface();

	g_object_unref(bt_pairing);
	bt_pairing = NULL;
}

static void relay_agent_reply(GObject *source_object, GAsyncResult *res,
							gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	struct agent_reply_data *reply_data = user_data;

	DBG("");

	ret = g_dbus_connection_call_finish(reply_data->connection,
							res, &error);

	if (ret == NULL && error != NULL) {
		DBG("%s", error->message);
		if (g_strrstr(error->message, "org.bluez.Error.Rejected"))
			g_dbus_method_invocation_return_dbus_error(
						reply_data->invocation,
						ERROR_INTERFACE ".Rejected",
						"RejectByUser");
		else if (g_strrstr(error->message, "org.bluez.Error.Canceled"))
			g_dbus_method_invocation_return_dbus_error(
						reply_data->invocation,
						ERROR_INTERFACE ".Canceled",
						"CancelByUser");
		g_free(reply_data);
		return;
	}

	g_dbus_method_invocation_return_value(reply_data->invocation, ret);

	g_free(reply_data);
}

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
	"    <method name='DisplayPasskey'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' name='passkey' direction='in'/>"
	"      <arg type='q' name='entered' direction='in'/>"
	"    </method>"
	"    <method name='RequestConfirmation'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' name='passkey' direction='in'/>"
	"    </method>"
	"    <method name='RequestAuthorization'>"
	"      <arg type='o' name='device' direction='in'/>"
	"    </method>"
	"    <method name='AuthorizeService'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' name='uuid' direction='in'/>"
	"      <arg type='h' name='fd' direction='in'/>"
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
				parameters,
				g_variant_type_new("(s)"),
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_request_pincode(GDBusConnection *connection,
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
				"RequestPinCode",
				parameters,
				g_variant_type_new("(s)"),
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_display_pincode(GDBusConnection *connection,
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
				"DisplayPinCode",
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_request_passkey(GDBusConnection *connection,
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
				"RequestPasskey",
				parameters,
				g_variant_type_new("(s)"),
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_display_passkey(GDBusConnection *connection,
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
				"DisplayPasskey",
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_request_confirmation(GDBusConnection *connection,
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
				"RequestConfirmation",
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_request_authorization(GDBusConnection *connection,
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
				"RequestAuthorization",
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_authorize_service(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;
	GDBusMessage *msg;
	GUnixFDList *in_fd_list, *out_fd_list;
	GError *error = NULL;
	gchar *device_path, *uuid;
	gint32 fd_index;
	gint fd;

	DBG("");

	g_variant_get(parameters, "(osh)", &device_path,
						&uuid, &fd_index);

	msg = g_dbus_method_invocation_get_message(invocation);

	in_fd_list = g_dbus_message_get_unix_fd_list(msg);

	fd = g_unix_fd_list_get(in_fd_list, fd_index, NULL);

	out_fd_list = g_unix_fd_list_new();

	g_unix_fd_list_append(out_fd_list, fd, &error);

	g_assert_no_error(error);

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_dbus_connection_call_with_unix_fd_list(connection,
						relay_agent->owner,
						relay_agent->object_path,
						AGENT_INTERFACE,
						"AuthorizeService",
						parameters,
						NULL,
						G_DBUS_CALL_FLAGS_NONE,
						-1,
						out_fd_list,
						NULL,
						relay_agent_reply,
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
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_pairing(GDBusConnection *connection,
					struct pairing_context *context)
{
	gchar *method_name = context->method_name;

	DBG("method_name: [%s]", method_name);

	if (g_strcmp0(method_name, "Release") == 0)
		handle_release(connection,
				context->parameters,
				context->invocation,
				context->user_data);
	else if (g_strcmp0(method_name, "RequestPinCode") == 0)
		handle_request_pincode(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "DisplayPinCode") == 0)
		handle_display_pincode(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "RequestPasskey") == 0)
		handle_request_passkey(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "DisplayPasskey") == 0)
		handle_display_passkey(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "RequestConfirmation") == 0)
		handle_request_confirmation(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "RequestAuthorization") == 0)
		handle_request_authorization(connection,
					context->parameters,
					context->invocation,
					context->user_data);
	else if (g_strcmp0(method_name, "AuthorizeService") == 0)
		handle_authorize_service(connection,
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

static struct pairing_context *create_pairing_context(
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	struct pairing_context *context;

	context = g_new0(struct pairing_context, 1);
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

static void free_pairing_context(gpointer user_data)
{
	struct pairing_context *context = user_data;

	g_free(context->method_name);
	g_variant_unref(context->parameters);

	g_free(context);
}

#ifndef TIZEN_COMMON
static gboolean relay_agent_timeout_cb(gpointer user_data)
{
	ERROR("Relay agent timeout");

	comms_error_failed(pairing_context->invocation, "Relay agent timeout");

	free_pairing_context(pairing_context);

	pairing_context = NULL;

	return FALSE;
}
#endif

#ifdef TIZEN_COMMON

#define PASSKEY_SIZE 6

static gchar* get_device_name_from_device_path(gchar* device_path)
{
  bluez_device_t *device;

  if (default_adapter == NULL) {
    ERROR("No default adapter");
    return NULL;
  }

  if (device_path == NULL) {
    ERROR("device_path is NULL");
    return NULL;
  }

  device = bluez_adapter_get_device_by_path(default_adapter,
              device_path);
  if (device == NULL) {
    ERROR("Can't find device %s", device_path);
    return NULL;
  }

  return bluez_device_get_property_alias(device);
}

static bundle* fill_notification_bundle(const gchar *method_name,
        GVariant *parameters,
        const gchar *object_path)
{
  DBG("");

  bundle* b = bundle_create();
  if (!b)
    return NULL;

  bundle_add(b, "event-type", (char *) method_name);
  bundle_add(b, "agent-path", (char *) object_path);

  if (!g_strcmp0(method_name, "DisplayPinCode")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    gchar *pincode =  NULL;
    g_variant_get(parameters, "(os)", &device_path, &pincode);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    bundle_add(b, "pincode", (char *) pincode);
    g_free(device_path);
    g_free(pincode);
  }
  else if (!g_strcmp0(method_name, "RequestPinCode")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    g_variant_get(parameters, "(o)", &device_path);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    g_free(device_path);
  }
  else if (!g_strcmp0(method_name, "RequestPasskey")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    g_variant_get(parameters, "(o)", &device_path);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    g_free(device_path);
  }
  else if (!g_strcmp0(method_name, "RequestConfirmation")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    guint32 passkey = 0;
    g_variant_get(parameters, "(ou)", &device_path, &passkey);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    gchar *passkey_str = g_strdup_printf("%u", passkey);
    // Set '0' padding if the passkey has less than 6 digits
    char passkey_tab[PASSKEY_SIZE] = "000000";
    int size = strlen((char *)passkey_str);
    if (size <= PASSKEY_SIZE) {
      memcpy(&passkey_tab[PASSKEY_SIZE - size], passkey_str, size);
    }
    bundle_add(b, "passkey", passkey_tab);
    g_free(device_path);
    g_free(passkey_str);
  }
  else if (!g_strcmp0(method_name, "AuthorizeService")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    gchar *uuid = NULL;
    guint32 fd = 0;
    g_variant_get(parameters, "(osh)", &device_path, &uuid, &fd);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    bundle_add(b, "uuid", (char *) uuid);
    g_free(device_path);
    g_free(uuid);
  }
  else if (!g_strcmp0(method_name, "RequestAuthorization")) {
    gchar *device_path = NULL;
    gchar *device_name = NULL;
    g_variant_get(parameters, "(o)", &device_path);
    device_name = get_device_name_from_device_path(device_path);
    bundle_add(b, "device-name", (char *) device_name);
    g_free(device_path);
  }
  else {
    DBG("There is no data to add in bundle for 'Release' or 'Cancel' method calls");
  }
  return b;
}
#endif // #ifdef TIZEN_COMMON

static void handle_pairing_agent_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	if (pairing_context) {
		WARN("Pairing context already exist");
		return;
	}

	pairing_context = create_pairing_context(method_name, parameters,
							invocation, user_data);

	if (relay_agent) {
		DBG("relay agent is defined");
		handle_pairing(connection, pairing_context);

		free_pairing_context(pairing_context);
		pairing_context = NULL;

#ifdef TIZEN_COMMON
		bundle* b;
		b = fill_notification_bundle(method_name, parameters, relay_agent->object_path);
		vertical_notify_bt_pairing_agent_on(b);
#endif
		return;
	}

#ifndef TIZEN_COMMON
	vertical_notify_bt_pairing_agent_on();

	relay_agent_timeout_id = g_timeout_add(5*1000,
					relay_agent_timeout_cb, NULL);
#endif
}

static const GDBusInterfaceVTable pairing_agent_vtable =
{
	handle_pairing_agent_method_call,
	NULL,
	NULL
};

static gboolean create_pairing_agent(GDBusConnection *connection)
{
	DBG("");

	pairing_introspection_data = g_dbus_node_info_new_for_xml(
					introspection_xml, NULL);

	if (pairing_introspection_data == NULL)
		return FALSE;

	pairing_agent_dbus_id =
		g_dbus_connection_register_object(connection,
					PAIRING_AGENT_PATH,
					pairing_introspection_data->interfaces[0],
					&pairing_agent_vtable,
					NULL, NULL, NULL);
	if (pairing_agent_dbus_id < 0) {
		ERROR("Register Pairing Agent Failed");
		return FALSE;
	}

	return TRUE;
}

static struct agent *create_relay_agent(const gchar *sender,
					const gchar *path,
					guint watch_id)
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

static void register_relay_agent_handler(
					GDBusConnection *connection,
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
			g_bus_watch_name_on_connection(connection,sender,
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

	if (!pairing_context)
		return;

	handle_pairing(connection, pairing_context);

	free_pairing_context(pairing_context);
	pairing_context = NULL;
}

static void unregister_relay_agent_handler(
					GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	gchar *relay_agent_path;

	DBG("");

	if (relay_agent == NULL)
		return comms_error_does_not_exist(invocation);

	g_variant_get(parameters, "(o)", &relay_agent_path);
	if (relay_agent_path == NULL)
		return comms_error_invalid_args(invocation);

	if (g_strcmp0(relay_agent_path, relay_agent->object_path))
		return comms_error_does_not_exist(invocation);

	g_dbus_method_invocation_return_value(invocation, NULL);

	g_free(relay_agent_path);

	free_relay_agent(relay_agent);
	relay_agent = NULL;
}

static void device_pair_cb(enum bluez_error_type type, void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;

	DBG("");

	if (type != ERROR_NONE) {
		handle_error_message(invocation, type);

		return;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void pairing_handler(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	bluez_device_t *device;
	gchar *address;

	DBG("");

	g_variant_get(parameters, "(s)", &address);

	if (pairing_device_address)
		g_free(pairing_device_address);

	pairing_device_address = g_strdup(address);

	device = bluez_adapter_get_device_by_address(
					default_adapter, address);
	if (device == NULL) {
		comms_error_does_not_exist(invocation);

		g_free(address);
		return;
	}

	bluez_device_pair(device, device_pair_cb, invocation);

	g_free(address);
}

static void device_cancel_pair_cb(enum bluez_error_type type, void *user_data)
{
	GDBusMethodInvocation *invocation = user_data;

	DBG("");

	if (type != ERROR_NONE) {
		handle_error_message(invocation, type);

		return;
	}

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void cancel_pairing_handler(GDBusConnection *connection,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	bluez_device_t *device;

	DBG("");

	device = bluez_adapter_get_device_by_address(default_adapter,
						pairing_device_address);
	if (device == NULL) {
		comms_error_does_not_exist(invocation);

		return;
	}

	bluez_device_cancel_pair(device, device_cancel_pair_cb, invocation);
}

static void pairing_skeleton_handle_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{

  DBG("method: %s", method_name);

	if (g_strcmp0(method_name, "RegisterPairingAgent") == 0)
		register_relay_agent_handler(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "UnregisterPairingAgent") == 0)
		unregister_relay_agent_handler(connection, parameters,
						invocation, user_data);
	else if (g_strcmp0(method_name, "Pair") == 0)
		pairing_handler(connection, parameters, invocation, user_data);
	else if (g_strcmp0(method_name, "CancelPairing") == 0)
		cancel_pairing_handler(connection, parameters,
					invocation, user_data);
	else
		WARN("Unknown method");
}

static const GDBusInterfaceVTable pairing_skeleton_vtable =
{
	pairing_skeleton_handle_method_call,
	NULL,
	NULL
};

static GDBusInterfaceVTable *pairing_skeleton_dbus_interface_get_vtable(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceVTable *) &pairing_skeleton_vtable;
}

static void pairing_skeleton_object_finalize(GObject *object)
{
	DBG("Finalize");

	G_OBJECT_CLASS(pairing_skeleton_parent_class)->finalize(object);
}

static void pairing_skeleton_init(PairingSkeleton *skeleton)
{
	DBG("Instance Init");
}

static GVariant *pairing_skeleton_dbus_interface_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	GVariantBuilder builder;

	DBG("");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	return g_variant_builder_end (&builder);
}

static void pairing_skeleton_class_init(PairingSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *gdbus_skeleton_class;

	DBG("Class Init");

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = pairing_skeleton_object_finalize;

	gdbus_skeleton_class = G_DBUS_INTERFACE_SKELETON_CLASS(klass);
	gdbus_skeleton_class->get_info =
				pairing_skeleton_dbus_interface_get_info;
	gdbus_skeleton_class->get_vtable =
				pairing_skeleton_dbus_interface_get_vtable;
	gdbus_skeleton_class->get_properties =
				pairing_skeleton_dbus_interface_get_properties;
}

static void bluez_agent_added_cb(bluez_agent_t *agent, void *user_data)
{
	GDBusConnection *connection = user_data;

	bluez_agent_unset_agent_added();

	if (!create_pairing_agent(connection)) {
		ERROR("Create pairing agent failed");

		g_object_unref(bt_pairing);
		bt_pairing = NULL;
	}

	bluez_agent_register_agent(PAIRING_AGENT_PATH,
					DISPLAY_YES_NO,
					register_pairing_agent_cb,
					connection);
}

PairingSkeleton *bt_service_pairing_new(void)
{
	return (PairingSkeleton *)g_object_new(TYPE_PAIRING_SKELETON, NULL);
}

void bt_service_pairing_init(GDBusObjectSkeleton *gdbus_object_skeleton,
						GDBusConnection *connection,
						bluez_adapter_t *adapter)
{
	if (bt_pairing)
		return;

	bt_object_skeleton = gdbus_object_skeleton;

	DBG("");

	default_adapter = adapter;

	bt_pairing = bt_service_pairing_new();

	bluez_agent = bluez_agent_get_agent();
	if (bluez_agent == NULL) {
		bluez_agent_set_agent_added(bluez_agent_added_cb,
							connection);

		return;
	}

	if (!create_pairing_agent(connection)) {
		ERROR("Create pairing agent failed");

		g_object_unref(bt_pairing);
		bt_pairing = NULL;

		return;
	}

	bluez_agent_register_agent(PAIRING_AGENT_PATH,
				DISPLAY_YES_NO,
				register_pairing_agent_cb,
				connection);

#ifdef TIZEN_COMMON
	bundle* b = bundle_create();
	bundle_add(b, "event-type", "RegisterPairingAgent");
	vertical_notify_bt_pairing_agent_on(b);
#endif
}

void bt_service_pairing_deinit(void)
{
	GDBusConnection *connection;

	DBG("");

	if (bt_pairing == NULL)
		return;

	connection = g_dbus_interface_skeleton_get_connection(
				G_DBUS_INTERFACE_SKELETON(bt_pairing));

	bluez_agent_unset_agent_added();

	bluez_agent_unregister_agent(PAIRING_AGENT_PATH,
				unregister_pairing_agent_cb,
				connection);
}

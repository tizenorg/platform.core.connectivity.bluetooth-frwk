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

#include <bundle.h>

#include <string.h>

#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "pairing.h"
#include "vertical.h"

#define PASSKEY_SIZE 6

#define PAIRING_TIMEOUT (20 * 1000) // BlueZ has 60s timeout to let user confirm pairing.

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

	ERROR("");

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

	ERROR("");
	if (type != ERROR_NONE) {
		ERROR("Register pairing agent failed %d", type);

		destruct_pairing_agent(connection);

		g_object_unref(bt_pairing);
		bt_pairing = NULL;

		return;
	}

	ERROR("request default agent: path [%s]", PAIRING_AGENT_PATH);

	bluez_agent_request_default_agent(PAIRING_AGENT_PATH);

	bt_pairing_register_dbus_interface(bt_pairing, connection);
}

static void unregister_pairing_agent_cb(enum bluez_error_type type, void *user_data)
{
	GDBusConnection *connection = user_data;

	if (type != ERROR_NONE)
		ERROR("%d", type);

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

	ERROR("");

	ret = g_dbus_connection_call_finish(reply_data->connection,
							res, &error);

	if (ret == NULL && error != NULL) {
		ERROR("%s", error->message);
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
	"    </method>"
	"    <method name='Cancel'>"
	"    </method>"
#ifndef JUNK
	"    <method name='ReplyConfirmation'>"
	"      <arg type='u' name='value' direction='in'/>"
	"    </method>"
#endif
	"  </interface>"
	"</node>";

static void handle_release(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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

#if JUNK
static void handle_request_confirmation(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	ERROR("call RequestConfirmation ");

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
#else

#define PAIRING_AGENT "bt_pairing_agent"

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

static bundle* fill_notification_bundle(const gchar *method_name, GVariant *parameters, int hndlid, const gchar *object_path)
{
	bundle* b = bundle_create();
	if (!b)
		return NULL;

	bundle_add(b, "event-type", (char *) method_name);

	bundle_add(b, "agent-path", (char *) object_path);
	ERROR("AGENT PATH: [%s] !", object_path);

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
		ERROR("set [%s] parameters in bundle !", method_name);
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
		ERROR("size [%d]", size);
		if (size <= PASSKEY_SIZE) {
			memcpy(&passkey_tab[PASSKEY_SIZE - size], passkey_str, size);
		}
		bundle_add(b, "passkey", passkey_tab);
		ERROR("device_path [%s] / passkey_str [%s]", device_path, passkey_str);
		ERROR("BUNDLE contains: device_name [%s] / passkey [%s]", bundle_get_val(b, "device-name"), bundle_get_val(b, "passkey"));
		g_free(device_path);
		g_free(passkey_str);
	}
	else if (!g_strcmp0(method_name, "AuthorizeService")) {
		gchar *device_path = NULL;
		gchar *device_name = NULL;
		gchar *uuid = NULL;
		g_variant_get(parameters, "(os)", &device_path, &uuid);
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
	ERROR("BUNDLE: event_type: [%s] and device_name: [%s]", bundle_get_val(b, "event-type"), bundle_get_val(b, "device-name"));
	return b;
}

struct agent_reply_data *common_reply = NULL;

static gboolean relay_agent_timeout_cb(gpointer user_data);

static gboolean handle_request_confirmation_timeout_cb(gpointer user_data)
{
	ERROR("free the agent reply !!!");
	struct agent_reply_data *reply = common_reply;
	common_reply = NULL;
	g_free(reply);
	return relay_agent_timeout_cb(user_data);
}

static void handle_request_confirmation(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;
	bundle* b;

	ERROR("'RequestConfirmation' on agent path [%s]", PAIRING_AGENT_PATH);

	reply_data = g_new0(struct agent_reply_data, 1);

	b = fill_notification_bundle("RequestConfirmation", parameters, 1, PAIRING_AGENT_PATH);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	ERROR("give the bundle to IVI plugin !!!");
	vertical_notify_bt_pairing_agent_on(b);

	// Save 'RequestConfirmation' connection/invocation data to release method call later after the reply.
	common_reply = reply_data;

	relay_agent_timeout_id = g_timeout_add(PAIRING_TIMEOUT,
					handle_request_confirmation_timeout_cb, NULL);
}

static void handle_reply_confirmation(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	// Retrieve 'RequestConfirmation' connection/invocation data to release the method call
	struct agent_reply_data *reply = common_reply;
	guint32 value;

	ERROR("'ReplyConfirmation'");

	common_reply = NULL;
	if (!reply)
		return;

	g_variant_get(parameters, "(u)", &value);
	ERROR("received value [%d]", value);
	switch (value) {
		case 0: /* ACCEPT */
			g_dbus_method_invocation_return_value(reply->invocation, NULL);
			break;
		
		case 1: /* REJECT */
			g_dbus_method_invocation_return_dbus_error(
				reply->invocation,
				ERROR_INTERFACE ".Rejected",
				"RejectByUser");
			break;
		case 2: /* CANCEL */
		default: /* unexpected! */
			g_dbus_method_invocation_return_dbus_error(
					reply->invocation,
					ERROR_INTERFACE ".Canceled",
					"CancelByUser");
			break;
	}
}

#endif


static void handle_request_authorization(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	ERROR("");

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

	ERROR("");

	reply_data = g_new0(struct agent_reply_data, 1);

	reply_data->connection = connection;
	reply_data->invocation = invocation;

	g_dbus_connection_call(connection,
				relay_agent->owner,
				relay_agent->object_path,
				AGENT_INTERFACE,
				"AuthorizeService",
				parameters,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				-1, NULL,
				relay_agent_reply,
				reply_data);
}

static void handle_cancel(GDBusConnection *connection,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	struct agent_reply_data *reply_data;

	ERROR("");

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

	ERROR("method_name [%s]", method_name);

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
	else if (g_strcmp0(method_name, "ReplyConfirmation") == 0)
		handle_reply_confirmation(connection,
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

	ERROR("method_name [%s]",method_name);

	return context;
}

static void free_pairing_context(gpointer user_data)
{
	struct pairing_context *context = user_data;

	g_free(context->method_name);
	g_variant_unref(context->parameters);

	g_free(context);
}

static gboolean relay_agent_timeout_cb(gpointer user_data)
{
	ERROR("Relay agent timeout");

	comms_error_failed(pairing_context->invocation, "Relay agent timeout");

	free_pairing_context(pairing_context);

	pairing_context = NULL;

	return FALSE;
}

static void handle_pairing_agent_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	ERROR("sender [%s] object_path [%s]", sender, object_path);
	ERROR("interface [%s] method [%s]", interface, method_name);

#if JUNK
	bundle* b;
#endif

	if (pairing_context) {
		WARN("Pairing context already exist");
		return;
	}

	pairing_context = create_pairing_context(method_name, parameters,
							invocation, user_data);

//	 if (relay_agent) {
//		ERROR("relay agent is defined ");
		handle_pairing(connection, pairing_context);

		free_pairing_context(pairing_context);
		pairing_context = NULL;

//		return;
//	}
#if JUNK
	b = fill_notification_bundle(pairing_context, object_path);

	ERROR("call plugin with timeout !!!");
	vertical_notify_bt_pairing_agent_on(b);

	relay_agent_timeout_id = g_timeout_add(5000,
					relay_agent_timeout_cb, NULL);
#else
	/* TODO: emettre un truc */
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
	ERROR("");

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

	ERROR("relay agent created : owner [%s] / object path [%s]", agent->owner, agent->object_path);

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
	ERROR("");

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

	ERROR("agent_path: [%s]");

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

	ERROR("call handle_pairing()");
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

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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

	ERROR("");

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
	ERROR("sender [%s] object_path [%s]", sender, object_path);
	ERROR("interface_name [%s] method [%s]", interface_name, method_name);

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
	ERROR("Finalize");

	G_OBJECT_CLASS(pairing_skeleton_parent_class)->finalize(object);
}

static void pairing_skeleton_init(PairingSkeleton *skeleton)
{
	ERROR("Instance Init");
}

static GVariant *pairing_skeleton_dbus_interface_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	GVariantBuilder builder;

	ERROR("");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	return g_variant_builder_end (&builder);
}

static void pairing_skeleton_class_init(PairingSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *gdbus_skeleton_class;

	ERROR("Class Init");

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

	ERROR("");

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

	ERROR("");

	bluez_agent_register_agent(PAIRING_AGENT_PATH,
				DISPLAY_YES_NO,
				register_pairing_agent_cb,
				connection);
}

void bt_service_pairing_deinit(void)
{
	GDBusConnection *connection;

	ERROR("");

	if (bt_pairing == NULL)
		return;

	connection = g_dbus_interface_skeleton_get_connection(
				G_DBUS_INTERFACE_SKELETON(bt_pairing));

	bluez_agent_unset_agent_added();

	bluez_agent_unregister_agent(PAIRING_AGENT_PATH,
				unregister_pairing_agent_cb,
				connection);
}

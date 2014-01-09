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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <gio/gio.h>

#include "bluetooth.h"
#include "obex.h"
#include "common.h"
#include "bluetooth-service.h"
#include "bluez.h"

#define OBEX_LIB_SERVICE "org.obex.lib"
#define AGENT_OBJECT_PATH "/org/obex/lib"

static struct {
	char *root_folder;
	char *pending_name;
	bt_opp_server_push_requested_cb requested_cb;
	void *user_data;
	obex_transfer_t *pending_transfer;
	GDBusMethodInvocation *pending_invocation;
} opp_server;

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

static void handle_cancel(GDBusMethodInvocation *invocation)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_release(GDBusMethodInvocation *invocation)
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
		gchar *transfer_path, *name, *destination;
		gchar *device_name = NULL;
		obex_transfer_t *transfer;
		bluez_adapter_t *adapter;
		bluez_device_t *device;
		guint64 size;

		g_variant_get(parameters, "(o)", &transfer_path);

		DBG("transfer_path %s", transfer_path);

		transfer = obex_transfer_get_transfer_from_path(
					(const gchar *) transfer_path);

		if (transfer == NULL)
			return;

		/*
		 * obexd does not emit size proptery change signal,
		 * so here needs to get the property from obexd directly
		 */
		obex_transfer_get_size(transfer, &size);

		/*
		 * save the property value to cached property, so next time
		 * the value can be acquired from cached property, and need not
		 * to get from obexd
		 */
		obex_transfer_set_property_size(transfer, size);

		name = obex_transfer_get_name(transfer);
		obex_transfer_set_property_name(transfer, (const char *) name);

		destination = obex_transfer_get_property_destination(transfer);

		adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
		device = bluez_adapter_get_device_by_address(adapter,
								destination);
		if (device)
			device_name = bluez_device_get_property_alias(device);

		opp_server.pending_name = g_strdup(name);
		opp_server.pending_transfer = transfer;
		opp_server.pending_invocation = invocation;

		if (opp_server.requested_cb)
			opp_server.requested_cb((const char *) device_name,
						(const char *) name, size,
						opp_server.user_data);

		g_free(destination);
		g_free(device_name);
		g_free(name);
		g_free(transfer_path);

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

static guint bus_id;
static GDBusConnection *conn;

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

	comms_bluetooth_register_opp_agent(AGENT_OBJECT_PATH, NULL, NULL);
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

static int register_agent(void)
{
	DBG("");

	introspection_data =
			g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	/* Error handle */
	bus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				OBEX_LIB_SERVICE,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				bus_acquired,
				name_acquired,
				name_lost,
				NULL,
				NULL);

	return 0;
}

int bt_opp_register_server(const char *dir,
			bt_opp_server_push_requested_cb push_requested_cb,
			void *user_data)
{
	if (dir == NULL || push_requested_cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (opp_server.root_folder != NULL) {
		ERROR("Already registered");
		return BT_ERROR_OPERATION_FAILED;
	}
	if (!g_file_test(dir, G_FILE_TEST_IS_DIR)) {
		ERROR("%s is not valid directory", dir);
		return BT_ERROR_INVALID_PARAMETER;
	}

	/* TODO: Do we need to check the dir privilege? */

	opp_server.root_folder = g_strdup(dir);
	opp_server.requested_cb = push_requested_cb;
	opp_server.user_data = user_data;

	register_agent();

	return 0;
}

int bt_opp_unregister_server(void)
{
	/* TODO: unregister agent */
	g_free(opp_server.root_folder);
	opp_server.root_folder = NULL;

	opp_server.requested_cb = NULL;
	opp_server.user_data = NULL;
	obex_lib_deinit();
	return 0;
}

struct _watch_notify_node {
	bt_opp_transfer_state_cb cb;
	void *user_data;
	gboolean is_watch;
	obex_session_t *session;
};

static struct _watch_notify_node *watch_node;

static void transfer_state_cb(
			const char *transfer_path,
			struct _obex_transfer *transfer,
			enum transfer_state state,
			guint64 transferred,
			void *data,
			char *error_msg)
{
	struct _watch_notify_node *node = data;
	guint64 size;
	unsigned char percent;
	int id;
	char *name;

	if (transfer && node->cb) {
		id = obex_transfer_get_id(transfer);
		name = obex_transfer_get_property_name(transfer);
		obex_transfer_property_get_size(transfer, &size);

		DBG("transferred %ju, size %ju", transferred, size);
		percent = transferred * 100 / size;

		node->cb(id, (bt_opp_transfer_state_e) state,
				name, size, percent, node->user_data);
	}

	if (node->is_watch)
		return;

	if (state == OBEX_TRANSFER_COMPLETE ||
				state == OBEX_TRANSFER_CANCELED || 
					state == OBEX_TRANSFER_ERROR) {
		obex_session_remove_session(node->session);
		g_free(node);
	}
}

int bt_opp_set_transfers_state_cb(bt_opp_transfer_state_cb cb, void *user_data)
{
	if (watch_node) {
		ERROR("transfer_state_cb already be set");
		return BT_ERROR_OPERATION_FAILED;
	}

	if (cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	watch_node = g_try_new0(struct _watch_notify_node, 1);

	watch_node->cb = cb;
	watch_node->user_data = user_data;
	watch_node->is_watch = TRUE;

	obex_transfer_set_watch(transfer_state_cb, (void *) watch_node);

	return 0;
}

void bt_opp_clear_transfers_state_cb(void)
{
	obex_transfer_clear_watch();

	g_free(watch_node);
	watch_node = NULL;
}

int bt_opp_server_accept(const char *name, bt_opp_transfer_state_cb cb,
					void *user_data, int *transfer_id)
{
	obex_transfer_t *transfer;
	struct _watch_notify_node *notify_node;
	GDBusMethodInvocation *invocation;
	char *n, *file_name;

	transfer = opp_server.pending_transfer;
	invocation = opp_server.pending_invocation;

	if (transfer == NULL) {
		ERROR("Can't find transfer");
		return BT_ERROR_OPERATION_FAILED;
	}

	if (invocation == NULL) {
		ERROR("Can't find invocation");
		return BT_ERROR_OPERATION_FAILED;
	}

	if (cb) {
		notify_node = g_try_new0(struct _watch_notify_node, 1);

		notify_node->cb = cb;
		notify_node->user_data = user_data;
		notify_node->is_watch = FALSE;

		obex_transfer_set_notify(transfer, transfer_state_cb,
						(void *) notify_node);
	}

	n = (name != NULL) ? (char *) name : opp_server.pending_name;

	file_name = g_build_filename(opp_server.root_folder, n, NULL);

	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", file_name));

	g_free(file_name);

	*transfer_id = obex_transfer_get_id(transfer);

	g_free(opp_server.pending_name);

	return BT_SUCCESS;
}

int bt_opp_server_reject(void)
{
	return 0;
}

int bt_opp_transfer_cancel(int transfer_id)
{
	obex_transfer_t *transfer =
		obex_transfer_get_transfer_from_id(transfer_id);
	if (transfer == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	obex_transfer_cancel(transfer);

	return BT_SUCCESS;
}

int bt_opp_server_set_directory(const char *dir)
{
	if (opp_server.root_folder == NULL) {
		ERROR("opp server is not initialized");
		return BT_ERROR_OPERATION_FAILED;
	}

	if (dir == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	g_free(opp_server.root_folder);

	opp_server.root_folder = g_strdup(dir);

	return BT_SUCCESS;
}

struct opp_push_data{
	char *file_name;
	bt_opp_client_push_responded_cb responded_cb;
	void *responded_data;
	bt_opp_transfer_state_cb transfer_state_cb;
	void *transfer_data;
};

int bt_opp_client_push_file(
			const char *file_name,
			const char *remote_address,
			bt_opp_client_push_responded_cb responded_cb,
			void *responded_data,
			bt_opp_transfer_state_cb transfer_state_cb,
			void *transfer_data)
{
	if (file_name == NULL || remote_address == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	comms_bluetooth_opp_send_file(remote_address, file_name, NULL, NULL);

	return 0;
}

int bt_opp_init(void)
{
	obex_lib_init();

	return 0;
}

int bt_opp_deinit(void)
{
	obex_lib_deinit();

	return 0;
}

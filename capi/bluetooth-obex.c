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
#include <dirent.h>
#include <dbus/dbus.h>
#include <gio/gunixfdlist.h>
#include <string.h>

#include "bluetooth.h"
#include "obex.h"
#include "common.h"
#include "bluetooth-service.h"
#include "bluez.h"

#define OBEX_LIB_SERVICE "org.obex.lib"
#define AGENT_OBJECT_PATH "/org/obex/lib"

#define OBEX_ERROR_INTERFACE "org.bluez.obex.Error"

#define ADDRESS_LEN 20
static char pushing_address[ADDRESS_LEN];

typedef enum {
	BT_OPP_TRANSFER_UNKNOWN = 0x0,
	BT_OPP_TRANSFER_QUEUED,
	BT_OPP_TRANSFER_ACTIVE,
	BT_OPP_TRANSFER_COMPLETED,
	BT_OPP_TRANSFER_CANCELED,
	BT_OPP_TRANSFER_ERROR,
} bt_opp_transfer_state_e;

typedef void (*bt_opp_server_push_file_requested_cb)(
			const char *remote_address,
			const char *name,
			uint64_t size,
			void *user_data);

typedef void (*bt_opp_transfer_state_cb)(
			int transfer_id,
			bt_opp_transfer_state_e state,
			const char *name,
			uint64_t size,
			unsigned char percent,
			void *user_data);

typedef enum {
	BT_OPP_PUSH_ACCETPED = 0,
	BT_OPP_PUSH_RETRY,
	BT_OPP_PUSH_FAILED,
	BT_OPP_PUSH_REFUSED,
	BT_OPP_PUSH_TIMEOUT,
	BT_OPP_PUSH_NO_SERVICE
} push_state_e;

typedef void (*bt_opp_client_push_responded_new_cb)(
			const char *remote_address,
			push_state_e state,
			void *user_data);

static struct {
	char *root_folder;
	char *pending_name;
	bt_opp_server_push_file_requested_cb requested_cb;
	void *user_data;
	obex_transfer_t *pending_transfer;
	GDBusMethodInvocation *pending_invocation;
} opp_server;

static char *setting_destination;

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

static GDBusConnection *conn;
static guint bluetooth_opp_agent_id;

static GDBusConnection *get_system_dbus_connect(void)
{
	GError *error = NULL;

	if (conn != NULL)
		return conn;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (conn == NULL) {
		DBG("%s", error->message);

		g_error_free(error);

		return NULL;
	}

	return conn;
}

static void release_dbus_connection(void)
{
	g_object_unref(conn);
	conn = NULL;
}

static void release_name_on_dbus(const char *name)
{
	GVariant *ret;
	guint32 request_name_reply;
	GError *error = NULL;

	if (bluetooth_opp_agent_id)
		return;

	ret = g_dbus_connection_call_sync(conn, "org.freedesktop.DBus",
			"/org/freedesktop/DBus", "org.freedesktop.DBus",
			"ReleaseName", g_variant_new("(s)", name),
			G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE,
			-1, NULL, &error);
	if (ret == NULL) {
		WARN("%s", error->message);
		return;
	}

	g_variant_get(ret, "(u)", &request_name_reply);
	g_variant_unref(ret);

	if (request_name_reply != 1) {
		WARN("Unexpected reply");
		return;
	}

	release_dbus_connection();

	return;
}

static int request_name_on_dbus(const char *name)
{
	GDBusConnection *connection;
	GVariant *ret;
	guint32 request_name_reply;
	GError *error = NULL;

	if (bluetooth_opp_agent_id)
		return 0;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return -1;

	ret = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus",
			"/org/freedesktop/DBus", "org.freedesktop.DBus",
			"RequestName", g_variant_new("(su)", name,
				G_BUS_NAME_OWNER_FLAGS_NONE),
			G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE,
			-1, NULL, &error);
	if (ret == NULL) {
		WARN("%s", error->message);
		g_error_free(error);

		goto failed;
	}

	g_variant_get(ret, "(u)", &request_name_reply);
	g_variant_unref(ret);

	/* RequestName will return the uint32 value:
	 * 1: DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
	 * 2: BUS_REQUEST_NAME_REPLY_IN_QUEUE
	 * 3: DBUS_REQUEST_NAME_REPLY_EXISTS
	 * 4: DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
	 * Also see dbus doc
	 */

	if (request_name_reply != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		DBG("Lost name");

		release_name_on_dbus(name);

		goto failed;
	}

	return 0;
failed:
	g_object_unref(connection);

	return -1;
}

static void destory_opp_agent(void)
{
	DBG("bluetooth_opp_agent_id = %d", bluetooth_opp_agent_id);

	if (bluetooth_opp_agent_id > 0) {
		comms_bluetooth_unregister_opp_agent(
				AGENT_OBJECT_PATH, NULL, NULL);

		g_dbus_connection_unregister_object(conn,
					bluetooth_opp_agent_id);

		bluetooth_opp_agent_id = 0;

		release_name_on_dbus(OBEX_LIB_SERVICE);
	}

	return;
}

static int register_opp_agent(void)
{
	int ret;

	DBG("");

	if (bluetooth_opp_agent_id)
		return BT_ERROR_ALREADY_DONE;

	introspection_data =
		g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	ret = request_name_on_dbus(OBEX_LIB_SERVICE);
	if (ret != 0)
		return -1;

	DBG("%s requested success", OBEX_LIB_SERVICE);

	bluetooth_opp_agent_id = g_dbus_connection_register_object(conn,
					AGENT_OBJECT_PATH,
					introspection_data-> interfaces[0],
					&interface_handle, NULL, NULL, NULL);

	DBG("bluetooth_opp_agent_id = %d", bluetooth_opp_agent_id);

	if (bluetooth_opp_agent_id == 0)
		return -1;

	ret = comms_bluetooth_register_opp_agent_sync(
					AGENT_OBJECT_PATH, NULL);

	DBG("ret = %d", ret);

	if (ret != BT_SUCCESS) {
		destory_opp_agent();
		return BT_ERROR_OPERATION_FAILED;
	}

	return 0;
}

int bt_opp_register_server(const char *dir,
			bt_opp_server_push_file_requested_cb push_requested_cb,
			void *user_data)
{
	int ret;

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

	ret = register_opp_agent();
	if (ret != BT_SUCCESS)
		return ret;

	/* TODO: Do we need to check the dir privilege? */

	opp_server.root_folder = g_strdup(dir);
	opp_server.requested_cb = push_requested_cb;
	opp_server.user_data = user_data;

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

	destory_opp_agent();

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

int bt_opp_server_accept_request(const char *name, bt_opp_transfer_state_cb cb,
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

	if (!setting_destination) {
		n = (name != NULL) ? (char *) name : opp_server.pending_name;

		file_name = g_build_filename(opp_server.root_folder, n, NULL);

		g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", file_name));

		g_free(file_name);
	} else
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(s)", setting_destination));

	opp_server.pending_invocation = NULL;

	*transfer_id = obex_transfer_get_id(transfer);

	g_free(opp_server.pending_name);

	return BT_SUCCESS;
}

int bt_opp_server_reject_request(void)
{
	if (opp_server.pending_invocation) {
		g_dbus_method_invocation_return_dbus_error(
					opp_server.pending_invocation,
					OBEX_ERROR_INTERFACE ".Rejected",
					"RejectByUser");

		opp_server.pending_invocation = NULL;
	}

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
			bt_opp_client_push_responded_new_cb responded_cb,
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

/* Deprecate OPP APIs.
 * Always implement using NEW OPP APIs*/
struct opp_server_push_cb_node {
	bt_opp_server_push_requested_cb callback;
	void *user_data;
};

struct opp_server_connection_requested_cb {
	bt_opp_server_connection_requested_cb callback;
	void *user_data;
};

static GList *sending_files;
static int pending_file_count;

struct opp_server_push_cb_node *opp_server_push_node;
struct opp_server_connection_requested_cb *opp_server_conn_req_node;
static bt_opp_server_transfer_progress_cb bt_transfer_progress_cb;
static bt_opp_server_transfer_finished_cb bt_transfer_finished_cb;
static bt_opp_client_push_progress_cb bt_progress_cb;
static bt_opp_client_push_responded_cb bt_push_request_cb;
static bt_opp_client_push_finished_cb bt_finished_cb;

void server_push_requested_cb(const char *remote_address, const char *name,
					uint64_t size, void *user_data)
{
	if (opp_server_push_node)
		opp_server_push_node->callback(name, size,
				opp_server_push_node->user_data);
}

void server_connect_requested_cb(const char *remote_address, const char *name,
					uint64_t size, void *user_data)
{
	if (opp_server_conn_req_node)
		opp_server_conn_req_node->callback(remote_address,
				opp_server_conn_req_node->user_data);
}

int bt_opp_server_initialize(const char *destination,
			bt_opp_server_push_requested_cb push_requested_cb,
			void *user_data)
{
	int ret;

	ret = bt_opp_init();
	if (ret != BT_SUCCESS)
		return ret;

	if (!destination || !push_requested_cb)
		return BT_ERROR_INVALID_PARAMETER;

	if (opp_server_push_node) {
		ERROR("Already registered");
		return BT_ERROR_OPERATION_FAILED;
	}

	opp_server_push_node = g_new0(struct opp_server_push_cb_node, 1);
	if (opp_server_push_node == NULL) {
		ERROR("no memroy");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	ret = bt_opp_register_server(destination,
				server_push_requested_cb, NULL);
	if (ret != BT_SUCCESS) {
		g_free(opp_server_push_node);
		opp_server_push_node = NULL;
	}

	opp_server_push_node->callback = push_requested_cb;
	opp_server_push_node->user_data = user_data;

	bt_opp_server_set_destination(destination);

	return ret;
}

int bt_opp_server_initialize_by_connection_request(const char *destination,
		bt_opp_server_connection_requested_cb connection_requested_cb,
		void *user_data)
{
	int ret;

	ret = bt_opp_init();
	if (ret != BT_SUCCESS)
		return ret;

	if (!destination || !connection_requested_cb)
		return BT_ERROR_INVALID_PARAMETER;

	if (opp_server_conn_req_node) {
		ERROR("Already registered");
		return BT_ERROR_OPERATION_FAILED;
	}

	opp_server_conn_req_node =
			g_new0(struct opp_server_connection_requested_cb, 1);
	if (opp_server_conn_req_node == NULL) {
		ERROR("no memroy");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	ret = bt_opp_register_server(destination,
				server_connect_requested_cb, NULL);
	if (ret != BT_SUCCESS) {
		g_free(opp_server_conn_req_node);
		opp_server_conn_req_node = NULL;
	}

	opp_server_conn_req_node->callback = connection_requested_cb;
	opp_server_conn_req_node->user_data = user_data;

	bt_opp_server_set_destination(destination);

	return ret;
}

int bt_opp_server_deinitialize(void)
{
	int ret;

	if (opp_server_push_node) {
		g_free(opp_server_push_node);
		opp_server_push_node = NULL;
	}

	if (opp_server_conn_req_node) {
		g_free(opp_server_conn_req_node);
		opp_server_conn_req_node = NULL;
	}

	bt_transfer_progress_cb = NULL;
	bt_transfer_finished_cb = NULL;

	if (setting_destination)
		g_free(setting_destination);

	ret = bt_opp_deinit();
	if (ret != BT_SUCCESS)
		return ret;

	return bt_opp_unregister_server();
}

static void bt_opp_server_transfer_state_cb(int transfer_id,
			bt_opp_transfer_state_e state, const char *name,
			uint64_t size, unsigned char percent, void *user_data)
{
	if (transfer_id < 10000)
		return;

	if (state == BT_OPP_TRANSFER_QUEUED ||
			state == BT_OPP_TRANSFER_ACTIVE)
		bt_transfer_progress_cb(name, size, percent, user_data);
	else if (state == BT_OPP_TRANSFER_COMPLETED)
		bt_transfer_finished_cb(BT_ERROR_NONE, name, size, user_data);
	else if (state == BT_OPP_TRANSFER_ERROR || BT_OPP_TRANSFER_CANCELED)
		bt_transfer_finished_cb(BT_ERROR_CANCELLED, name, size, user_data);

}

int bt_opp_server_accept(bt_opp_server_transfer_progress_cb progress_cb,
			bt_opp_server_transfer_finished_cb finished_cb,
			const char *name, void *user_data, int *transfer_id)
{
	bt_transfer_progress_cb = progress_cb;
	bt_transfer_finished_cb = finished_cb;

	return bt_opp_server_accept_request(name, bt_opp_server_transfer_state_cb,
							user_data, transfer_id);
}

int bt_opp_server_reject(void)
{
	return bt_opp_server_reject_request();
}

int bt_opp_server_cancel_transfer(int transfer_id)
{
	return bt_opp_transfer_cancel(transfer_id);
}

int bt_opp_server_set_destination(const char *destination)
{
	DIR *dp = NULL;

	if (destination == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	dp = opendir(destination);

	if (dp == NULL) {
		DBG("The directory does not exist");
		return BT_ERROR_INVALID_PARAMETER;
	}

	if (setting_destination)
		g_free(setting_destination);

	setting_destination = g_strdup(destination);
	return BT_ERROR_NONE;
}

int bt_opp_client_initialize(void)
{
	int ret;

	DBG("");

	ret = bt_opp_init();

	return ret;
}

int bt_opp_client_deinitialize(void)
{
	int ret;

	DBG("");

	ret = bt_opp_deinit();

	return ret;
}

int bt_opp_client_add_file(const char *file)
{
	int ret = BT_ERROR_NONE;

	if (file == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (access(file, F_OK) == 0) {
		sending_files = g_list_append(sending_files,
						g_strdup(file));
	} else {
		ret = BT_ERROR_INVALID_PARAMETER;
		DBG("ret = %d", ret);
	}

	return ret;
}

int bt_opp_client_clear_files(void)
{
	int i = 0;
	int file_num = 0;
	char *c_file = NULL;

	if (sending_files) {
		file_num = g_list_length(sending_files);

		for (i = 0; i < file_num; i++) {
			c_file = (char *)g_list_nth_data(sending_files, i);

			if (c_file == NULL)
				continue;

			free(c_file);
		}

		g_list_free(sending_files);
		sending_files = NULL;
	}

	return BT_ERROR_NONE;
}

static void client_transfer_state_cb(int id, bt_opp_transfer_state_e state,
				const char *name, uint64_t size,
				unsigned char percent, void *data)
{
	struct _obex_transfer *transfer = NULL;
	char *remote_address;

	DBG("");

	if (id < 10000 && bt_progress_cb != NULL) {

		DBG("state: %d", state);

		if (state == BT_OPP_TRANSFER_QUEUED) {
			bt_progress_cb(name, size, 0, data);
			return;
		}

		if (state == BT_OPP_TRANSFER_ACTIVE) {
			bt_progress_cb(name, size, percent, data);

			return;
		}

		if (state == BT_OPP_TRANSFER_COMPLETED) {
			bt_progress_cb(name, size, 100, data);

			pending_file_count--;
		}

		if (state == BT_OPP_TRANSFER_CANCELED ||
				state == BT_OPP_TRANSFER_ERROR)
			pending_file_count--;
	}

	transfer = obex_transfer_get_transfer_from_id(id);
	if (transfer == NULL) {
		ERROR("invalid transfer");
		return;
	}

	remote_address = obex_transfer_get_property_destination(transfer);

	if (pending_file_count == 0) {
		bt_finished_cb(BT_SUCCESS, remote_address, data);

		bt_push_request_cb = NULL;
		bt_progress_cb = NULL;
		bt_finished_cb = NULL;
	}
}

static void session_state_changed(const char *session_id,
				struct _obex_session *session,
				enum session_state state,
				void *data, char *error_msg)
{
	DBG("session id %s state %d", session_id, state);
	if (state == OBEX_SESSION_CREATED) {
		char *remote_address;

		remote_address =
			obex_session_property_get_destination(session);
		bt_push_request_cb(BT_SUCCESS, remote_address, data);
		g_free(remote_address);
	}
}

static int bt_device_get_privileges(const char *remote_address)
{
	int user_privilieges;

	DBG("address = %s", remote_address);

	user_privilieges = comms_bluetooth_get_user_privileges_sync(
						remote_address);

	return user_privilieges;
}

int bt_opp_client_push_files(const char *remote_address,
				bt_opp_client_push_responded_cb responded_cb,
				bt_opp_client_push_progress_cb progress_cb,
				bt_opp_client_push_finished_cb finished_cb,
				void *user_data)
{
	char *c_file = NULL;
	GList *list, *next;
	int user_privilieges;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	DBG("");

	user_privilieges = bt_device_get_privileges(remote_address);

	memset(pushing_address, 0, ADDRESS_LEN);
	strcpy(pushing_address, remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		memset(pushing_address, 0, ADDRESS_LEN);
		return BT_ERROR_NOT_ENABLED;
	}

	bt_push_request_cb = responded_cb;
	bt_progress_cb = progress_cb;
	bt_finished_cb = finished_cb;

	bt_opp_set_transfers_state_cb(client_transfer_state_cb, user_data);
	obex_session_set_watch(session_state_changed, user_data);

	pending_file_count = g_list_length(sending_files);

	for (list = g_list_first(sending_files); list; list = next) {
		c_file = list->data;

		next = g_list_next(list);

		if (c_file == NULL)
			continue;

		bt_opp_client_push_file(c_file, remote_address,
					NULL, NULL, NULL, NULL);

		sending_files = g_list_remove(sending_files, c_file);
	}

	g_list_free_full(sending_files, g_free);
	sending_files = NULL;

	return BT_ERROR_NONE;
}

int bt_opp_client_cancel_push(void)
{
	const GList *transfer_list;
	GList *list, *next;
	int user_privilieges;

	if (strlen(pushing_address) == 0) {
		DBG("not need to cancel bonding");
		return BT_ERROR_NOT_ENABLED;
	}

	user_privilieges = bt_device_get_privileges(pushing_address);
	memset(pushing_address, 0, ADDRESS_LEN);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	transfer_list = obex_transfer_get_pathes();

	for (list = g_list_first((GList *)transfer_list); list; list = next) {
		struct _obex_transfer *transfer;
		int transfer_id;

		next = g_list_next(list);

		transfer = obex_transfer_get_transfer_from_path(list->data);
		transfer_id = obex_transfer_get_id(transfer);

		/* Only cancel client push */
		if (transfer_id < 10000)
			comms_bluetooth_opp_cancel_transfer(
						transfer_id, NULL, NULL);
	}

	return 0;
}


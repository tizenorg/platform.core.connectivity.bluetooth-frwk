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
	char *pending_transfer_path;
	bt_opp_server_push_file_requested_cb requested_cb;
	void *user_data;
	int pending_transfer_id;
	GDBusMethodInvocation *pending_invocation;
} opp_server;

struct opp_transfer_state_cb_node {
	bt_opp_transfer_state_cb cb;
	void *user_data;
};

static gboolean is_client_register;
static gboolean is_server_register;
static void *opp_client_data;

static struct opp_transfer_state_cb_node *opp_transfer_state_node;

static void bt_opp_server_transfer_state_cb(bt_opp_transfer_state_e state,
					const char *name, uint64_t size,
					unsigned char percent, void *user_data);

static void bt_opp_client_transfer_state_cb(unsigned int id,
			bt_opp_transfer_state_e state, const char *address,
			const char *name, uint64_t size,
			unsigned char percent, void *user_data);

static int bt_opp_server_reject_request(void);

static int bt_device_get_privileges(const char *remote_address)
{
	int user_privilieges;

	DBG("address = %s", remote_address);

	user_privilieges = comms_bluetooth_get_user_privileges_sync(
						remote_address);

	return user_privilieges;
}

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.obex.Agent1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='AuthorizePush'>"
	"      <arg type='s' name='address' direction='in'/>"
	"      <arg type='s' name='name' direction='in'/>"
	"      <arg type='s' name='path' direction='in'/>"
	"      <arg type='t' name='size' direction='in'/>"
	"      <arg type='i' name='transfer_id' direction='in'/>"
	"      <arg type='s' direction='out'/>"
	"    </method>"
	"    <method name='PushStatus'>"
	"      <arg type='s' name='address' direction='in'/>"
	"      <arg type='s' name='name' direction='in'/>"
	"      <arg type='t' name='size' direction='in'/>"
	"      <arg type='i' name='transfer_id' direction='in'/>"
	"      <arg type='i' name='status' direction='in'/>"
	"      <arg type='d' name='percent' direction='in'/>"
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
	} else if (g_strcmp0(method_name, "AuthorizePush") == 0) {
		gchar *address, *name, *transfer_path;
		gchar *device_name = NULL;
		bluez_adapter_t *adapter;
		bluez_device_t *device;
		int transfer_id;
		guint64 size;

		opp_server.pending_invocation = invocation;

		g_variant_get(parameters, "(sssti)", &address,
				&name, &transfer_path, &size, &transfer_id);

		adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
		device = bluez_adapter_get_device_by_address(adapter,
								address);
		if (device)
			device_name = bluez_device_get_property_alias(device);

		opp_server.pending_name = g_strdup(name);
		opp_server.pending_transfer_path = g_strdup(transfer_path);
		opp_server.pending_transfer_id = transfer_id;

		if (opp_server.requested_cb)
			opp_server.requested_cb((const char *) device_name,
					(const char *) name,
					size, opp_server.user_data);

		g_free(name);
		g_free(address);
		return;
	} else if (g_strcmp0(method_name, "PushStatus") == 0) {
		gchar *name, *address;
		guint64 size;
		guint id = 0;
		int status;
		double percent;

		g_variant_get(parameters, "(sstiid)", &address, &name,
						&size, &id, &status, &percent);

		DBG("transfer_id = %d, status = %d", id, status);

		g_dbus_method_invocation_return_value(invocation, NULL);

		if (id >= 10000)
			bt_opp_server_transfer_state_cb(status, name, size,
						percent, opp_server.user_data);
		else
			bt_opp_client_transfer_state_cb(id, status,
				address, name, size, percent, opp_client_data);
	} else if (g_strcmp0(method_name, "Cancel") == 0) {
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

static void destory_opp_object(void)
{
	DBG("bluetooth_opp_agent_id = %d", bluetooth_opp_agent_id);

	if (is_client_register || is_server_register)
		return;

	if (bluetooth_opp_agent_id > 0) {

		g_dbus_connection_unregister_object(conn,
					bluetooth_opp_agent_id);

		bluetooth_opp_agent_id = 0;

		release_name_on_dbus(OBEX_LIB_SERVICE);
	}

	return;
}

static void destory_opp_agent(void)
{
	DBG("bluetooth_opp_agent_id = %d", bluetooth_opp_agent_id);

	destory_opp_object();

	comms_bluetooth_unregister_opp_agent(
				AGENT_OBJECT_PATH, NULL, NULL);

	return;
}

static int register_opp_object(void)
{
	int ret;

	DBG("");

	if (bluetooth_opp_agent_id)
		return BT_SUCCESS;

	introspection_data =
		g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	ret = request_name_on_dbus(OBEX_LIB_SERVICE);
	if (ret != 0)
		return BT_ERROR_OPERATION_FAILED;

	DBG("%s requested success", OBEX_LIB_SERVICE);

	bluetooth_opp_agent_id = g_dbus_connection_register_object(conn,
					AGENT_OBJECT_PATH,
					introspection_data-> interfaces[0],
					&interface_handle, NULL, NULL, NULL);

	DBG("bluetooth_opp_agent_id = %d", bluetooth_opp_agent_id);

	if (bluetooth_opp_agent_id == 0)
		return BT_ERROR_OPERATION_FAILED;

	return BT_SUCCESS;
}

static int register_opp_agent(void)
{
	int ret;

	DBG("");

	ret = register_opp_object();

	if (ret == BT_SUCCESS) {
		if (is_server_register)
			return BT_SUCCESS;
	} else {
		return BT_ERROR_OPERATION_FAILED;
	}

	ret = comms_bluetooth_register_opp_agent_sync(
					AGENT_OBJECT_PATH, NULL);

	DBG("ret = %d", ret);

	if (ret != BT_SUCCESS) {
		is_server_register = FALSE;
		destory_opp_agent();
		return BT_ERROR_OPERATION_FAILED;
	}

	return BT_SUCCESS;
}

static int bt_opp_register_server(const char *dir,
			bt_opp_server_push_file_requested_cb push_requested_cb,
			void *user_data)
{
	int ret;

	if (dir == NULL || push_requested_cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (!g_file_test(dir, G_FILE_TEST_IS_DIR)) {
		ERROR("%s is not valid directory", dir);
		return BT_ERROR_INVALID_PARAMETER;
	}

	ret = register_opp_agent();
	if (ret != BT_SUCCESS)
		return ret;

	is_server_register = TRUE;

	/* TODO: Do we need to check the dir privilege? */

	opp_server.root_folder = g_strdup(dir);
	opp_server.requested_cb = push_requested_cb;
	opp_server.user_data = user_data;

	return BT_SUCCESS;
}

static int bt_opp_unregister_server(void)
{
	/* TODO: unregister agent */
	g_free(opp_server.root_folder);
	opp_server.root_folder = NULL;

	opp_server.requested_cb = NULL;
	opp_server.user_data = NULL;

	is_server_register = FALSE;
	destory_opp_agent();

	return 0;
}

int bt_opp_set_transfers_state_cb(bt_opp_transfer_state_cb cb, void *user_data)
{
	struct opp_transfer_state_cb_node *state_node;

	DBG("");

	if (cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (opp_transfer_state_node) {
		DBG("transfer state callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	state_node = g_new0(struct opp_transfer_state_cb_node, 1);
	if (state_node == NULL) {
		ERROR("no memory.");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	state_node->cb = cb;
	state_node->user_data = user_data;

	opp_transfer_state_node = state_node;

	return BT_SUCCESS;
}

void bt_opp_clear_transfers_state_cb(void)
{
	DBG("");

	if (!opp_transfer_state_node)
		return;

	g_free(opp_transfer_state_node);
	opp_transfer_state_node = NULL;
}

int bt_opp_server_accept_request(const char *name, void *user_data,
							int *transfer_id)
{
	GDBusMethodInvocation *invocation;
	char *n, *file_name;

	invocation = opp_server.pending_invocation;

	if (invocation == NULL) {
		ERROR("Can't find invocation");
		return BT_ERROR_OPERATION_FAILED;
	}

	n = (name != NULL) ? (char *) name : opp_server.pending_name;

	if (opp_server.root_folder) {
		file_name = g_build_filename(opp_server.root_folder, n, NULL);

		g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", file_name));

		g_free(file_name);
	} else
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(s)", n));

	opp_server.pending_invocation = NULL;
	opp_server.user_data = user_data;

	comms_bluetooth_opp_add_notify(opp_server.pending_transfer_path,
							NULL, NULL);

	*transfer_id = opp_server.pending_transfer_id;

	g_free(opp_server.pending_transfer_path);
	opp_server.pending_transfer_path = NULL;
	g_free(opp_server.pending_name);
	opp_server.pending_name = NULL;

	return BT_SUCCESS;
}

static int bt_opp_server_reject_request(void)
{
	if (opp_server.pending_invocation) {
		g_dbus_method_invocation_return_dbus_error(
					opp_server.pending_invocation,
					OBEX_ERROR_INTERFACE ".Rejected",
					"RejectByUser");

		opp_server.pending_invocation = NULL;
	}

	opp_server.user_data = NULL;
	g_free(opp_server.pending_transfer_path);
	opp_server.pending_transfer_path = NULL;
	g_free(opp_server.pending_name);
	opp_server.pending_name = NULL;

	return 0;
}

int bt_opp_transfer_cancel(int transfer_id)
{
	comms_bluetooth_opp_cancel_transfer(transfer_id, NULL, NULL);
	return BT_SUCCESS;
}

int bt_opp_server_set_destination(const char *dir)
{
	if (dir == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (opp_server.root_folder != NULL)
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

	comms_bluetooth_opp_send_file(remote_address, file_name,
					AGENT_OBJECT_PATH, NULL, NULL);

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
static bt_opp_client_push_responded_cb bt_push_responded_cb;
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

	return ret;
}

int bt_opp_server_initialize_by_connection_request(const char *destination,
		bt_opp_server_connection_requested_cb connection_requested_cb,
		void *user_data)
{
	int ret;

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
		return BT_ERROR_OPERATION_FAILED;
	}

	opp_server_conn_req_node->callback = connection_requested_cb;
	opp_server_conn_req_node->user_data = user_data;

	return ret;
}

int bt_opp_server_deinitialize(void)
{
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

	return bt_opp_unregister_server();
}

static void bt_opp_server_transfer_state_cb(bt_opp_transfer_state_e state,
					const char *name, uint64_t size,
					unsigned char percent, void *user_data)
{
	if (state == BT_OPP_TRANSFER_QUEUED ||
			state == BT_OPP_TRANSFER_ACTIVE) {
		if (bt_transfer_progress_cb)
			bt_transfer_progress_cb(name, size, percent, user_data);
	} else if (state == BT_OPP_TRANSFER_COMPLETED) {
		if (bt_transfer_finished_cb)
			bt_transfer_finished_cb(BT_ERROR_NONE,
						name, size, user_data);
	} else if (state == BT_OPP_TRANSFER_ERROR || BT_OPP_TRANSFER_CANCELED) {
		if (bt_transfer_finished_cb)
			bt_transfer_finished_cb(BT_ERROR_CANCELLED,
						name, size, user_data);
	}
}

static void bt_opp_client_transfer_state_cb(unsigned int id,
				bt_opp_transfer_state_e state,
				const char *address, const char *name,
				uint64_t size, unsigned char percent,
				void *user_data)
{
	DBG("+");

	if (state == BT_OPP_TRANSFER_QUEUED) {
		DBG("id = %d, name =%s, len = %d", id, name, (int)strlen(name));
		if (id == 0 && g_strcmp0(name, "OBEX_TRANSFER_QUEUED")) {
			if (bt_push_responded_cb)
				bt_push_responded_cb(BT_ERROR_NONE,
							address, user_data);
		} else {
			if (bt_progress_cb)
				bt_progress_cb(name, size, percent, user_data);
		}
	} else if  (state == BT_OPP_TRANSFER_ACTIVE) {
		DBG("1");
		if (bt_progress_cb)
			bt_progress_cb(name, size, percent, user_data);
	} else if (state == BT_OPP_TRANSFER_COMPLETED) {
		DBG("2");
		if (bt_finished_cb)
			bt_finished_cb(BT_ERROR_NONE, address, user_data);
	} else if (state == BT_OPP_TRANSFER_ERROR ||
		state == BT_OPP_TRANSFER_CANCELED ||
					state == BT_OPP_TRANSFER_UNKNOWN) {
		DBG("3");
		if (bt_finished_cb)
			bt_finished_cb(BT_ERROR_CANCELLED, address, user_data);
	}

	DBG("-");
}

int bt_opp_server_accept(bt_opp_server_transfer_progress_cb progress_cb,
			bt_opp_server_transfer_finished_cb finished_cb,
			const char *name, void *user_data, int *transfer_id)
{
	bt_transfer_progress_cb = progress_cb;
	bt_transfer_finished_cb = finished_cb;

	return bt_opp_server_accept_request(name, user_data, transfer_id);
}

int bt_opp_server_reject(void)
{
	return bt_opp_server_reject_request();
}

int bt_opp_server_cancel_transfer(int transfer_id)
{
	return bt_opp_transfer_cancel(transfer_id);
}

int bt_opp_client_initialize(void)
{
	int ret;

	ret = register_opp_object();
	if (ret != BT_SUCCESS)
		return ret;

	is_client_register = TRUE;

	return BT_SUCCESS;
}

int bt_opp_client_deinitialize(void)
{
	is_client_register = FALSE;

	destory_opp_object();

	return BT_SUCCESS;
}

int bt_opp_client_add_file(const char *file)
{
	int ret = BT_ERROR_NONE;

	DBG("+");

	if (file == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (access(file, F_OK) == 0) {
		sending_files = g_list_append(sending_files,
						g_strdup(file));
	} else {
		ret = BT_ERROR_INVALID_PARAMETER;
		DBG("ret = %d", ret);
	}

	DBG("-");

	return ret;
}

int bt_opp_client_clear_files(void)
{
	int i = 0;
	int file_num = 0;
	char *c_file = NULL;

	DBG("+");

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

	DBG("-");

	return BT_ERROR_NONE;
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

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		memset(pushing_address, 0, ADDRESS_LEN);
		return BT_ERROR_NOT_ENABLED;
	}

	DBG("11");

	memset(pushing_address, 0, ADDRESS_LEN);
	strcpy(pushing_address, remote_address);

	bt_push_responded_cb = responded_cb;
	bt_progress_cb = progress_cb;
	bt_finished_cb = finished_cb;
	opp_client_data = user_data;

	pending_file_count = g_list_length(sending_files);

	DBG("pending_file_count = %d", pending_file_count);

	for (list = g_list_first(sending_files); list; list = next) {
		c_file = list->data;

		next = g_list_next(list);

		if (c_file == NULL)
			continue;

		DBG("before bt_opp_client_push_file");

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

	comms_bluetooth_opp_cancel_transfers(NULL, NULL);

	return 0;
}

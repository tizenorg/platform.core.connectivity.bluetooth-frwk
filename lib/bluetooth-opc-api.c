/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "bluetooth-api-common.h"
#include "bluetooth-opc-api.h"

#include "obex-agent.h"
#include <sys/time.h>
#include <dbus/dbus-glib.h>
#include <unistd.h>
#include <fcntl.h>

static ObexAgent *opc_obex_agent = NULL;
static DBusGProxy *client_proxy = NULL;
static DBusGProxy *current_transfer = NULL;

static gboolean cancel_sending_files = FALSE;
struct obexd_transfer_hierarchy opc_current_transfer = { 0, };

unsigned int g_counter = 0;

static int __bt_obex_client_agent_init(char *agent_path);

static void __bt_free_obexd_transfer_hierarchy(struct obexd_transfer_hierarchy
					       *current_transfer);

static void __bt_send_files_cb(DBusGProxy *proxy,
			       DBusGProxyCall *call, void *user_data);

static void __bt_value_free(GValue *value)
{
	g_value_unset(value);
	g_free(value);
}
static GQuark __bt_opc_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

static GError *__bt_opc_agent_error(bt_opc_agent_error_t error,
				     const char *err_msg)
{
	return g_error_new(BT_OPC_AGENT_ERROR, error, err_msg);
}
static void __bt_opc_internal_event_cb(int event, int result, void *param_data)
{
	DBG("+");
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param_data;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info && bt_internal_info->bt_cb_ptr)
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event,
					bt_internal_info->user_data);

	DBG("-");
}


BT_EXPORT_API int bluetooth_opc_init(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info == NULL) {
		DBG("bt_internal_info is NULL\n");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	if (client_proxy) {
		DBG("Already initialized");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	client_proxy =  dbus_g_proxy_new_for_name(bt_internal_info->conn,
							"org.openobex.client", "/",
						     	 "org.openobex.Client");

	if (NULL == client_proxy) {
		DBG("client_proxy is null");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("- \n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_opc_deinit(void)
{
	DBG("+\n");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == client_proxy) {
		DBG("Not  initialized");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	g_object_unref(client_proxy);
	client_proxy = NULL;

	DBG("- \n");
	return BLUETOOTH_ERROR_NONE;
}


BT_EXPORT_API int bluetooth_opc_push_files(bluetooth_device_address_t *remote_address,
		   		 char **file_name_array)
{
	DBG("+ \n");
	GHashTable *hash;
	GValue *value;
	char address[BT_BD_ADDR_MAX_LEN] = { 0 };
	GError *error = NULL;
	char agent_path[100] = {0};

	if (remote_address == NULL || file_name_array == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == client_proxy) {
		DBG("client_proxy is NULL\n");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	if (current_transfer || opc_obex_agent) {
		DBG("Transfer in progress\n");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if ((NULL == remote_address) || (NULL == file_name_array)) {
		DBG("Invalid Param\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	snprintf(agent_path, sizeof(agent_path), OBEX_CLIENT_AGENT_PATH,
				getpid(), g_counter++);

	if (__bt_obex_client_agent_init(agent_path)) {
		DBG("agent init failedL\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	hash = g_hash_table_new_full(g_str_hash, g_str_equal,
				     g_free, (GDestroyNotify) __bt_value_free);

	_bluetooth_internal_print_bluetooth_device_address_t(remote_address);

	_bluetooth_internal_addr_type_to_addr_string(address, remote_address);

	value = g_new0(GValue, 1);
	g_value_init(value, G_TYPE_STRING);
	g_value_set_string(value, address);
	g_hash_table_insert(hash, "Destination", value);

	cancel_sending_files = FALSE;

	if (!dbus_g_proxy_begin_call(client_proxy, "SendFiles",
				__bt_send_files_cb, NULL, NULL,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
						    G_TYPE_VALUE), hash,
				G_TYPE_STRV, file_name_array,
				DBUS_TYPE_G_OBJECT_PATH, agent_path,
				G_TYPE_INVALID)) {
				DBG("SendFiles failed \n");
				g_object_unref(opc_obex_agent);
				opc_obex_agent = NULL;
				return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("- \n");
	return BLUETOOTH_ERROR_NONE;

}

BT_EXPORT_API int bluetooth_opc_cancel_push(void)
{
	DBG("+");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == opc_obex_agent) {
		DBG("No Transfer");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	cancel_sending_files = TRUE;

	if (current_transfer)
		dbus_g_proxy_call_no_reply(current_transfer, "Cancel", G_TYPE_INVALID,
				   G_TYPE_INVALID);

	DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API gboolean bluetooth_opc_sessioin_is_exist(void)
{
	DBG("+");

	gboolean exist = FALSE;
	DBusGProxy *opc_proxy = NULL;
	DBusGConnection *conn = NULL;
	GError *error = NULL;
	GPtrArray *gp_array = NULL;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL)
		return FALSE;

	opc_proxy = dbus_g_proxy_new_for_name(conn,
					OBEX_CLIENT_SERVICE, "/",
				     	 OBEX_CLIENT_INTERFACE);

	if (opc_proxy == NULL) {
		dbus_g_connection_unref(conn);
		return FALSE;
	}

	dbus_g_proxy_call(opc_proxy, "GetTransfers", &error,
			G_TYPE_INVALID,
			dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
			&gp_array, G_TYPE_INVALID);

	if (error == NULL) {
		if (gp_array != NULL) {
			int i;
			for (i = 0; i < gp_array->len; i++) {
				gchar *gp_path = g_ptr_array_index(gp_array, i);

				if (gp_path != NULL) {
					DBG("Session [%s]", gp_path);
					exist = TRUE;
					g_free(gp_path);
				}
			}
			g_ptr_array_free(gp_array, TRUE);
		}
	} else {
		DBG("GetSessions error: [%s]", error->message);
		g_error_free(error);
	}

	g_object_unref(opc_proxy);
	dbus_g_connection_unref(conn);

	DBG("exist: %d", exist);

	DBG("-");

	return exist;
}

static void __bt_send_files_cb(DBusGProxy *proxy, DBusGProxyCall *call,
				void *user_data)
{
	GError *error = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	DBG("+");

	if (dbus_g_proxy_end_call(proxy, call, &error,
				G_TYPE_INVALID) == FALSE) {

		DBG("%s", error->message);

		g_error_free(error);

		result = BLUETOOTH_ERROR_SERVICE_NOT_FOUND;
	}

	if (TRUE == cancel_sending_files)
		result = BLUETOOTH_ERROR_CANCEL_BY_USER;

	if (result != BLUETOOTH_ERROR_NONE) {
		g_object_unref(opc_obex_agent);
		opc_obex_agent = NULL;
	}

	__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_CONNECTED,
						result, NULL);
	DBG("-");
}

static gboolean __bt_progress_callback(DBusGMethodInvocation *context,
					DBusGProxy *transfer,
					guint64 transferred,
					gpointer user_data)
{
	gdouble percentage_progress = 0;
	int percentage_int = 0;

	DBG("+");
	DBG("transferred:[%ld] \n", transferred);

	dbus_g_method_return(context);

	if (opc_current_transfer.size != 0)
		percentage_progress = (gdouble) transferred / (gdouble) opc_current_transfer.size * 100;
	else
		percentage_progress = 0;

	percentage_int = percentage_progress;

	__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_PROGRESS,
						BLUETOOTH_ERROR_NONE, &percentage_int);

	DBG("-");

	return TRUE;
}

static gboolean __bt_complete_callback(DBusGMethodInvocation *context,
					DBusGProxy *transfer,
					gpointer user_data)
{
	bt_opc_transfer_info_t info;
	DBG("+");

	dbus_g_method_return(context);

	g_object_unref(current_transfer);
	current_transfer = NULL;

	info.filename = opc_current_transfer.name;
	info.size = opc_current_transfer.size;

	__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_COMPLETE,
						BLUETOOTH_ERROR_NONE, &info);

	__bt_free_obexd_transfer_hierarchy(&opc_current_transfer);

	DBG("-");
	return TRUE;
}

static void __bt_free_obexd_transfer_hierarchy(struct obexd_transfer_hierarchy
					       *current_transfer)
{
	if (!current_transfer)
		return;

	if (current_transfer->name) {
		free(current_transfer->name);
		current_transfer->name = NULL;
	}

	if (current_transfer->file_name) {
		free(current_transfer->file_name);
		current_transfer->file_name = NULL;
	}

	current_transfer->size = 0;
}

static gboolean __bt_request_callback(DBusGMethodInvocation *context,
					DBusGProxy *transfer,
					gpointer user_data)
{
	g_assert(current_transfer == NULL);
	bt_opc_transfer_info_t info;
	GHashTable *hash = NULL;
	GError *error;

	DBG("+");
	current_transfer = g_object_ref(transfer);

	__bt_free_obexd_transfer_hierarchy(&opc_current_transfer);

	if (TRUE == cancel_sending_files) {
		DBG("Cancelling");
		error = __bt_opc_agent_error(BT_OBEX_AGENT_ERROR_CANCEL, "CancelledByUser");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		g_object_unref(opc_obex_agent);
		opc_obex_agent = NULL;
		__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_DISCONNECTED,
						BLUETOOTH_ERROR_CANCEL_BY_USER, NULL);
		return TRUE;
	} else {
		dbus_g_method_return(context, "");
	}

	dbus_g_proxy_call(transfer, "GetProperties", NULL,
	                        G_TYPE_INVALID,
	                        dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
	                        &hash, G_TYPE_INVALID);

	if (hash) {
	        GValue *value;
	        value = g_hash_table_lookup(hash, "Name");
	        opc_current_transfer.name = value ? g_strdup( g_value_get_string(value)) : NULL;

	        value = g_hash_table_lookup(hash, "Filename");
	        opc_current_transfer.file_name = value ? g_strdup( g_value_get_string(value)) : NULL;

	        value = g_hash_table_lookup(hash, "Size");
	        opc_current_transfer.size = value ? g_value_get_uint64(value) : 0;

	        g_hash_table_destroy(hash);

	        DBG("Name %s :",opc_current_transfer.name);
	        DBG("FileName %s :",opc_current_transfer.file_name);
	        DBG("Size %d :",opc_current_transfer.size);

		info.filename = opc_current_transfer.name;
		info.size = opc_current_transfer.size;

		__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_STARTED,
						BLUETOOTH_ERROR_NONE, &info);
	}

	DBG("-");
	return TRUE;
}

static gboolean __bt_release_callback(DBusGMethodInvocation *context,
					gpointer user_data)
{
	DBG("+");

	dbus_g_method_return(context);

	if (current_transfer) {
		g_object_unref(current_transfer);
		current_transfer = NULL;
	}

	g_object_unref(opc_obex_agent);
	opc_obex_agent = NULL;

	/*release */
	__bt_free_obexd_transfer_hierarchy(&opc_current_transfer);

	__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_DISCONNECTED,
						BLUETOOTH_ERROR_NONE, NULL);
	DBG("-");

	return TRUE;
}

static gboolean __bt_error_callback(DBusGMethodInvocation *context,
					DBusGProxy *transfer,
					const char *message,
					gpointer user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	bt_opc_transfer_info_t info;
	DBG("+ \n");

	DBG("message:[%s] \n", message);

	dbus_g_method_return(context);

	g_object_unref(current_transfer);
	current_transfer = NULL;

	if (TRUE == cancel_sending_files)  {
		result = BLUETOOTH_ERROR_CANCEL_BY_USER;
	} else if (0 == g_strcmp0(message, "Forbidden")) {
		result = BLUETOOTH_ERROR_ACCESS_DENIED;
	} else if (TRUE == g_str_has_prefix(message,
				"Transport endpoint is not connected")) {
		result = BLUETOOTH_ERROR_NOT_CONNECTED;
		cancel_sending_files = TRUE;
	} else if (0 == g_strcmp0(message, "Database full")) {
		result = BLUETOOTH_ERROR_OUT_OF_MEMORY;
		cancel_sending_files = TRUE;
	} else {
		result = BLUETOOTH_ERROR_INTERNAL;
	}

	info.filename = opc_current_transfer.name;
	info.size = opc_current_transfer.size;

	__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_TRANSFER_COMPLETE,
						result, &info);

	__bt_free_obexd_transfer_hierarchy(&opc_current_transfer);

	if (TRUE == cancel_sending_files)  {
		/* User cancelled or Remote device is switched off / memory full*/
		g_object_unref(opc_obex_agent);
		opc_obex_agent = NULL;

		__bt_opc_internal_event_cb(BLUETOOTH_EVENT_OPC_DISCONNECTED,
						result, NULL);
	}

	DBG("- \n");
	return TRUE;
}

static int __bt_obex_client_agent_init(char *agent_path)
{
	int random_num = 0;

	opc_obex_agent = obex_agent_new();
	if(NULL == opc_obex_agent)
		return -1;

	obex_agent_set_release_func(opc_obex_agent,
				    __bt_release_callback, NULL);
	obex_agent_set_request_func(opc_obex_agent,
				    __bt_request_callback, NULL);
	obex_agent_set_progress_func(opc_obex_agent,
				     __bt_progress_callback, NULL);
	obex_agent_set_complete_func(opc_obex_agent,
				     __bt_complete_callback, NULL);
	obex_agent_set_error_func(opc_obex_agent,
				__bt_error_callback, NULL);

	obex_agent_setup(opc_obex_agent, agent_path);

	return 0;

}



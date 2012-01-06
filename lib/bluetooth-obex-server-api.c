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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <sys/time.h>
#include <dbus/dbus-glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vconf.h>

#include "bluetooth-api-common.h"
#include "bluetooth-obex-server-api.h"
#include "obex-agent.h"

static GSList *transfers = NULL;
char *g_dst_path = NULL;
obex_server_info_t g_obex_server_info;

static gboolean __bt_authorize_callback(DBusGMethodInvocation *context,
					const char *path,
					const char *bdaddress,
					const char *name,
					const char *type,
					gint length,
					gint time,
					gpointer user_data);

static int __bt_obex_agent_register(obex_server_info_t *obex_server_info,
							DBusGConnection *conn);

static void __bt_obex_agent_unregister(obex_server_info_t *obex_server_info);

static void __bt_transfer_progress_cb(DBusGProxy *object,
					gint total,
					gint transferred,
					gpointer user_data);

static void __bt_ops_internal_event_cb(int event, int result, void *param_data)
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

static GQuark __bt_obex_agent_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

static GError *__bt_obex_agent_error(bt_obex_agent_error_t error,
				     const char *err_msg)
{
	return g_error_new(BT_OBEX_AGENT_ERROR, error, err_msg);
}

BT_EXPORT_API int bluetooth_obex_server_init(char *dst_path)
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

	if (g_obex_server_info.obex_server_agent) {
		DBG("Agent already registered");
		return BLUETOOTH_ERROR_AGENT_ALREADY_EXIST;
	}

	if (NULL == dst_path) {
		DBG("Invalid Param");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	g_dst_path = g_strdup(dst_path);

	DBG("- \n");
	return __bt_obex_agent_register(&g_obex_server_info,
					bt_internal_info->conn);
}

BT_EXPORT_API int bluetooth_obex_server_deinit(void)
{
	DBG("+\n");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == g_obex_server_info.obex_server_agent) {
		DBG("Agent not registered");
		return BLUETOOTH_ERROR_AGENT_DOES_NOT_EXIST;
	}

	__bt_obex_agent_unregister(&g_obex_server_info);

	g_free(g_dst_path);
	g_dst_path = NULL;

	DBG("- \n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API gboolean bluetooth_obex_server_is_activated(void)
{
	gboolean exist = FALSE;
	DBusGConnection *conn = NULL;
	DBusGProxy *obex_proxy = NULL;
	GError *error = NULL;

	DBG("+");

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL)
		return FALSE;

	obex_proxy = dbus_g_proxy_new_for_name(conn,
					OBEX_SERVER_SERVICE,
					"/", OBEX_SERVER_MANAGER);

	if (obex_proxy == NULL) {
		DBG("obex_proxy is NULL \n");
		dbus_g_connection_unref(conn);
		return FALSE;
	}

	dbus_g_proxy_call(obex_proxy, "RegisterAgent", &error,
			  DBUS_TYPE_G_OBJECT_PATH, BT_INVALID_PATH,
			  G_TYPE_INVALID, G_TYPE_INVALID);
	if (error != NULL) {
		DBG("Error: %s\n", error->message);

		if (!strcmp(error->message, "Agent already exists"))
			exist = TRUE;

		g_error_free(error);
	}

	g_object_unref(obex_proxy);
	dbus_g_connection_unref(conn);

	DBG("-");

	return exist;
}

static transfer_info_t *_bt_find_transfer(const char *transfer_path)
{
	GSList *l;

	for (l = transfers; l != NULL; l = l->next) {
		transfer_info_t *transfer = l->data;

		if (transfer) {
			if (0 == g_strcmp0(transfer->path, transfer_path))
				return transfer;
		}
	}

	return NULL;
}

static void __bt_obex_server_transfer_free(transfer_info_t *transfer_info)
{
	DBG("+");

	if (transfer_info == NULL)
		return;

	if (transfer_info->transfer_proxy) {
		dbus_g_proxy_disconnect_signal(transfer_info->transfer_proxy,
				       "Progress",
				       G_CALLBACK(__bt_transfer_progress_cb),
				       transfer_info);

			g_object_unref(transfer_info->transfer_proxy);
			transfer_info->transfer_proxy = NULL;
	}

	g_free(transfer_info->path);
	g_free(transfer_info->filename);
	g_free(transfer_info->device_name);
	g_free(transfer_info->type);
	g_free(transfer_info);

	DBG("-");
}

static int __bt_obex_server_reply_authorize(const guint accept,
					const char *filepath,
					obex_server_info_t *obex_server_info)
{
	DBG("+\n");

	if (obex_server_info) {
		if (accept == BT_OBEX_AGENT_ACCEPT) {
			dbus_g_method_return(obex_server_info->reply_context, filepath);
		} else {
			GError *error = NULL;
			error = __bt_obex_agent_error(BT_OBEX_AGENT_ERROR_CANCEL,
						  "CanceledbyUser");
			dbus_g_method_return_error(obex_server_info->reply_context, error);
			g_error_free(error);
			g_free(obex_server_info->filename);
			obex_server_info->filename = NULL;
			g_free(obex_server_info->device_name);
			obex_server_info->device_name = NULL;
			g_free(obex_server_info->type);
			obex_server_info->type = NULL;
		}
	}

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}


BT_EXPORT_API int bluetooth_obex_server_accept_authorize(char *filename)
{
	DBG("+\n");

	char file_path[FILE_PATH_LEN] = { 0, };

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == g_obex_server_info.obex_server_agent) {
		DBG("Agent not registered");
		return BLUETOOTH_ERROR_AGENT_DOES_NOT_EXIST;
	}

	if (NULL == filename) {
		DBG("Invalid param");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (g_dst_path)
		snprintf(file_path, sizeof(file_path), "%s/%s",
			g_dst_path, filename);

	DBG("- \n");
	return __bt_obex_server_reply_authorize(BT_OBEX_AGENT_ACCEPT,
					file_path,
					&g_obex_server_info);
}

BT_EXPORT_API int bluetooth_obex_server_reject_authorize(void)
{
	DBG("+\n");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == g_obex_server_info.obex_server_agent) {
		DBG("Agent not registered");
		return BLUETOOTH_ERROR_AGENT_DOES_NOT_EXIST;
	}

	DBG("- \n");
	return __bt_obex_server_reply_authorize(BT_OBEX_AGENT_REJECT,
					NULL,
					&g_obex_server_info);
}

BT_EXPORT_API int bluetooth_obex_server_set_destination_path(char *dst_path)
{
	DBG("+\n");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == g_obex_server_info.obex_server_agent) {
		DBG("Agent not registered");
		return BLUETOOTH_ERROR_AGENT_DOES_NOT_EXIST;
	}

	if (NULL == dst_path) {
		DBG("Invalid Param");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	g_free(g_dst_path);
	g_dst_path = g_strdup(dst_path);

	DBG("- \n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_obex_server_set_root(char *root)
{
	GError *error = NULL;
	GValue folder = { 0 };
	obex_server_info_t *obex_server_info = &g_obex_server_info;

	DBG("+\n");

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (NULL == obex_server_info->obex_server_agent) {
		DBG("Agent not registered");
		return BLUETOOTH_ERROR_AGENT_DOES_NOT_EXIST;
	}


	if (obex_server_info->obex_proxy == NULL) {
		DBG("obex_proxy is NULL \n");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	if (root == NULL) {
		DBG("Invalid parameter \n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	DBG("Set Root Foler: %s", root);

	g_value_init(&folder, G_TYPE_STRING);
	g_value_set_string(&folder, root);

	dbus_g_proxy_call(obex_server_info->obex_proxy, "SetProperty",
			&error, G_TYPE_STRING, "Root",
			G_TYPE_VALUE, &folder, G_TYPE_INVALID, G_TYPE_INVALID);

	g_value_unset(&folder);

	if (error) {
		DBG("SetProperty Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

static char *__bt_get_remote_device_name(DBusGConnection *bus,
					 const char *bdaddress)
{
	DBusGProxy *manager_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	GError *error = NULL;
	const char *adapter_path = NULL;
	char *device_path = NULL;
	DBusGProxy *device = NULL;
	GHashTable *hash = NULL;
	GValue *value;
	gchar *name = NULL;
	DBG("+\n");

	if ((NULL == bus) || (NULL == bdaddress)) {
		return NULL;
	}

	manager_proxy = dbus_g_proxy_new_for_name(bus,
					"org.bluez", "/",
				      "org.bluez.Manager");

	if (NULL == manager_proxy) {
		ERR("ERROR: Can't make dbus proxy");
		goto done;
	}

	if (!dbus_g_proxy_call(manager_proxy, "DefaultAdapter", &error,
			       G_TYPE_INVALID,
			       DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
			       G_TYPE_INVALID)) {
		DBG("Getting DefaultAdapter failed: [%s]", error->message);
		g_error_free(error);
		error = NULL;
		goto done;
	}

	adapter_proxy = dbus_g_proxy_new_for_name(bus, "org.bluez",
					adapter_path,
				      "org.bluez.Adapter");

	if (NULL == adapter_proxy)
		goto done;

	if (!dbus_g_proxy_call(adapter_proxy, "FindDevice", NULL,
			       G_TYPE_STRING, bdaddress, G_TYPE_INVALID,
			       DBUS_TYPE_G_OBJECT_PATH, &device_path,
			       G_TYPE_INVALID)) {
		goto done;
	}

	device = dbus_g_proxy_new_from_proxy(adapter_proxy,
					"org.bluez.Device",
					device_path);
	if (NULL == device)
		goto done;

	if (!dbus_g_proxy_call(device, "GetProperties", &error,
			       G_TYPE_INVALID,
			       dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
						   G_TYPE_VALUE), &hash,
			       G_TYPE_INVALID)) {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
		goto done;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_dup_string(value) : NULL;
	}

 done:
	if (device)
		g_object_unref(device);

	if (adapter_proxy)
		g_object_unref(adapter_proxy);

	if (manager_proxy)
		g_object_unref(manager_proxy);

	DBG("-");
	return name;
}

static gboolean __bt_authorize_callback(DBusGMethodInvocation *context,
					const char *path,
					const char *bdaddress,
					const char *name,
					const char *type,
					gint length,
					gint time,
					gpointer user_data)
{
	char *device_path = NULL;
	DBusGProxy *device = NULL;
	bt_obex_server_authorize_into_t auth_info;
	const gchar *device_name = NULL;
	obex_server_info_t *obex_server_info = user_data;
	DBG("+\n");
	DBG(" File name [%s] Address [%s] Type [%s] length [%d] path [%s] \n",
	    name, bdaddress, type, length, path);
	obex_server_info->reply_context = context;

	/* We have to free filename to handle the case -
	 * authorize reply is sent but transfer started did not come. */
	g_free(obex_server_info->filename);
	g_free(obex_server_info->device_name);
	g_free(obex_server_info->type);
	obex_server_info->filename = g_strdup(name);
	auth_info.type = g_strdup(type);
	obex_server_info->type = auth_info.type;
	auth_info.filename = obex_server_info->filename;
	auth_info.length = length;
	obex_server_info->file_size = length;
	obex_server_info->device_name = __bt_get_remote_device_name(obex_server_info->bus,
											bdaddress);
	if (NULL == obex_server_info->device_name)
		obex_server_info->device_name = g_strdup(bdaddress);

	auth_info.device_name = obex_server_info->device_name;

	__bt_ops_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_AUTHORIZE,
						BLUETOOTH_ERROR_NONE, &auth_info);

	DBG("-\n");
	return TRUE;
}

static int __bt_get_transfer_id(const char *path)
{
	char *tmp = NULL;
	if (path == NULL)
		return -1;
	tmp = strrchr(path, 'r') + 1;
	return atoi(tmp);
}

static void __bt_transfer_progress_cb(DBusGProxy *object,
					gint total,
					gint transferred,
					gpointer user_data)
{
	bt_obex_server_transfer_info_t info;
	transfer_info_t *transfer_info = user_data;
	gdouble percentage_progress = 0;

	if (transfer_info) {
		DBG("File [%s] path [%s]\n", transfer_info->filename,
		    transfer_info->path);
		info.filename = transfer_info->filename;

		percentage_progress = (gdouble) transferred / (gdouble) total * 100;
		info.percentage = percentage_progress;
		info.transfer_id = __bt_get_transfer_id(transfer_info->path);
		info.type = transfer_info->type;
		info.device_name = transfer_info->device_name;
		info.file_size = transfer_info->file_size;

		DBG("Transfer ID : %d    Percentage : %d \n",
			info.transfer_id, (int)percentage_progress);

		__bt_ops_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_PROGRESS,
						BLUETOOTH_ERROR_NONE, &info);
	}
}

static void __bt_session_created_cb(DBusGProxy *object,
				    const char *session_path,
				    gpointer user_data)
{
	DBG("%s\n", session_path);
}

static void __bt_session_removed_cb(DBusGProxy *object,
				    const char *session_path,
				    gpointer user_data)
{
	DBG("%s\n", session_path);
}

static void __bt_transfer_started_cb(DBusGProxy *object,
				     const char *transfer_path,
				     gpointer user_data)
{
	obex_server_info_t *obex_server_info = user_data;
	bt_obex_server_transfer_info_t app_transfer_info;
	DBG("%s\n", transfer_path);
	transfer_info_t *transfer_info = g_new0(transfer_info_t, 1);
	if (transfer_info) {
		transfer_info->transfer_proxy = dbus_g_proxy_new_for_name(obex_server_info->bus,
					      "org.openobex", transfer_path,
					      "org.openobex.Transfer");
		if (transfer_info->transfer_proxy) {
			dbus_g_proxy_add_signal(transfer_info->transfer_proxy,
						"Progress", G_TYPE_INT,
						G_TYPE_INT, G_TYPE_INVALID);

			dbus_g_proxy_connect_signal(transfer_info->transfer_proxy,
							"Progress",
						    G_CALLBACK(__bt_transfer_progress_cb),
						    transfer_info, NULL);
		}

		transfer_info->path = g_strdup(transfer_path);
		transfer_info->filename = obex_server_info->filename;
		obex_server_info->filename = NULL;
		transfer_info->device_name = obex_server_info->device_name;
		transfer_info->transfer_id = __bt_get_transfer_id(transfer_info->path);
		DBG("Transfer ID : %d \n", transfer_info->transfer_id);
		obex_server_info->device_name = NULL;
		transfer_info->type = obex_server_info->type;
		transfer_info->file_size = obex_server_info->file_size;
		obex_server_info->type = NULL;

		transfers = g_slist_append(transfers, transfer_info);

		app_transfer_info.filename = transfer_info->filename;
		app_transfer_info.device_name = transfer_info->device_name;
		app_transfer_info.transfer_id = transfer_info->transfer_id;
		app_transfer_info.type = transfer_info->type;
		app_transfer_info.file_size = transfer_info->file_size;

		DBG("Transfer id %d\n", app_transfer_info.transfer_id);

		__bt_ops_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_STARTED,
						BLUETOOTH_ERROR_NONE, &app_transfer_info);
	}
}

static void __bt_transfer_completed_cb(DBusGProxy *object,
					const char *transfer_path,
					gboolean success,
					gpointer user_data)
{
	obex_server_info_t *obex_server_info = user_data;
	transfer_info_t *transfer_info;
	int result;
	DBG("Transfer [%s] Success [%d] \n", transfer_path, success);
	if (success)
		result = BLUETOOTH_ERROR_NONE;
	else
		result = BLUETOOTH_ERROR_CANCEL;

	transfer_info = _bt_find_transfer(transfer_path);
	if (transfer_info) {
		bt_obex_server_transfer_info_t transfer_complete_info;
		transfers = g_slist_remove(transfers, transfer_info);
		transfer_complete_info.filename = transfer_info->filename;
		transfer_complete_info.device_name = transfer_info->device_name;
		transfer_complete_info.transfer_id = __bt_get_transfer_id(transfer_path);
		transfer_complete_info.type = transfer_info->type;
		transfer_complete_info.file_size - transfer_info->file_size;

		__bt_ops_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_COMPLETED,
						result, &transfer_complete_info);

		__bt_obex_server_transfer_free(transfer_info);
	}
}

static int __bt_obex_agent_register(obex_server_info_t *obex_server_info,
							DBusGConnection *conn)
{
	GError *error = NULL;
	DBG("\n");

	obex_server_info->obex_server_agent = obex_agent_new();
	if (NULL == obex_server_info->obex_server_agent) {
		DBG("obex_server_agent is NULL \n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	obex_agent_set_authorize_func(obex_server_info->obex_server_agent,
				      __bt_authorize_callback,
				      obex_server_info);
	obex_agent_setup(obex_server_info->obex_server_agent,
			 OBEX_SERVER_AGENT_PATH);

	obex_server_info->obex_proxy = dbus_g_proxy_new_for_name(conn,
							"org.openobex",
				      			"/", "org.openobex.Manager");

	if (obex_server_info->obex_proxy == NULL) {
		DBG("obex_proxy is NULL \n");
		g_object_unref(obex_server_info->obex_server_agent);
		obex_server_info->obex_server_agent = NULL;
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("Register Agent");
	dbus_g_proxy_call(obex_server_info->obex_proxy, "RegisterAgent", &error,
			  DBUS_TYPE_G_OBJECT_PATH, OBEX_SERVER_AGENT_PATH,
			  G_TYPE_INVALID, G_TYPE_INVALID);
	if (error != NULL) {
		DBG("Agent registration failed: %s\n", error->message);
		int result;
		g_object_unref(obex_server_info->obex_proxy);
		obex_server_info->obex_proxy = NULL;
		g_object_unref(obex_server_info->obex_server_agent);
		obex_server_info->obex_server_agent = NULL;
		if(!g_strcmp0(error->message, "Agent already exists"))
			result = BLUETOOTH_ERROR_AGENT_ALREADY_EXIST;
		else
			result = BLUETOOTH_ERROR_INTERNAL;
		g_error_free(error);
		return result;
	}

	obex_server_info->bus = conn;

	dbus_g_proxy_add_signal(obex_server_info->obex_proxy, "TransferStarted",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(obex_server_info->obex_proxy,
				    "TransferStarted",
				    G_CALLBACK(__bt_transfer_started_cb),
				    obex_server_info, NULL);

	dbus_g_proxy_add_signal(obex_server_info->obex_proxy,
				"TransferCompleted", DBUS_TYPE_G_OBJECT_PATH,
				G_TYPE_BOOLEAN, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(obex_server_info->obex_proxy,
				    "TransferCompleted",
				    G_CALLBACK(__bt_transfer_completed_cb),
				    obex_server_info, NULL);

	dbus_g_proxy_add_signal(obex_server_info->obex_proxy, "SessionCreated",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(obex_server_info->obex_proxy,
				    "SessionCreated",
				    G_CALLBACK(__bt_session_created_cb),
				    obex_server_info, NULL);

	dbus_g_proxy_add_signal(obex_server_info->obex_proxy, "SessionRemoved",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(obex_server_info->obex_proxy,
				    "SessionRemoved",
				    G_CALLBACK(__bt_session_removed_cb),
				    obex_server_info, NULL);

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_obex_agent_unregister(obex_server_info_t *obex_server_info)
{
	GError *error = NULL;
	DBG("\n");

	dbus_g_proxy_call(obex_server_info->obex_proxy, "UnregisterAgent", &error,
			  DBUS_TYPE_G_OBJECT_PATH, OBEX_SERVER_AGENT_PATH,
			  G_TYPE_INVALID, G_TYPE_INVALID);
	if (error != NULL) {
		DBG("Agent unregistration failed: %s\n", error->message);
		g_error_free(error);
	}

	dbus_g_proxy_disconnect_signal(obex_server_info->obex_proxy,
				    "TransferStarted",
				    G_CALLBACK(__bt_transfer_started_cb),
				    obex_server_info);

	dbus_g_proxy_disconnect_signal(obex_server_info->obex_proxy,
				    "TransferCompleted",
				    G_CALLBACK(__bt_transfer_completed_cb),
				    obex_server_info);

	dbus_g_proxy_disconnect_signal(obex_server_info->obex_proxy,
				    "SessionCreated",
				    G_CALLBACK(__bt_session_created_cb),
				    obex_server_info);

	dbus_g_proxy_disconnect_signal(obex_server_info->obex_proxy,
				    "SessionRemoved",
				    G_CALLBACK(__bt_session_removed_cb),
				    obex_server_info);

	obex_server_info->bus = NULL;

	g_object_unref(obex_server_info->obex_proxy);
	obex_server_info->obex_proxy = NULL;

	g_object_unref(obex_server_info->obex_server_agent);
	obex_server_info->obex_server_agent = NULL;
}



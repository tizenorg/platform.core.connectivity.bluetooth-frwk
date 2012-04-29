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

static void __bt_send_deinit_message(void)
{
	DBG("+");

	DBusMessage *msg = NULL;
	DBusGConnection *conn = NULL;
	DBusConnection *connecton = NULL;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		DBG("conn is NULL");
		return;
	}

	connecton = dbus_g_connection_get_connection(conn);

	msg = dbus_message_new_signal(BT_FRWK_OBJECT,
				      BT_FRWK_INTERFACE,
				      BT_FRWK_SIGNAL_DEINIT);

	if (msg == NULL) {
		DBG("Unable to allocate D-Bus signal");
		return;
	}

	if (!dbus_message_append_args(msg,
				      DBUS_TYPE_INVALID,
				      DBUS_TYPE_INVALID)) {
		DBG("Deinit sending failed");
		dbus_message_unref(msg);
		dbus_g_connection_unref(conn);
		return;
	}

	dbus_connection_send(connecton, msg, NULL);
	dbus_message_unref(msg);
	dbus_g_connection_unref(conn);

	DBG("-");

	return;
}

BT_EXPORT_API int bluetooth_obex_server_init(char *dst_path)
{
	DBG("+\n");

	int ret = BLUETOOTH_ERROR_NONE;
	DBusGConnection *conn = NULL;

	_bluetooth_internal_session_init();

	if (FALSE == _bluetooth_internal_is_adapter_enabled()) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (g_obex_server_info.obex_server_agent) {
		DBG("Agent already registered");
		return BLUETOOTH_ERROR_AGENT_ALREADY_EXIST;
	}

	if (NULL == dst_path) {
		DBG("Invalid Param");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	/* Get the session bus. This bus reff will be unref during deinit */
	conn = dbus_g_bus_get(DBUS_BUS_SESSION, NULL);

	if (conn == NULL) {
		DBG("conn is NULL\n");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	/* Send deinit signal (To deinit the native Obex server) */
	__bt_send_deinit_message();

	g_dst_path = g_strdup(dst_path);

	ret = __bt_obex_agent_register(&g_obex_server_info, conn);

	if (ret != BLUETOOTH_ERROR_NONE) {
		g_free(g_dst_path);
		dbus_g_connection_unref(conn);
		g_dst_path = NULL;
	}

	DBG("- \n");

	return ret;
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

	conn = dbus_g_bus_get(DBUS_BUS_SESSION, NULL);
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

static transfer_info_t *_bt_find_transfer_by_id(int transfer_id)
{
	GSList *l;

	for (l = transfers; l != NULL; l = l->next) {
		transfer_info_t *transfer = l->data;

		if (transfer) {
			if (transfer->transfer_id == transfer_id)
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
	g_free(transfer_info->type);
	g_free(transfer_info->device_name);
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
			dbus_g_method_return(obex_server_info->reply_context,
						filepath);
		} else {
			GError *error = NULL;
			error = __bt_obex_agent_error(BT_OBEX_AGENT_ERROR_CANCEL,
						  "CanceledbyUser");
			dbus_g_method_return_error(obex_server_info->reply_context,
							error);
			g_error_free(error);

			g_free(obex_server_info->filename);
			obex_server_info->filename = NULL;
			g_free(obex_server_info->transfer_path);
			obex_server_info->transfer_path = NULL;
			g_free(obex_server_info->device_name);
			obex_server_info->device_name = NULL;
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

BT_EXPORT_API int bluetooth_obex_server_cancel_transfer(int transfer_id)
{
	obex_server_info_t *obex_server_info = &g_obex_server_info;
	transfer_info_t *transfer = NULL;

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
		return BLUETOOTH_ERROR_INTERNAL;
	}

	transfer = _bt_find_transfer_by_id(transfer_id);

	if (transfer == NULL) {
		DBG("No transfer information");
		return BLUETOOTH_ERROR_NOT_FOUND;
	}

	dbus_g_proxy_call_no_reply(transfer->transfer_proxy, "Cancel",
				G_TYPE_INVALID, G_TYPE_INVALID);

	DBG("+\n");

	return BLUETOOTH_ERROR_NONE;
}

static char *__bt_get_remote_device_name(const char *bdaddress)
{
	GError *error = NULL;
	char *device_path = NULL;
	char *name = NULL;
	DBusGProxy *device = NULL;
	GHashTable *hash = NULL;
	GValue *value;
	DBusGProxy *device_proxy = NULL;
	bt_info_t *bt_internal_info = NULL;

	DBG("+\n");

	if (NULL == bdaddress)
		return NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return NULL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", &error,
			  G_TYPE_STRING, bdaddress, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Error occured in FindDevice Proxy call [%s]\n", error->message);
		g_error_free(error);
		return NULL;
	}

	device_proxy = _bluetooth_internal_find_device_by_path(device_path);

	if (!device_proxy)
		return NULL;

	if (!dbus_g_proxy_call(device_proxy, "GetProperties", &error,
			G_TYPE_INVALID,
			dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			&hash, G_TYPE_INVALID)) {
		DBG( "error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		return NULL;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_dup_string(value) : NULL;
	}

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
 	bt_obex_server_authorize_into_t auth_info;
 	obex_server_info_t *obex_server_info = user_data;
	char *device_name = NULL;
	DBG("+\n");
	DBG(" File name [%s] Address [%s] Type [%s] length [%d] path [%s] \n",
	    name, bdaddress, type, length, path);

	obex_server_info->reply_context = context;
 	obex_server_info->filename = g_strdup(name);
	obex_server_info->file_size = length;
	obex_server_info->transfer_path = g_strdup(path);

	device_name = __bt_get_remote_device_name(bdaddress);

	if (!device_name)
		device_name = g_strdup(bdaddress);

	obex_server_info->device_name = device_name;

 	auth_info.filename = obex_server_info->filename;
	auth_info.length = length;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_AUTHORIZE,
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
		percentage_progress = (gdouble) transferred / (gdouble) total * 100;

		info.filename = transfer_info->filename;
		info.percentage = percentage_progress;
		info.transfer_id = transfer_info->transfer_id;
 		info.file_size = transfer_info->file_size;
		info.type = transfer_info->type;

		DBG("Transfer ID : %d    Percentage : %d \n",
			info.transfer_id, (int)percentage_progress);

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_PROGRESS,
						BLUETOOTH_ERROR_NONE, &info);
	}
}

static transfer_info_t *__bt_create_transfer(DBusGConnection *conn,
						const char *transfer_path)
{
	transfer_info_t *transfer_info = g_new0(transfer_info_t, 1);

	transfer_info->transfer_proxy = dbus_g_proxy_new_for_name(conn,
							"org.openobex",
							transfer_path,
							"org.openobex.Transfer");
	if (NULL == transfer_info->transfer_proxy) {
		DBG("proxy faliled");
		g_free(transfer_info);
		return NULL;
	}

	dbus_g_proxy_add_signal(transfer_info->transfer_proxy,
				"Progress", G_TYPE_INT,
				G_TYPE_INT, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(transfer_info->transfer_proxy,
					"Progress",
					G_CALLBACK(__bt_transfer_progress_cb),
					transfer_info, NULL);

	transfer_info->transfer_id = __bt_get_transfer_id(transfer_path);
	DBG("Transfer ID : %d \n", transfer_info->transfer_id);

	return transfer_info;
}

static int __bt_transfer_get_properties(transfer_info_t *transfer_info)
{
	GHashTable *hash = NULL;
	GValue *value;

	dbus_g_proxy_call(transfer_info->transfer_proxy, "GetProperties", NULL,
	                        G_TYPE_INVALID,
	                        dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
	                        &hash, G_TYPE_INVALID);
	if (NULL == hash) {
		DBG("hash faliled");
		return -1;
	}

        value = g_hash_table_lookup(hash, "Operation");
        transfer_info->type = value ? g_strdup(g_value_get_string(value)) : NULL;
	if (transfer_info->type == NULL) {
		g_hash_table_destroy(hash);
		DBG("Operation faliled");
		return -1;
	}

        value = g_hash_table_lookup(hash, "Filename");
        transfer_info->filename = value ? g_strdup(g_value_get_string(value)) : NULL;
	if (transfer_info->filename == NULL) {
		g_hash_table_destroy(hash);
		return -1;
	}

        value = g_hash_table_lookup(hash, "Size");
        transfer_info->file_size  = value ? g_value_get_uint64(value) : 0;

        g_hash_table_destroy(hash);

        DBG("Operation %s :",transfer_info->type);
        DBG("FileName %s :", transfer_info->filename);
        DBG("Size %d :", transfer_info->file_size);

	return 0;
}
static void __bt_transfer_started_cb(DBusGProxy *object,
				     const char *transfer_path,
				     gpointer user_data)
{
	obex_server_info_t *obex_server_info = user_data;
	bt_obex_server_transfer_info_t app_transfer_info;
	transfer_info_t *transfer_info;
	DBG("%s\n", transfer_path);

	transfer_info = __bt_create_transfer(obex_server_info->bus, transfer_path);
	if (NULL == transfer_info)
		return;

	if (0 == g_strcmp0(transfer_path, obex_server_info->transfer_path)) {
		DBG("OPP transfer");
		transfer_info->filename = obex_server_info->filename;
		transfer_info->file_size =  obex_server_info->file_size;
		transfer_info->type = g_strdup(TRANSFER_PUT);
		transfer_info->path = obex_server_info->transfer_path;
		transfer_info->device_name = obex_server_info->device_name;

		obex_server_info->filename = NULL;
		obex_server_info->transfer_path = NULL;
		obex_server_info->device_name = NULL;
	} else {
		if (__bt_transfer_get_properties(transfer_info) < 0) {
			DBG("Get Properties failed");
			__bt_obex_server_transfer_free(transfer_info);
			return;
		}

		transfer_info->path = g_strdup(transfer_path);
	}

	transfers = g_slist_append(transfers, transfer_info);

 	app_transfer_info.filename = transfer_info->filename;
 	app_transfer_info.transfer_id = transfer_info->transfer_id;
	app_transfer_info.type = transfer_info->type;

	DBG("Transfer id %d\n", app_transfer_info.transfer_id);

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_STARTED,
					BLUETOOTH_ERROR_NONE, &app_transfer_info);
 }

static void __bt_transfer_completed_cb(DBusGProxy *object,
					const char *transfer_path,
					gboolean success,
					gpointer user_data)
{
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
 		transfer_complete_info.transfer_id = transfer_info->transfer_id;
 		transfer_complete_info.file_size = transfer_info->file_size;
		transfer_complete_info.type = transfer_info->type;
		transfer_complete_info.device_name = transfer_info->device_name;

		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_COMPLETED,
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

	if (obex_server_info->bus) {
		dbus_g_connection_unref(obex_server_info->bus);
		obex_server_info->bus = NULL;
	}

	g_object_unref(obex_server_info->obex_proxy);
	obex_server_info->obex_proxy = NULL;

	g_object_unref(obex_server_info->obex_server_agent);
	obex_server_info->obex_server_agent = NULL;
}



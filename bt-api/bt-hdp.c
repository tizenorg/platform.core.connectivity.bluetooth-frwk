/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <sys/types.h>
#include <sys/socket.h>
#include <gio/gio.h>
#include <glib.h>
#include <string.h>
#include <gio/gunixfdlist.h>

#include "bluetooth-api.h"
#include "bt-common.h"
#include "bt-internal-types.h"

#define HDP_BUFFER_SIZE 1024
#define BLUEZ_HDP_MANAGER_INTERFACE  "org.bluez.HealthManager1"
#define BLUEZ_HDP_DEVICE_INTERFACE  "org.bluez.HealthDevice1"
#define BLUEZ_HDP_CHANNEL_INTERFACE  "org.bluez.HealthChannel1"

typedef struct {
	char *obj_channel_path;
	int fd;
	guint watch_id;
} hdp_obj_info_t;

typedef struct {
	void *app_handle;
	GSList *obj_info;
} hdp_app_list_t;

/* Variable for privilege, only for write API,
  before we should reduce time to bt-service dbus calling
  -1 : Don't have a permission to access API
  0 : Initial value, not yet check
  1 : Have a permission to access API
*/
static int privilege_token;


/**********************************************************************
*		Static Functions declaration				*
***********************************************************************/
static int __bt_hdp_internal_create_application(unsigned int data_type,
						int role,
						bt_hdp_qos_type_t channel_type,
						char **app_handle);

static void __bt_hdp_internal_event_filter(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data);

static void __bt_hdp_internal_handle_connect(GVariant *parameters);

static void __bt_hdp_internal_handle_disconnect(GVariant *parameters,
				const gchar *object_path);

static void __bt_hdp_internal_handle_property_changed(GVariant *parameters);

static int __bt_hdp_internal_add_filter(void);

static int __bt_hdp_internal_acquire_fd(const char *path);

static guint __bt_hdp_internal_watch_fd(int file_desc, const char *path);

static gboolean __bt_hdp_internal_data_received(GIOChannel *gio,
						GIOCondition cond,
						gpointer data);

static int __bt_hdp_internal_destroy_application(const char *app_handle);

static void __bt_hdp_internal_remove_filter(void);

static hdp_app_list_t *__bt_hdp_internal_gslist_find_app_handler(void *app_handle);

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_fd(int fd);

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_path(const char *obj_channel_path);

/*Global Variables*/
static GDBusConnection *g_hdp_dus_conn;

static GSList *g_app_list = NULL;

/**********************************************************************
*			Health device APIs (HDP)			*
***********************************************************************/

BT_EXPORT_API int bluetooth_hdp_activate(unsigned short data_type,
					bt_hdp_role_type_t role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");

	BT_CHECK_ENABLED(return);

	/*For source role is mandatory */
	if (role == HDP_ROLE_SOURCE && channel_type == HDP_QOS_ANY) {
		BT_ERR("For source, type is mandatory - Reliable/Streaming");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	result = __bt_hdp_internal_create_application(data_type, role,
						channel_type, app_handle);

	return result;
}

static void __bt_hdp_obj_info_free(hdp_obj_info_t *info)
{
	if (info) {
		g_source_remove(info->watch_id);
		close(info->fd);
		g_free(info->obj_channel_path);
		g_free(info);
	}
}

static int __bt_hdp_internal_create_application(unsigned int data_type,
					int role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	GDBusProxy *proxy = NULL;
	GVariant *reply = NULL;
	GVariantBuilder *builder;
	const char *svalue;
	const char *key_type;
	char *app_path;
	hdp_app_list_t *list;
	GError *err = NULL;
	guint16 value;
	GDBusConnection *conn;
	int ret = BLUETOOTH_ERROR_NONE;

	BT_DBG("+");

	conn = _bt_gdbus_get_system_gconn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
					NULL,
					BT_BLUEZ_NAME,
					"/org/bluez",
					BLUEZ_HDP_MANAGER_INTERFACE,
					NULL, &err);

	if (!proxy) {
		BT_ERR("Unable to create proxy: %s", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	key_type = "DataType";
	value = (guint16) data_type;
	g_variant_builder_add(builder, "{sv}",
			key_type, g_variant_new("q",
				value));

	key_type = "Role";
	/*0-Source,1-Sink*/
	svalue = (role == HDP_ROLE_SINK) ? "Sink" : "Source";
	g_variant_builder_add(builder, "{sv}",
			key_type, g_variant_new("s",
				svalue));

	key_type = "Description";
	svalue = "Health Device";
	g_variant_builder_add(builder, "{sv}",
			key_type, g_variant_new("s",
				svalue));

	if (role == HDP_ROLE_SOURCE) {
		key_type = "ChannelType";
		if (channel_type == HDP_QOS_RELIABLE)
			svalue = "reliable";
		else if (channel_type == HDP_QOS_STREAMING)
			svalue = "streaming";

		g_variant_builder_add(builder, "{sv}",
			key_type, g_variant_new("s",
				svalue));
	}

	reply = g_dbus_proxy_call_sync(proxy, "CreateApplication",
					g_variant_new("(a{sv})", builder),
					G_DBUS_CALL_FLAGS_NONE, -1,
					NULL, &err);

	g_variant_builder_unref(builder);
	g_object_unref(proxy);

	if (!reply) {
		BT_ERR(" HDP:dbus Can't create application");
		if (err) {
			BT_ERR("%s", err->message);
			if (g_strrstr(err->message, BT_ACCESS_DENIED_MSG))
				ret = BLUETOOTH_ERROR_PERMISSION_DEINED;
			else
				ret = BLUETOOTH_ERROR_INTERNAL;
			g_clear_error(&err);
		}
		return ret;
	}

	g_variant_get(reply, "(&o)", &app_path);
	BT_DBG("Created health application: %s", (char *)app_path);

	ret = __bt_hdp_internal_add_filter();

	if (ret != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Funtion failed");
		return ret;
	}

	list = g_new0(hdp_app_list_t, 1);
	list->app_handle = (void *)g_strdup(app_path);
	*app_handle = list->app_handle;

	g_app_list = g_slist_append(g_app_list, list);

	g_variant_unref(reply);
	return BLUETOOTH_ERROR_NONE;
}

static int __bt_hdp_add_filter_subscribe_signal(GDBusConnection *conn,
		gboolean subscribe)
{
	static guint subs_add_filter_id = 0;

	if (conn == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (subscribe) {
		if (subs_add_filter_id == 0) {
			subs_add_filter_id = g_dbus_connection_signal_subscribe(
				conn, NULL, BLUEZ_HDP_DEVICE_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_hdp_internal_event_filter, NULL, NULL);
		}
	} else {
		if (subs_add_filter_id > 0) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_add_filter_id);
			subs_add_filter_id = 0;
		}
	}
	return BLUETOOTH_ERROR_NONE;
}

static int __bt_hdp_internal_add_filter(void)
{
	BT_DBG("+");

	/*Single process only one signal registration is required */
	if (g_hdp_dus_conn) {
		BT_ERR("g_hdp_dus_conn already exist");
		return BLUETOOTH_ERROR_NONE;
	}

	g_hdp_dus_conn = _bt_gdbus_get_system_gconn();
	retv_if(g_hdp_dus_conn == NULL, BLUETOOTH_ERROR_INTERNAL);


	return __bt_hdp_add_filter_subscribe_signal(g_hdp_dus_conn, TRUE);

	BT_DBG("-\n");
}

static void __bt_hdp_internal_event_filter(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	BT_DBG("Path = %s\n", object_path);
	if (object_path == NULL || g_strcmp0(object_path, "/") == 0)
		return;

	if (signal_name == NULL)
		return;

	if (strcasecmp(signal_name, "ChannelConnected") == 0) 
		__bt_hdp_internal_handle_connect(parameters);

	else if (strcasecmp(signal_name, "ChannelDeleted") == 0)
		__bt_hdp_internal_handle_disconnect(parameters, object_path);

	else if (strcasecmp(signal_name, "PropertyChanged") == 0)
		__bt_hdp_internal_handle_property_changed(parameters);

	return;
}

static void __bt_hdp_internal_handle_connect(GVariant *parameters)
{
	BT_DBG("+");
	const char *obj_channel_path;
	bt_user_info_t *user_info;
	int ret;

	BT_INFO("*********Signal - ChannelConnected******\n\n");
	g_variant_get(parameters, "(&o)", &obj_channel_path);

	BT_INFO("Channel connected, Path = %s", obj_channel_path);

	user_info = _bt_get_user_data(BT_COMMON);
	if (user_info == NULL || user_info->cb == NULL)
		return;

	ret = __bt_hdp_internal_acquire_fd(obj_channel_path);
	if (ret != BLUETOOTH_ERROR_NONE) {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_CONNECTED,
				BLUETOOTH_ERROR_CONNECTION_ERROR, NULL,
				user_info->cb, user_info->user_data);
	}
	BT_DBG("-");
}

static void __bt_hdp_internal_handle_disconnect(GVariant *parameters,
					const gchar *object_path)
{
	const char *obj_channel_path;
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	bt_hdp_disconnected_t dis_ind;
	hdp_obj_info_t *info;
	bt_user_info_t *user_info;

	BT_INFO("+********Signal - ChannelDeleted ******\n\n");
	BT_DBG("Path = %s", object_path);

	g_variant_get(parameters, "(&o)", &obj_channel_path);

	BT_INFO("Channel Deleted, Path = %s", obj_channel_path);

	info = __bt_hdp_internal_gslist_obj_find_using_path(obj_channel_path);
	if (!info) {
		BT_ERR("No obj info for ob_channel_path [%s]\n", obj_channel_path);
		return;
	}

	/*Since bluetoothd is not sending the ChannelDeleted signal */
	_bt_convert_device_path_to_address(object_path, address);

	_bt_convert_addr_string_to_type(device_addr.addr, address);

	dis_ind.channel_id = info->fd;
	dis_ind.device_address = device_addr;

	user_info = _bt_get_user_data(BT_COMMON);

	if (user_info->cb) {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
				BLUETOOTH_ERROR_NONE, &dis_ind,
				user_info->cb, user_info->user_data);
	}

	BT_DBG(" Removed connection from list\n");

	__bt_hdp_obj_info_free(info);

}

static void __bt_hdp_internal_handle_property_changed(GVariant *parameters)
{
	char *property = NULL;
	GVariant *value = NULL;
	gsize len;
	char *obj_main_channel_path = NULL;
	GVariantIter *property_iter;

	BT_DBG("+*******Signal - PropertyChanged*******\n");

	g_variant_get(parameters, "(a{sv})", &property_iter);

	while (g_variant_iter_loop(property_iter, "{sv}", &property, &value)) {
		if (g_strcmp0("MainChannel", property) == 0) {
			BT_INFO("Property MainChannel received");
			obj_main_channel_path = g_variant_dup_string(value, &len);
			BT_DBG("Main Channel  Path = %s", obj_main_channel_path);
			break;
		}
	}
	g_variant_iter_free(property_iter);

	g_free(property);
	g_variant_unref(value);
	g_free(obj_main_channel_path);
	BT_DBG("-*************\n");
}

static int __bt_hdp_internal_acquire_fd(const char *path)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	const char *property;
	GVariant *value = NULL;
	char *type_qos = NULL;
	char *device = NULL;
	char *app_handle = NULL;
	hdp_app_list_t *list = NULL;
	GDBusProxy *proxy = NULL;
	GVariant *reply = NULL;
	GDBusConnection *conn;
	bt_hdp_connected_t conn_ind;
	GError *err = NULL;
	int fd;
	bt_user_info_t *user_info;
	char *dev_path;
	GUnixFDList *out_fd_list;
	int index;
	GVariantIter *property_iter;
	gsize len;

	BT_DBG("+");

	conn = _bt_gdbus_get_system_gconn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
					NULL,
					BT_BLUEZ_NAME,
					path,
					BLUEZ_HDP_CHANNEL_INTERFACE,
					NULL, &err);

	if (!proxy) {
		BT_ERR("Unable to create proxy: %s", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	reply = g_dbus_proxy_call_with_unix_fd_list_sync(proxy,
                                                   "Acquire",
                                                   NULL,
                                                   G_DBUS_CALL_FLAGS_NONE,
                                                   -1,
                                                   NULL,
                                                   &out_fd_list,
                                                   NULL,
                                                  &err);

	g_object_unref(proxy);

	if (!reply) {
		BT_ERR(" HDP:****** dbus Can't create application ****");

		if (err) {
			BT_ERR("%s", err->message);;
			g_clear_error(&err);
		}

		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_get(reply, "(h)", &index);
	fd = g_unix_fd_list_get(out_fd_list, index, NULL);

	g_variant_unref(reply);

	BT_DBG("File Descriptor = %d, Dev_path = %s \n", fd, path);

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
					NULL,
					BT_BLUEZ_NAME,
					path,
					BT_PROPERTIES_INTERFACE,
					NULL, &err);

	if (!proxy) {
		BT_ERR("Unable to create proxy: %s", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dev_path = g_strdup(BLUEZ_HDP_CHANNEL_INTERFACE);

	reply = g_dbus_proxy_call_sync(proxy, "GetAll",
				g_variant_new("(s)", dev_path),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&err);

	g_free(dev_path);
	g_object_unref(proxy);

	if (!reply) {
		BT_ERR(" HDP:dbus Can't get the reply");

		if (err) {
			BT_ERR("%s", err->message);;
			g_clear_error(&err);
		}

		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_variant_get(reply, "(a{sv})", &property_iter);

	while (g_variant_iter_loop(property_iter, "{sv}", &property, &value)) {
		BT_DBG("String received = %s\n", property);

		if (g_strcmp0("Type", property) == 0) {
			type_qos = g_variant_dup_string(value, &len);
		} else if (g_strcmp0("Device", property) == 0) {
			device = g_variant_dup_string(value, &len);
		} else if (g_strcmp0("Application", property) == 0) {
			app_handle = g_variant_dup_string(value, &len);
		}
	}
	g_variant_iter_free(property_iter);

	g_variant_unref(reply);
	BT_DBG("QOS = %s, Device = %s, Apphandler = %s",
			type_qos, device, app_handle);

	if (NULL == type_qos || NULL == app_handle) {
		BT_ERR("Pasing failed\n");
		goto error;
	}

	list = __bt_hdp_internal_gslist_find_app_handler((void *)app_handle);

	/*Only process register with app handle receive the Connected event */
	if (NULL == list) {
		BT_ERR("**** Could not locate the list for %s*****\n", app_handle);
		goto error;
	}

	hdp_obj_info_t *info = g_new0(hdp_obj_info_t, 1);
	info->fd = fd;
	info->obj_channel_path = g_strdup(path);
	info->watch_id = __bt_hdp_internal_watch_fd(fd, info->obj_channel_path);
	list->obj_info = g_slist_append(list->obj_info, info);

	_bt_convert_device_path_to_address(path, address);

	_bt_convert_addr_string_to_type(device_addr.addr, address);

	conn_ind.app_handle = app_handle;
	conn_ind.channel_id = fd;
	conn_ind.device_address = device_addr;
	conn_ind.type = (g_strcmp0(type_qos, "Reliable") == 0) ?
			HDP_QOS_RELIABLE : HDP_QOS_STREAMING;

	BT_DBG("Going to give callback\n");

	user_info = _bt_get_user_data(BT_COMMON);

	if (user_info->cb) {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_CONNECTED,
				BLUETOOTH_ERROR_NONE, &conn_ind,
				user_info->cb, user_info->user_data);
	}

	BT_DBG("Updated fd in the list*\n");
	BT_DBG("-\n");

	g_free(type_qos);
	g_free(device);
	g_free(app_handle);
	return BLUETOOTH_ERROR_NONE;
error:
	g_free(type_qos);
	g_free(device);
	g_free(app_handle);
	return BLUETOOTH_ERROR_INTERNAL;
}

static guint __bt_hdp_internal_watch_fd(int file_desc, const char *path)
{
	GIOChannel *gio;
	guint id;

	BT_DBG("+");

	gio = g_io_channel_unix_new(file_desc);

	g_io_channel_set_close_on_unref(gio, TRUE);

	id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			__bt_hdp_internal_data_received, (void *)path);
	BT_DBG("-");
	return id;
}


static void __bt_hdp_internal_handle_disconnect_cb(int sk, const char *path)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	bt_hdp_disconnected_t dis_ind;
	hdp_obj_info_t *info;
	bt_user_info_t *user_info;

	BT_INFO("******** Socket Error  ******\n");

	info = __bt_hdp_internal_gslist_obj_find_using_path(path);
	ret_if(info == NULL);

	/*Since bluetoothd is not sending the ChannelDeleted signal */
	_bt_convert_device_path_to_address(path, address);

	_bt_convert_addr_string_to_type(device_addr.addr, address);

	dis_ind.channel_id = sk;
	dis_ind.device_address = device_addr;

	user_info = _bt_get_user_data(BT_COMMON);

	if (user_info->cb) {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
				BLUETOOTH_ERROR_NONE, &dis_ind,
				user_info->cb, user_info->user_data);
	}

	BT_DBG(" Removed connection from list\n");

	__bt_hdp_obj_info_free(info);
}

static gboolean __bt_hdp_internal_data_received(GIOChannel *gio,
					GIOCondition cond, gpointer data)
{
	char buff[HDP_BUFFER_SIZE] = { 0, };
	int sk;
	int act_read;
	bt_hdp_data_ind_t data_ind = { 0, };
	const char *path = (const char *)data;
	bt_user_info_t *user_info;

	BT_DBG("+");

	sk = g_io_channel_unix_get_fd(gio);

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		BT_DBG("GIOCondition %d.............path = %s\n", cond, path);
		g_io_channel_shutdown(gio, TRUE, NULL);
		g_io_channel_unref(gio);
		 __bt_hdp_internal_handle_disconnect_cb(sk, path);
		return FALSE;
	}

	act_read = recv(sk, (void *)buff, sizeof(buff), 0);

	if (act_read > 0) {
		BT_DBG("Received data of %d\n", act_read);
	} else {
		BT_ERR("Read failed.....\n");
		return FALSE;
	}

	data_ind.channel_id = sk;
	data_ind.buffer = buff;
	data_ind.size = act_read;

	user_info = _bt_get_user_data(BT_COMMON);

	if (user_info->cb) {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_DATA_RECEIVED,
				BLUETOOTH_ERROR_NONE, &data_ind,
				user_info->cb, user_info->user_data);
	}

	BT_DBG("-\n");

	return TRUE;
}

BT_EXPORT_API int bluetooth_hdp_deactivate(const char *app_handle)
{
	BT_DBG("+");

	BT_CHECK_ENABLED(return);
	BT_CHECK_PARAMETER(app_handle, return);

	return __bt_hdp_internal_destroy_application(app_handle);
}

static hdp_app_list_t *__bt_hdp_internal_gslist_find_app_handler(void *app_handle)
{
	GSList *l;

	retv_if(g_app_list == NULL, NULL);

	BT_DBG("List length = %d\n", g_slist_length(g_app_list));

	for (l = g_app_list; l != NULL; l = l->next) {
		hdp_app_list_t *list = l->data;

		if (list) {
			if (0 == g_strcmp0((char *)list->app_handle,
						(char *)app_handle))
				return list;
		}
	}
	return NULL;
}

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_fd(int fd)
{
	GSList *l;
	GSList *iter;

	retv_if(g_app_list == NULL, NULL);

	BT_DBG("List length = %d\n", g_slist_length(g_app_list));

	for (l = g_app_list; l != NULL; l = l->next) {
		hdp_app_list_t *list = l->data;
		if (!list)
			return NULL;

		for (iter = list->obj_info; iter != NULL; iter = iter->next) {
			hdp_obj_info_t *info = iter->data;
			if (!info)
				return NULL;

			if (fd == info->fd)
				return info;
		}
	}
	return NULL;
}

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_path(const char *obj_channel_path)
{
	GSList *l;
	GSList *iter;
	hdp_obj_info_t *info = NULL;

	retv_if(g_app_list == NULL, NULL);

	BT_DBG("List length = %d\n", g_slist_length(g_app_list));
	for (l = g_app_list; l != NULL; l = l->next) {
		hdp_app_list_t *list = l->data;
		if (!list)
			return NULL;

		for (iter = list->obj_info; iter != NULL; iter = iter->next) {
			 info = iter->data;
			if (!info)
				return NULL;

			if (0 == g_strcmp0(info->obj_channel_path, obj_channel_path)) {
				list->obj_info = g_slist_remove(list->obj_info, info);
				return info;
			}
		}
	}
	return NULL;
}

static gboolean  __bt_hdp_internal_destroy_application_cb(gpointer data)
{
	const char *app_handle;
	hdp_app_list_t *list = NULL;
	app_handle = (const char *)data;

	BT_DBG("+");

	list = __bt_hdp_internal_gslist_find_app_handler((void *)app_handle);
	if (NULL == list) {
		BT_ERR("**** list not found for %s ******\n", app_handle);
		return FALSE;
	}

	g_app_list = g_slist_remove(g_app_list, list);

	g_free(list->app_handle);
	g_slist_foreach(list->obj_info, (GFunc)__bt_hdp_obj_info_free, NULL);
	g_free(list);

	BT_DBG("List length = %d\n", g_slist_length(g_app_list));

	if (0 == g_slist_length(g_app_list))
		__bt_hdp_internal_remove_filter();
	BT_DBG("-");
	return FALSE;
}

static int __bt_hdp_internal_destroy_application(const char *app_handle)
{
	GDBusProxy *proxy = NULL;
	GVariant *reply = NULL;
	GError *err = NULL;
	GDBusConnection *conn;
	int result = BLUETOOTH_ERROR_NONE;

	conn = _bt_gdbus_get_system_gconn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
					NULL,
					BT_BLUEZ_NAME,
					"/org/bluez",
					BLUEZ_HDP_MANAGER_INTERFACE,
					NULL, &err);

	if (!proxy) {
		BT_ERR("Unable to create proxy: %s", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	reply = g_dbus_proxy_call_sync(proxy, "DestroyApplication",
				g_variant_new("o", app_handle),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				NULL,
				&err);

	g_object_unref(proxy);
	if (!reply) {
		BT_ERR(" HDP:dbus Can't Destroy application");

		if (err) {
			BT_ERR("%s", err->message);
			if (g_strrstr(err->message, BT_ACCESS_DENIED_MSG))
				result  = BLUETOOTH_ERROR_ACCESS_DENIED;
			else
				result  = BLUETOOTH_ERROR_INTERNAL;
			g_clear_error(&err);
		}
		return result ;
	}

	g_variant_unref(reply);

	BT_DBG("Destroyed health application: %s", (char *)app_handle);

	g_idle_add(__bt_hdp_internal_destroy_application_cb,
			(gpointer)app_handle);

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_hdp_internal_remove_filter(void)
{
	BT_DBG("+");

	ret_if(g_hdp_dus_conn == NULL);

	__bt_hdp_add_filter_subscribe_signal(g_hdp_dus_conn, FALSE);

	g_hdp_dus_conn = NULL;	/*should not unref here, bcz no ++reff */

	BT_DBG("-");
}

BT_EXPORT_API int bluetooth_hdp_send_data(unsigned int channel_id,
					    const char *buffer,
					    unsigned int size)
{
	int wbytes = 0;
	int written = 0;
	int result;

	BT_DBG("+");

	BT_CHECK_ENABLED(return);

	if ((channel_id == 0) || (NULL == buffer) || (size == 0)) {
		BT_ERR("Invalid arguments..\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	switch (privilege_token) {
	case 0:
		result = _bt_check_privilege(BT_BLUEZ_SERVICE, BT_HDP_SEND_DATA);

		if (result == BLUETOOTH_ERROR_NONE) {
			privilege_token = 1; /* Have a permission */
		} else if (result == BLUETOOTH_ERROR_PERMISSION_DEINED) {
			BT_ERR("Don't have a privilege to use this API");
			privilege_token = -1; /* Don't have a permission */
			return BLUETOOTH_ERROR_PERMISSION_DEINED;
		} else {
			/* Just break - It is not related with permission error */
		}
		break;
	case 1:
		/* Already have a privilege */
		break;
	case -1:
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	default:
		/* Invalid privilge token value */
		return BLUETOOTH_ERROR_INTERNAL;
	}

	while (wbytes < size) {
		written = write(channel_id, buffer + wbytes, size - wbytes);
		if (written <= 0) {
			BT_ERR("write failed..\n");
			return BLUETOOTH_ERROR_NOT_IN_OPERATION;
		}
		wbytes += written;
	}

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_hdp_connect_request_cb(GDBusProxy *hdp_proxy,
				GAsyncResult *res, gpointer user_data)
{
	GError *err = NULL;
	char *obj_connect_path = NULL;
	bt_hdp_connected_t *conn_ind = user_data;
	bt_user_info_t *user_info;
	GVariant *reply = NULL;

	reply = g_dbus_proxy_call_finish(hdp_proxy, res, &err);

	g_object_unref(hdp_proxy);

	if (!reply) {
		if (err) {
			BT_ERR("HDP connection  Dbus Call Error: %s\n", err->message);
			g_clear_error(&err);
		}

		user_info = _bt_get_user_data(BT_COMMON);

		if (user_info->cb) {
			_bt_common_event_cb(BLUETOOTH_EVENT_HDP_CONNECTED,
					BLUETOOTH_ERROR_CONNECTION_ERROR, conn_ind,
					user_info->cb, user_info->user_data);
		}
	} else {
		g_variant_get(reply, "(&o)", &obj_connect_path);
		BT_DBG("Obj Path returned = %s\n", obj_connect_path);
	}
	g_free((void *)conn_ind->app_handle);
	g_free(conn_ind);
}


BT_EXPORT_API int bluetooth_hdp_connect(const char *app_handle,
			bt_hdp_qos_type_t channel_type,
			const bluetooth_device_address_t *device_address)
{
	GError *err = NULL;
	GDBusConnection *conn = NULL;
	GDBusProxy *hdp_proxy = NULL;
	bt_hdp_connected_t *param;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char *dev_path = NULL;
	char *role;

	BT_DBG("+");

	BT_CHECK_ENABLED(return);
	BT_CHECK_PARAMETER(app_handle, return);
	BT_CHECK_PARAMETER(device_address, return);

	if (_bt_check_privilege(BT_BLUEZ_SERVICE, BT_HDP_CONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	if (channel_type == HDP_QOS_RELIABLE) {
		role = "Reliable";
	} else if (channel_type == HDP_QOS_STREAMING) {
		role = "Streaming";
	} else if (channel_type == HDP_QOS_ANY) {
		role = "Any";
	} else {
		BT_ERR("Invalid channel_type %d", channel_type);
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);

	if (err) {
		BT_ERR("ERROR: Can't get on system bus [%s]", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bt_get_adapter_path(_bt_gdbus_get_system_gconn(),
					default_adapter_path) < 0) {
		BT_ERR("Could not get adapter path\n");
		g_object_unref(conn);
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	_bt_convert_addr_type_to_string(address,
				(unsigned char *)device_address->addr);

	BT_DBG("create conection to %s", address);

	dev_path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (dev_path == NULL) {
		g_object_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(dev_path, ":", '_');

	BT_DBG("path: %s", dev_path);

	hdp_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
						NULL, BT_BLUEZ_NAME,
						dev_path, BLUEZ_HDP_DEVICE_INTERFACE,
						NULL, NULL);
	g_object_unref(conn);

	if (hdp_proxy == NULL) {
		BT_ERR("Failed to get the HDP server proxy\n");
		g_free(dev_path);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	BT_DBG("app path %s\n", app_handle);

	param = g_new0(bt_hdp_connected_t, 1);
	param->app_handle = g_strdup(app_handle);
	memcpy(&param->device_address, device_address, BLUETOOTH_ADDRESS_LENGTH);
	param->type = channel_type;

	g_dbus_proxy_call(hdp_proxy, "CreateChannel",
				g_variant_new("(os)", app_handle, role),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				(GAsyncReadyCallback)__bt_hdp_connect_request_cb,
				param);

	g_free(dev_path);

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_hdp_disconnect_request_cb(GDBusProxy *hdp_proxy,
			GAsyncResult *res, gpointer user_data)
{
	GError *err = NULL;
	bt_hdp_disconnected_t *disconn_ind = user_data;
	bt_user_info_t *user_info;
	GVariant *reply = NULL;

	reply = g_dbus_proxy_call_finish(hdp_proxy, res, &err);
	g_object_unref(hdp_proxy);

	user_info = _bt_get_user_data(BT_COMMON);
	if (user_info == NULL || user_info->cb == NULL) {
		g_free(disconn_ind);
		if (err) {
				g_clear_error(&err);
			return;
		}
		g_variant_unref(reply);
		return;
	}

	if (!reply) {
		if (err) {
			BT_ERR("HDP disconnection Dbus Call Error: %s\n",
							err->message);
			g_clear_error(&err);
		}

		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
				BLUETOOTH_ERROR_CONNECTION_ERROR, disconn_ind,
				user_info->cb, user_info->user_data);
	} else {
		_bt_common_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
				BLUETOOTH_ERROR_NONE, disconn_ind,
				user_info->cb, user_info->user_data);
		BT_INFO("HDP disconnection Dbus Call is done\n");
		g_variant_unref(reply);
	}

	g_free(disconn_ind);
}

BT_EXPORT_API int bluetooth_hdp_disconnect(unsigned int channel_id,
			const bluetooth_device_address_t *device_address)
{
	GError *err = NULL;
	GDBusConnection *conn = NULL;
	GDBusProxy *hdp_proxy = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char *dev_path = NULL;
	bt_hdp_disconnected_t *param;

	BT_DBG("+\n");

	BT_CHECK_ENABLED(return);
	BT_CHECK_PARAMETER(device_address, return);

	if (_bt_check_privilege(BT_BLUEZ_SERVICE, BT_HDP_DISCONNECT)
	     == BLUETOOTH_ERROR_PERMISSION_DEINED) {
		BT_ERR("Don't have a privilege to use this API");
		return BLUETOOTH_ERROR_PERMISSION_DEINED;
	}

	hdp_obj_info_t *info =
		__bt_hdp_internal_gslist_obj_find_using_fd(channel_id);
	if (NULL == info) {
		BT_ERR("*** Could not locate the list for %d*****\n",
							channel_id);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);

	if (err) {
		BT_ERR("ERROR: Can't get on system bus [%s]", err->message);
		g_clear_error(&err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bt_get_adapter_path(_bt_gdbus_get_system_gconn(),
					default_adapter_path) < 0) {
		BT_ERR("Could not get adapter path\n");
		g_object_unref(conn);
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	_bt_convert_addr_type_to_string(address,
				(unsigned char *)device_address->addr);

	BT_DBG("create conection to  %s\n", address);

	dev_path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (dev_path == NULL) {
		g_object_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(dev_path, ":", '_');

	BT_DBG("path  %s\n", dev_path);

	hdp_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_NONE,
						NULL, BT_BLUEZ_NAME,
						dev_path, BLUEZ_HDP_DEVICE_INTERFACE,
						NULL, NULL);

	g_object_unref(conn);

	if (hdp_proxy == NULL) {
		BT_ERR("Failed to get the HDP proxy\n");
		g_free(dev_path);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	param = g_new0(bt_hdp_disconnected_t, 1);
	param->channel_id = channel_id;
	memcpy(&param->device_address, device_address, BLUETOOTH_ADDRESS_LENGTH);

	g_dbus_proxy_call(hdp_proxy, "DestroyChannel",
				g_variant_new("o", info->obj_channel_path),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				(GAsyncReadyCallback)__bt_hdp_disconnect_request_cb,
				param);

	g_free(dev_path);
	g_free(param);
	g_object_unref(hdp_proxy);

	return BLUETOOTH_ERROR_NONE;

}

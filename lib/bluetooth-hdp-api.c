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
#include "bluetooth-hdp-api.h"

#define HDP_BUFFER_SIZE 1024

/**********************************************************************
*		Static Functions declaration				*
***********************************************************************/
static int __bt_hdp_internal_create_application(unsigned int data_type,
						bool role,
						bt_hdp_qos_type_t channel_type,
						char **app_handle);

static DBusHandlerResult __bt_hdp_internal_event_filter(DBusConnection *sys_conn,
							DBusMessage *msg,
							void *data);

static void __bt_hdp_internal_handle_connect(DBusMessage *msg);

static void __bt_hdp_internal_handle_disconnect(DBusMessage *msg);

static void __bt_hdp_internal_handle_property_changed(DBusMessage *msg);

static int __bt_hdp_internal_add_filter(void);

static int __bt_hdp_internal_acquire_fd(const char *path);

static void __bt_hdp_internal_watch_fd(int file_desc, const char *path);

static gboolean __bt_hdp_internal_data_received(GIOChannel *gio,
						GIOCondition cond,
						gpointer data);

static int __bt_hdp_internal_destroy_application(const char *app_handle);

static void __bt_hdp_internal_remove_filter(void);

static hdp_app_list_t *__bt_hdp_internal_gslist_find_app_handler(void *app_handle);

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_fd(int fd);

static hdp_obj_info_t *__bt_hdp_internal_gslist_obj_find_using_path(const char *obj_channel_path);

/*Global Variables*/
static DBusConnection *g_hdp_dus_conn;

static GSList *g_app_list = NULL;

/**********************************************************************
*			Health device APIs (HDP)			*
***********************************************************************/

BT_EXPORT_API int bluetooth_hdp_activate(unsigned short data_type,
					bt_hdp_role_type_t role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	DBG("+\n");
	int result = BLUETOOTH_ERROR_NONE;
	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_adapter_state != BLUETOOTH_ADAPTER_ENABLED) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	/*For source role is mandatory */
	if (role == HDP_ROLE_SOURCE && channel_type == HDP_QOS_ANY) {
		DBG("For source, type is mandatory - Reliable/Streaming\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	result = __bt_hdp_internal_create_application(data_type, role,
						channel_type, app_handle);

	return result;
}

static void __bt_hdp_obj_info_free(hdp_obj_info_t *info)
{
	if (info) {
		close(info->fd);
		g_free(info->obj_channel_path);
		g_free(info);
	}
}

static int __bt_hdp_internal_create_application(unsigned int data_type,
					bool role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	DBG(" +\n");
	DBusMessage *msg, *reply;
	const char *svalue;
	const char *key_type;
	char *app_path;
	DBusError err;
	DBusMessageIter iter, array_iter, entry, variant;
	guint16 value;
	bt_info_t *bt_internal_info = NULL;
	int ret = BLUETOOTH_ERROR_NONE;

	bt_internal_info = _bluetooth_internal_get_information();

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, "/org/bluez",
					  BLUEZ_HDP_MANAGER_INTERFACE,
					  "CreateApplication");

	if (!msg) {
		DBG(" HDP:dbus allocate new method call failed");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
		&array_iter);

	key_type = "DataType";
	value = (guint16) data_type;
	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY,
					NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key_type);
	dbus_message_iter_open_container(&entry,
		DBUS_TYPE_VARIANT, DBUS_TYPE_UINT16_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT16, &value);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(&array_iter, &entry);

	key_type = "Role";
	svalue = (role == HDP_ROLE_SINK) ? "Sink" : "Source";/*0-Source,1-Sink*/
	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY,
					NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key_type);
	dbus_message_iter_open_container(&entry,
		DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &svalue);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(&array_iter, &entry);

	key_type = "Description";
	svalue = "Health Device";
	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY,
					NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key_type);
	dbus_message_iter_open_container(&entry,
		DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &svalue);
	dbus_message_iter_close_container(&entry, &variant);
	dbus_message_iter_close_container(&array_iter, &entry);

	if (role == HDP_ROLE_SOURCE) {
		key_type = "ChannelType";
		if (channel_type == HDP_QOS_RELIABLE)
			svalue = "Reliable";
		else if (channel_type == HDP_QOS_STREAMING)
			svalue = "Streaming";

		dbus_message_iter_open_container(&array_iter,
			DBUS_TYPE_DICT_ENTRY, NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
						&key_type);
		dbus_message_iter_open_container(&entry,
			DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING,
			&variant);
		dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING,
						&svalue);
		dbus_message_iter_close_container(&entry, &variant);
		dbus_message_iter_close_container(&array_iter, &entry);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(
		dbus_g_connection_get_connection(bt_internal_info->conn),
		msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		DBG(" HDP:dbus Can't create application");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_message_get_args(reply, &err, DBUS_TYPE_OBJECT_PATH,
				&app_path, DBUS_TYPE_INVALID)) {

		DBG(" HDP: Can't get reply arguments from Dbus");

		if (dbus_error_is_set(&err)) {
			DBG("Error: %s", err.message);
			dbus_error_free(&err);
		}

		dbus_message_unref(reply);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	DBG("Created health application: %s", (char *)app_path);

	ret = __bt_hdp_internal_add_filter();

	if (ret != BLUETOOTH_ERROR_NONE) {
		DBG("Funtion failed");
		return ret;
	}

	hdp_app_list_t *list = g_new0(hdp_app_list_t, 1);
	list->app_handle = (void *)g_strdup(app_path);
	*app_handle = list->app_handle;

	g_app_list = g_slist_append(g_app_list, list);

	return BLUETOOTH_ERROR_NONE;
}

static int __bt_hdp_internal_add_filter(void)
{
	DBG("+\n");
	bt_info_t *bt_internal_info = NULL;
	DBusError dbus_error;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->conn == NULL) {
		DBG("Internel Conn == NULL\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/*Single process only one signal registration is required */
	if (g_hdp_dus_conn) {
		DBG("g_hdp_dus_conn already exist");
		goto done;
	}

	/* Add the filter for HDP client functions */
	dbus_error_init(&dbus_error);

	g_hdp_dus_conn = dbus_g_connection_get_connection(bt_internal_info->conn);

	dbus_connection_add_filter(g_hdp_dus_conn,
				__bt_hdp_internal_event_filter, NULL, NULL);

	dbus_bus_add_match(g_hdp_dus_conn,
			"type='signal',interface=" BLUEZ_HDP_DEVICE_INTERFACE,
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		g_hdp_dus_conn = NULL;
		return BLUETOOTH_ERROR_INTERNAL;
	}

done:
	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;

}

static DBusHandlerResult __bt_hdp_internal_event_filter(DBusConnection *sys_conn,
					DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	DBG("Path = %s\n", path);
	if (path == NULL || strcmp(path, "/") == 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_signal(msg, BLUEZ_HDP_DEVICE_INTERFACE,
					"ChannelConnected"))
		__bt_hdp_internal_handle_connect(msg);

	else if (dbus_message_is_signal(msg, BLUEZ_HDP_DEVICE_INTERFACE,
					"ChannelDeleted"))
		__bt_hdp_internal_handle_disconnect(msg);

	else if (dbus_message_is_signal(msg, BLUEZ_HDP_DEVICE_INTERFACE,
					"PropertyChanged"))
		__bt_hdp_internal_handle_property_changed(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void __bt_hdp_internal_handle_connect(DBusMessage *msg)
{
	DBG("+********Signal - ChannelConnected******\n\n");
	const char *path = dbus_message_get_path(msg);
	const char *obj_channel_path;
	DBG("Path = %s\n", path);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH,
				&obj_channel_path, DBUS_TYPE_INVALID)) {
		DBG("Unexpected parameters in ChannelConnected signal");
		return;
	}

	DBG("Channel connected, Path = %s\n", obj_channel_path);

	__bt_hdp_internal_acquire_fd(obj_channel_path);

	DBG("-*************\n\n");
}

static void __bt_hdp_internal_handle_disconnect(DBusMessage *msg)
{
	DBG("+********Signal - ChannelDeleted ******\n\n");
	const char *path = dbus_message_get_path(msg);
	const char *obj_channel_path;
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	bt_hdp_disconnected_t dis_ind;
	hdp_obj_info_t *info;

	DBG("Path = %s\n", path);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH,
				&obj_channel_path, DBUS_TYPE_INVALID)) {
		DBG("Unexpected parameters in ChannelDeleted signal");
		return;
	}

	DBG("Channel Deleted, Path = %s\n", obj_channel_path);

	info = __bt_hdp_internal_gslist_obj_find_using_path(obj_channel_path);
	if (!info) {
		DBG("No obj info for ob_channel_path [%s]\n", obj_channel_path);
		return;
	}

	/*Since bluetoothd is not sending the ChannelDeleted signal */
	_bluetooth_internal_device_path_to_address(path, address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr,
							address);

	dis_ind.channel_id = info->fd;
	dis_ind.device_address = device_addr;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
					BLUETOOTH_ERROR_NONE, &dis_ind);

	DBG(" Removed connection from list\n");

	__bt_hdp_obj_info_free(info);

}

static void __bt_hdp_internal_handle_property_changed(DBusMessage *msg)
{
	DBG("+*******Signal - PropertyChanged*******\n\n");
	const char *path = dbus_message_get_path(msg);
	DBusMessageIter item_iter, value_iter;
	const char *property;
	const char *obj_main_channel_path;

	DBG("Path = %s\n", path);

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		DBG("This is bad format dbus\n");
		return;
	}

	dbus_message_iter_get_basic(&item_iter, &property);

	if (property == NULL) {
		DBG("Property is NULL\n");
		return;
	}

	DBG("Property (%s)\n", property);

	if (0 == g_strcmp0(property, "MainChannel")) {
		DBG("Property MainChannel received\n");

		dbus_message_iter_next(&item_iter);

		dbus_message_iter_recurse(&item_iter, &value_iter);

		dbus_message_iter_get_basic(&value_iter,
						&obj_main_channel_path);
		DBG("Path = %s\n", path);

		DBG("Main Channel  Path = %s\n", obj_main_channel_path);
	}
	DBG("-*************\n\n");
}

static int __bt_hdp_internal_acquire_fd(const char *path)
{
	DBG("+\n");
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	DBusMessageIter reply_iter, reply_iter_entry;
	const char *property;
	char *type_qos = NULL;
	char *device = NULL;;
	char *app_handle = NULL;;
	hdp_app_list_t *list = NULL;;
	DBusMessage *msg, *reply;
	bt_info_t *bt_internal_info = NULL;
	bt_hdp_connected_t conn_ind;
	DBusError err;
	int fd;

	bt_internal_info = _bluetooth_internal_get_information();

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, path,
					  BLUEZ_HDP_CHANNEL_INTERFACE,
					  "Acquire");
	if (!msg) {
		DBG(" HDP:Acquire dbus failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(
			dbus_g_connection_get_connection(bt_internal_info->conn),
			msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		DBG(" HDP:****** dbus Can't create application ****");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}

		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_message_get_args(reply, &err, DBUS_TYPE_UNIX_FD, &fd,
				DBUS_TYPE_INVALID)) {
		DBG(" HDP:dbus Can't get reply arguments");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}
		goto error;
	}

	dbus_message_unref(reply);

	DBG("File Descriptor = %d, Dev_path = %s \n", fd, path);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, path,
			BLUEZ_HDP_CHANNEL_INTERFACE, "GetProperties");
	if (!msg) {
		DBG(" HDP:dbus Can't allocate new method call");
		return BLUETOOTH_ERROR_INTERNAL;
	}
	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(
			dbus_g_connection_get_connection(bt_internal_info->conn),
			msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		DBG(" HDP:dbus Can't get the reply");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}

		return BLUETOOTH_ERROR_INTERNAL;
	}
	dbus_message_iter_init(reply, &reply_iter);

	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		DBG("Can't get reply arguments - DBUS_TYPE_ARRAY\n");
		goto error;
	}

	dbus_message_iter_recurse(&reply_iter, &reply_iter_entry);

	/*Parse the dict */
	while (dbus_message_iter_get_arg_type(&reply_iter_entry) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter dict_entry, dict_entry_val;
		dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);
		dbus_message_iter_get_basic(&dict_entry, &property);
		DBG("String received = %s\n", property);

		if (g_strcmp0("Type", property) == 0) {
			dbus_message_iter_next(&dict_entry);
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);
			if (dbus_message_iter_get_arg_type(&dict_entry_val) !=
						DBUS_TYPE_STRING)
				continue;

			dbus_message_iter_get_basic(&dict_entry_val, &type_qos);

		} else if (g_strcmp0("Device", property) == 0) {
			dbus_message_iter_next(&dict_entry);
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);
			if (dbus_message_iter_get_arg_type(&dict_entry_val) !=
						DBUS_TYPE_OBJECT_PATH)
				continue;

			dbus_message_iter_get_basic(&dict_entry_val, &device);

		} else if (g_strcmp0("Application", property) == 0) {
			dbus_message_iter_next(&dict_entry);
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);
			if (dbus_message_iter_get_arg_type(&dict_entry_val) !=
						DBUS_TYPE_OBJECT_PATH)
				continue;

			dbus_message_iter_get_basic(&dict_entry_val,
							&app_handle);
		}
		dbus_message_iter_next(&reply_iter_entry);
	}

	DBG("QOS = %s, Device = %s, Apphandler = %s",
			type_qos, device, app_handle);

	if (NULL == type_qos || NULL == app_handle) {
		DBG("Pasing failed\n");
		goto error;
	}

	list = __bt_hdp_internal_gslist_find_app_handler((void *)app_handle);

	/*Only process register with app handle receive the Connected event */
	if (NULL == list) {
		DBG("**** Could not locate the list for %s*****\n", app_handle);
		goto error;
	}

	hdp_obj_info_t *info = g_new0(hdp_obj_info_t, 1);
	info->fd = fd;
	info->obj_channel_path = g_strdup(path);
	list->obj_info = g_slist_append(list->obj_info, info);

	__bt_hdp_internal_watch_fd(fd, info->obj_channel_path);

	_bluetooth_internal_device_path_to_address(path, address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr,
								address);

	conn_ind.app_handle = app_handle;

	conn_ind.channel_id = fd;

	conn_ind.device_address = device_addr;

	conn_ind.type = (g_strcmp0(type_qos, "Reliable") == 0) ?
			HDP_QOS_RELIABLE : HDP_QOS_STREAMING;

	DBG("Going to give callback\n");

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_HDP_CONNECTED,
					BLUETOOTH_ERROR_NONE, &conn_ind);

	dbus_message_unref(reply);

	DBG("Updated fd in the list*\n");
	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
 error:
	dbus_message_unref(reply);
	return BLUETOOTH_ERROR_INTERNAL;
}

static void __bt_hdp_internal_watch_fd(int file_desc, const char *path)
{
	DBG("+\n");
	GIOChannel *gio;

	gio = g_io_channel_unix_new(file_desc);

	g_io_channel_set_close_on_unref(gio, TRUE);

	g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			__bt_hdp_internal_data_received, (void *)path);
	DBG("-\n");
}


static void __bt_hdp_internal_handle_disconnect_cb(int sk, const char *path)
{
	DBG("******** Socket Error  ******\n\n");
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	bluetooth_device_address_t device_addr = { {0} };
	bt_hdp_disconnected_t dis_ind;
	hdp_obj_info_t *info;

	info = __bt_hdp_internal_gslist_obj_find_using_path(path);
	if (!info) {
		DBG("No obj info for ob_channel_path [%s]\n", path);
		return;
	}

	/*Since bluetoothd is not sending the ChannelDeleted signal */
	_bluetooth_internal_device_path_to_address(path, address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr,
							address);

	dis_ind.channel_id = sk;
	dis_ind.device_address = device_addr;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_HDP_DISCONNECTED,
					BLUETOOTH_ERROR_NONE, &dis_ind);

	DBG(" Removed connection from list\n");

	__bt_hdp_obj_info_free(info);
}

static gboolean __bt_hdp_internal_data_received(GIOChannel *gio,
					GIOCondition cond, gpointer data)
{
	DBG("+\n");
	char buff[HDP_BUFFER_SIZE] = { 0, };
	int sk;
	int act_read;
	bt_hdp_data_ind_t data_ind = { 0, };

	const char *path = (const char *)data;

	sk = g_io_channel_unix_get_fd(gio);

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		DBG("GIOCondition %d.............path = %s\n", cond, path);
		 __bt_hdp_internal_handle_disconnect_cb(sk, path);
		return FALSE;
	}

	act_read = recv(sk, (void *)buff, sizeof(buff), 0);


	if (act_read > 0) {
		DBG("Received data of %d\n", act_read);
	} else {
		DBG("Read failed.....\n");
		return FALSE;
	}

	data_ind.channel_id = sk;

	data_ind.buffer = buff;

	data_ind.size = act_read;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_HDP_DATA_RECEIVED,
					BLUETOOTH_ERROR_NONE, &data_ind);

	return TRUE;

	DBG("-\n");
}

BT_EXPORT_API int bluetooth_hdp_deactivate(const char *app_handle)
{
	DBG("+\n");
	int ret = BLUETOOTH_ERROR_NONE;
	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_adapter_state != BLUETOOTH_ADAPTER_ENABLED) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	if (NULL == app_handle) {
		DBG("APP handler is nULL\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	ret = __bt_hdp_internal_destroy_application(app_handle);

	app_handle = NULL;

	return ret;
}

static hdp_app_list_t *__bt_hdp_internal_gslist_find_app_handler(void *app_handle)
{
	DBG("List length = %d\n", g_slist_length(g_app_list));

	GSList *l;
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

	DBG("List length = %d\n", g_slist_length(g_app_list));

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

	DBG("List length = %d\n", g_slist_length(g_app_list));
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
	DBG(" +\n");
	const char *app_handle;
	hdp_app_list_t *list = NULL;
	app_handle = (const char *)data;

	list = __bt_hdp_internal_gslist_find_app_handler((void *)app_handle);
	if (NULL == list) {
		DBG("**** list not found for %s ******\n", app_handle);
		return FALSE;
	}

	g_app_list = g_slist_remove(g_app_list, list);

	g_free(list->app_handle);
	g_slist_foreach(list->obj_info, (GFunc)__bt_hdp_obj_info_free, NULL);
	g_free(list);

	DBG("List length = %d\n", g_slist_length(g_app_list));

	if (0 == g_slist_length(g_app_list))
		__bt_hdp_internal_remove_filter();
	DBG(" -\n");
	return FALSE;
}

static int __bt_hdp_internal_destroy_application(const char *app_handle)
{
	DBusMessage *msg, *reply;
	DBusError err;
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, "/org/bluez",
			BLUEZ_HDP_MANAGER_INTERFACE, "DestroyApplication");

	if (!msg) {
		DBG(" HDP:dbus Can't allocate new method call");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &app_handle,
					DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(
			dbus_g_connection_get_connection(bt_internal_info->conn),
			msg, -1, &err);
	dbus_message_unref(msg);
	if (!reply) {
		DBG(" HDP:dbus Can't Destroy application");

		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}

		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	DBG("Destroyed health application: %s", (char *)app_handle);

	g_idle_add(__bt_hdp_internal_destroy_application_cb,
			(gpointer)app_handle);

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_hdp_internal_remove_filter(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->conn == NULL)
		return;

	if (g_hdp_dus_conn == NULL) {
		DBG("hdp_conn is NULL");
		return;
	}

	dbus_connection_remove_filter(g_hdp_dus_conn,
					__bt_hdp_internal_event_filter, NULL);

	g_hdp_dus_conn = NULL;	/*should not unref here, bcz no ++reff */

	DBG("-\n");
}

BT_EXPORT_API int bluetooth_hdp_send_data(unsigned int channel_id,
					    const char *buffer,
					    unsigned int size)
{
	DBG("+\n");

	int wbytes = 0, written = 0;
	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_adapter_state != BLUETOOTH_ADAPTER_ENABLED) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	if ((channel_id <= 0) || (NULL == buffer) || (size <= 0)) {
		DBG("Invalid arguments..\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	} else {
		while (wbytes < size) {
			written = write(channel_id, buffer + wbytes, size - wbytes);
			if (written <= 0) {
				DBG("write failed..\n");
				return BLUETOOTH_ERROR_NOT_IN_OPERATION;
			}
			wbytes += written;
		}
	}

	return BLUETOOTH_ERROR_NONE;
}


static void __bt_hdp_connect_request_cb(DBusGProxy *hdp_proxy, DBusGProxyCall *call,
						 gpointer user_data)
{
	GError *g_error = NULL;
	char *obj_connect_path = NULL;
	DBusGConnection *conn = NULL;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(hdp_proxy, call, &g_error,
		DBUS_TYPE_G_OBJECT_PATH, &obj_connect_path, G_TYPE_INVALID);

	g_object_unref(hdp_proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("HDP connection  Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
	} else {
		DBG("Obj Path returned = %s\n", obj_connect_path);
	}
}


BT_EXPORT_API int bluetooth_hdp_connect(const char *app_handle,
			bt_hdp_qos_type_t channel_type,
			const bluetooth_device_address_t *device_address)
{
	DBG("+\n");
	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *hdp_proxy = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char *dev_path = NULL;
	char *role;
	char *obj_connect_path = NULL;

	bt_info_t *bt_internal_info = NULL;
	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_adapter_state != BLUETOOTH_ADAPTER_ENABLED) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	if (NULL == app_handle || NULL == device_address) {
		DBG("Invalid param\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (channel_type == HDP_QOS_RELIABLE)
		role = "Reliable";

	else if (channel_type == HDP_QOS_STREAMING)
		role = "Streaming";

	else if (channel_type == HDP_QOS_ANY)
		role = "Any";
	else {
		DBG("Invalid channel_type %d", channel_type);
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (err != NULL) {
		DBG("ERROR: Can't get on system bus [%s]", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bluetooth_internal_get_adapter_path(conn, default_adapter_path) < 0) {
		DBG("Could not get adapter path\n");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	DBG("create conection to  %s\n", address);

	dev_path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (dev_path == NULL) {
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(dev_path, ":", '_');

	DBG("path  %s\n", dev_path);

	hdp_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME, dev_path,
					       BLUEZ_HDP_DEVICE_INTERFACE);

	if (hdp_proxy == NULL) {
		DBG("Failed to get the HDP server proxy\n");
		g_free(dev_path);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	DBG("app path %s\n", app_handle);
	if (!dbus_g_proxy_begin_call(hdp_proxy, "CreateChannel",
				(DBusGProxyCallNotify) __bt_hdp_connect_request_cb,
				conn,	/*user_data*/
				NULL,	/*destroy*/
				DBUS_TYPE_G_OBJECT_PATH, app_handle,
				G_TYPE_STRING, role,
				G_TYPE_INVALID)) {
		DBG("HDP connection Dbus Call Error");
		g_free(dev_path);
		g_object_unref(hdp_proxy);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_free(dev_path);
	return BLUETOOTH_ERROR_NONE;
}


static void __bt_hdp_disconnect_request_cb(DBusGProxy *hdp_proxy, DBusGProxyCall *call,
						    gpointer user_data)
{
	GError *g_error = NULL;
	DBusGConnection *conn = NULL;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(hdp_proxy, call, &g_error, G_TYPE_INVALID);

	g_object_unref(hdp_proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("HDP disconnection Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
	} else {
		DBG("HDP disconnection Dbus Call is done\n");
	}
}

BT_EXPORT_API int bluetooth_hdp_disconnect(unsigned int channel_id,
			const bluetooth_device_address_t *device_address)
{
	DBG("+\n");
	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *hdp_proxy = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char *dev_path = NULL;
	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_adapter_state != BLUETOOTH_ADAPTER_ENABLED) {
		DBG("Adapter not enabled");
		return BLUETOOTH_ERROR_ACCESS_DENIED;
	}

	if (NULL == device_address) {
		DBG("Invalid param\n");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	hdp_obj_info_t *info = __bt_hdp_internal_gslist_obj_find_using_fd(channel_id);
	if (NULL == info) {
		DBG("*** Could not locate the list for %d*****\n", channel_id);
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &err);

	if (err != NULL) {
		DBG("ERROR: Can't get on system bus [%s]", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* If the adapter path is wrong, we can think the BT is not enabled. */
	if (_bluetooth_internal_get_adapter_path(conn, default_adapter_path) < 0) {
		DBG("Could not get adapter path\n");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	DBG("create conection to  %s\n", address);

	dev_path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (dev_path == NULL) {
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(dev_path, ":", '_');

	DBG("path  %s\n", dev_path);

	hdp_proxy = dbus_g_proxy_new_for_name(conn, BLUEZ_SERVICE_NAME, dev_path,
					       BLUEZ_HDP_DEVICE_INTERFACE);

	if (hdp_proxy == NULL) {
		DBG("Failed to get the HDP proxy\n");
		g_free(dev_path);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	if (!dbus_g_proxy_begin_call(hdp_proxy, "DestroyChannel",
				(DBusGProxyCallNotify) __bt_hdp_disconnect_request_cb,
				conn,	/*user_data*/
				NULL,	/*destroy*/
				DBUS_TYPE_G_OBJECT_PATH, info->obj_channel_path,
				G_TYPE_INVALID)) {
		DBG("HDP connection Dbus Call Error");
		g_free(dev_path);
		g_object_unref(hdp_proxy);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_free(dev_path);

	return BLUETOOTH_ERROR_NONE;
}

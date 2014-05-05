#include <stdlib.h>
#include <string.h>
#include <gio/gunixfdlist.h>
#include <gio/gio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "common.h"
#include "bluez.h"

typedef struct {
	char *obj_channel_path;
	int fd;
} hdp_obj_info_t;

typedef struct {
	void *app_handle;
	GSList *obj_info;
} hdp_app_list_t;

#define HDP_BUFFER_SIZE 1024

static void hdp_obj_info_free(hdp_obj_info_t *info);
static hdp_app_list_t *hdp_internal_gslist_find_app_handler(void *app_handle);

static GSList *g_app_list;

void bluez_set_hdp_state_changed_cb(
				struct _bluez_device *device,
				bluez_hdp_state_changed_t cb,
				gpointer user_data)
{
	DBG("");

	device->hdp_state_changed_cb = cb;
	device->hdp_state_changed_cb_data = user_data;
}

void bluez_unset_hdp_state_changed_cb(struct _bluez_device *device)
{
	DBG("");

	device->hdp_state_changed_cb = NULL;
	device->hdp_state_changed_cb_data = NULL;
}

void bluez_set_data_received_changed_cb(
				struct _bluez_device *device,
				bluez_set_data_received_changed_t cb,
				gpointer user_data)
{
	DBG("");

	device->data_received_changed_cb = cb;
	device->data_received_changed_data = user_data;
}

void bluez_unset_data_received_changed_cb(struct _bluez_device *device)
{
	DBG("");

	device->data_received_changed_cb = NULL;
	device->data_received_changed_data = NULL;
}

static hdp_obj_info_t *hdp_internal_gslist_obj_find_using_path(
					const char *obj_channel_path)
{
	GSList *l;
	GSList *iter;
	hdp_obj_info_t *info = NULL;

	if (g_app_list == NULL)
		return NULL;

	DBG("List length = %d\n", g_slist_length(g_app_list));
	for (l = g_app_list; l != NULL; l = l->next) {
		hdp_app_list_t *list = l->data;
		if (!list)
			return NULL;

		for (iter = list->obj_info; iter != NULL;
						iter = iter->next) {
			info = iter->data;
			if (!info)
				return NULL;

			if (0 == g_strcmp0(info->obj_channel_path,
							obj_channel_path)) {
				list->obj_info = g_slist_remove(list->obj_info,
									info);
				return info;
			}
		}
	}

	return NULL;
}

static void hdp_internal_handle_disconnect_cb(int sk, const char *path)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	hdp_obj_info_t *info;
	bluez_adapter_t *adapter = NULL;
	struct _bluez_device *device = NULL;

	DBG("******** Socket Error  ******\n");

	info = hdp_internal_gslist_obj_find_using_path(path);
	if (info == NULL)
		return;

	adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
	if (adapter == NULL)
		goto done;

	device = bluez_adapter_get_device_by_path(adapter, path);
	if (device == NULL)
		goto done;

	device_path_to_address(path, address);

	if (device->hdp_state_changed_cb)
		device->hdp_state_changed_cb(BLUETOOTH_ERROR_NONE,
				address, NULL, 0, sk,
				device->hdp_state_changed_cb_data);

	DBG(" Removed connection from list\n");

done:
	hdp_obj_info_free(info);
}

static gboolean hdp_internal_data_received(GIOChannel *gio,
				GIOCondition cond, gpointer data)
{
	char buff[HDP_BUFFER_SIZE] = { 0, };
	int sk;
	int act_read;
	const char *path = (const char *)data;
	bluez_adapter_t *adapter = NULL;
	struct _bluez_device *device = NULL;

	DBG("+");

	adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
	if (adapter == NULL)
		return BT_ERROR_OPERATION_FAILED;

	device = bluez_adapter_get_device_by_path(adapter, path);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	sk = g_io_channel_unix_get_fd(gio);

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		DBG("GIOCondition %d.............path = %s\n", cond, path);
		hdp_internal_handle_disconnect_cb(sk, path);
		return FALSE;
	}

	act_read = recv(sk, (void *)buff, sizeof(buff), 0);

	if (act_read > 0) {
		DBG("Received data of %d\n", act_read);
	} else {
		DBG("Read failed.....\n");
		return FALSE;
	}

	if (device->data_received_changed_cb)
		device->data_received_changed_cb(sk, buff, act_read,
				device->data_received_changed_data);

	DBG("-\n");

	return TRUE;
}

static void hdp_internal_watch_fd(int file_desc, const char *path)
{
	GIOChannel *gio;

	DBG("+");

	gio = g_io_channel_unix_new(file_desc);

	g_io_channel_set_close_on_unref(gio, TRUE);

	g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				hdp_internal_data_received, (void *)path);

	DBG("-");
}

static int hdp_internal_acquire_fd(struct _bluez_device *device,
							const char *path)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	char *type_qos = NULL;
	char *device_name = NULL;
	char *app_handle = NULL;
	hdp_app_list_t *list = NULL;
	bt_hdp_channel_type_e type = HDP_QOS_RELIABLE;
	hdp_obj_info_t *info;
	gint fd = 0;
	GVariant *val;
	GDBusConnection *conn;
	int ret;
	GUnixFDList *fd_list;
	GDBusMessage *msg;
	GDBusMessage *msg_reply;
	GError *error;

	DBG("+");

	conn = get_system_lib_dbus_connect();
	if (conn == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	msg = g_dbus_message_new_method_call(BLUEZ_NAME, path,
				HDP_CHANNEL_INTERFACE, "Acquire");

	msg_reply = g_dbus_connection_send_message_with_reply_sync(
			conn, msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE,
			-1, NULL, NULL, &error);

	if (msg_reply && g_dbus_message_get_message_type(msg_reply)
				== G_DBUS_MESSAGE_TYPE_ERROR) {
		DBG(" HDP:****** dbus Can't create application ****");
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	fd_list = g_dbus_message_get_unix_fd_list(msg_reply);
	fd = g_unix_fd_list_get(fd_list, 0, NULL);

	if (fd == 0) {
		DBG("HDP:dbus Can't get reply arguments");
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	DBG("File Descriptor = %d, Dev_path = %s\n", fd, path);

	val =  g_dbus_connection_call_sync(conn, BLUEZ_NAME, path,
		PROPERTIES_INTERFACE, "GetAll",
		g_variant_new("(s)", HDP_CHANNEL_INTERFACE),
		NULL, 0, -1, NULL, &error);

	if (error) {
		DBG(" HDP:dbus Can't get the reply");
		DBG("error %s", error->message);
		g_error_free(error);
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	if (val != NULL) {
		if (g_variant_is_of_type(val, G_VARIANT_TYPE("(a{sv})"))) {
			GVariantIter *iter;
			GVariant *item;
			g_variant_get(val, "(a{sv})", &iter);
			while ((item = g_variant_iter_next_value(iter))) {
				gchar *key;
				GVariant *value;
				g_variant_get(item, "{sv}", &key, &value);
				if (g_strcmp0("Type", key) == 0)
					g_variant_get(value, "(s)", &type_qos);
				else if (g_strcmp0("Device", key) == 0)
					g_variant_get(value, "(o)",
								&device_name);
				else if (g_strcmp0("Application", key) == 0)
					g_variant_get(value, "(o)",
								&app_handle);
			}
		}
	}

	DBG("QOS = %s, Device = %s, Apphandler = %s",
				type_qos, device_name, app_handle);

	if (NULL == type_qos || NULL == app_handle) {
		DBG("Pasing failed\n");
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	type = (g_strcmp0(type_qos, "Reliable") == 0) ?
		HDP_QOS_RELIABLE : HDP_QOS_STREAMING;

	list = hdp_internal_gslist_find_app_handler((void *)app_handle);

	if (NULL == list) {
		DBG("**** Could not locate the list for %s*****\n", app_handle);
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	info = g_new0(hdp_obj_info_t, 1);
	info->fd = fd;
	info->obj_channel_path = g_strdup(path);
	list->obj_info = g_slist_append(list->obj_info, info);

	hdp_internal_watch_fd(fd, info->obj_channel_path);

	device_path_to_address(path, address);

	DBG("Going to give callback\n");

	if (device)
		if (device->hdp_state_changed_cb)
			device->hdp_state_changed_cb(
				BLUETOOTH_ERROR_NONE,
				address, app_handle, type, fd,
				device->hdp_state_changed_cb_data);

	DBG("Updated fd in the list*\n");
	DBG("-\n");

	ret = BT_ERROR_NONE;
done:
	DBG("error");

	if (device)
		if (device->hdp_state_changed_cb)
			device->hdp_state_changed_cb(
				BLUETOOTH_ERROR_CONNECTION_ERROR,
				address, app_handle, type, fd,
				device->hdp_state_changed_cb_data);

	return ret;
}

void hdp_internal_handle_connect(gpointer user_data,
						GVariant *param)
{
	const char *obj_channel_path;
	struct _bluez_device *device = user_data;

	DBG("+********Signal - ChannelConnected******\n\n");
	DBG("Path = %s", device->object_path);

	g_variant_get(param, "o", &obj_channel_path);
	if (obj_channel_path == NULL) {
		DBG("Unexpected parameters in ChannelConnected signal");
		return;
	}

	DBG("Channel connected, Path = %s", obj_channel_path);

	hdp_internal_acquire_fd(device, obj_channel_path);

	DBG("-");
}

void hdp_internal_handle_disconnect(gpointer user_data,
						GVariant *param)
{
	const char *obj_channel_path;
	char address[BT_ADDRESS_STRING_SIZE] = { 0, };
	hdp_obj_info_t *info;
	struct _bluez_device *device = user_data;

	DBG("+********Signal - ChannelDeleted ******\n\n");
	DBG("Path = %s", device->object_path);

	g_variant_get(param, "o", &obj_channel_path);

	if (obj_channel_path == NULL) {
		DBG("Unexpected parameters in ChannelDeleted signal");
		return;
	}

	DBG("Channel Deleted, Path = %s", obj_channel_path);

	info = hdp_internal_gslist_obj_find_using_path(obj_channel_path);
	if (!info) {
		DBG("No obj info for ob_channel_path [%s]\n",
						obj_channel_path);
		return;
	}

	device_path_to_address(device->object_path, address);

	if (device->hdp_state_changed_cb)
		device->hdp_state_changed_cb(BLUETOOTH_ERROR_NONE, address,
			NULL, 0, info->fd, device->hdp_state_changed_cb_data);

	DBG(" Removed connection from list\n");

	hdp_obj_info_free(info);
}

static int hdp_internal_create_application(unsigned int data_type,
					int role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	GVariantBuilder *opts;
	guint16 value;
	const char *svalue;
	GDBusConnection *connection;
	GVariant *val;
	GError *error = NULL;
	int ret;
	hdp_app_list_t *list;
	char *app_path;

	connection = get_system_lib_dbus_connect();
	if (connection == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	opts = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);

	value = (guint16)data_type;
	g_variant_builder_add(opts, "{sv}", "DataType",
					g_variant_new("q", value));

	svalue = (role == HDP_ROLE_SINK) ? "Sink" : "Source";
	g_variant_builder_add(opts, "{sv}", "Role",
					g_variant_new("s", svalue));

	g_variant_builder_add(opts, "{sv}", "Description",
				g_variant_new("s", "Health Device"));

	if (role == HDP_ROLE_SOURCE) {
		if (channel_type == HDP_QOS_RELIABLE)
			svalue = "Reliable";
		else if (channel_type == HDP_QOS_STREAMING)
			svalue = "Streaming";
		else
			svalue = "";

		g_variant_builder_add(opts, "{sv}", "ChannelType",
					g_variant_new("s", svalue));
	}

	val = g_dbus_connection_call_sync(connection, BLUEZ_NAME,
					"/org/bluez",
					HDP_MANAGER_INTERFACE,
					"CreateApplication",
					g_variant_new("(a{sv})", opts),
					NULL, 0, -1,
					NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_variant_get(val, "(o)", &app_path);

	DBG("path = %s", app_path);

	list = g_new0(hdp_app_list_t, 1);
	list->app_handle = (void *)g_strdup(app_path);
	*app_handle = list->app_handle;

	g_app_list = g_slist_append(g_app_list, list);

	ret = BT_ERROR_NONE;
done:
	return ret;
}

int bluetooth_hdp_activate(unsigned short data_type,
					bt_hdp_role_type_t role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle)
{
	int result = BT_ERROR_NONE;

	DBG("");

	if (role == HDP_ROLE_SOURCE && channel_type == HDP_QOS_ANY) {
		DBG("For source, type is mandatory - Reliable/Streaming");
		return BT_ERROR_INVALID_PARAMETER;
	}

	result = hdp_internal_create_application(data_type, role,
						channel_type, app_handle);

	return result;
}

static hdp_app_list_t *hdp_internal_gslist_find_app_handler(void *app_handle)
{
	GSList *l;

	if (g_app_list == NULL)
		return NULL;

	DBG("List length = %d\n", g_slist_length(g_app_list));

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

static void hdp_obj_info_free(hdp_obj_info_t *info)
{
	if (info) {
		close(info->fd);
		g_free(info->obj_channel_path);
		g_free(info);
	}
}

static hdp_obj_info_t *hdp_internal_gslist_obj_find_using_fd(int fd)
{
	GSList *l;
	GSList *iter;

	if (g_app_list == NULL)
		return NULL;

	DBG("List length = %d\n", g_slist_length(g_app_list));

	for (l = g_app_list; l != NULL; l = l->next) {
		hdp_app_list_t *list = l->data;
		if (!list)
			return NULL;

		for (iter = list->obj_info; iter != NULL;
						iter = iter->next) {
			hdp_obj_info_t *info = iter->data;
			if (!info)
				return NULL;

			if (fd == info->fd)
				return info;
		}
	}
	return NULL;
}

static gboolean hdp_internal_destroy_application_cb(gpointer data)
{
	const char *app_handle;
	hdp_app_list_t *list = NULL;
	app_handle = (const char *)data;

	DBG("+");

	list = hdp_internal_gslist_find_app_handler((void *)app_handle);
	if (NULL == list) {
		DBG("**** list not found for %s ******\n", app_handle);
		return FALSE;
	}

	g_app_list = g_slist_remove(g_app_list, list);

	g_free(list->app_handle);
	g_slist_foreach(list->obj_info, (GFunc)hdp_obj_info_free, NULL);
	g_free(list);

	DBG("List length = %d\n", g_slist_length(g_app_list));

	DBG("-");
	return FALSE;
}

static int hdp_internal_destroy_application(const char *app_handle)
{
	GDBusConnection *connection;
	GError *error = NULL;
	int ret;

	connection = get_system_lib_dbus_connect();
	if (connection == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_dbus_connection_call_sync(connection, BLUEZ_NAME,
				"/org/bluez",
				HDP_MANAGER_INTERFACE,
				"DestroyApplication",
				g_variant_new("(o)", app_handle),
				NULL, 0, -1,
				NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	DBG("Destroyed health application: %s", (char *)app_handle);

	g_idle_add(hdp_internal_destroy_application_cb,
					(gpointer)app_handle);

	ret = BT_ERROR_NONE;
done:
	return ret;
}

int bluetooth_hdp_deactivate(const char *app_handle)
{
	return hdp_internal_destroy_application(app_handle);
}

int bluetooth_hdp_send_data(unsigned int channel_id,
					const char *buffer,
					unsigned int size)
{
	int wbytes = 0;
	int written = 0;

	DBG("+");

	if ((channel_id == 0) || (NULL == buffer) || (size == 0)) {
		DBG("Invalid arguments..\n");
		return BT_ERROR_INVALID_PARAMETER;
	} else {
		while (wbytes < size) {
			written = write(channel_id, buffer + wbytes,
						size - wbytes);
			if (written <= 0) {
				DBG("write failed..\n");
				return BT_ERROR_OPERATION_FAILED;
			}
			wbytes += written;
		}
	}

	return BT_ERROR_NONE;
}

static void hdp_connect_request_cb(GObject *source_object,
				GAsyncResult *res, gpointer user_data)
{
	GError *error;
	GVariant *result;
	char *obj_connect_path;
	GDBusConnection *conn;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	bt_hdp_connected_t *conn_ind = user_data;
	bluez_adapter_t *adapter = NULL;
	struct _bluez_device *device = NULL;

	conn = get_system_lib_dbus_connect();
	if (conn == NULL)
		goto done;
	result = g_dbus_connection_call_finish(conn,
							res,
							&error);
	if (error) {
		DBG("HDP connection  Dbus Call Error: %s\n", error->message);
		g_error_free(error);

		adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
		if (adapter == NULL)
			goto done;

		convert_addr_type_to_string(address,
			(unsigned char *)conn_ind->device_address.addr);

		device = bluez_adapter_get_device_by_address(adapter,
								address);
		if (device == NULL)
			goto done;

		if (device->hdp_state_changed_cb)
			device->hdp_state_changed_cb(
				BLUETOOTH_ERROR_CONNECTION_ERROR,
				address, conn_ind->app_handle,
				conn_ind->type, 0,
				device->hdp_state_changed_cb_data);
	} else {
		g_variant_get(result, "(o)", &obj_connect_path);
		DBG("Obj Path returned = %s\n", obj_connect_path);
	}

done:
	g_free((void *)conn_ind->app_handle);
	g_free(conn_ind);
}

int bluetooth_hdp_connect(const char *app_handle,
			bt_hdp_qos_type_t channel_type,
			const bluetooth_device_address_t *device_address)
{
	bt_hdp_connected_t *param;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_path = NULL;
	char *role;
	bluez_adapter_t *adapter = NULL;
	GDBusConnection *conn;
	int ret;

	DBG("+");

	adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);

	if (adapter == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	if (channel_type == HDP_QOS_RELIABLE) {
		role = "Reliable";
	} else if (channel_type == HDP_QOS_STREAMING) {
		role = "Streaming";
	} else if (channel_type == HDP_QOS_ANY) {
		role = "Any";
	} else {
		DBG("Invalid channel_type %d", channel_type);
		return BT_ERROR_INVALID_PARAMETER;
	}

	conn = get_system_lib_dbus_connect();
	if (conn == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	convert_addr_type_to_string(address,
			(unsigned char *)device_address->addr);

	DBG("create conection to %s", address);

	dev_path = g_strdup_printf("/org/bluez/%s/dev_%s",
					DEFAULT_ADAPTER_NAME, address);
	if (dev_path == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_strdelimit(dev_path, ":", '_');

	DBG("path: %s", dev_path);

	param = g_new0(bt_hdp_connected_t, 1);
	param->app_handle = g_strdup(app_handle);
	memcpy(&param->device_address, device_address,
					BLUETOOTH_ADDRESS_LENGTH);
	param->type = channel_type;

	g_dbus_connection_call(conn, BLUEZ_NAME,
				dev_path,
				HDP_DEVICE_INTERFACE,
				"CreateChannel",
				g_variant_new("(os)", app_handle, role),
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				hdp_connect_request_cb, param);

	g_free(dev_path);

	ret = BT_ERROR_NONE;
done:
	return ret;
}

static void hdp_disconnect_request_cb(GObject *source_object,
			GAsyncResult *res, gpointer user_data)
{
	bt_hdp_disconnected_t *disconn_ind = user_data;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	GError *error;
	GDBusConnection *conn;
	bluez_adapter_t *adapter = NULL;
	struct _bluez_device *device = NULL;

	conn = get_system_lib_dbus_connect();
	if (conn == NULL)
		goto done;

	g_dbus_connection_call_finish(conn, res, &error);

	if (error) {
		DBG("HDP discon  Dbus Call Error: %s\n", error->message);
		g_error_free(error);

		adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
		if (adapter == NULL)
			goto done;

		convert_addr_type_to_string(address,
			(unsigned char *)disconn_ind->device_address.addr);
		device = bluez_adapter_get_device_by_address(adapter,
								address);
		if (device == NULL)
			goto done;

		if (device->hdp_state_changed_cb)
			device->hdp_state_changed_cb(
					BLUETOOTH_ERROR_CONNECTION_ERROR,
					address, NULL,
					0, disconn_ind->channel_id,
					device->hdp_state_changed_cb_data);
	} else {
		DBG("HDP disconnection Dbus Call is done\n");
	}

done:
	g_free(disconn_ind);
}

int bluetooth_hdp_disconnect(unsigned int channel_id,
		const bluetooth_device_address_t *device_address)
{
	bt_hdp_disconnected_t *param;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_path = NULL;
	bluez_adapter_t *adapter = NULL;
	GDBusConnection *conn;
	hdp_obj_info_t *info = NULL;
	int ret;

	DBG("+");

	adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);

	if (adapter == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	info = hdp_internal_gslist_obj_find_using_fd(channel_id);
	if (NULL == info) {
		DBG("*** Could not locate the list for %d*****\n", channel_id);
		ret = BT_ERROR_INVALID_PARAMETER;
		goto done;
	}

	conn = get_system_lib_dbus_connect();
	if (conn == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	convert_addr_type_to_string(address,
		(unsigned char *)device_address->addr);

	DBG("create conection to %s", address);

	dev_path = g_strdup_printf("/org/bluez/%s/dev_%s",
					DEFAULT_ADAPTER_NAME, address);
	if (dev_path == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_strdelimit(dev_path, ":", '_');

	DBG("path: %s", dev_path);

	param = g_new0(bt_hdp_disconnected_t, 1);
	param->channel_id = channel_id;
	memcpy(&param->device_address, device_address,
					BLUETOOTH_ADDRESS_LENGTH);

	g_dbus_connection_call(conn, BLUEZ_NAME,
				dev_path,
				HDP_DEVICE_INTERFACE,
				"DestroyChannel",
				g_variant_new("(o)", info->obj_channel_path),
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				hdp_disconnect_request_cb, param);

	g_free(dev_path);

	ret = BT_ERROR_NONE;
done:
	return ret;
}
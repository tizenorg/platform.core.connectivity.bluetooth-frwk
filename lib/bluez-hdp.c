#include <stdlib.h>
#include <string.h>
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

static bluez_hdp_state_changed_t hdp_state_changed_cb;
static gpointer hdp_state_changed_cb_data;
static bluez_set_data_received_changed_t data_received_changed_cb;
static gpointer data_received_changed_data;

static void hdp_obj_info_free(hdp_obj_info_t *info);
static hdp_app_list_t *hdp_internal_gslist_find_app_handler(void *app_handle);

static GSList *g_app_list;

void bluez_set_hdp_state_changed_cb(
				bluez_hdp_state_changed_t cb,
				gpointer user_data)
{
	hdp_state_changed_cb = cb;
	hdp_state_changed_cb_data = user_data;
}

void bluez_unset_hdp_state_changed_cb()
{
	hdp_state_changed_cb = NULL;
	hdp_state_changed_cb_data = NULL;
}

void bluez_set_data_received_changed_cb(
				bluez_set_data_received_changed_t cb,
				gpointer user_data)
{
	data_received_changed_cb = cb;
	data_received_changed_data = user_data;
}

void bluez_unset_data_received_changed_cb()
{
	data_received_changed_cb = NULL;
	data_received_changed_data = NULL;
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

	conn = get_system_lib_dbus_connect();
	if (conn == NULL)
		goto done;
	result = g_dbus_connection_call_finish(conn,
							res,
							&error);
	if (error) {
		DBG("HDP connection  Dbus Call Error: %s\n", error->message);
		convert_addr_type_to_string(address,
			(unsigned char *)conn_ind->device_address.addr);

		if (hdp_state_changed_cb)
			hdp_state_changed_cb(
				BT_ERROR_REMOTE_DEVICE_NOT_CONNECTED,
				address, conn_ind->app_handle,
				conn_ind->type, 0,
				hdp_state_changed_cb_data);
		g_error_free(error);
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

	conn = get_system_lib_dbus_connect();
	if (conn == NULL)
		goto done;

	g_dbus_connection_call_finish(conn, res, &error);

	if (error) {
		DBG("HDP discon  Dbus Call Error: %s\n", error->message);
		convert_addr_type_to_string(address,
			(unsigned char *)disconn_ind->device_address.addr);
		if (hdp_state_changed_cb)
			hdp_state_changed_cb(BT_ERROR_NONE,
					address, NULL,
					0, disconn_ind->channel_id,
					hdp_state_changed_cb_data);
		g_error_free(error);
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

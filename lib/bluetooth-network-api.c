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
#include "bluetooth-network-api.h"

/**********************************************************************
*                                      Static Functions declaration    *
***********************************************************************/

static void __bluetooth_network_activate_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						  gpointer user_data);
static void __bluetooth_network_deactivate_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data);
static void __bluetooth_network_connect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						 gpointer user_data);
static void __bluetooth_network_disconnect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data);
static void __bluetooth_network_server_connected(DBusGProxy *proxy, const char *device,
					       const char *address, gpointer user_data);
static void __bluetooth_network_server_disconnected(DBusGProxy *proxy, const char *device,
						  const char *address, gpointer user_data);
static DBusHandlerResult __bluetooth_network_event_filter(DBusConnection *sys_conn,
							DBusMessage *msg, void *data);

/**********************************************************************
*                                      Network server APIs (NAP)      *
***********************************************************************/

BT_EXPORT_API int bluetooth_network_activate_server(void)
{
	DBG("+\n");

	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *proxy_net_server = NULL;
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };

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

	proxy_net_server = dbus_g_proxy_new_for_name(conn, "org.bluez",
						     default_adapter_path, BLUEZ_NET_SERVER_PATH);

	if (proxy_net_server == NULL) {
		DBG("Failed to get the network server proxy\n");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_g_proxy_begin_call(proxy_net_server, "Register",
			(DBusGProxyCallNotify) __bluetooth_network_activate_request_cb,
			conn,/*user data*/
			NULL, /*destroy*/
			G_TYPE_STRING,
			NAP_UUID_NAME,/*first_arg_type*/
			G_TYPE_STRING,
			NET_BRIDGE_INTERFACE,/*second_arg_type*/
			G_TYPE_INVALID)) {
		DBG("Network server register Dbus Call Error");
		g_object_unref(proxy_net_server);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_network_deactivate_server(void)
{
	DBG("+\n");

	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *proxy_net_server = NULL;
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };

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

	proxy_net_server = dbus_g_proxy_new_for_name(conn, "org.bluez",
						     default_adapter_path, BLUEZ_NET_SERVER_PATH);

	if (proxy_net_server == NULL) {
		DBG("Failed to get the network server proxy\n");
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_g_proxy_begin_call(proxy_net_server, "Unregister",
				(DBusGProxyCallNotify) __bluetooth_network_deactivate_request_cb,
				conn,	/*user_data*/
				NULL,	/*destroy*/
				G_TYPE_STRING, NAP_UUID_NAME,	/*first_arg_type*/
				G_TYPE_INVALID)) {
		DBG("Network server deregister Dbus Call Error");
		g_object_unref(proxy_net_server);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
}

static void __bluetooth_network_activate_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						  gpointer user_data)
{
	GError *g_error = NULL;
	int result = BLUETOOTH_ERROR_NONE;
	DBusGConnection *conn = NULL;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_INVALID);

	g_object_unref(proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("Network server register Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		DBG("Network server register Dbus Call is done\n");
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_ACTIVATED,
					result, NULL);

}

static void __bluetooth_network_deactivate_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data)
{
	GError *g_error = NULL;
	int result = BLUETOOTH_ERROR_NONE;
	DBusGConnection *conn = NULL;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_INVALID);

	g_object_unref(proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("Network server unregister Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		DBG("Network server unregister Dbus Call is done\n");
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_DEACTIVATED,
					result, NULL);

}

void _bluetooth_network_server_add_signal(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->conn == NULL)
		return;

	if (strlen(bt_internal_info->adapter_path) <= 0)
		return;

	if (bt_internal_info->network_server_proxy != NULL) {
		DBG("The network proxy already exist");
		return;
	}

	/* Add the network server signal */
	bt_internal_info->network_server_proxy =
	    dbus_g_proxy_new_for_name(bt_internal_info->conn, "org.bluez",
				      bt_internal_info->adapter_path, BLUEZ_NET_SERVER_PATH);

	dbus_g_proxy_add_signal(bt_internal_info->network_server_proxy, "PeerConnected",
				G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_internal_info->network_server_proxy, "PeerConnected",
				    G_CALLBACK(__bluetooth_network_server_connected), NULL, NULL);

	dbus_g_proxy_add_signal(bt_internal_info->network_server_proxy, "PeerDisconnected",
				G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(bt_internal_info->network_server_proxy, "PeerDisconnected",
				    G_CALLBACK(__bluetooth_network_server_disconnected), NULL, NULL);

	DBG("-\n");
}

void _bluetooth_network_server_remove_signal(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->network_server_proxy == NULL) {
		DBG("No network proxy exist");
		return;
	}

	/* Remove the network server signal */
	dbus_g_proxy_disconnect_signal(bt_internal_info->network_server_proxy, "PeerConnected",
				       G_CALLBACK(__bluetooth_network_server_connected), NULL);

	dbus_g_proxy_disconnect_signal(bt_internal_info->network_server_proxy, "PeerDisconnected",
				       G_CALLBACK(__bluetooth_network_server_disconnected), NULL);

	g_object_unref(bt_internal_info->network_server_proxy);

	bt_internal_info->network_server_proxy = NULL;

	DBG("-\n");
}

static void __bluetooth_network_server_connected(DBusGProxy *proxy,
					       const char *device, const char *address,
					       gpointer user_data)
{
	DBG("+");
	bluetooth_network_device_info_t device_info = {{{0}}};
	if (device == NULL || address == NULL)
		return;

	DBG("device[%s], address[%s] ", device, address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_info.device_address, address);

	memcpy(device_info.interface_name, device, BLUETOOTH_INTERFACE_NAME_LENGTH);

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_CONNECTED,
					BLUETOOTH_ERROR_NONE, &device_info);
	DBG("-");
}

static void __bluetooth_network_server_disconnected(DBusGProxy *proxy,
						  const char *device, const char *address,
						  gpointer user_data)
{
	DBG("+");
	bluetooth_network_device_info_t device_info = {{{0}}};
	if (device == NULL || address == NULL)
		return;

	DBG("device[%s], address[%s] ", device, address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_info.device_address, address);

	memcpy(device_info.interface_name, device, BLUETOOTH_INTERFACE_NAME_LENGTH);

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_SERVER_DISCONNECTED,
					BLUETOOTH_ERROR_NONE, &device_info);

	DBG("-");
}

/**********************************************************************
*                                                 Network client APIs *
***********************************************************************/

BT_EXPORT_API int bluetooth_network_connect(const bluetooth_device_address_t *device_address,
					    bluetooth_network_role_t role, char *custom_uuid)
{
	DBG("+\n");

	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *proxy_net_client = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char theRemoteRole[BLUETOOTH_UUID_STRING_MAX] = { 0 };
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };
	char *path = NULL;

	if (role == BLUETOOTH_NETWORK_CUSTOM_UUID && custom_uuid == NULL) {
		DBG("custom_uuid is NULL\n");
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

	path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (path == NULL) {
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(path, ":", '_');
	DBG("path  %s\n", path);

	proxy_net_client = dbus_g_proxy_new_for_name(conn, "org.bluez",
						     path, BLUEZ_NET_CLIENT_PATH);

	if (proxy_net_client == NULL) {
		DBG("Failed to get the network client proxy\n");
		g_free(path);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	switch (role) {
	case BLUETOOTH_NETWORK_PANU_ROLE:
		g_strlcpy(theRemoteRole, PANU_UUID_NAME, BLUETOOTH_UUID_STRING_MAX);
		break;

	case BLUETOOTH_NETWORK_NAP_ROLE:
		g_strlcpy(theRemoteRole, NAP_UUID_NAME, BLUETOOTH_UUID_STRING_MAX);
		break;

	case BLUETOOTH_NETWORK_GN_ROLE:
		g_strlcpy(theRemoteRole, GN_UUID_NAME, BLUETOOTH_UUID_STRING_MAX);
		break;

	case BLUETOOTH_NETWORK_CUSTOM_UUID:
		g_strlcpy(theRemoteRole, custom_uuid, BLUETOOTH_UUID_STRING_MAX);
		break;

	default:
		g_strlcpy(theRemoteRole, PANU_UUID_NAME, BLUETOOTH_UUID_STRING_MAX);
		break;
	}

	if (!dbus_g_proxy_begin_call(proxy_net_client, "Connect",
					(DBusGProxyCallNotify) __bluetooth_network_connect_request_cb,
					conn,/*user_data*/
					NULL,	/*destroy*/
					G_TYPE_STRING, theRemoteRole,	/* first_arg_type*/
					G_TYPE_INVALID)) {
		DBG("Network client connection Dbus Call Error");
		g_free(path);
		g_object_unref(proxy_net_client);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_free(path);

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;

}

BT_EXPORT_API int bluetooth_network_disconnect(const bluetooth_device_address_t *device_address)
{
	DBG("+\n");

	GError *err = NULL;
	DBusGConnection *conn = NULL;
	DBusGProxy *proxy_net_client = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *path = NULL;
	char default_adapter_path[BT_ADAPTER_OBJECT_PATH_MAX + 1] = { 0 };

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

	path = g_strdup_printf("%s/dev_%s", default_adapter_path, address);

	if (path == NULL) {
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_MEMORY_ALLOCATION;
	}

	g_strdelimit(path, ":", '_');
	DBG("path  %s\n", path);

	proxy_net_client = dbus_g_proxy_new_for_name(conn, "org.bluez",
						     path, BLUEZ_NET_CLIENT_PATH);

	if (proxy_net_client == NULL) {
		DBG("Failed to get the network client proxy\n");
		g_free(path);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	if (!dbus_g_proxy_begin_call(proxy_net_client, "Disconnect",
				(DBusGProxyCallNotify) __bluetooth_network_disconnect_request_cb,
				conn,	/*user_data*/
				NULL,	/*destroy*/
				G_TYPE_INVALID)) {
		DBG("Network client connection Dbus Call Error");
		g_free(path);
		g_object_unref(proxy_net_client);
		dbus_g_connection_unref(conn);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_free(path);

	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;

}

static void __bluetooth_network_connect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						 gpointer user_data)
{
	GError *g_error = NULL;
	char *device = NULL;
	DBusGConnection *conn = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_STRING, &device, G_TYPE_INVALID);

	g_object_unref(proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("Network Client connection  Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		DBG("Network Client connection Dbus Call is done %s\n", device);
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_CONNECTED,
					result, NULL);

}

static void __bluetooth_network_disconnect_request_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data)
{
	GError *g_error = NULL;
	DBusGConnection *conn = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	conn = (DBusGConnection *) user_data;

	dbus_g_proxy_end_call(proxy, call, &g_error, G_TYPE_INVALID);

	g_object_unref(proxy);
	dbus_g_connection_unref(conn);

	if (g_error != NULL) {
		DBG("Network Client disconnection Dbus Call Error: %s\n", g_error->message);
		g_error_free(g_error);
		result = BLUETOOTH_ERROR_INTERNAL;
	} else {
		DBG("Network Client disconnection Dbus Call is done\n");
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_NETWORK_DISCONNECTED,
					result, NULL);

}

void _bluetooth_network_client_add_filter(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;
	DBusError dbus_error;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->conn == NULL)
		return;

	if (bt_internal_info->sys_conn) {
		DBG("sys_conn already exist");
		return;
	}

	/* Add the filter for network client functions */
	dbus_error_init(&dbus_error);

	bt_internal_info->sys_conn = dbus_g_connection_get_connection(bt_internal_info->conn);

	dbus_connection_add_filter(bt_internal_info->sys_conn, __bluetooth_network_event_filter,
					NULL, NULL);

	dbus_bus_add_match(bt_internal_info->sys_conn,
			   "type='signal',interface='" BLUEZ_NET_CLIENT_PATH
			   "',member='PropertyChanged'", &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
	}

	DBG("-\n");
}

void _bluetooth_network_client_remove_filter(void)
{
	DBG("+\n");

	bt_info_t *bt_internal_info = NULL;
	DBusError dbus_error;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->sys_conn == NULL) {
		DBG("sys_conn is NULL");
		return;
	}

	/* Add the filter for network client functions */
	dbus_error_init(&dbus_error);

	dbus_connection_remove_filter(bt_internal_info->sys_conn, __bluetooth_network_event_filter,
				      NULL);

	bt_internal_info->sys_conn = NULL;

	DBG("-\n");
}

static DBusHandlerResult __bluetooth_network_event_filter(DBusConnection *sys_conn,
							DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	DBusMessageIter item_iter, value_iter;
	const char *property;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_is_signal(msg, BLUEZ_NET_CLIENT_PATH, "PropertyChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (path == NULL || strcmp(path, "/") == 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		DBG("This is bad format dbus\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	DBG("Property (%s)\n", property);

	if (!strcmp(property, "Connected")) {
		gboolean connected = FALSE;
		char address[BT_ADDRESS_STRING_SIZE] = { 0, };
		bluetooth_device_address_t device_addr = { {0} };

		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &connected);

		DBG("connected: %d", connected);

		_bluetooth_internal_device_path_to_address(path, address);
		_bluetooth_internal_convert_addr_string_to_addr_type(&device_addr, address);
		_bluetooth_internal_event_cb(connected ? BLUETOOTH_EVENT_NETWORK_CONNECTED :
						BLUETOOTH_EVENT_NETWORK_DISCONNECTED,
						BLUETOOTH_ERROR_NONE, &device_addr);
	} else if (!strcmp(property, "Interface")) {
		const gchar *device = NULL;

		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &device);

		if (device)
			DBG("device is %s", device);
	} else if (!strcmp(property, "UUID")) {
		const gchar *uuid = NULL;

		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &uuid);

		if (uuid)
			DBG("uuid is %s", uuid);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

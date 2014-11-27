/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vconf.h>
#include <vconf-keys.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>

#include "bt_core.h"
#include "bt-internal-types.h"

static GMainLoop *main_loop = NULL;
static DBusGConnection *conn = NULL;

#ifdef __TIZEN_MOBILE__
typedef enum {
	BT_DEACTIVATED,
	BT_ACTIVATED,
	BT_ACTIVATING,
	BT_DEACTIVATING,
} bt_status_t;

static bt_status_t adapter_status = BT_DEACTIVATED;

static void __bt_core_set_status(bt_status_t status)
{
	adapter_status = status;
}

static bt_status_t __bt_core_get_status(void)
{
	return adapter_status;
}
#endif

static void __bt_core_terminate(void)
{
	if (main_loop) {
		g_main_loop_quit(main_loop);
	} else {
		BT_DBG("Terminating bt-core daemon");
		exit(0);
	}
}

static gboolean bt_core_enable_adapter(BtCore *agent,
						DBusGMethodInvocation *context);

static gboolean bt_core_disable_adapter(BtCore *agent,
						DBusGMethodInvocation *context);

static gboolean bt_core_reset_adapter(BtCore *agent,
						DBusGMethodInvocation *context);

#include "bt_core_glue.h"

GType bt_core_get_type (void);


G_DEFINE_TYPE(BtCore, bt_core, G_TYPE_OBJECT);

/*This is part of platform provided code skeleton for client server model*/
static void bt_core_class_init (BtCoreClass *bt_core_class)
{
	dbus_g_object_type_install_info(G_TYPE_FROM_CLASS(bt_core_class),
					&dbus_glib_bt_core_object_info);
}

/*This is part of platform provided code skeleton for client server model*/
static void bt_core_init (BtCore *core)
{
}

typedef enum {
	BT_CORE_ERROR_REJECT,
	BT_CORE_ERROR_CANCEL,
	BT_CORE_ERROR_TIMEOUT,
} BtCoreError;

#define BT_CORE_ERROR (bt_core_error_quark())

static GQuark bt_core_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("BtCore");

	return quark;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GError *bt_core_error(BtCoreError error, const char *err_msg)
{
	return g_error_new(BT_CORE_ERROR, error, err_msg, NULL);
}

static DBusGProxy *_bt_get_connman_proxy(void)
{
	DBusGProxy *proxy;

	if (conn == NULL) {
		conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
		retv_if(conn == NULL, NULL);
	}

	proxy = dbus_g_proxy_new_for_name(conn,
			CONNMAN_DBUS_NAME,
			CONNMAN_BLUETOOTH_TECHNOLOGY_PATH,
			CONNMAN_BLUETOTOH_TECHNOLOGY_INTERFACE);
	retv_if(proxy == NULL, NULL);

	return proxy;
}

static int _bt_power_adapter(gboolean powered)
{
	GValue state = { 0 };
	GError *error = NULL;
	DBusGProxy *proxy;

	proxy = _bt_get_connman_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	g_value_init(&state, G_TYPE_BOOLEAN);
	g_value_set_boolean(&state, powered);

	BT_DBG("set power property state: %d to connman", powered);

	dbus_g_proxy_call(proxy, "SetProperty", &error,
				G_TYPE_STRING, "Powered",
				G_TYPE_VALUE, &state,
				G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		BT_ERR("Powered set err:[%s]", error->message);
		g_error_free(error);
		g_value_unset(&state);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	return BLUETOOTH_ERROR_NONE;
}

static int __bt_enable_adapter(void)
{
	BT_DBG("");
#ifdef __TIZEN_MOBILE__
	int ret;

	__bt_core_set_status(BT_ACTIVATING);

	ret = system("/usr/etc/bluetooth/bt-stack-up.sh &");
	if (ret < 0) {
		BT_DBG("running script failed");
		ret = system("/usr/etc/bluetooth/bt-dev-end.sh &");
		__bt_core_set_status(BT_DEACTIVATED);
		return -1;
	}
#else
	_bt_power_adapter(TRUE);
#endif
	return 0;
}

static int __bt_disable_adapter(void)
{
	BT_DBG("");

#ifdef __TIZEN_MOBILE__
	__bt_core_set_status(BT_DEACTIVATING);

	if (system("/usr/etc/bluetooth/bt-stack-down.sh &") < 0) {
		BT_DBG("running script failed");
		__bt_core_set_status(BT_ACTIVATED);
		return -1;
	}
#else
	_bt_power_adapter(FALSE);
#endif
	__bt_core_terminate();
	return 0;
}

static gboolean bt_core_enable_adapter(BtCore *agent,
						DBusGMethodInvocation *context)
{
	char *sender = dbus_g_method_get_sender(context);
	int ret;

	if (sender == NULL)
		return FALSE;

	ret = __bt_enable_adapter();
	if (ret < 0) {
		GError *error = bt_core_error(BT_CORE_ERROR_REJECT,
							"Activation failed");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		g_free(sender);
		return FALSE;
	} else {
		dbus_g_method_return(context);
	}

	g_free(sender);
	return TRUE;
}

static gboolean bt_core_disable_adapter(BtCore *agent,
						DBusGMethodInvocation *context)
{
	char *sender = dbus_g_method_get_sender(context);
	int ret;

	if (sender == NULL)
		return FALSE;

	ret = __bt_disable_adapter();
	if (ret < 0) {
		GError *error = bt_core_error(BT_CORE_ERROR_REJECT,
							"Deactivation failed");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		g_free(sender);
		return FALSE;
	} else {
		dbus_g_method_return(context);
	}

	g_free(sender);
	return TRUE;
}

static int __bt_reset_adapter(void)
{
	/* Forcely terminate */
	if (system("/usr/etc/bluetooth/bt-reset-env.sh &") < 0) {
		BT_DBG("running script failed");
	}
	__bt_core_terminate();
	return 0;
}

static gboolean bt_core_reset_adapter(BtCore *agent,
						DBusGMethodInvocation *context)
{
	char *sender = dbus_g_method_get_sender(context);
	int ret;

	if (sender == NULL)
		return FALSE;

	ret = __bt_reset_adapter();
	if (ret < 0) {
		GError *error = bt_core_error(BT_CORE_ERROR_REJECT,
							"Deactivation failed");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		g_free(sender);
		return FALSE;
	} else {
		dbus_g_method_return(context);
	}

	g_free(sender);
	return TRUE;
}

static int __bt_core_get_object_path(DBusMessage *msg, char **path)
{
	DBusMessageIter item_iter;

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_OBJECT_PATH) {
		BT_ERR("This is bad format dbus\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_get_basic(&item_iter, path);

	if (*path == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	return BLUETOOTH_ERROR_NONE;
}

static int __bt_core_get_owner_info(DBusMessage *msg, char **name,
				char **previous, char **current)
{
	DBusMessageIter item_iter;

	dbus_message_iter_init(msg, &item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_STRING) {
		BT_ERR("This is bad format dbus\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_get_basic(&item_iter, name);

	if (*name == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_message_iter_next(&item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_STRING) {
		BT_ERR("This is bad format dbus\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_get_basic(&item_iter, previous);

	if (*previous == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_message_iter_next(&item_iter);

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_STRING) {
		BT_ERR("This is bad format dbus\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_get_basic(&item_iter, current);

	if (*current == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	return BLUETOOTH_ERROR_NONE;
}

static DBusHandlerResult __bt_core_event_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	char *object_path = NULL;
	const char *member = dbus_message_get_member(msg);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (member == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcasecmp(member, "InterfacesAdded") == 0) {
		if (__bt_core_get_object_path(msg, &object_path)) {
			BT_ERR("Fail to get the path");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
#ifdef __TIZEN_MOBILE__
		if (strcasecmp(object_path, "/org/bluez/hci0") == 0) {
			__bt_core_set_status(BT_ACTIVATED);
		}
#endif
	} else if (strcasecmp(member, "InterfacesRemoved") == 0) {
		if (__bt_core_get_object_path(msg, &object_path)) {
			BT_ERR("Fail to get the path");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (strcasecmp(object_path, "/org/bluez/hci0") == 0) {
#ifdef __TIZEN_MOBILE__
			__bt_core_set_status(BT_DEACTIVATED);
#endif
			__bt_core_terminate();
		}
	} else if (strcasecmp(member, "NameOwnerChanged") == 0) {
		char *name = NULL;
		char *previous = NULL;
		char *current = NULL;

		if (__bt_core_get_owner_info(msg, &name, &previous, &current)) {
			BT_ERR("Fail to get the owner info");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (*current != '\0')
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (strcasecmp(name, "org.bluez") == 0) {
			BT_DBG("Bluetoothd is terminated");
			__bt_disable_adapter();
			__bt_core_terminate();
		} else if (strcasecmp(name, "org.projectx.bt") == 0) {
			BT_DBG("bt-service is terminated abnormally");
			__bt_disable_adapter();
		}
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusGProxy *__bt_core_register_event_filter(DBusGConnection *g_conn,
						BtCore *bt_core)
{
	DBusError dbus_error;
	DBusConnection *conn;
	DBusGProxy *proxy;
	GError *err = NULL;
	guint result = 0;

	if (g_conn == NULL)
		return NULL;

	conn = dbus_g_connection_get_connection(g_conn);
	if (conn == NULL)
		return NULL;

	proxy = dbus_g_proxy_new_for_name(g_conn, DBUS_SERVICE_DBUS,
				DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (proxy == NULL) {
		BT_ERR("proxy is NULL");
		return NULL;
	}

	if (!dbus_g_proxy_call(proxy, "RequestName", &err, G_TYPE_STRING,
			BT_CORE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("RequestName RPC failed[%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(proxy);
		return NULL;
	}

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		BT_ERR("Failed to get the primary well-known name.\n");
		g_object_unref(proxy);
		return NULL;
	}

	if (!dbus_connection_add_filter(conn, __bt_core_event_filter,
					NULL, NULL)) {
		BT_ERR("Fail to add filter");
		g_object_unref(proxy);
		return NULL;
	}

	dbus_error_init(&dbus_error);

	dbus_bus_add_match(conn,
			"type='signal',interface='org.freedesktop.DBus'"
			",member='NameOwnerChanged'",
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		g_object_unref(proxy);
		return NULL;
	}

	dbus_bus_add_match(conn,
			"type='signal',interface='org.freedesktop.DBus.ObjectManager'"
			",member='InterfacesAdded'",
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		g_object_unref(proxy);
		return NULL;
	}

	dbus_bus_add_match(conn,
			"type='signal',interface='org.freedesktop.DBus.ObjectManager'"
			",member='InterfacesRemoved'",
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		g_object_unref(proxy);
		return NULL;
	}

	dbus_g_connection_register_g_object(g_conn, BT_CORE_PATH,
					G_OBJECT(bt_core));

	return proxy;
}

static void __bt_unregister_event_filter(DBusGConnection *g_conn,
					BtCore *bt_core,
					DBusGProxy *dbus_proxy)
{
	DBusConnection *conn;

	if (g_conn == NULL ||
	     bt_core == NULL ||
	      dbus_proxy == NULL) {
		BT_ERR("Invalid parameter");
		return;
	}

	conn = dbus_g_connection_get_connection(g_conn);

	dbus_connection_remove_filter(conn, __bt_core_event_filter, NULL);

	dbus_g_connection_unregister_g_object(g_conn, G_OBJECT(bt_core));

	g_object_unref(bt_core);
	g_object_unref(dbus_proxy);
}

static void __bt_core_sigterm_handler(int signo)
{
	BT_DBG("Got the signal: %d", signo);

	__bt_core_terminate();
}

int main(void)
{
	GError *error = NULL;
	BtCore *bt_core;
	DBusGProxy *dbus_proxy = NULL;
	struct sigaction sa;

	BT_DBG("+");

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		BT_ERR("ERROR: Can't get on system bus [%s]", error->message);
		g_error_free(error);
		return FALSE;
	}

	bt_core = g_object_new(BT_CORE_TYPE, NULL);
	if (bt_core == NULL) {
		BT_ERR("bt_service is NULL");
		goto fail;
	}

	dbus_proxy = __bt_core_register_event_filter(conn, bt_core);
	if (!dbus_proxy) {
		BT_ERR("__bt_core_register_event_filter failed");
		g_object_unref(bt_core);
		bt_core = NULL;
		goto fail;
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __bt_core_sigterm_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

fail:
	__bt_unregister_event_filter(conn, bt_core, dbus_proxy);

	if (main_loop)
		g_main_loop_unref(main_loop);

	dbus_g_connection_unref(conn);

	BT_DBG("-");
	return FALSE;
}


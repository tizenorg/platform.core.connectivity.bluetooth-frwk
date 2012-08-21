/*
 * Bluetooth-telephony
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 * 		GirishAshok Joshi <girish.joshi@samsung.com>
 *		Chanyeol Park <chanyeol.park@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-bindings.h>
#include <unistd.h>

#include "vconf.h"
#include "vconf-keys.h"

#include "bluetooth-telephony-internal.h"
#include "bluetooth-telephony-glue.h"
#include "bluetooth-telephony-api.h"
#include "marshal.h"

typedef struct {
	DBusGConnection *conn;
	DBusGProxy *proxy;
	DBusGProxy *dbus_proxy;
	DBusGProxy *manager_proxy;
} telephony_dbus_info_t;

static GObject *object;
static bt_telephony_info_t telephony_info;
static telephony_dbus_info_t telephony_dbus_info;
static gboolean is_active = FALSE;

#define BT_EXPORT_API __attribute__((visibility("default")))

#define BT_TELEPHONY "BT_TELEPHONY"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_TELEPHONY, \
				"%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_TELEPHONY, \
				"%s():%d "fmt, __func__, __LINE__, ##args)

#define BLUETOOTH_TELEPHONY_ERROR (__bluetooth_telephony_error_quark())

#define BLUEZ_SERVICE_NAME "org.bluez"
#define BLUEZ_HEADSET_INTERFACE "org.bluez.Headset"
#define BLUEZ_MANAGER_INTERFACE "org.bluez.Manager"
#define BLUEZ_ADAPTER_INTERFACE "org.bluez.Adapter"
#define BLUEZ_DEVICE_INTERFACE "org.bluez.Device"

#define HFP_AGENT_SERVICE "org.bluez.hfp_agent"
#define HFP_AGENT_PATH "/org/bluez/hfp_agent"
#define HFP_AGENT_INTERFACE "Org.Hfp.App.Interface"

#define CSD_CALL_APP_PATH "/org/tizen/csd/%d"

#define BT_TELEPHONY_CHECK_BT_STATUS() \
	if (!is_active) { \
		DBG("Bluetooth is inactive \n"); \
		return BLUETOOTH_TELEPHONY_ERROR_NOT_ENABLED; \
	}

/*Function Declaration*/
static int __bt_telephony_get_error(const char *error_message);
static int __bt_telephony_event_cb(int event, int result, void *param_data);
static GQuark __bluetooth_telephony_error_quark(void);
static int __bluetooth_telephony_dbus_method_send(const char *path,
		const char *interface, const char *method, int type, ...);
static int __bluetooth_telephony_send_call_status(
			bt_telephony_call_status_t call_status,
			unsigned int call_id);
static GError *__bluetooth_telephony_error(bluetooth_telephony_error_t error,
					const char *err_msg);

static DBusHandlerResult __bluetooth_telephony_event_filter(
						DBusConnection *conn,
						DBusMessage *msg, void *data);

static void __bluetooth_telephony_name_owner_changed(DBusGProxy *dbus_proxy,
					const char *name, const char *prev,
					const char *new, gpointer user_data);
static void __bluetooth_telephony_adapter_added_cb(DBusGProxy *manager_proxy,
				const char *adapter_path, gpointer user_data);
static int __bluetooth_telephony_proxy_init(void);
static void __bluetooth_telephony_proxy_deinit(void);
static int __bluetooth_telephony_register(bt_telephony_func_ptr cb,
							void  *user_data);
static int __bluetooth_telephony_unregister(void);
static int __bluetooth_get_default_adapter_path(DBusGConnection *GConn,
							char *path);
static gboolean __bluetooth_telephony_is_headset(uint32_t device_class);
static int __bluetooth_telephony_get_connected_device(void);
static DBusGProxy *__bluetooth_telephony_get_connected_device_proxy(void);

/*Function Definition*/
static int __bt_telephony_get_error(const char *error_message)
{
	if (error_message == NULL) {
		DBG("Error message NULL\n");
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	DBG("Error message = %s \n", error_message);
	if (g_strcmp0(error_message, "NotAvailable") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_NOT_AVAILABLE;
	else if (g_strcmp0(error_message, "NotConnected") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_NOT_CONNECTED;
	else if (g_strcmp0(error_message, "InProgress") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_BUSY;
	else if (g_strcmp0(error_message, "InvalidArguments") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;
	else if (g_strcmp0(error_message, "AlreadyExists") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_EXSIST;
	else if (g_strcmp0(error_message, "Already Connected") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_CONNECTED;
	else if (g_strcmp0(error_message, "No memory") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_NO_MEMORY;
	else if (g_strcmp0(error_message, "I/O error") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_I_O_ERROR;
	else if (g_strcmp0(error_message, "Operation currently not available") == 0)
		return BLUETOOTH_TELEPHONY_ERROR_OPERATION_NOT_AVAILABLE;
	else
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
}

static int __bt_telephony_event_cb(int event, int result, void *param_data)
{
	telephony_event_param_t bt_event = { 0, };

	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param_data;

	return telephony_info.cb(bt_event.event, &bt_event, telephony_info.user_data);
}

static GQuark __bluetooth_telephony_error_quark(void)
{
	static GQuark quark = 0;

	quark = g_quark_from_static_string("telephony");

	return quark;
}

static int __bluetooth_telephony_dbus_method_send(const char *path,
			const char *interface, const char *method, int type, ...)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	va_list args;

	DBG("__bluetooth_telephony_dbus_method_send +\n");

	msg = dbus_message_new_method_call(HFP_AGENT_SERVICE,
			path, interface, method);
	if (!msg) {
		DBG("Unable to allocate new D-Bus %s message \n", method);
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	va_end(args);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(
		dbus_g_connection_get_connection(telephony_dbus_info.conn),
		msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		DBG("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			int ret = __bt_telephony_get_error(err.message);
			dbus_error_free(&err);
			return ret;
		}
	}

	dbus_message_unref(reply);

	DBG("__bluetooth_telephony_dbus_method_send -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static int __bluetooth_telephony_send_call_status(
			bt_telephony_call_status_t call_status,
			unsigned int call_id)
{
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	DBG("__bluetooth_telephony_send_call_status +\n");

	ret = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"ChangeCallStatus", DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INT32, &call_status,
			DBUS_TYPE_INT32, &call_id, DBUS_TYPE_INVALID);
	g_free(path);
	return ret;
}

static GError *__bluetooth_telephony_error(bluetooth_telephony_error_t error,
					const char *err_msg)
{
	return g_error_new(BLUETOOTH_TELEPHONY_ERROR, error, err_msg);
}

static void bluetooth_telephony_method_init(BluetoothTelephonyMethod *object)
{
	DBG("bluetooth_telephony_method_init +\n");
	DBG("agent %p\n", object);
	DBG("bluetooth_telephony_method_init -\n");

	return;
}

static void __bluetooth_telephony_method_finalize(
					BluetoothTelephonyMethod *object)
{
	DBG("__bluetooth_telephony_method_finalize +\n");
	G_OBJECT_CLASS(bluetooth_telephony_method_parent_class)->finalize((
							GObject *)object);
	DBG("__bluetooth_telephony_method_finalize -\n");

	return;
}

static BluetoothTelephonyMethod *__bluetooth_telephony_method_new(void)
{
	BluetoothTelephonyMethod *obj;

	DBG("__bluetooth_telephony_method_new +\n");
	obj = g_object_new(BLUETOOTH_TELEPHONY_METHOD, NULL);
	DBG("__bluetooth_telephony_method_new -\n");

	return obj;
}

static void bluetooth_telephony_method_class_init(
					BluetoothTelephonyMethodClass *klass)
{
	GObjectClass *object_class = NULL;
	DBG("bluetooth_telephony_method_class_init +\n");

	object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = (void *)__bluetooth_telephony_method_finalize;

	/*Registration of the Framework methods */
	dbus_g_object_type_install_info(BLUETOOTH_TELEPHONY_METHOD,
			&dbus_glib_bluetooth_telephony_method_object_info);
	DBG("bluetooth_telephony_method_class_init -\n");
	return;
}

static gboolean bluetooth_telephony_method_answer(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };
	GError *err;
	int error;

	DBG("bluetooth_telephony_method_answer +\n");
	DBG("call_id = [%d]\n", callid);

	call_data.callid = callid;

	error = __bt_telephony_event_cb(BLUETOOTH_EVENT_AG_ANSWER,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&call_data);

	if (error != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_APPLICATION,
				"Application error");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("bluetooth_telephony_method_answer -\n");
	return TRUE;
}

static gboolean bluetooth_telephony_method_release(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };
	GError *err;
	int error;

	DBG("bluetooth_telephony_method_release +\n");
	DBG("call_id = [%d]\n", callid);

	call_data.callid = callid;

	error = __bt_telephony_event_cb(BLUETOOTH_EVENT_AG_RELEASE,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&call_data);

	if (error != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_APPLICATION,
				"Application error");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("bluetooth_telephony_method_release-\n");
	return TRUE;

}

static gboolean bluetooth_telephony_method_reject(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };
	GError *err;
	int error;

	DBG("bluetooth_telephony_method_reject +\n");
	DBG("call_id = [%d]\n", callid);

	call_data.callid = callid;

	error = __bt_telephony_event_cb(BLUETOOTH_EVENT_AG_REJECT,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void  *)&call_data);

	if (error != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_APPLICATION,
				"Application error");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("bluetooth_telephony_method_reject-\n");
	return TRUE;
}

static gboolean bluetooth_telephony_method_threeway(
				BluetoothTelephonyMethod *object,
				guint value, DBusGMethodInvocation *context)
{
	int event = 0;
	GError *err;
	int error;

	DBG("bluetooth_telephony_method_threeway \n");
	DBG("chld value  = [%d]\n", value);

	if (value >= 0) {
		switch (value) {
		case 0:
			event = BLUETOOTH_EVENT_AG_CALL_HOLD_RELEASE_ALL;
			break;
		case 1:
			event = BLUETOOTH_EVENT_AG_CALL_HOLD_RELEASE_ACTIVE;
			break;
		case 2:
			event = BLUETOOTH_EVENT_AG_CALL_HOLD_HOLD_ACTIVE;
			break;
		case 3:
			event = BLUETOOTH_EVENT_AG_CALL_HOLD_ADD_NEW;
			break;
		case 4:
			event = BLUETOOTH_EVENT_AG_CALL_HOLD_TRANSFER;
			break;
		default:
			DBG("Invalid CHLD command\n");
			err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_INVALID_CHLD_INDEX,
				"Invalid chld command");
			dbus_g_method_return_error(context, err);
			g_error_free(err);
			return FALSE;
		}

		DBG("event  = [%d]\n", event);

		error = __bt_telephony_event_cb(event,
				BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);

		if (error != BLUETOOTH_TELEPHONY_ERROR_NONE) {
			err = __bluetooth_telephony_error(
					BLUETOOTH_TELEPHONY_ERROR_APPLICATION,
					"Application error");
			dbus_g_method_return_error(context, err);
			g_error_free(err);
			return FALSE;
		}
	} else {
		err = __bluetooth_telephony_error(
			BLUETOOTH_TELEPHONY_ERROR_INVALID_CHLD_INDEX,
			"Invalid chld command");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("bluetooth_telephony_method_threeway -\n");
	return TRUE;
}

static gboolean bluetooth_telephony_method_send_dtmf(
				BluetoothTelephonyMethod *object,
				gchar *dtmf, DBusGMethodInvocation *context)
{
	telephony_event_dtmf_t call_data = { 0, };
	GError *err;
	int error;

	DBG("bluetooth_ag_method_send_dtmf +\n");

	if (dtmf == NULL) {
		DBG("Number dial failed\n");
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_INVALID_DTMF,
				"Invalid dtmf");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	DBG("Dtmf = %s \n", dtmf);

	call_data.dtmf = g_strdup(dtmf);

	error = __bt_telephony_event_cb(BLUETOOTH_EVENT_AG_DTMF,
		BLUETOOTH_TELEPHONY_ERROR_NONE, (void *)&call_data);

	if (error != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("Number dial failed\n");
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_APPLICATION,
				"Application error");
		dbus_g_method_return_error(context, err);
		g_free(call_data.dtmf);
		g_error_free(err);
		return FALSE;
	}

	dbus_g_method_return(context);
	g_free(call_data.dtmf);
	DBG("bluetooth_ag_method_send_dtmf -\n");
	return TRUE;
}

static DBusHandlerResult __bluetooth_telephony_event_filter(
						DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	char *dev_addr = NULL;
	DBusMessageIter item_iter;
	DBusMessageIter value_iter;
	const char *property;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init(msg, &item_iter);
	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	DBG("Property (%s)\n", property);

	if (g_strcmp0(property, "State") == 0) {
		char *state = NULL;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &state);
		if (NULL == state) {
			DBG("State is null\n");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		DBG("State %s\n", state);

		if (g_strcmp0(state, "connected") == 0)
			telephony_info.headset_state = BLUETOOTH_STATE_CONNECTED;
		else if (g_strcmp0(state, "playing") == 0)
			telephony_info.headset_state = BLUETOOTH_STATE_PLAYING;
		else if (g_strcmp0(state, "disconnected") == 0)
			telephony_info.headset_state = BLUETOOTH_STATE_DISCONNETED;

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (g_strcmp0(property, "Connected") == 0) {
		gboolean connected = FALSE;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &connected);
		DBG("Connected %d\n", connected);

		if (connected) {
			/*Get device address*/
			if (path != NULL)
				dev_addr = strstr(path, "dev_");

			if (dev_addr != NULL) {
				dev_addr += 4;
				g_strlcpy(telephony_info.address,
					dev_addr,
					sizeof(telephony_info.address));
				g_strdelimit(telephony_info.address, "_", ':');
				DBG("address is %s \n",
					telephony_info.address);

				telephony_info.headset_state =
						BLUETOOTH_STATE_CONNECTED;

				if (telephony_dbus_info.proxy == NULL)
					telephony_dbus_info.proxy =
							__bluetooth_telephony_get_connected_device_proxy();

				DBG("Headset Connected\n");
			}
		} else { /*Device disconnected*/
			memset(telephony_info.address, 0x00,
					sizeof(telephony_info.address));
			telephony_info.headset_state =
						BLUETOOTH_STATE_DISCONNETED;

			if (telephony_dbus_info.proxy != NULL) {
				g_object_unref(telephony_dbus_info.proxy);
				telephony_dbus_info.proxy = NULL;
			}
			DBG("Headset Disconnected\n");
		}
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (g_strcmp0(property, "Playing") == 0) {
		gboolean audio_sink_playing = FALSE;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &audio_sink_playing);

		if (audio_sink_playing) {
			if (!vconf_set_bool(VCONFKEY_BT_HEADSET_SCO, TRUE)) {
				DBG("SVCONFKEY_BT_HEADSET_SCO -"
					"Set to TRUE\n");
			} else {
				DBG("vconf_set_bool - Failed\n");
			}
			telephony_info.headset_state = BLUETOOTH_STATE_PLAYING;
			 __bt_telephony_event_cb(
				BLUETOOTH_EVENT_AUDIO_CONNECTED,
				BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
		} else {
			if (!vconf_set_bool(VCONFKEY_BT_HEADSET_SCO, FALSE)) {
				DBG("SVCONFKEY_BT_HEADSET_SCO -"
						"Set to FALSE\n");
			} else {
				DBG("vconf_set_bool - Failed\n");
			}
			telephony_info.headset_state =
						BLUETOOTH_STATE_CONNECTED;
			__bt_telephony_event_cb(
				BLUETOOTH_EVENT_AUDIO_DISCONNECTED,
				BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __bluetooth_telephony_name_owner_changed(DBusGProxy *dbus_proxy,
					const char *name, const char *prev,
					const char *new, gpointer user_data)
{
	DBG("Name str = %s \n", name);

	if (g_strcmp0(name, BLUEZ_SERVICE_NAME) == 0 && *new == '\0') {
		DBG("BlueZ is terminated and flag need to be reset");
		is_active = FALSE;
		DBG("Send disabled to application\n");
		__bt_telephony_event_cb(BLUETOOTH_EVENT_BT_DISABLED,
			BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
	}

}

static void __bluetooth_telephony_adapter_added_cb(DBusGProxy *manager_proxy,
				const char *adapter_path, gpointer user_data)
{
	DBG("Adapter added [%s] \n", adapter_path);

	if (strstr(adapter_path, "hci0")) {
		DBG("BlueZ is Activated and flag need to be reset");
		is_active = TRUE;
		DBG("Send enabled to application\n");
		__bt_telephony_event_cb(BLUETOOTH_EVENT_BT_ENABLED,
			BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
	}
}

static int __bluetooth_telephony_proxy_init(void)
{
	DBG("__bluetooth_audio_proxy_init +\n");

	telephony_dbus_info.dbus_proxy = dbus_g_proxy_new_for_name(
			telephony_dbus_info.conn, DBUS_SERVICE_DBUS,
			DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (NULL == telephony_dbus_info.dbus_proxy)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	/*Add Signal callback for BT disabled*/
	dbus_g_proxy_add_signal(telephony_dbus_info.dbus_proxy,
					"NameOwnerChanged",
					G_TYPE_STRING, G_TYPE_STRING,
					G_TYPE_STRING, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(telephony_dbus_info.dbus_proxy,
					"NameOwnerChanged",
					G_CALLBACK(__bluetooth_telephony_name_owner_changed),
					NULL, NULL);

	/*Add Signal callback for BT enabled*/

	dbus_g_proxy_add_signal(telephony_dbus_info.manager_proxy,
				"AdapterAdded",
				DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(telephony_dbus_info.manager_proxy,
			"AdapterAdded",
			G_CALLBACK(__bluetooth_telephony_adapter_added_cb),
			NULL, NULL);

	object = (GObject *)__bluetooth_telephony_method_new();

	if (NULL == object) {
		g_object_unref(telephony_dbus_info.dbus_proxy);
		telephony_dbus_info.dbus_proxy = NULL;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	DBG("telephony_object = %d\n", object);

	dbus_g_connection_register_g_object(telephony_dbus_info.conn,
			telephony_info.call_path, G_OBJECT(object));

	DBG("__bluetooth_audio_proxy_init -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static void __bluetooth_telephony_proxy_deinit(void)
{
	DBG("__bluetooth_telephony_proxy_deinit +\n");


	/*Remove BT disabled signal*/
	dbus_g_proxy_disconnect_signal(telephony_dbus_info.dbus_proxy ,
		"NameOwnerChanged",
		G_CALLBACK(__bluetooth_telephony_name_owner_changed),
		NULL);

	g_object_unref(telephony_dbus_info.dbus_proxy);

	/*Remove BT enabled signal*/
	dbus_g_proxy_disconnect_signal(
		telephony_dbus_info.manager_proxy,
		"AdapterAdded",
		G_CALLBACK(__bluetooth_telephony_adapter_added_cb),
		NULL);

	dbus_g_connection_unregister_g_object(telephony_dbus_info.conn,
				G_OBJECT(object));

	g_object_unref(object);
	object = NULL;

	g_object_unref(telephony_dbus_info.proxy);
	telephony_dbus_info.proxy = NULL;

	DBG("__bluetooth_telephony_proxy_deinit -\n");
	return;
}

static int __bluetooth_telephony_register(bt_telephony_func_ptr cb,
							void  *user_data)
{
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	DBG("bluetooth_telephony_register +\n");

	telephony_info.cb = cb;
	telephony_info.user_data = user_data;

	ret =  __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"RegisterApplication", DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	g_free(path);
	DBG("bluetooth_telephony_register -\n");
	return ret;
}

static  int __bluetooth_telephony_unregister(void)
{
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	DBG("bluetooth_telephony_unregister +\n");

	telephony_info.cb = NULL;
	telephony_info.user_data = NULL;
	telephony_info.call_count = 0;

	ret = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"UnregisterApplication", DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	g_free(path);
	DBG("bluetooth_telephony_unregister +\n");
	return ret;
}

static int __bluetooth_get_default_adapter_path(DBusGConnection *GConn,
							char *path)
{
	GError *err = NULL;
	char *adapter_path = NULL;

	DBG("__bluetooth_get_default_adapter_path + \n");


	if (!dbus_g_proxy_call(telephony_dbus_info.manager_proxy,
				"DefaultAdapter", &err, G_TYPE_INVALID,
				DBUS_TYPE_G_OBJECT_PATH, &adapter_path,
				G_TYPE_INVALID)) {
		if (err != NULL) {
			DBG("Getting DefaultAdapter failed: [%s]\n",
							err->message);
			g_error_free(err);
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	if (adapter_path == NULL) {
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	if (strlen(adapter_path) >= BT_ADAPTER_PATH_LEN) {
		DBG("Path too long.\n");
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	DBG("path = %s\n", adapter_path);
	g_strlcpy(path, adapter_path, BT_ADAPTER_PATH_LEN);
	DBG("__bluetooth_get_default_adapter_path -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static gboolean __bluetooth_telephony_is_headset(uint32_t device_class)
{
	gboolean flag = FALSE;
	DBG("__bluetooth_telephony_is_headset + \n");

	switch ((device_class & 0x1f00) >> 8) {
	case 0x04:
		switch ((device_class & 0xfc) >> 2) {
		case 0x01:
		case 0x02:
			flag = TRUE;
			break;
		case 0x06:
			flag = TRUE;
			break;
		case 0x0b:
		case 0x0c:
		case 0x0d:
			break;
		default:
			flag = TRUE;
			break;
		}
		break;
	}
	DBG("__bluetooth_telephony_is_headset -\n");
	return flag;
}

static int __bluetooth_telephony_get_connected_device(void)
{
	DBusGProxy *list_proxy = NULL;
	DBusGProxy *device_proxy = NULL;
	GPtrArray *gp_array = NULL;
	GError *error = NULL;
	gchar *gp_path = NULL;
	GHashTable *list_hash = NULL;
	GHashTable *device_hash = NULL;
	GValue *value = {0};
	uint32_t device_class;
	gboolean playing = FALSE;
	gboolean connected = FALSE;
	const gchar *address;
	char object_path[BT_ADAPTER_PATH_LEN] = {0};
	int i = 0;
	DBusGProxy *proxy = NULL;

	DBG("__bluetooth_telephony_get_connected_device +\n");

	/*Get default adapter path*/
	if (__bluetooth_get_default_adapter_path(telephony_dbus_info.conn,
			object_path) < 0)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	/*Get List of All devices*/
	list_proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
						BLUEZ_SERVICE_NAME, object_path,
						BLUEZ_ADAPTER_INTERFACE);

	if (list_proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	dbus_g_proxy_call(list_proxy, "ListDevices", &error, G_TYPE_INVALID,
				dbus_g_type_get_collection("GPtrArray",
				DBUS_TYPE_G_OBJECT_PATH),
				&gp_array, G_TYPE_INVALID);

	if (error != NULL) {
		g_error_free(error);
		goto done;
	}

	if (gp_array == NULL)
		goto done;

	/*Check for headset devices*/
	for (i = 0; i < gp_array->len; i++) {
		gp_path = g_ptr_array_index(gp_array, i);

		if (gp_path == NULL)
			goto done;

		proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
						BLUEZ_SERVICE_NAME, gp_path,
						BLUEZ_DEVICE_INTERFACE);

		if (proxy == NULL)
			goto done;

		dbus_g_proxy_call(proxy, "GetProperties", NULL,
				G_TYPE_INVALID, dbus_g_type_get_map(
				"GHashTable", G_TYPE_STRING,
				G_TYPE_VALUE), &list_hash, G_TYPE_INVALID);

		if (list_hash == NULL)
			goto done;

		value = g_hash_table_lookup(list_hash, "Class");
		device_class = value ? g_value_get_uint(value) : 0;

		if (!__bluetooth_telephony_is_headset(device_class)) {
			g_object_unref(proxy);
			proxy = NULL;
			g_free(gp_path);
			gp_path = NULL;
			continue;
		}

		/*Check for Connection*/
		device_proxy = dbus_g_proxy_new_for_name(
				telephony_dbus_info.conn,
				BLUEZ_SERVICE_NAME, gp_path,
				BLUEZ_HEADSET_INTERFACE);

		if (device_proxy == NULL)
			goto done;

		dbus_g_proxy_call(device_proxy, "GetProperties",
				&error, G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable",
				G_TYPE_STRING, G_TYPE_VALUE),
				&device_hash, G_TYPE_INVALID);

		if (error == NULL) {
			value = g_hash_table_lookup(device_hash,
					"Connected");
			connected = value ? g_value_get_boolean(
					value) : FALSE;
			if (connected) {
				value = g_hash_table_lookup(list_hash,
								"Address");
				address = value ? g_value_get_string(
							value) : NULL;
				g_strlcpy(telephony_info.address, address,
						sizeof(telephony_info.address));
				value = g_hash_table_lookup(device_hash,
								"Playing");
				playing = value ? g_value_get_boolean(
							value) : FALSE;
				if (playing)
					telephony_info.headset_state =
						BLUETOOTH_STATE_PLAYING;
				else
					telephony_info.headset_state =
						BLUETOOTH_STATE_CONNECTED;

				goto done;
			}
		} else
			g_error_free(error);

		g_object_unref(proxy);
		proxy = NULL;
		g_free(gp_path);
		gp_path = NULL;
	}
done:
	if (list_proxy)
		g_object_unref(list_proxy);
	if (device_proxy)
		g_object_unref(device_proxy);
	if (proxy)
		g_object_unref(proxy);
	g_free(gp_path);
	g_ptr_array_free(gp_array, TRUE);
	DBG("__bluetooth_telephony_get_connected_device -\n");
	return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
}

static DBusGProxy *__bluetooth_telephony_get_connected_device_proxy(void)
{
	DBusGProxy *proxy = NULL;
	char object_path[BT_ADAPTER_PATH_LEN] = {0};
	GError *error = NULL;
	DBusGProxy *default_proxy;

	DBG("__bluetooth_telephony_get_connected_device_proxy + \n");

	/*Get default adapter path*/
	if (__bluetooth_get_default_adapter_path(telephony_dbus_info.conn,
			object_path) < 0)
		return NULL;

	/*Get List of All devices*/
	default_proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
						BLUEZ_SERVICE_NAME, object_path,
						BLUEZ_ADAPTER_INTERFACE);

	if (default_proxy == NULL)
		return NULL;

	if (strlen(telephony_info.address) == 0)
		__bluetooth_telephony_get_connected_device();

	if (strlen(telephony_info.address) == 0) {
		g_object_unref(default_proxy);
		return NULL;
	}

	if (NULL == telephony_info.obj_path) {
		dbus_g_proxy_call(default_proxy, "FindDevice", &error,
				G_TYPE_STRING, telephony_info.address,
				G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH,
				&telephony_info.obj_path,
				G_TYPE_INVALID);
		if (error != NULL) {
			DBG("dbus_g_proxy_call Failed!\n");
			g_error_free(error);
			g_object_unref(default_proxy);
			return NULL;
		}
	}

	proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
			BLUEZ_SERVICE_NAME, telephony_info.obj_path,
			BLUEZ_HEADSET_INTERFACE);

	g_object_unref(default_proxy);

	return proxy;
}

BT_EXPORT_API int bluetooth_telephony_init(bt_telephony_func_ptr cb,
							void  *user_data)
{
	DBusError dbus_error;
	DBusConnection *conn;
	int ret;
	GError *error = NULL;
	char object_path[BT_ADAPTER_PATH_LEN] = {0};
	DBG("bluetooth_telephony_init +\n");

	if (NULL == cb)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	if (telephony_dbus_info.conn != NULL) {
		DBG("Bluetooth telephony already initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_INITIALIZED;
	}

	telephony_dbus_info.conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!telephony_dbus_info.conn) {
		if (NULL != error) {
			DBG("dbus_g_bus_get() failed:[%d:%s]\n",
					error->code, error->message);
			g_error_free(error);
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	telephony_dbus_info.manager_proxy = dbus_g_proxy_new_for_name(
						telephony_dbus_info.conn,
						BLUEZ_SERVICE_NAME,
						"/", BLUEZ_MANAGER_INTERFACE);

	if (telephony_dbus_info.manager_proxy == NULL) {
		DBG("Could not create a manager proxy\n");
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}


	/*Check for BT status*/
	ret = __bluetooth_get_default_adapter_path(telephony_dbus_info.conn,
								object_path);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		g_object_unref(telephony_dbus_info.manager_proxy);
		telephony_dbus_info.manager_proxy = NULL;
		return BLUETOOTH_TELEPHONY_ERROR_NOT_ENABLED;
	}
	/*Bluetooth is active, therefore set the flag */
	is_active = TRUE;

	/* Call Path */
	snprintf(telephony_info.call_path, sizeof(telephony_info.call_path),
					CSD_CALL_APP_PATH, getpid());
	DBG("Call Path = %s \n", telephony_info.call_path);
	memset(telephony_info.address, 0x00, sizeof(telephony_info.address));

	if (__bluetooth_telephony_proxy_init()) {
		DBG("__bluetooth_telephony_proxy_init failed\n");
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		g_object_unref(telephony_dbus_info.manager_proxy);
		telephony_dbus_info.manager_proxy = NULL;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	ret = __bluetooth_telephony_register(cb, user_data);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("__bluetooth_telephony_register failed\n");
		__bluetooth_telephony_proxy_deinit();
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		g_object_unref(telephony_dbus_info.manager_proxy);
		telephony_dbus_info.manager_proxy = NULL;
		return ret;
	}

	dbus_error_init(&dbus_error);
	conn = dbus_g_connection_get_connection(telephony_dbus_info.conn);
	dbus_connection_add_filter(conn, __bluetooth_telephony_event_filter,
				NULL, NULL);

	dbus_bus_add_match(conn,
			"type='signal',interface='" BLUEZ_HEADSET_INTERFACE
			"',member='PropertyChanged'", &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		DBG("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		__bluetooth_telephony_unregister();
		__bluetooth_telephony_proxy_deinit();
		dbus_connection_remove_filter(dbus_g_connection_get_connection(
				telephony_dbus_info.conn),
				__bluetooth_telephony_event_filter, NULL);
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		g_object_unref(telephony_dbus_info.manager_proxy);
		telephony_dbus_info.manager_proxy = NULL;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	DBG("bluetooth_telephony_init -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_deinit(void)
{
	DBG("bluetooth_telephony_deinit +\n");

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	dbus_connection_remove_filter(dbus_g_connection_get_connection(
				telephony_dbus_info.conn),
				__bluetooth_telephony_event_filter, NULL);

	__bluetooth_telephony_unregister();
	__bluetooth_telephony_proxy_deinit();

	g_object_unref(telephony_dbus_info.manager_proxy);
	telephony_dbus_info.manager_proxy = NULL;

	dbus_g_connection_unref(telephony_dbus_info.conn);
	telephony_dbus_info.conn = NULL;

	DBG("bluetooth_telephony_deinit -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API gboolean bluetooth_telephony_is_sco_connected(void)
{
	DBG("+ \n");

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return FALSE;
	}

	if (telephony_info.headset_state == BLUETOOTH_STATE_PLAYING)
		return TRUE;

	DBG("- \n");
	return FALSE;
}

BT_EXPORT_API int bluetooth_telephony_start_voice_recognition(void)
{
	GError *error = NULL;
	int ret;

	DBG("+\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "SetVoiceDial",
			&error, G_TYPE_BOOLEAN, TRUE, G_TYPE_INVALID,
			G_TYPE_INVALID)) {
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}

	DBG("-\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_stop_voice_recognition(void)
{
	GError *error = NULL;
	int ret;

	DBG("+\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "SetVoiceDial",
				&error, G_TYPE_BOOLEAN,
				FALSE, G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Dbus Call Failed!\n");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}

	DBG("-\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_audio_open(void)
{
	GError *error = NULL;
	int ret;

	DBG("bluetooth_telephony_audio_open +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (telephony_info.headset_state == BLUETOOTH_STATE_PLAYING)
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_CONNECTED;

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "Play", &error,
					G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Dbus Call Failed!\n");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}
	DBG("bluetooth_telephony_audio_open -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_audio_close(void)
{
	GError *error = NULL;
	int ret;

	DBG("bluetooth_telephony_audio_close +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (telephony_info.headset_state != BLUETOOTH_STATE_PLAYING) {
		return BLUETOOTH_TELEPHONY_ERROR_NOT_CONNECTED;
	}

	if (NULL == telephony_dbus_info.proxy)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "Stop", &error,
			G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Dbus Call Failed!\n");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}

	DBG("bluetooth_telephony_audio_close -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_call_remote_ringing(unsigned int call_id)
{
	int ret;

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	DBG("bluetooth_telephony_call_remote_ringing +\n");
	/*Make sure SCO is already connected */
	ret = __bluetooth_telephony_send_call_status(
				CSD_CALL_STATUS_MO_ALERTING, call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("send call status Failed = [%d]\n", ret);
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}
	DBG("bluetooth_telephony_call_remote_ringing -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_call_answered(unsigned int call_id,
							unsigned int bt_audio)
{
	int ret;
	DBG("bluetooth_telephony_call_answered +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_ACTIVE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("send call status Failed = [%d]\n", ret);
		return ret;
	}

	if (bt_audio) {
		if (!bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_open();
			if (ret != 0) {
				DBG(" Audio connection call Failed = %d\n", ret);
				return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
			}
		}
	}

	DBG("bluetooth_telephony_call_answered -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_end(unsigned int call_id)
{
	int ret;
	DBG("bluetooth_telephony_call_end +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_MT_RELEASE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("send call status Failed = [%d]\n", ret);
		return ret;
	}
	if (telephony_info.call_count > 0)
		telephony_info.call_count = telephony_info.call_count - 1;

	if (telephony_info.call_count  == 0) {
		if (bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_close();
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				DBG(" Failed = [%d]\n", ret);
				return ret;
			}
		}
	}
	DBG("bluetooth_telephony_call_end -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_held(unsigned int call_id)
{
	int ret;
	DBG("bluetooth_telephony_call_held +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_HOLD,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("send call status Failed = [%d]\n", ret);
	}
	DBG("bluetooth_telephony_call_held -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_retrieved(unsigned int call_id)
{
	int ret;
	DBG("bluetooth_telephony_call_retrieved +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_ACTIVE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("send call status Failed = [%d]\n", ret);
	}
	DBG("bluetooth_telephony_call_retrieved -\n");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_swapped(void *call_list,
				unsigned int call_count)
{
	int i;
	int ret;
	GList *list = call_list;
	bt_telephony_call_status_info_t *call_status;

	DBG("bluetooth_telephony_call_swapped +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (NULL == list) {
		DBG("call_list is invalid \n");
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;
	}

	DBG(" call_count = [%d] \n", call_count);

	for (i = 0; i < call_count; i++) {
		call_status = g_list_nth_data(list, i);

		if (NULL == call_status)
			continue;

		DBG(" %d : Call id [%d] status[%d]\n", i,
					call_status->call_id,
					call_status->call_status);

		switch (call_status->call_status) {
		case BLUETOOTH_CALL_STATE_HELD:
			ret = __bluetooth_telephony_send_call_status(
						CSD_CALL_STATUS_HOLD,
						call_status->call_id);
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				DBG("Failed = %d\n", ret);
				return ret;
			}
		break;

		case BLUETOOTH_CALL_STATE_CONNECTED:
			ret = __bluetooth_telephony_send_call_status(
					CSD_CALL_STATUS_ACTIVE,
					call_status->call_id);
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				DBG("Failed = [%d]\n", ret);
				return ret;
			}
		break;

		default:
			DBG(" Unknown Call state\n");
			return BLUETOOTH_TELEPHONY_ERROR_NOT_AVAILABLE;
		}
	}

	DBG("bluetooth_telephony_call_swapped -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_set_call_status(void *call_list,
				unsigned int call_count)
{
	int ret;

	DBG("bluetooth_telephony_set_call_status +\n");

	ret = bluetooth_telephony_call_swapped(call_list, call_count);

	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		DBG("bluetooth_telephony_call_swapped Failed = [%d]\n", ret);
		return ret;
	}

	telephony_info.call_count = call_count;

	DBG("bluetooth_telephony_set_call_status -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_indicate_outgoing_call(
			const char *ph_number, unsigned int call_id,
			unsigned int bt_audio)
{
	const char *path = telephony_info.call_path;
	int ret;

	DBG("bluetooth_telephony_indicate_outgoing_call +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (NULL == ph_number)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	ret = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"OutgoingCall", DBUS_TYPE_STRING, &path,
			DBUS_TYPE_STRING, &ph_number, DBUS_TYPE_INT32,
			&call_id, DBUS_TYPE_INVALID);

	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE)
		return ret;


	telephony_info.call_count++;
	DBG(" ag_info.ag_call_count = [%d]\n", telephony_info.call_count);

	if (bt_audio) {
		if (!bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_open();
			if (ret != 0) {
				DBG(" Audio connection call Failed = %d\n", ret);
				return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
			}
		}
	}

	DBG("bluetooth_telephony_indicate_outgoing_call -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_indicate_incoming_call(
		const char *ph_number, unsigned int call_id)
{
	const char *path = telephony_info.call_path;
	int ret;

	DBG("bluetooth_telephony_indicate_incoming_call +\n");

	BT_TELEPHONY_CHECK_BT_STATUS();

	if (telephony_dbus_info.conn == NULL) {
		DBG("Bluetooth telephony not initilized \n");
		return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED;
	}

	if (NULL == ph_number)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	ret = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"IncomingCall", DBUS_TYPE_STRING, &path,
			DBUS_TYPE_STRING, &ph_number, DBUS_TYPE_INT32,
			&call_id, DBUS_TYPE_INVALID);

	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE)
		return ret;

	telephony_info.call_count++;
	DBG(" telephony_info.call_count = [%d]\n", telephony_info.call_count);
	DBG("bluetooth_telephony_indicate_incoming_call -\n");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

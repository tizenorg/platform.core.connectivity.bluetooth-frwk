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
#include <string.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-bindings.h>
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "bt-common.h"
#include "bluetooth-telephony-api.h"
#include "marshal.h"

typedef struct {
	DBusGConnection *conn;
	DBusGProxy *proxy;
	DBusGProxy *dbus_proxy;
	DBusGProxy *manager_proxy;
} telephony_dbus_info_t;

typedef struct {
	bt_telephony_func_ptr cb;
	unsigned int call_count;
	char *obj_path;
	char address[BT_ADDRESS_STR_LEN];
	char call_path[BT_AUDIO_CALL_PATH_LEN];
	bluetooth_headset_state_t headset_state;
	void *user_data;
} bt_telephony_info_t;

#define BLUETOOTH_TELEPHONY_ERROR (__bluetooth_telephony_error_quark())
#define BLUEZ_SERVICE_NAME "org.bluez"
#define BLUEZ_MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"
#define BLUEZ_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define BLUEZ_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BLUEZ_DEVICE_INTERFACE "org.bluez.Device1"

#define HFP_AGENT_SERVICE "org.bluez.hfp_agent"
#define HFP_AGENT_PATH "/org/bluez/hfp_ag"
#define HFP_AGENT_INTERFACE "Org.Hfp.App.Interface"

#define CSD_CALL_APP_PATH "/org/tizen/csd/%d"
#define HFP_NREC_STATUS_CHANGE "NrecStatusChanged"

#define BT_TELEPHONY_CHECK_ENABLED() \
	do { \
		if (bluetooth_check_adapter() == BLUETOOTH_ADAPTER_DISABLED) \
		{ \
			BT_ERR("BT is not enabled"); \
			return BLUETOOTH_TELEPHONY_ERROR_NOT_ENABLED; \
		} \
	} while (0)

static gboolean is_initialized = FALSE;
#define BT_TELEPHONY_CHECK_INITIALIZED() \
	do { \
		if (is_initialized == FALSE) \
		{ \
			BT_ERR("Bluetooth telephony not initilized"); \
			return BLUETOOTH_TELEPHONY_ERROR_NOT_INITIALIZED; \
		} \
	} while (0)

#define BLUETOOTH_TELEPHONY_METHOD (bluetooth_telephony_method_get_type())
#define BLUETOOTH_TELEPHONY_METHOD_GET_OBJECT(obj) \
		(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethod))

#define BLUETOOTH_TELEPHONY_METHOD_IS_OBJECT(obj) \
		(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		BLUETOOTH_TELEPHONY_METHOD))

#define BLUETOOTH_TELEPHONY_METHOD_CLASS(class) \
		(G_TYPE_CHECK_CLASS_CAST((class), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodClass))

#define BLUETOOTH_TELEPHONY_METHOD_GET_AGENT_CLASS(obj) \
		(G_TYPE_INSTANCE_GET_CLASS((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodClass))

#define BLUETOOTH_TELEPHONY_METHOD_IS_AGENT_CLASS(class) \
		(G_TYPE_CHECK_CLASS_TYPE((class), BLUETOOTH_TELEPHONY_METHOD))

#define BLUETOOTH_TELEPHONY_METHOD_AGENT_GET_PRIVATE(obj) \
		(G_TYPE_INSTANCE_GET_PRIVATE((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodPrivate))

typedef struct _BluetoothTelephonyMethod BluetoothTelephonyMethod;
typedef struct _BluetoothTelephonyMethodClass BluetoothTelephonyMethodClass;

struct _BluetoothTelephonyMethod {
	GObject parent;
};

struct _BluetoothTelephonyMethodClass {
	GObjectClass parent_class;
};

BluetoothTelephonyMethod *bluetooth_telephony_method_new(void);
GType bluetooth_telephony_method_get_type(void);

G_DEFINE_TYPE(BluetoothTelephonyMethod, bluetooth_telephony_method, G_TYPE_OBJECT)

static DBusHandlerResult __bt_telephony_adapter_filter(DBusConnection *conn,
           DBusMessage *msg, void *data);

static int __bt_telephony_get_object_path(DBusMessage *msg, char **path);

static char *__bt_extract_device_path(DBusMessageIter *msg_iter, char *address);

static char *_bt_get_device_object_path(char *address);

static void _bt_convert_device_path_to_address(const char *device_path,
						char *device_address);

static char *__bt_get_default_adapter_path(DBusMessageIter *msg_iter);

static gboolean bluetooth_telephony_method_answer(BluetoothTelephonyMethod *object,
				guint callid,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_release(
				BluetoothTelephonyMethod *object, guint callid,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_reject(BluetoothTelephonyMethod  *object,
				guint callid, DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_threeway(
				BluetoothTelephonyMethod *object, guint value,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_send_dtmf(
				BluetoothTelephonyMethod *object,
				gchar *dtmf, DBusGMethodInvocation *context);

#include "bt-telephony-glue.h"

static GObject *object;
static bt_telephony_info_t telephony_info;
static telephony_dbus_info_t telephony_dbus_info;
static gboolean is_active = FALSE;

/*Function Declaration*/
static int __bt_telephony_get_error(const char *error_message);
static void __bt_telephony_event_cb(int event, int result, void *param_data);
static GQuark __bluetooth_telephony_error_quark(void);
static DBusMessage* __bluetooth_telephony_dbus_method_send(const char *path,
			const char *interface, const char *method, DBusError *err,  int type, ...);
static int __bluetooth_telephony_send_call_status(
			bt_telephony_call_status_t call_status,
			unsigned int call_id);
static GError *__bluetooth_telephony_error(bluetooth_telephony_error_t error,
					const char *err_msg);

static DBusHandlerResult __bluetooth_telephony_event_filter(
						DBusConnection *conn,
						DBusMessage *msg, void *data);

static int __bluetooth_telephony_proxy_init(void);
static void __bluetooth_telephony_proxy_deinit(void);
static int __bluetooth_telephony_register(void);
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
		BT_DBG("Error message NULL\n");
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	BT_DBG("Error message = %s \n", error_message);
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

static void __bt_telephony_event_cb(int event, int result, void *param_data)
{
	telephony_event_param_t bt_event = { 0, };

	bt_event.event = event;
	bt_event.result = result;
	bt_event.param_data = param_data;

	ret_if(telephony_info.cb == NULL);
	telephony_info.cb(bt_event.event, &bt_event, telephony_info.user_data);
	return;
}

static GQuark __bluetooth_telephony_error_quark(void)
{
	static GQuark quark = 0;

	quark = g_quark_from_static_string("telephony");

	return quark;
}

static DBusMessage* __bluetooth_telephony_dbus_method_send(const char *path,
			const char *interface, const char *method, DBusError *err,  int type, ...)
{
	DBusMessage *msg;
	DBusMessage *reply;
	va_list args;

	BT_DBG("+");

	msg = dbus_message_new_method_call(HFP_AGENT_SERVICE,
			path, interface, method);
	if (!msg) {
		BT_ERR("Unable to allocate new D-Bus %s message \n", method);
		return NULL;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		return NULL;
	}

	va_end(args);

	dbus_error_init(err);

	reply = dbus_connection_send_with_reply_and_block(
		dbus_g_connection_get_connection(telephony_dbus_info.conn),
		msg, -1, err);

	dbus_message_unref(msg);

	BT_DBG("-");
	return reply;
}

static int __bluetooth_telephony_send_call_status(
			bt_telephony_call_status_t call_status,
			unsigned int call_id)
{
	DBusMessage *reply;
	DBusError err;
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	BT_DBG("+");

	reply = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"ChangeCallStatus", &err, DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INT32, &call_status,
			DBUS_TYPE_INT32, &call_id, DBUS_TYPE_INVALID);
	g_free(path);

	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			ret = __bt_telephony_get_error(err.message);
			dbus_error_free(&err);
			return ret;
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static GError *__bluetooth_telephony_error(bluetooth_telephony_error_t error,
					const char *err_msg)
{
	return g_error_new(BLUETOOTH_TELEPHONY_ERROR, error, err_msg, NULL);
}

static void bluetooth_telephony_method_init(BluetoothTelephonyMethod *object)
{
	BT_DBG("+");
	BT_DBG("agent %p\n", object);
	BT_DBG("-");
}

static void __bluetooth_telephony_method_finalize(
					BluetoothTelephonyMethod *object)
{
	BT_DBG("+");
	G_OBJECT_CLASS(bluetooth_telephony_method_parent_class)->finalize((
							GObject *)object);
	BT_DBG("-");
}

static BluetoothTelephonyMethod *__bluetooth_telephony_method_new(void)
{
	BluetoothTelephonyMethod *obj;

	BT_DBG("+");
	obj = g_object_new(BLUETOOTH_TELEPHONY_METHOD, NULL);
	BT_DBG("-");

	return obj;
}

static void bluetooth_telephony_method_class_init(
					BluetoothTelephonyMethodClass *klass)
{
	GObjectClass *object_class = NULL;
	BT_DBG("+");

	object_class = G_OBJECT_CLASS(klass);
	object_class->finalize = (void *)__bluetooth_telephony_method_finalize;

	/*Registration of the Framework methods */
	dbus_g_object_type_install_info(BLUETOOTH_TELEPHONY_METHOD,
			&dbus_glib_bluetooth_telephony_method_object_info);
	BT_DBG("-");
	return;
}

static gboolean bluetooth_telephony_method_answer(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };

	BT_DBG("+");
	BT_DBG("call_id = [%d]", callid);

	call_data.callid = callid;

	__bt_telephony_event_cb(BLUETOOTH_EVENT_TELEPHONY_ANSWER_CALL,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&call_data);

	dbus_g_method_return(context);
	BT_DBG("-");
	return TRUE;
}

static gboolean bluetooth_telephony_method_release(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };

	BT_DBG("+");
	BT_DBG("call_id = [%d]\n", callid);

	call_data.callid = callid;

	__bt_telephony_event_cb(BLUETOOTH_EVENT_TELEPHONY_RELEASE_CALL,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&call_data);

	dbus_g_method_return(context);
	BT_DBG("-");
	return TRUE;

}

static gboolean bluetooth_telephony_method_reject(
				BluetoothTelephonyMethod *object,
				guint callid, DBusGMethodInvocation *context)
{
	telephony_event_callid_t call_data = { 0, };

	BT_DBG("+");
	BT_DBG("call_id = [%d]", callid);

	call_data.callid = callid;

	__bt_telephony_event_cb(BLUETOOTH_EVENT_TELEPHONY_REJECT_CALL,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void  *)&call_data);

	dbus_g_method_return(context);
	BT_DBG("-");
	return TRUE;
}

static gboolean bluetooth_telephony_method_threeway(
				BluetoothTelephonyMethod *object,
				guint value, DBusGMethodInvocation *context)
{
	int event = 0;
	GError *err;

	BT_DBG("+");
	BT_DBG("chld value  = [%d]", value);

	switch (value) {
	case 0:
		event = BLUETOOTH_EVENT_TELEPHONY_CHLD_0_RELEASE_ALL_HELD_CALL;
		break;
	case 1:
		event = BLUETOOTH_EVENT_TELEPHONY_CHLD_1_RELEASE_ALL_ACTIVE_CALL;
		break;
	case 2:
		event = BLUETOOTH_EVENT_TELEPHONY_CHLD_2_ACTIVE_HELD_CALL;
		break;
	case 3:
		event = BLUETOOTH_EVENT_TELEPHONY_CHLD_3_MERGE_CALL;
		break;
	default:
		BT_ERR("Invalid CHLD command");
		err = __bluetooth_telephony_error(
			BLUETOOTH_TELEPHONY_ERROR_INVALID_CHLD_INDEX,
			"Invalid chld command");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	BT_DBG("event  = [%d]", event);

	__bt_telephony_event_cb(event,
			BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
	dbus_g_method_return(context);
	BT_DBG("-");
	return TRUE;
}

static gboolean bluetooth_telephony_method_send_dtmf(
				BluetoothTelephonyMethod *object,
				gchar *dtmf, DBusGMethodInvocation *context)
{
	telephony_event_dtmf_t call_data = { 0, };
	GError *err;

	BT_DBG("+");

	if (dtmf == NULL) {
		BT_DBG("Number dial failed\n");
		err = __bluetooth_telephony_error(
				BLUETOOTH_TELEPHONY_ERROR_INVALID_DTMF,
				"Invalid dtmf");
		dbus_g_method_return_error(context, err);
		g_error_free(err);
		return FALSE;
	}

	BT_DBG("Dtmf = %s \n", dtmf);

	call_data.dtmf = g_strdup(dtmf);

	__bt_telephony_event_cb(BLUETOOTH_EVENT_TELEPHONY_SEND_DTMF,
		BLUETOOTH_TELEPHONY_ERROR_NONE, (void *)&call_data);

	dbus_g_method_return(context);
	g_free(call_data.dtmf);
	BT_DBG("-");
	return TRUE;
}

static void __bluetooth_handle_nrec_status_change(DBusMessage *msg)
{
	gboolean status = FALSE;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_BOOLEAN, &status,
				DBUS_TYPE_INVALID)) {
		BT_DBG("Error Getting parameters\n");
		return;
	}
	BT_DBG("NREC status = %d\n", status);

	__bt_telephony_event_cb(BLUETOOTH_EVENT_TELEPHONY_NREC_CHANGED,
		BLUETOOTH_TELEPHONY_ERROR_NONE, (void *)&status);

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

	/* Check NREC status change Signal*/
	if (dbus_message_is_signal(msg, HFP_AGENT_SERVICE,
				HFP_NREC_STATUS_CHANGE)) {
		__bluetooth_handle_nrec_status_change(msg);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init(msg, &item_iter);
	if (dbus_message_iter_get_arg_type(&item_iter) != DBUS_TYPE_STRING) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_message_iter_get_basic(&item_iter, &property);

	if (property == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	BT_DBG("Property (%s)\n", property);

	if (g_strcmp0(property, "State") == 0) {
		char *state = NULL;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &state);
		if (NULL == state) {
			BT_ERR("State is null\n");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		BT_DBG("State %s\n", state);

		if (g_strcmp0(state, "connected") == 0) {
			telephony_info.headset_state = BLUETOOTH_STATE_CONNECTED;
		} else if (g_strcmp0(state, "playing") == 0) {
			telephony_info.headset_state = BLUETOOTH_STATE_PLAYING;
		} else if (g_strcmp0(state, "disconnected") == 0) {
			/* Headset state: playing -> disconnected */
			if (telephony_info.headset_state == BLUETOOTH_STATE_PLAYING) {
				if (!vconf_set_bool(VCONFKEY_BT_HEADSET_SCO, FALSE)) {
					BT_DBG("SVCONFKEY_BT_HEADSET_SCO - Set to FALSE\n");
				} else {
					 BT_DBG("vconf_set_bool - Failed\n");
				}

				__bt_telephony_event_cb(
					 BLUETOOTH_EVENT_TELEPHONY_AUDIO_DISCONNECTED,
					 BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
			}

			telephony_info.headset_state = BLUETOOTH_STATE_DISCONNETED;
		}

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (g_strcmp0(property, "Connected") == 0) {
		gboolean connected = FALSE;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &connected);
		BT_DBG("Connected %d\n", connected);

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
				BT_DBG("address is %s",
					telephony_info.address);

				telephony_info.headset_state =
						BLUETOOTH_STATE_CONNECTED;

				if (telephony_dbus_info.proxy != NULL) {
					g_object_unref(telephony_dbus_info.proxy);
					telephony_dbus_info.proxy = NULL;
				}

				telephony_dbus_info.proxy =
						__bluetooth_telephony_get_connected_device_proxy();

				BT_DBG("Headset Connected");

				 __bt_telephony_event_cb(
						BLUETOOTH_EVENT_TELEPHONY_HFP_CONNECTED,
						BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
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

			BT_DBG("Headset Disconnected");

			 __bt_telephony_event_cb(
					BLUETOOTH_EVENT_TELEPHONY_HFP_DISCONNECTED,
					BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (g_strcmp0(property, "SpeakerGain") == 0) {
		unsigned int spkr_gain;
		guint16 gain;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &gain);

		spkr_gain = (unsigned int)gain;
		BT_DBG("spk_gain[%d]\n", spkr_gain);

		__bt_telephony_event_cb(
					BLUETOOTH_EVENT_TELEPHONY_SET_SPEAKER_GAIN,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&spkr_gain);

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (g_strcmp0(property, "MicrophoneGain") == 0) {
		unsigned int mic_gain;
		guint16 gain;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &gain);

		mic_gain = (unsigned int)gain;
		BT_DBG("mic_gain[%d]\n", mic_gain);

		__bt_telephony_event_cb(
					BLUETOOTH_EVENT_TELEPHONY_SET_MIC_GAIN,
					BLUETOOTH_TELEPHONY_ERROR_NONE,
					(void *)&mic_gain);

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (g_strcmp0(property, "Playing") == 0) {
		gboolean audio_sink_playing = FALSE;
		dbus_message_iter_next(&item_iter);
		dbus_message_iter_recurse(&item_iter, &value_iter);
		dbus_message_iter_get_basic(&value_iter, &audio_sink_playing);

		if (audio_sink_playing) {
			if (!vconf_set_bool(VCONFKEY_BT_HEADSET_SCO, TRUE)) {
				BT_DBG("SVCONFKEY_BT_HEADSET_SCO -"
					"Set to TRUE\n");
			} else {
				BT_DBG("vconf_set_bool - Failed\n");
			}
			telephony_info.headset_state = BLUETOOTH_STATE_PLAYING;
			 __bt_telephony_event_cb(
				BLUETOOTH_EVENT_TELEPHONY_AUDIO_CONNECTED,
				BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
		} else {
			if (!vconf_set_bool(VCONFKEY_BT_HEADSET_SCO, FALSE)) {
				BT_DBG("SVCONFKEY_BT_HEADSET_SCO -"
						"Set to FALSE\n");
			} else {
				BT_DBG("vconf_set_bool - Failed\n");
			}
			telephony_info.headset_state =
						BLUETOOTH_STATE_CONNECTED;
			__bt_telephony_event_cb(
				BLUETOOTH_EVENT_TELEPHONY_AUDIO_DISCONNECTED,
				BLUETOOTH_TELEPHONY_ERROR_NONE, NULL);
		}

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int __bluetooth_telephony_proxy_init(void)
{
	BT_DBG("+");

	object = (GObject *)__bluetooth_telephony_method_new();

	if (NULL == object)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	BT_DBG("telephony_object = %x", object);

	dbus_g_connection_register_g_object(telephony_dbus_info.conn,
			telephony_info.call_path, G_OBJECT(object));

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static void __bluetooth_telephony_proxy_deinit(void)
{
	BT_DBG("+");

	dbus_g_connection_unregister_g_object(telephony_dbus_info.conn,
				G_OBJECT(object));

	g_object_unref(object);
	object = NULL;

	BT_DBG("-");
	return;
}

static int __bluetooth_telephony_register(void)
{
	DBusMessage *reply;
	DBusError err;
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	BT_DBG("+");

	reply =  __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"RegisterApplication", &err, DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			ret = __bt_telephony_get_error(err.message);
			BT_ERR("Error here %d\n", ret);
			dbus_error_free(&err);
			return ret;
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static  int __bluetooth_telephony_unregister(void)
{
	DBusMessage *reply;
	DBusError err;
	char *path = g_strdup(telephony_info.call_path);
	int ret;

	BT_DBG("+");

	reply = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"UnregisterApplication", &err, DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			ret = __bt_telephony_get_error(err.message);
			dbus_error_free(&err);
			return ret;
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);
	BT_DBG("+");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static int __bluetooth_get_default_adapter_path(DBusGConnection *GConn,
							char *path)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	char *adapter_path = NULL;

	BT_DBG("+");

	conn = dbus_g_connection_get_connection(telephony_dbus_info.conn);

	retv_if(conn == NULL, NULL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
			BT_MANAGER_INTERFACE,
			"GetManagedObjects");

	retv_if(msg == NULL, NULL);
	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
				conn, msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
        BT_ERR("Fail to iterate the reply");
        return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
				DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		adapter_path = __bt_get_default_adapter_path(&msg_iter);
		if (adapter_path != NULL) {
			BT_DBG("Found the adapter path");
			break;
		}
		dbus_message_iter_next(&value_iter);
	}

	if (adapter_path == NULL) {
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	if (strlen(adapter_path) >= BT_ADAPTER_PATH_LEN) {
		BT_ERR("Path too long.\n");
		g_free(adapter_path);
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	BT_DBG("object path = %s", adapter_path);
	g_strlcpy(path, adapter_path, BT_ADAPTER_PATH_LEN);
	g_free(adapter_path);
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static gboolean __bluetooth_telephony_is_headset(uint32_t device_class)
{
	gboolean flag = FALSE;
	BT_DBG("+");

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
	BT_DBG("-");
	return flag;
}

static int __bluetooth_telephony_get_connected_device(void)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	DBusGProxy *headset_agent_proxy = NULL;

	GError *error = NULL;
	uint32_t device_class;
	gboolean playing = FALSE;
	gboolean connected = FALSE;
	GHashTable *list_hash;
	GValue *value = {0};
	char *object_path = NULL;
	DBusGProxy *proxy = NULL;
	const gchar *address;

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, "/",
						BLUEZ_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
		BT_ERR("Fail to iterate the reply");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:	a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		/* Parse the signature:	oa{sa{sv}}} */
		retv_if(dbus_message_iter_get_arg_type(&msg_iter) !=
				DBUS_TYPE_OBJECT_PATH, NULL);

		dbus_message_iter_get_basic(&msg_iter, &object_path);


		if (object_path) {
			proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
					  BLUEZ_SERVICE_NAME, object_path,
                      BLUEZ_PROPERTIES_INTERFACE);

			if (proxy == NULL)
				goto done;

			dbus_g_proxy_call(proxy, "GetAll", &err,
						G_TYPE_STRING, BLUEZ_DEVICE_INTERFACE,
						G_TYPE_INVALID,
						dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
						G_TYPE_VALUE), &list_hash, G_TYPE_INVALID);

			if (list_hash != NULL) {
				value = g_hash_table_lookup(list_hash, "Class");
				device_class = value ? g_value_get_uint(value) : 0;
			}

			if (!__bluetooth_telephony_is_headset(device_class)) {
				g_object_unref(proxy);
				proxy = NULL;
				g_hash_table_destroy(list_hash);
				dbus_message_iter_next(&value_iter);
				continue;
			}
			/* this is headset; Check for Connection */
			headset_agent_proxy = dbus_g_proxy_new_for_name(
						telephony_dbus_info.conn,
						HFP_AGENT_SERVICE, object_path,
						HFP_AGENT_INTERFACE);

			if (headset_agent_proxy == NULL) {
				g_hash_table_destroy(list_hash);
				goto done;
			}

			dbus_g_proxy_call(headset_agent_proxy, "IsConnected",
					&error, G_TYPE_INVALID,
					&connected, G_TYPE_INVALID);

			if (error == NULL) {
				if (connected) {
					value = g_hash_table_lookup(list_hash,
									"Address");
					address = value ? g_value_get_string(
									 value) : NULL;

					g_strlcpy(telephony_info.address, address,
									sizeof(telephony_info.address));
					dbus_g_proxy_call(headset_agent_proxy, "IsPlaying",
									&error, G_TYPE_INVALID,
									&playing, G_TYPE_INVALID);

					if (playing)
						telephony_info.headset_state =
							BLUETOOTH_STATE_PLAYING;
					else
						telephony_info.headset_state =
							BLUETOOTH_STATE_CONNECTED;

					g_hash_table_destroy(list_hash);
					goto done;
				}
			} else {
				g_error_free(error);
			}

			g_hash_table_destroy(list_hash);
			g_object_unref(proxy);
			proxy = NULL;
		} /* end of if(object_path) */

	dbus_message_iter_next(&value_iter);
	} /* end of while */

done:
	if (proxy)
		g_object_unref(proxy);
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
}

static DBusGProxy *__bluetooth_telephony_get_connected_device_proxy(void)
{
	DBusGProxy *proxy = NULL;
	char *object_path = NULL;

	BT_DBG("+");

	if (strlen(telephony_info.address) == 0)
		__bluetooth_telephony_get_connected_device();

	if (strlen(telephony_info.address) == 0) {
		return NULL;
	}

	if (telephony_info.obj_path) {
		g_free(telephony_info.obj_path);
		telephony_info.obj_path = NULL;
	}

	object_path = _bt_get_device_object_path(telephony_info.address);
	g_strlcpy(telephony_info.obj_path, object_path, BT_ADAPTER_PATH_LEN);

	proxy = dbus_g_proxy_new_for_name(telephony_dbus_info.conn,
			HFP_AGENT_SERVICE, telephony_info.obj_path,
			HFP_AGENT_INTERFACE);

	return proxy;
}

BT_EXPORT_API int bluetooth_telephony_init(bt_telephony_func_ptr cb,
							void  *user_data)
{
	DBusError dbus_error;
	DBusConnection *conn;
	int ret = BLUETOOTH_TELEPHONY_ERROR_NONE;
	GError *error = NULL;
	char object_path[BT_ADAPTER_PATH_LEN] = {0};
	BT_DBG("+");
	DBusConnection *dbus_conn;

	g_type_init();

	if (is_initialized == TRUE) {
		BT_ERR("Bluetooth telephony already initilized");
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_INITIALIZED;
	}

	is_initialized = TRUE;

	telephony_dbus_info.conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!telephony_dbus_info.conn) {
		if (NULL != error) {
			BT_ERR("dbus_g_bus_get() failed:[%d:%s]\n",
					error->code, error->message);
			g_error_free(error);
		}
		is_initialized = FALSE;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	/* Call Path */
	snprintf(telephony_info.call_path, sizeof(telephony_info.call_path),
					CSD_CALL_APP_PATH, getpid());
	BT_DBG("Call Path = %s", telephony_info.call_path);
	memset(telephony_info.address, 0x00, sizeof(telephony_info.address));

	if (__bluetooth_telephony_proxy_init()) {
		BT_ERR("__bluetooth_telephony_proxy_init failed\n");
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		is_initialized = FALSE;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	telephony_dbus_info.manager_proxy = dbus_g_proxy_new_for_name(
						telephony_dbus_info.conn,
						BLUEZ_SERVICE_NAME,
						"/", BLUEZ_MANAGER_INTERFACE);

	if (telephony_dbus_info.manager_proxy == NULL) {
		BT_ERR("Could not create a manager proxy\n");
		__bluetooth_telephony_proxy_deinit();
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		is_initialized = FALSE;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	telephony_dbus_info.dbus_proxy = dbus_g_proxy_new_for_name(
			telephony_dbus_info.conn, DBUS_SERVICE_DBUS,
			DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);

	if (NULL == telephony_dbus_info.dbus_proxy) {
		__bluetooth_telephony_proxy_deinit();
		dbus_g_connection_unref(telephony_dbus_info.conn);
		telephony_dbus_info.conn = NULL;
		g_object_unref(telephony_dbus_info.manager_proxy);
		telephony_dbus_info.manager_proxy = NULL;
		is_initialized = FALSE;
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_conn = dbus_g_connection_get_connection(telephony_dbus_info.conn);

	/*Add Signal callback for BT enabled*/
	if (!dbus_connection_add_filter(dbus_conn, __bt_telephony_adapter_filter,
					NULL, NULL)) {
		BT_ERR("Fail to add filter");
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_error_init(&dbus_error);

	dbus_bus_add_match(dbus_conn,
			"type='signal',interface='org.freedesktop.DBus.ObjectManager'"
			",member='InterfacesAdded'",
			&dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add match: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		goto fail;
	}

	/*Callback and user applicaton data*/
	telephony_info.cb = cb;
	telephony_info.user_data = user_data;
	telephony_info.headset_state = BLUETOOTH_STATE_DISCONNETED;

	dbus_error_init(&dbus_error);
	conn = dbus_g_connection_get_connection(telephony_dbus_info.conn);
	dbus_connection_add_filter(conn, __bluetooth_telephony_event_filter,
				NULL, NULL);

	dbus_bus_add_match(conn,
			"type='signal',interface='"HFP_AGENT_SERVICE
			"',member='PropertyChanged'", &dbus_error);
	dbus_bus_add_match(conn,
			"type='signal',interface='"HFP_AGENT_SERVICE
			"',member='"HFP_NREC_STATUS_CHANGE"'" , &dbus_error);

	if (dbus_error_is_set(&dbus_error)) {
		BT_ERR("Fail to add dbus filter signal\n");
		dbus_error_free(&dbus_error);
		goto fail;
	}

	/*Check for BT status*/
	ret = __bluetooth_get_default_adapter_path(telephony_dbus_info.conn,
								object_path);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE)
		return BLUETOOTH_TELEPHONY_ERROR_NONE;

	/*Bluetooth is active, therefore set the flag */
	is_active = TRUE;

	ret = __bluetooth_telephony_register();
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("__bluetooth_telephony_register failed\n");
		goto fail;
	}

	BT_DBG("-");
	return ret;

fail:
	bluetooth_telephony_deinit();
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_deinit(void)
{
	DBusConnection *conn;
	DBusError error;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();

	is_initialized = FALSE;
	conn = dbus_g_connection_get_connection(telephony_dbus_info.conn);

	dbus_error_init(&error);

	dbus_bus_remove_match(conn,
			"type='signal',interface='"HFP_AGENT_SERVICE
			"',member='PropertyChanged'", &error);
	dbus_bus_remove_match(conn,
			"type='signal',interface='"HFP_AGENT_SERVICE
			"',member='"HFP_NREC_STATUS_CHANGE"'", &error);
	if (dbus_error_is_set(&error)) {
		BT_ERR("Fail to remove dbus filter signal\n");
		dbus_error_free(&error);
	}

	dbus_connection_remove_filter(conn, __bluetooth_telephony_event_filter,
         NULL);

	if (bluetooth_check_adapter() == BLUETOOTH_ADAPTER_ENABLED)
		__bluetooth_telephony_unregister();

	__bluetooth_telephony_proxy_deinit();

	telephony_info.cb = NULL;
	telephony_info.user_data = NULL;
	telephony_info.call_count = 0;
	telephony_info.headset_state = BLUETOOTH_STATE_DISCONNETED;

	/*Remove BT enabled signal*/
	dbus_bus_remove_match(conn,
			"type='signal',interface='org.freedesktop.DBus.ObjectManager'"
			",member='InterfacesAdded'",
			&error);
	if (dbus_error_is_set(&error)) {
		BT_ERR("Fail to remove dbus filter signal\n");
		dbus_error_free(&error);
	}

	dbus_connection_remove_filter(dbus_g_connection_get_connection(
				telephony_dbus_info.conn), __bt_telephony_adapter_filter,
		 NULL);

	g_object_unref(telephony_dbus_info.manager_proxy);
	telephony_dbus_info.manager_proxy = NULL;

	dbus_g_connection_unref(telephony_dbus_info.conn);
	telephony_dbus_info.conn = NULL;

	g_object_unref(telephony_dbus_info.dbus_proxy);
	telephony_dbus_info.dbus_proxy = NULL;

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API gboolean bluetooth_telephony_is_sco_connected(void)
{
	BT_DBG("+");

	if (telephony_dbus_info.conn == NULL) {
		BT_ERR("Bluetooth telephony not initilized");
		return FALSE;
	}

	/* To get the headset state */
	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return FALSE;

	if (telephony_info.headset_state == BLUETOOTH_STATE_PLAYING)
		return TRUE;

	BT_DBG("-");
	return FALSE;
}

BT_EXPORT_API int bluetooth_telephony_is_nrec_enabled(gboolean *status)
{
	DBusMessage* reply;
	DBusError err;
	DBusMessageIter reply_iter;
	DBusMessageIter reply_iter_entry;
	const char *property;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (status == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	reply = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"GetProperties", &err, DBUS_TYPE_INVALID);

	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			BT_DBG("Error message = %s \n", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_iter_init(reply, &reply_iter);

	if (dbus_message_iter_get_arg_type(&reply_iter) != DBUS_TYPE_ARRAY) {
		BT_ERR("Can't get reply arguments - DBUS_TYPE_ARRAY\n");
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(&reply_iter, &reply_iter_entry);

	/*Parse the dict */
	while (dbus_message_iter_get_arg_type(&reply_iter_entry) ==
						DBUS_TYPE_DICT_ENTRY) {

		DBusMessageIter dict_entry, dict_entry_val;
		dbus_message_iter_recurse(&reply_iter_entry, &dict_entry);
		dbus_message_iter_get_basic(&dict_entry, &property);
		BT_DBG("String received = %s\n", property);

		if (g_strcmp0("nrec", property) == 0) {
			dbus_message_iter_next(&dict_entry);
			dbus_message_iter_recurse(&dict_entry, &dict_entry_val);
			if (dbus_message_iter_get_arg_type(&dict_entry_val) !=
						DBUS_TYPE_BOOLEAN)
				continue;

			dbus_message_iter_get_basic(&dict_entry_val, status);
			BT_DBG("NREC status = [%d]", *status);
		}
		dbus_message_iter_next(&reply_iter_entry);
	}
	dbus_message_unref(reply);
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_start_voice_recognition(void)
{
	GError *error = NULL;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

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

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_stop_voice_recognition(void)
{
	GError *error = NULL;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "SetVoiceDial",
				&error, G_TYPE_BOOLEAN,
				FALSE, G_TYPE_INVALID, G_TYPE_INVALID)) {
		BT_ERR("Dbus Call Failed!\n");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_audio_open(void)
{
	GError *error = NULL;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (telephony_info.headset_state == BLUETOOTH_STATE_PLAYING)
		return BLUETOOTH_TELEPHONY_ERROR_ALREADY_CONNECTED;

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "Play", &error,
					G_TYPE_INVALID, G_TYPE_INVALID)) {
		BT_ERR("Dbus Call Failed!");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_audio_close(void)
{
	GError *error = NULL;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (telephony_info.headset_state != BLUETOOTH_STATE_PLAYING) {
		return BLUETOOTH_TELEPHONY_ERROR_NOT_CONNECTED;
	}

	if (!dbus_g_proxy_call(telephony_dbus_info.proxy, "Stop", &error,
			G_TYPE_INVALID, G_TYPE_INVALID)) {
		BT_ERR("Dbus Call Failed");
		if (error != NULL) {
			ret = __bt_telephony_get_error(error->message);
			g_error_free(error);
			return ret;
		}
	}

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_call_remote_ringing(unsigned int call_id)
{
	int ret;

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	BT_DBG("+");

	/*Make sure SCO is already connected */
	ret = __bluetooth_telephony_send_call_status(
				CSD_CALL_STATUS_MO_ALERTING, call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("send call status Failed = [%d]", ret);
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_call_answered(unsigned int call_id,
							unsigned int bt_audio)
{
	int ret;
	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_ACTIVE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("send call status Failed = [%d]", ret);
		return ret;
	}

	if (bt_audio) {
		if (!bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_open();
			if (ret != 0) {
				BT_ERR("Audio connection call Failed = %d", ret);
				return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
			}
		}
	}

	BT_DBG("-");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_end(unsigned int call_id)
{
	int ret;
	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_MT_RELEASE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("send call status Failed = [%d]", ret);
		return ret;
	}
	if (telephony_info.call_count > 0)
		telephony_info.call_count = telephony_info.call_count - 1;

	if (telephony_info.call_count  == 0) {
		if (bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_close();
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				BT_ERR(" Failed = [%d]", ret);
				return ret;
			}
		}
	}
	BT_DBG("-");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_held(unsigned int call_id)
{
	int ret;
	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_HOLD,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("send call status Failed = [%d]", ret);
	}
	BT_DBG("-");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_retrieved(unsigned int call_id)
{
	int ret;
	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	ret = __bluetooth_telephony_send_call_status(CSD_CALL_STATUS_ACTIVE,
								call_id);
	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("send call status Failed = [%d]", ret);
	}
	BT_DBG("-");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_call_swapped(void *call_list,
				unsigned int call_count)
{
	int i;
	int ret;
	GList *list = call_list;
	bt_telephony_call_status_info_t *call_status;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (NULL == list) {
		BT_ERR("call_list is invalid");
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;
	}

	BT_DBG(" call_count = [%d]", call_count);

	for (i = 0; i < call_count; i++) {
		call_status = g_list_nth_data(list, i);

		if (NULL == call_status)
			continue;

		BT_DBG(" %d : Call id [%d] status[%d]", i,
					call_status->call_id,
					call_status->call_status);

		switch (call_status->call_status) {
		case BLUETOOTH_CALL_STATE_HELD:
			ret = __bluetooth_telephony_send_call_status(
						CSD_CALL_STATUS_HOLD,
						call_status->call_id);
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				BT_ERR("Failed = %d", ret);
				return ret;
			}
		break;

		case BLUETOOTH_CALL_STATE_CONNECTED:
			ret = __bluetooth_telephony_send_call_status(
					CSD_CALL_STATUS_ACTIVE,
					call_status->call_id);
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				BT_ERR("Failed = [%d]", ret);
				return ret;
			}
		break;

		default:
			if ((call_status->call_status < BLUETOOTH_CALL_STATE_NONE) ||
				(call_status->call_status >= BLUETOOTH_CALL_STATE_ERROR)) {
				BT_ERR("Unknown Call state");
				return BLUETOOTH_TELEPHONY_ERROR_NOT_AVAILABLE;
			}
		}
	}

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_set_call_status(void *call_list,
				unsigned int call_count)
{
	int ret;

	BT_DBG("+");

	ret = bluetooth_telephony_call_swapped(call_list, call_count);

	if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
		BT_ERR("Failed = [%d]", ret);
		return ret;
	}

	telephony_info.call_count = call_count;

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_indicate_outgoing_call(
			const char *ph_number, unsigned int call_id,
			unsigned int bt_audio)
{
	DBusMessage *reply;
	DBusError err;
	const char *path = telephony_info.call_path;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (NULL == ph_number)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	reply = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"OutgoingCall", &err, DBUS_TYPE_STRING, &path,
			DBUS_TYPE_STRING, &ph_number, DBUS_TYPE_INT32,
			&call_id, DBUS_TYPE_INVALID);

	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			ret = __bt_telephony_get_error(err.message);
			dbus_error_free(&err);
			return ret;
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	telephony_info.call_count++;
	BT_DBG(" ag_info.ag_call_count = [%d]", telephony_info.call_count);

	if (bt_audio) {
		if (!bluetooth_telephony_is_sco_connected()) {
			ret = bluetooth_telephony_audio_open();
			if (ret != 0) {
				BT_ERR(" Audio connection call Failed = %d", ret);
				return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
			}
		}
	}

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_indicate_incoming_call(
		const char *ph_number, unsigned int call_id)
{
	DBusMessage *reply;
	DBusError err;
	const char *path = telephony_info.call_path;
	int ret;

	BT_DBG("+");

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (NULL == ph_number)
		return BLUETOOTH_TELEPHONY_ERROR_INVALID_PARAM;

	reply = __bluetooth_telephony_dbus_method_send(
			HFP_AGENT_PATH, HFP_AGENT_INTERFACE,
			"IncomingCall", &err, DBUS_TYPE_STRING, &path,
			DBUS_TYPE_STRING, &ph_number, DBUS_TYPE_INT32,
			&call_id, DBUS_TYPE_INVALID);

	if (!reply) {
		BT_ERR("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			ret = __bt_telephony_get_error(err.message);
			dbus_error_free(&err);
			return ret;
		}
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;
	}

	dbus_message_unref(reply);

	telephony_info.call_count++;
	BT_DBG("telephony_info.call_count = [%d]", telephony_info.call_count);
	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_telephony_set_speaker_gain(unsigned short speaker_gain)
{
	GError *error = NULL;
	int ret = BLUETOOTH_TELEPHONY_ERROR_NONE;
	DBusGProxy *headset_agent_proxy = NULL;
	BT_DBG("+");
	BT_DBG("set speaker_gain= [%d]", speaker_gain);

	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (telephony_info.obj_path == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(headset_agent_proxy, "SetSpeakerGain",
					&error, G_TYPE_UINT, speaker_gain, G_TYPE_INVALID,
					G_TYPE_INVALID)) {
			if (error != NULL) {
			BT_ERR("Calling SetSpeakerGain failed: [%s]",
							error->message);
			g_error_free(error);
		}
	}

	BT_DBG("-");
	return ret;
}

BT_EXPORT_API int bluetooth_telephony_get_headset_volume(unsigned int *speaker_gain)
{
	DBusGProxy *headset_agent_proxy = NULL;
	GError *error = NULL;

	BT_DBG("+");
	BT_TELEPHONY_CHECK_INITIALIZED();
	BT_TELEPHONY_CHECK_ENABLED();

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (telephony_info.obj_path == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (telephony_dbus_info.proxy == NULL)
		telephony_dbus_info.proxy =
			__bluetooth_telephony_get_connected_device_proxy();

	if (telephony_dbus_info.proxy == NULL)
		return BLUETOOTH_TELEPHONY_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(headset_agent_proxy, "GetSpeakerGain",
					&error, G_TYPE_INVALID, G_TYPE_UINT, &speaker_gain,
					G_TYPE_INVALID)) {
			if (error != NULL) {
			BT_ERR("Calling G`etSpeakerGain failed: [%s]",
							error->message);
			g_error_free(error);
		}
	}

	BT_DBG("-");
	return BLUETOOTH_TELEPHONY_ERROR_NONE;
}

static char *_bt_get_device_object_path(char *address)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;
	char *object_path = NULL;
	BT_DBG("+");

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, NULL);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME, BT_MANAGER_PATH,
						BLUEZ_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, NULL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
			BT_ERR("Fail to iterate the reply");
			return NULL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:	a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		object_path = __bt_extract_device_path(&msg_iter, address);
		if (object_path != NULL) {
			BT_DBG("Found the device path");
			break;
		}

		dbus_message_iter_next(&value_iter);
	}
	BT_DBG("-");
	return object_path;
}

static char *__bt_extract_device_path(DBusMessageIter *msg_iter, char *address)
{
	char *object_path = NULL;
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };
	BT_DBG("+");

	/* Parse the signature:	oa{sa{sv}}} */
	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
				DBUS_TYPE_OBJECT_PATH, NULL);

	dbus_message_iter_get_basic(msg_iter, &object_path);
	retv_if(object_path == NULL, NULL);

	_bt_convert_device_path_to_address(object_path, device_address);

	if (g_strcmp0(address, device_address) == 0) {
		return g_strdup(object_path);
	}
	BT_DBG("-");
	return NULL;
}

static DBusHandlerResult __bt_telephony_adapter_filter(DBusConnection *conn,
						 DBusMessage *msg, void *data)
{
	int ret;
	char *object_path = NULL;
	const char *member = dbus_message_get_member(msg);
	BT_DBG("+");

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (member == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcasecmp(member, "InterfacesAdded") == 0) {
		if (__bt_telephony_get_object_path(msg, &object_path)) {
			BT_ERR("Fail to get the path");
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		if (strcasecmp(object_path, "/org/bluez/hci0") == 0) {
			BT_DBG("Adapter added [%s] \n", object_path);
			BT_DBG("BlueZ is Activated and flag need to be reset");
			BT_DBG("Send enabled to application\n");

			ret = __bluetooth_telephony_register();
			if (ret != BLUETOOTH_TELEPHONY_ERROR_NONE) {
				BT_DBG("__bluetooth_telephony_register failed\n");
			}
		}
	}
	BT_DBG("-");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int __bt_telephony_get_object_path(DBusMessage *msg, char **path)
{
	DBusMessageIter item_iter;
	dbus_message_iter_init(msg, &item_iter);
	BT_DBG("+");

	if (dbus_message_iter_get_arg_type(&item_iter)
					!= DBUS_TYPE_OBJECT_PATH) {
		BT_ERR("This is bad format dbus\n");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_get_basic(&item_iter, path);

	if (*path == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

static void _bt_convert_device_path_to_address(const char *device_path,
						char *device_address)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr;
	BT_DBG("+");

	ret_if(device_path == NULL);
	ret_if(device_address == NULL);

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		char *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL) {
			*pos = ':';
		}
		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
	BT_DBG("-");
}

static char *__bt_get_default_adapter_path(DBusMessageIter *msg_iter)
{
	char *object_path = NULL;
	DBusMessageIter value_iter;
	BT_DBG("+");

	/* Parse the signature:  oa{sa{sv}}} */
	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
			DBUS_TYPE_OBJECT_PATH, NULL);

	dbus_message_iter_get_basic(msg_iter, &object_path);

	retv_if(dbus_message_iter_next(msg_iter) == FALSE, NULL);
  	retv_if(dbus_message_iter_get_arg_type(msg_iter) !=
			DBUS_TYPE_ARRAY, NULL);

	dbus_message_iter_recurse(msg_iter, &value_iter);

	while (dbus_message_iter_get_arg_type(&value_iter) ==
		  DBUS_TYPE_DICT_ENTRY) {
		char *interface_name = NULL;
		DBusMessageIter interface_iter;

		dbus_message_iter_recurse(&value_iter, &interface_iter);

		retv_if(dbus_message_iter_get_arg_type(&interface_iter) !=
	  			DBUS_TYPE_STRING, NULL);

		dbus_message_iter_get_basic(&interface_iter, &interface_name);

		if (g_strcmp0(interface_name, "org.bluez.Adapter1") == 0) {
			return g_strdup(object_path);
		}
	dbus_message_iter_next(&value_iter);
	}
	BT_DBG("Adapter Not Found");
	BT_DBG("-");
	return NULL;
}


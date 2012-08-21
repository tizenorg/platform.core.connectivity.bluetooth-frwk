/*
 * Bluetooth-hfp-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 *		Girishashok Joshi <girish.joshi@samsung.com>
 *		Chanyeol Park <chanyeol.park@samsung.com>
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
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <signal.h>

#include "vconf.h"
#include "vconf-keys.h"
#include "contacts-svc.h"
#include "appsvc.h"

#include "bluetooth-hfp-agent.h"

static GMainLoop *gmain_loop = NULL;
static DBusConnection *gconn = NULL;

#define BT_ERROR_INTERNAL "InternalError"
#define BT_ERROR_NOT_AVAILABLE "NotAvailable"
#define BT_ERROR_NOT_CONNECTED "NotConnected"
#define BT_ERROR_BUSY "InProgress"
#define BT_ERROR_INVALID_PARAM "InvalidArguments"
#define BT_ERROR_ALREADY_EXSIST "AlreadyExists"
#define BT_ERROR_ALREADY_CONNECTED "Already Connected"
#define BT_ERROR_NO_MEMORY "No memory"
#define BT_ERROR_I_O_ERROR "I/O error"
#define BT_ERROR_OPERATION_NOT_AVAILABLE "Operation currently not available"
#define BT_ERROR_BATTERY "Battery error "
#define BT_ERROR_SIGNAL "Signal error"
#define BT_ERROR_NO_CALL_LOG "No Call log"
#define BT_ERROR_INVLAID_DTMF "Invalid dtmf"

#define BLUEZ_SERVICE_NAME "org.bluez"
#define TELEPHONY_CSD_INTERFACE "org.tizen.telephony.csd"
#define TELEPHONY_CSD_OBJECT_PATH "/org/tizen/csd"
#define TELEPHONY_APP_INTERFACE "org.tizen.csd.Call.Instance"

#define BT_HFP_AGENT_SET_PROPERTY "SetProperty"

/* AT+CSQ : Returns received signal strength indication.
     Command response: +CSQ: <rssi>,<ber>
    <ber> is not supported and has a constant value of 99, included for compatibility reasons.
*/
#define BT_SIGNAL_QUALITY_BER 99

/*Length of the string used to send telephone number to app-svc
   format: tel:<number>
*/
#define BT_MAX_TEL_NUM_STRING 20

typedef struct {
	GObject parent;
} BtHfpAgent;

typedef struct {
	GObjectClass parent;
} BtHfpAgentClass;

GType bt_hfp_agent_get_type(void);

#define BT_HFP_TYPE_AGENT (bt_hfp_agent_get_type())

#define BT_HFP_AGENT(object)(G_TYPE_CHECK_INSTANCE_CAST((object), \
			BT_HFP_TYPE_AGENT , BtHfpAgent))

#define BT_HFP_AGENT_CLASS(klass)(G_TYPE_CHECK_CLASS_CAST((klass), \
			BT_HFP_TYPE_AGENT , BtHfpAgentClass))

#define BT_HFP_IS_AGENT(object)(G_TYPE_CHECK_INSTANCE_TYPE((object), \
			BT_HFP_TYPE_AGENT))

#define BT_HFP_IS_AGENT_CLASS(klass)(G_TYPE_CHECK_CLASS_TYPE((klass), \
			BT_HFP_TYPE_AGENT))

#define BT_HFP_AGENT_GET_CLASS(obj)(G_TYPE_INSTANCE_GET_CLASS((obj), \
			BT_HFP_TYPE_AGENT , BtHfpAgentClass))

G_DEFINE_TYPE(BtHfpAgent, bt_hfp_agent, G_TYPE_OBJECT)

static gboolean bt_hfp_agent_register_application(BtHfpAgent *agent,
				const gchar *path, DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_unregister_application(BtHfpAgent *agent,
				const gchar *path, DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_incoming_call(BtHfpAgent *agent, const gchar *path,
				const gchar *number, gint call_id,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_outgoing_call(BtHfpAgent *agent, const gchar *path,
				const gchar *number, gint call_id,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_change_call_status(BtHfpAgent *agent,
				const gchar *path, gint status, gint call_id,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_answer_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_release_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_reject_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_threeway_call(BtHfpAgent *agent, gint call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_dial_last_num(BtHfpAgent *agent,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_dial_num(BtHfpAgent *agent,
				const gchar *number, guint flags,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_dial_memory(BtHfpAgent *agent, gint location,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_send_dtmf(BtHfpAgent *agent, const gchar *dtmf,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_voice_dial(BtHfpAgent *agent, gboolean activate,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_get_battery_status(BtHfpAgent *object,
				DBusGMethodInvocation *context);

static gboolean bt_hfp_agent_get_signal_quality(BtHfpAgent *object,
				DBusGMethodInvocation *context);

#include "bluetooth_hfp_agent_glue.h"

static void bt_hfp_agent_init(BtHfpAgent *obj)
{
	DBG("+\n");

	g_assert(obj != NULL);
}

static void bt_hfp_agent_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(bt_hfp_agent_parent_class)->finalize(obj);
}

static void bt_hfp_agent_class_init(BtHfpAgentClass *klass)
{
	DBG("+\n");

	GObjectClass *object_class = (GObjectClass *)klass;

	g_assert(klass != NULL);

	object_class->finalize = bt_hfp_agent_finalize;

	dbus_g_object_type_install_info(BT_HFP_TYPE_AGENT,
					&dbus_glib_bt_hfp_agent_object_info);
}

static GQuark __bt_hfp_agent_error_quark(void)
{
	DBG("+\n");

	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

static GError *__bt_hfp_agent_set_error(bt_hfp_agent_error_t error)
{
	DBG("+\n");

	switch (error) {
	case BT_HFP_AGENT_ERROR_NOT_AVAILABLE:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_NOT_AVAILABLE);
	case BT_HFP_AGENT_ERROR_NOT_CONNECTED:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_NOT_CONNECTED);
	case BT_HFP_AGENT_ERROR_BUSY:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_BUSY);
	case BT_HFP_AGENT_ERROR_INVALID_PARAM:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_INVALID_PARAM);
	case BT_HFP_AGENT_ERROR_ALREADY_EXSIST:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_ALREADY_EXSIST);
	case BT_HFP_AGENT_ERROR_ALREADY_CONNECTED:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_ALREADY_CONNECTED);
	case BT_HFP_AGENT_ERROR_NO_MEMORY:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_NO_MEMORY);
	case BT_HFP_AGENT_ERROR_I_O_ERROR:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_I_O_ERROR);
	case BT_HFP_AGENT_ERROR_OPERATION_NOT_AVAILABLE:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
					BT_ERROR_OPERATION_NOT_AVAILABLE);
	case BT_HFP_AGENT_ERROR_BATTERY_STATUS:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
					BT_ERROR_BATTERY);
	case BT_HFP_AGENT_ERROR_SIGNAL_STATUS:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
					BT_ERROR_SIGNAL);
	case BT_HFP_AGENT_ERROR_NO_CALL_LOGS:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
					BT_ERROR_NO_CALL_LOG);
	case BT_HFP_AGENT_ERROR_INTERNAL:
	default:
		return g_error_new(BT_HFP_AGENT_ERROR, error,
						BT_ERROR_INTERNAL);
	}
}

static int __bt_hfp_agent_get_error(const char *error_message)
{
	if (error_message == NULL) {
		DBG("Error message NULL\n");
		return BT_HFP_AGENT_ERROR_INTERNAL;
	}

	DBG("Error message = %s \n", error_message);

	if (g_strcmp0(error_message, BT_ERROR_NOT_AVAILABLE) == 0)
		return BT_HFP_AGENT_ERROR_NOT_AVAILABLE;
	else if (g_strcmp0(error_message, BT_ERROR_NOT_CONNECTED) == 0)
		return BT_HFP_AGENT_ERROR_NOT_CONNECTED;
	else if (g_strcmp0(error_message, BT_ERROR_BUSY) == 0)
		return BT_HFP_AGENT_ERROR_BUSY;
	else if (g_strcmp0(error_message, BT_ERROR_INVALID_PARAM) == 0)
		return BT_HFP_AGENT_ERROR_INVALID_PARAM;
	else if (g_strcmp0(error_message, BT_ERROR_ALREADY_EXSIST) == 0)
		return BT_HFP_AGENT_ERROR_ALREADY_EXSIST;
	else if (g_strcmp0(error_message, BT_ERROR_ALREADY_CONNECTED) == 0)
		return BT_HFP_AGENT_ERROR_ALREADY_CONNECTED;
	else if (g_strcmp0(error_message, BT_ERROR_NO_MEMORY) == 0)
		return BT_HFP_AGENT_ERROR_NO_MEMORY;
	else if (g_strcmp0(error_message, BT_ERROR_I_O_ERROR) == 0)
		return BT_HFP_AGENT_ERROR_I_O_ERROR;
	else if (g_strcmp0(error_message,
				BT_ERROR_OPERATION_NOT_AVAILABLE) == 0)
		return BT_HFP_AGENT_ERROR_OPERATION_NOT_AVAILABLE;
	else if (g_strcmp0(error_message, BT_ERROR_INVLAID_DTMF) == 0)
		return BT_HFP_AGENT_ERROR_INVALID_DTMF;
	else
		return BT_HFP_AGENT_ERROR_INTERNAL;
}

static int __bt_hfp_agent_dbus_method_send(const char *service,
				const char *path, const char *interface,
				const char *method, gboolean response,
				int type, ...)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	va_list args;
	int error;

	DBG("__bt_hfp_agent_dbus_method_send +\n");

	msg = dbus_message_new_method_call(service, path, interface,
								method);
	if (!msg) {
		DBG("Unable to allocate new D-Bus %s message \n", method);
		return BT_HFP_AGENT_ERROR_INTERNAL;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		return BT_HFP_AGENT_ERROR_INTERNAL;
	}

	va_end(args);

	dbus_error_init(&err);

	if (response) {
		reply = dbus_connection_send_with_reply_and_block(gconn,
							msg, -1, &err);
		dbus_message_unref(msg);

		if (!reply) {
			DBG("Error returned in method call\n");
			if (dbus_error_is_set(&err)) {
				error = __bt_hfp_agent_get_error(err.message);
				dbus_error_free(&err);
				return error;
			} else {
				DBG("Error is not set\n");
				return BT_HFP_AGENT_ERROR_INTERNAL;
			}
		}
		dbus_message_unref(reply);
	} else {
		dbus_connection_send(gconn, msg, NULL);
		dbus_message_unref(msg);
	}

	DBG("__bt_hfp_agent_dbus_method_send -\n");

	return BT_HFP_AGENT_ERROR_NONE;
}

static gboolean bt_hfp_agent_register_application(BtHfpAgent *agent,
				const gchar *path, DBusGMethodInvocation *context)
{
	gboolean flag = TRUE;
	char *sender;
	GError *error;
	int ret;

	DBG("bt_hfp_agent_register_application + \n");

	if (path == NULL) {
		DBG("Invalid Argument path\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s\n", path);

	sender = dbus_g_method_get_sender(context);

	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(BLUEZ_SERVICE_NAME,
				TELEPHONY_CSD_OBJECT_PATH,
				TELEPHONY_CSD_INTERFACE,
				"RegisterTelephonyAgent", TRUE,
				DBUS_TYPE_BOOLEAN, &flag,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &sender, DBUS_TYPE_INVALID);
	g_free(sender);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("bt_hfp_agent_register_application - \n");
	return TRUE;
}

static gboolean bt_hfp_agent_unregister_application(BtHfpAgent *agent,
				const gchar *path, DBusGMethodInvocation *context)
{
	gboolean flag = FALSE;
	char *sender;
	GError *error;
	int ret;

	DBG("bt_hfp_agent_unregister_application + \n");

	if (path == NULL) {
		DBG("Invalid Argument path\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s \n", path);

	sender = dbus_g_method_get_sender(context);

	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(BLUEZ_SERVICE_NAME,
				TELEPHONY_CSD_OBJECT_PATH,
				TELEPHONY_CSD_INTERFACE,
				"RegisterTelephonyAgent", TRUE,
				DBUS_TYPE_BOOLEAN, &flag,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &sender, DBUS_TYPE_INVALID);
	g_free(sender);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("bt_hfp_agent_unregister_application - \n");
	return TRUE;
}

static gboolean bt_hfp_agent_incoming_call(BtHfpAgent *agent, const gchar *path,
				const gchar *number, gint call_id,
				DBusGMethodInvocation *context)
{
	GError *error;
	char *sender;
	int ret;

	DBG("bt_hfp_agent_incoming_call + \n");

	if (path == NULL || number == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s\n", path);
	DBG("Phone number = %s\n", number);
	DBG("Call id = %d\n", call_id);

	sender = dbus_g_method_get_sender(context);

	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(BLUEZ_SERVICE_NAME,
				TELEPHONY_CSD_OBJECT_PATH,
				TELEPHONY_CSD_INTERFACE,
				"Incoming", TRUE,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_STRING, &sender,
				DBUS_TYPE_INVALID);
	g_free(sender);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("bt_hfp_agent_incoming_call - \n");
	return TRUE;
}

static gboolean bt_hfp_agent_outgoing_call(BtHfpAgent *agent, const gchar *path,
				const gchar *number, gint call_id,
				DBusGMethodInvocation *context)
{
	GError *error;
	char *sender;
	int ret;

	DBG("bt_hfp_agent_outgoing_call + \n");

	if (path == NULL || number == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s\n", path);
	DBG("Phone number = %s\n", number);
	DBG("Call id = %d\n", call_id);

	sender = dbus_g_method_get_sender(context);

	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(BLUEZ_SERVICE_NAME,
				TELEPHONY_CSD_OBJECT_PATH,
				TELEPHONY_CSD_INTERFACE,
				"Outgoing", TRUE,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_STRING, &sender,
				DBUS_TYPE_INVALID);
	g_free(sender);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("bt_hfp_agent_outgoing_call - \n");
	return TRUE;
}

static gboolean bt_hfp_agent_change_call_status(BtHfpAgent *agent,
				const gchar *path, gint status, gint call_id,
				DBusGMethodInvocation *context)
{
	GError *error;
	char *sender;
	int ret;

	DBG("bt_hfp_agent_change_call_status + \n");

	if (path == NULL) {
		DBG("Invalid Argument path\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s\n", path);
	DBG("Status = %d\n", status);
	DBG("Call id = %d\n", call_id);

	sender = dbus_g_method_get_sender(context);

	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(BLUEZ_SERVICE_NAME,
				TELEPHONY_CSD_OBJECT_PATH,
				TELEPHONY_CSD_INTERFACE,
				"SetCallStatus", TRUE,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_UINT32, &status,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_STRING, &sender,
				DBUS_TYPE_INVALID);
	g_free(sender);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("bt_hfp_agent_change_call_status - \n");
	return TRUE;
}

static gboolean bt_hfp_agent_answer_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context)
{
	int ret;
	GError *error;
	DBG("+\n");

	if (path == NULL || sender == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s \n", path);
	DBG("Call Id = %d", call_id);
	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(sender,
				path, TELEPHONY_APP_INTERFACE,
				"Answer", FALSE,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_INVALID);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
}

static gboolean bt_hfp_agent_release_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context)
{
	int ret;
	GError *error;
	DBG("+\n");

	if (path == NULL || sender == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s \n", path);
	DBG("Call Id = %d", call_id);
	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(sender,
				path, TELEPHONY_APP_INTERFACE,
				"Release", FALSE,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_INVALID);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("-\n");
	return TRUE;
}

static gboolean bt_hfp_agent_reject_call(BtHfpAgent *agent, unsigned int call_id,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context)
{
	int ret;
	GError *error;
	DBG("+\n");

	if (path == NULL || sender == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s \n", path);
	DBG("Call Id = %d", call_id);
	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(sender,
				path, TELEPHONY_APP_INTERFACE,
				"Reject", FALSE,
				DBUS_TYPE_UINT32, &call_id,
				DBUS_TYPE_INVALID);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("-\n");
	return TRUE;
}

static gboolean bt_hfp_agent_threeway_call(BtHfpAgent *agent, gint value,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context)
{
	int ret;
	GError *error;
	DBG("+\n");

	if (path == NULL || sender == NULL) {
		DBG("Invalid Arguments\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Application path = %s \n", path);
	DBG("Value = %d", value);
	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(sender,
				path, TELEPHONY_APP_INTERFACE,
				"Threeway", TRUE,
				DBUS_TYPE_UINT32, &value,
				DBUS_TYPE_INVALID);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	dbus_g_method_return(context);
	DBG("-\n");
	return TRUE;
}

static gboolean __bt_hfp_agent_make_call(const char *number)
{
	bundle *b;
	char telnum[BT_MAX_TEL_NUM_STRING];

	b = bundle_create();
	if (NULL == b)
		return FALSE;

	appsvc_set_operation(b, APPSVC_OPERATION_CALL);
	snprintf(telnum, sizeof(telnum), "tel:%s", number);
	appsvc_set_uri(b, telnum);
	appsvc_add_data(b, "ctindex", "-1");
	appsvc_run_service(b, 0, NULL, NULL);
	bundle_free(b);

	return TRUE;
}

static gboolean bt_hfp_agent_dial_last_num(BtHfpAgent *agent,
				DBusGMethodInvocation *context)
{
	GError *error;
	int error_code;
	char *last_number;

	DBG("+ \n");

	/*Get last dialed number*/
	if (contacts_svc_connect() != CTS_SUCCESS) {
		ERR("contacts_svc_connect failed \n");
		error_code = BT_HFP_AGENT_ERROR_INTERNAL;
		goto fail;
	}

	last_number = contacts_svc_phonelog_get_last_number(CTS_PLOG_LAST_ALL);

	if (last_number == NULL) {
		ERR("No last number \n");
		contacts_svc_disconnect();
		error_code = BT_HFP_AGENT_ERROR_NO_CALL_LOGS;
		goto fail;
	}

	DBG("Last dialed number = %s\n", last_number);

	contacts_svc_disconnect();

	/*Make Voice call*/
	if (!__bt_hfp_agent_make_call(last_number)) {
		ERR("Problem launching application \n");
		error_code = BT_HFP_AGENT_ERROR_INTERNAL;
		goto fail;
	}

	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
fail:
	error = __bt_hfp_agent_set_error(error_code);
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	return FALSE;
}

static gboolean bt_hfp_agent_dial_num(BtHfpAgent *agent,
				const gchar *number, guint flags,
				DBusGMethodInvocation *context)
{
	GError *error;
	int error_code;

	DBG("+\n");

	if (number == NULL) {
		ERR("Invalid Argument\n");
		error_code = BT_HFP_AGENT_ERROR_INVALID_PARAM;
		goto fail;
	}

	DBG("Number = %s \n", number);
	DBG("flags = %d", flags);

	/*TODO: Make use of flags*/

	/*Make Voice call*/
	if (!__bt_hfp_agent_make_call(number)) {
		ERR("Problem launching application \n");
		error_code = BT_HFP_AGENT_ERROR_INTERNAL;
		goto fail;
	}

	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
fail:
	error = __bt_hfp_agent_set_error(error_code);
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	DBG("-\n");
	return FALSE;
}

static gboolean bt_hfp_agent_dial_memory(BtHfpAgent *agent, gint location,
				DBusGMethodInvocation *context)
{
	GError *error;
	int error_code;
	CTSvalue *contact = NULL;
	const char *number;

	DBG("+\n");

	DBG("location = %d \n", location);

	/*Get number from contacts location*/
	if (contacts_svc_connect() != CTS_SUCCESS) {
		ERR("contacts_svc_connect failed \n");
		error_code = BT_HFP_AGENT_ERROR_INTERNAL;
		goto fail;
	}

	if (contacts_svc_get_contact_value(CTS_GET_DEFAULT_NUMBER_VALUE,
				location, &contact) != CTS_SUCCESS)  {
		ERR("contacts_svc_get_contact_value failed \n");
		error_code = BT_HFP_AGENT_ERROR_INVALID_MEMORY_INDEX;
		contacts_svc_disconnect();
		goto fail;
	}

	number = contacts_svc_value_get_str(contact, CTS_NUM_VAL_NUMBER_STR);

	if (number == NULL) {
		ERR("No number at the location \n");
		error_code = BT_HFP_AGENT_ERROR_INVALID_MEMORY_INDEX;
		contacts_svc_disconnect();
		goto fail;
	}

	contacts_svc_disconnect();

	/*Make Voice call*/
	if (!__bt_hfp_agent_make_call(number)) {
		ERR("Problem launching application \n");
		error_code = BT_HFP_AGENT_ERROR_INTERNAL;
		goto fail;
	}

	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
fail:
	error = __bt_hfp_agent_set_error(error_code);
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	DBG("-\n");
	return FALSE;
}

static gboolean bt_hfp_agent_send_dtmf(BtHfpAgent *agent, const gchar *dtmf,
				const gchar *path, const gchar *sender,
				DBusGMethodInvocation *context)
{
	GError *error;
	int ret;

	DBG("+\n");

	if (dtmf == NULL || path == NULL || sender == NULL) {
		ERR("Invalid Argument\n");
		error = __bt_hfp_agent_set_error(
					BT_HFP_AGENT_ERROR_INVALID_PARAM);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	DBG("Dtmf = %s \n", dtmf);
	DBG("Application path = %s \n", path);
	DBG("Sender = %s\n", sender);

	ret = __bt_hfp_agent_dbus_method_send(sender,
				path, TELEPHONY_APP_INTERFACE,
				"SendDtmf", FALSE,
				DBUS_TYPE_STRING, &dtmf,
				DBUS_TYPE_INVALID);

	if (ret != BT_HFP_AGENT_ERROR_NONE) {
		error = __bt_hfp_agent_set_error(ret);
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	}

	/*App Selector code here needed*/
	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
}

static gboolean bt_hfp_agent_voice_dial(BtHfpAgent *agent, gboolean activate,
				DBusGMethodInvocation *context)
{
	DBG("+\n");

	DBG("Activate = %d \n", activate);

	/*App Selector code here needed*/
	dbus_g_method_return(context);

	DBG("-\n");
	return TRUE;
}

static gboolean bt_hfp_agent_get_battery_status(BtHfpAgent *object,
				DBusGMethodInvocation *context)
{
	gint battery_chrg_status;
	gint battery_capacity;
	GError *error;

	DBG("+\n");

	if (vconf_get_int(VCONFKEY_SYSMAN_BATTERY_CHARGE_NOW,
						&battery_chrg_status)) {
		DBG("VCONFKEY_SYSMAN_BATTERY_CHARGE_NOW failed\n");
		goto fail;
	}

	DBG("Status : %d\n", battery_chrg_status);

	if (vconf_get_int(VCONFKEY_SYSMAN_BATTERY_CAPACITY,
						&battery_capacity)) {
		DBG("VCONFKEY_SYSMAN_BATTERY_CAPACITY failed\n");
		goto fail;
	}

	DBG("Capacity : %d\n", battery_capacity);

	dbus_g_method_return(context, battery_chrg_status, battery_capacity);
	DBG("-\n");
	return TRUE;

fail:
	error = __bt_hfp_agent_set_error(BT_HFP_AGENT_ERROR_BATTERY_STATUS);
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	DBG("-\n");
	return FALSE;
}

static gboolean bt_hfp_agent_get_signal_quality(BtHfpAgent *object,
					DBusGMethodInvocation *context)
{
	gint rssi;
	GError *error;

	DBG("+\n");

	if (!vconf_get_int(VCONFKEY_TELEPHONY_RSSI, &rssi)) {
		DBG("VCONFKEY_TELEPHONY_RSSI failed\n");
		goto fail;
	}

	DBG("RSSI : %d \n", rssi);

	dbus_g_method_return(context, rssi, BT_SIGNAL_QUALITY_BER);
	DBG("-\n");
	return TRUE;
fail:
	error = __bt_hfp_agent_set_error(BT_HFP_AGENT_ERROR_SIGNAL_STATUS);
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	DBG("-\n");
	return FALSE;
}

static void __bt_hfp_agent_append_variant(DBusMessageIter *iter,
			int type, void *val)
{
	DBusMessageIter value_iter;
	const char *variant;

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		variant = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		variant = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		variant = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		variant = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		variant = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		variant = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		variant = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		variant = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		variant = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, variant,
							&value_iter);
	dbus_message_iter_append_basic(&value_iter, type, val);
	dbus_message_iter_close_container(iter, &value_iter);
}

static gboolean __bt_hfp_agent_dbus_method_variant_send(const char *path,
		const char *interface, const char *method, const char *name,
		int type, void *value)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	DBusMessageIter iter;

	DBG(" +\n");

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
			path, interface, method);

	if (!msg) {
		DBG("Unable to allocate new D-Bus %s message", method);
		return FALSE;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	__bt_hfp_agent_append_variant(&iter, type, value);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(gconn,
				msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		DBG("Error returned in method call\n");
		if (dbus_error_is_set(&err)) {
			if (err.message != NULL) {
				DBG("Error message = %s\n", err.message);
			}
			dbus_error_free(&err);
		}
		return FALSE;
	}

	dbus_message_unref(reply);

	DBG(" -\n");
	return TRUE;
}

static gboolean __bt_hfp_agent_send_registration_status_changed(
		bt_hfp_agent_network_registration_status_t status)
{
	const char *property = g_strdup("RegistrationChanged");

	DBG(" +\n");

	if (!__bt_hfp_agent_dbus_method_variant_send(TELEPHONY_CSD_OBJECT_PATH,
			TELEPHONY_CSD_INTERFACE,
			BT_HFP_AGENT_SET_PROPERTY,
			property, DBUS_TYPE_BYTE, &status)) {
		DBG("__bt_hfp_agent_dbus_method_variant_send - ERROR\n");
		g_free((void *)property);
		return FALSE;
	}
	DBG(" -\n");

	g_free((void *)property);
	return TRUE;
}

static gboolean __bt_hfp_agent_send_operator_name_changed(const char *name)
{
	const char *property = g_strdup("OperatorNameChanged");

	DBG(" +\n");

	if (!__bt_hfp_agent_dbus_method_variant_send(TELEPHONY_CSD_OBJECT_PATH,
			TELEPHONY_CSD_INTERFACE,
			BT_HFP_AGENT_SET_PROPERTY,
			property, DBUS_TYPE_STRING, &name)) {
		DBG("__bt_hfp_agent_dbus_method_variant_send - ERROR\n");
		g_free((void *)property);
		return FALSE;
	}
	DBG(" -\n");
	g_free((void *)property);
	return TRUE;
}

static gboolean __bt_hfp_agent_send_subscriber_number_changed(
							const char *number)
{
	const char *property = g_strdup("SubscriberNumberChanged");

	DBG(" +\n");

	if (!__bt_hfp_agent_dbus_method_variant_send(TELEPHONY_CSD_OBJECT_PATH,
			TELEPHONY_CSD_INTERFACE,
			BT_HFP_AGENT_SET_PROPERTY,
			property,
			DBUS_TYPE_STRING, &number)) {
		DBG("__bt_hfp_agent_dbus_method_variant_send - ERROR\n");
		g_free((void *)property);
		return FALSE;
	}

	DBG(" -\n");
	g_free((void *)property);
	return TRUE;
}

static gboolean __bt_hfp_agent_send_signal_bar_changed(int signal_bar)
{
	const char *property = g_strdup("SignalBarsChanged");

	DBG(" +\n");

	if (!__bt_hfp_agent_dbus_method_variant_send(TELEPHONY_CSD_OBJECT_PATH,
			TELEPHONY_CSD_INTERFACE,
			BT_HFP_AGENT_SET_PROPERTY,
			property, DBUS_TYPE_INT32, &signal_bar)) {
		DBG("__bt_hfp_agent_dbus_method_variant_send - ERROR\n");
		g_free((void *)property);
		return FALSE;
	}

	g_free((void *)property);
	DBG(" -\n");
	return TRUE;
}

static gboolean __bt_hfp_agent_send_battery_level_changed(int battery_level)
{
	const char *property = g_strdup("BatteryBarsChanged");
	int battery_status;

	DBG(" +\n");

	/* We need to send battery status ranging from 0-5 */
	if (battery_level < 5)
		 battery_status = 0;
	else if (battery_level >= 100)
		battery_status = 5;
	else
		battery_status = battery_level / 20 + 1;

	if (!__bt_hfp_agent_dbus_method_variant_send(TELEPHONY_CSD_OBJECT_PATH,
			TELEPHONY_CSD_INTERFACE,
			BT_HFP_AGENT_SET_PROPERTY,
			property,
			DBUS_TYPE_INT32, &battery_status)) {
		DBG("__bt_hfp_agent_dbus_method_variant_send - ERROR\n");
		g_free((void *)property);
		return FALSE;
	}

	DBG(" -\n");
	g_free((void *)property);
	return TRUE;
}

static void __bt_hfp_agent_send_battery_level(void)
{
	int ret;
	int batt;

	DBG(" +\n");

	ret = vconf_get_int(VCONFKEY_SYSMAN_BATTERY_CAPACITY, &batt);
	if (ret != 0) {
		DBG("vconf_get_int failed err = %d \n", ret);
		return;
	}

	DBG("Current battery Level = [%d] \n", batt);

	__bt_hfp_agent_send_battery_level_changed(batt);

	DBG(" -\n");
}

static void __bt_hfp_agent_send_signal_status(void)
{
	int ret;
	int signal_level;

	DBG(" +\n");

	ret = vconf_get_int(VCONFKEY_TELEPHONY_RSSI, &signal_level);
	if (ret != 0) {
		DBG("vconf_get_int failed err = %d \n", ret);
		return;
	}

	DBG("Current Signal Level = [%d] \n", signal_level);

	__bt_hfp_agent_send_signal_bar_changed(signal_level);

	DBG(" -\n");
}

static void __bt_hfp_agent_send_operator_name(void)
{
	char *operator_name;

	DBG(" +\n");

	operator_name = vconf_get_str(VCONFKEY_TELEPHONY_NWNAME);
	if (NULL == operator_name) {
		DBG("vconf_get_int failed \n");
		return;
	}

	DBG("operator_name  = [%s] \n", operator_name);

	__bt_hfp_agent_send_operator_name_changed(operator_name);

	free(operator_name);

	DBG(" -\n");
}

static void __bt_hfp_agent_send_subscriber_number(void)
{
	char *subscriber_number
		;
	DBG(" +\n");

	subscriber_number = vconf_get_str(VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER);
	if (NULL == subscriber_number) {
		DBG("vconf_get_int failed\n");
		return;
	}

	DBG("subscriber_number  = [%s] \n", subscriber_number);

	__bt_hfp_agent_send_subscriber_number_changed(subscriber_number);

	free(subscriber_number);

	DBG(" -\n");
	return;
}

static void __bt_hfp_agent_network_send( int service, int roam_status)
{
	int ret;
	bt_hfp_agent_network_registration_status_t network_service;

	DBG(" +\n");

	switch (service) {
	case VCONFKEY_TELEPHONY_SVCTYPE_NONE:
	case VCONFKEY_TELEPHONY_SVCTYPE_NOSVC:
	case VCONFKEY_TELEPHONY_SVCTYPE_SEARCH:
		service = 0;
		break;
	default:
		service = 1;
		break;
	}

	ret = vconf_get_int(VCONFKEY_TELEPHONY_SVC_ROAM, &roam_status);
	if (ret != 0) {
		DBG("Get roaming status failed err = %d\n", ret);
		return;
	}

	if (roam_status == 0 && service == 1)
		network_service = BT_HFP_AGENT_NETWORK_REG_STATUS_HOME;
	else if (roam_status == 1 && service == 1)
		network_service = BT_HFP_AGENT_NETWORK_REG_STATUS_ROAMING;
	else
		network_service = BT_HFP_AGENT_NETWORK_REG_STATUS_UNKOWN;

	DBG("Network service = %d\n", network_service);

	__bt_hfp_agent_send_registration_status_changed(network_service);

	DBG(" -\n");
}

static void __bt_hfp_agent_send_network_status(void)
{
	int ret;
	int roam_status;
	int service;


	DBG(" +\n");

	ret = vconf_get_int(VCONFKEY_TELEPHONY_SVC_ROAM, &roam_status);
	if (ret != 0) {
		DBG("vconf_get_int failed for \n");
		return;
	}

	DBG("roam_status  = [%d] \n", roam_status);

	ret = vconf_get_int(VCONFKEY_TELEPHONY_SVCTYPE, &service);
	if (ret != 0) {
		DBG("vconf_get_int failed\n");
		return;
	}

	DBG("service  = [%d] \n", service);

	__bt_hfp_agent_network_send(service, roam_status);

	DBG(" -\n");
}

static void __bt_hfp_agent_send_vconf_values(void)
{
	__bt_hfp_agent_send_battery_level();
	__bt_hfp_agent_send_signal_status();
	__bt_hfp_agent_send_operator_name();
	__bt_hfp_agent_send_subscriber_number();
	__bt_hfp_agent_send_network_status();
}

static void __bt_hfp_agent_battery_status_cb(keynode_t *node)
{
	int batt = vconf_keynode_get_int(node);

	DBG(" +\n");

	DBG("Current Battery Level = [%d] \n", batt);

	__bt_hfp_agent_send_battery_level_changed(batt);

	DBG(" -\n");
}

static void __bt_hfp_agent_network_signal_status_cb(keynode_t *node)
{
	int signal_bar = vconf_keynode_get_int(node);

	DBG(" +\n");

	DBG("Current Signal Level = [%d] \n", signal_bar);

	__bt_hfp_agent_send_signal_bar_changed(signal_bar);

	DBG(" -\n");
}

static void __bt_hfp_agent_network_register_status_cb(keynode_t *node)
{
	int service = vconf_keynode_get_int(node);
	int roam_status;
	int ret;

	DBG(" +\n");

	DBG("Current Signal Level = [%d] \n", service);

	ret = vconf_get_int(VCONFKEY_TELEPHONY_SVC_ROAM, &roam_status);
	if (ret != 0) {
		DBG("Get roaming status failed err = %d\n", ret);
		return;
	}

	__bt_hfp_agent_network_send(service, roam_status);

	DBG(" -\n");
}

static void __bt_hfp_agent_subscribe_vconf_updates(void)
{
	int ret;

	DBG(" +\n");

	ret = vconf_notify_key_changed(VCONFKEY_SYSMAN_BATTERY_CAPACITY,
				(void *)__bt_hfp_agent_battery_status_cb, NULL);
	if (0 != ret) {
		DBG("Subsrciption to battery status failed err =  [%d]\n", ret);
	}

	ret = vconf_notify_key_changed(VCONFKEY_TELEPHONY_RSSI,
			(void *)__bt_hfp_agent_network_signal_status_cb, NULL);
	if (0 != ret) {
		DBG("Subsrciption to netowrk signal failed err =  [%d]\n", ret);
	}

	ret = vconf_notify_key_changed(VCONFKEY_TELEPHONY_SVCTYPE,
			(void *)__bt_hfp_agent_network_register_status_cb, NULL);
	if (0 != ret) {
		DBG("Subsrciption to network failed err =  [%d]\n", ret);
	}

	DBG(" -\n");
}

static void __bt_hfp_agent_release_vconf_updates(void)
{
	int ret;

	DBG(" +\n");

	ret = vconf_ignore_key_changed(VCONFKEY_SYSMAN_BATTERY_CAPACITY,
			(vconf_callback_fn)__bt_hfp_agent_battery_status_cb);
	if (0 != ret) {
		DBG("vconf_ignore_key_changed failed\n");
	}

	ret = vconf_ignore_key_changed(VCONFKEY_TELEPHONY_RSSI,
		(vconf_callback_fn)__bt_hfp_agent_network_signal_status_cb);
	if (0 != ret) {
		DBG("vconf_ignore_key_changed failed\n");
	}

	ret = vconf_ignore_key_changed(VCONFKEY_TELEPHONY_SVCTYPE,
		(vconf_callback_fn)__bt_hfp_agent_network_register_status_cb);
	if (0 != ret) {
		DBG("vconf_ignore_key_changed failed\n");
	}

	DBG(" -\n");
}

static void __bt_hfp_agent_sigterm_handler(int signo)
{
	DBG("+\n");

	if (gmain_loop)
		g_main_loop_quit(gmain_loop);
	else
		exit(0);

	DBG("-\n");
}

int main(void)
{
	BtHfpAgent *bt_hfp_obj = NULL;
	DBusGConnection *connection;
	GError *error = NULL;
	DBusGProxy *bus_proxy = NULL;
	guint result;
	int ret = EXIT_FAILURE;
	struct sigaction sa;

	g_type_init();

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = __bt_hfp_agent_sigterm_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	gmain_loop = g_main_loop_new(NULL, FALSE);

	if (gmain_loop == NULL) {
		ERR("GMainLoop create failed \n");
		return EXIT_FAILURE;
	}

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		ERR("Failed connection to system bus[%s] \n", error->message);
		g_error_free(error);
		goto fail;
	}

	bus_proxy = dbus_g_proxy_new_for_name(connection,
					DBUS_SERVICE_DBUS,
					DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (bus_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		goto fail;
	}

	if (!dbus_g_proxy_call(bus_proxy, "RequestName", &error, G_TYPE_STRING,
			BT_HFP_SERVICE, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (error != NULL) {
			ERR("RequestName RPC failed[%s]\n", error->message);
			g_error_free(error);
		}
		goto fail;
	}

	DBG("result : %d %d\n", result, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		ERR("Failed to get the primary well-known name.\n");
		goto fail;
	}

	g_object_unref(bus_proxy);
	bus_proxy = NULL;

	bt_hfp_obj = g_object_new(BT_HFP_TYPE_AGENT, NULL);
	if (bt_hfp_obj == NULL) {
		ERR("Failed to create BtHfpAgent instance \n");
		goto fail;
	}

	dbus_g_connection_register_g_object(connection,
		BT_HFP_SERVICE_OBJECT_PATH, G_OBJECT(bt_hfp_obj));

	gconn = dbus_g_connection_get_connection(connection);
	if (gconn == NULL) {
		ERR("Failed to get connection \n");
		goto fail;
	}

	__bt_hfp_agent_send_vconf_values();
	__bt_hfp_agent_subscribe_vconf_updates();

	g_main_loop_run(gmain_loop);

	ret = EXIT_SUCCESS;
fail:
	__bt_hfp_agent_release_vconf_updates();

	if (bt_hfp_obj) {
		dbus_g_connection_unregister_g_object(connection,
						G_OBJECT(bt_hfp_obj));
		g_object_unref(bt_hfp_obj);
	}
	if (bus_proxy)
		g_object_unref(bus_proxy);
	if (connection)
		dbus_g_connection_unref(connection);
	if (gmain_loop) {
		g_main_loop_unref(gmain_loop);
	}
	return ret;
}

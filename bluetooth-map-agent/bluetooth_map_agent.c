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
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <time.h>
#include <errno.h>
#include "vconf.h"
#include "vconf-keys.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*Messaging Header Files*/
#include "MapiTransport.h"
#include "MapiMessage.h"

/*Email Header Files*/
#include "Emf_Mapi_Types.h"

#include <bluetooth_map_agent.h>

#define DBUS_STRUCT_STRING_STRING_UINT (dbus_g_type_get_struct("GValueArray", \
		G_TYPE_STRING, G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))

#define DBUS_STRUCT_MESSAGE_LIST (dbus_g_type_get_struct("GValueArray", \
		G_TYPE_STRING, G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))

static MSG_HANDLE_T g_msg_handle = NULL;
#define BT_MAP_NEW_MESSAGE "NewMessage"
#define BT_MAP_STATUS_CB "sent status callback"
#define BT_MAP_MSG_CB "sms message callback"
#define BT_MAP_EMAIL_DEFAULTACCOUNT "db/email/defaultaccount"
#define BT_MAP_SMS "_s"
#define BT_MAP_EMAIL "_e"
#define BT_MAP_MSG_INFO_MAX 256
#define BT_MAP_MSG_HANDLE_MAX 16
#define BT_MNS_OBJECT_PATH "/org/bluez/mns"
#define BT_MNS_INTERFACE "org.bluez.mns"
#define BT_MSG_UPDATE	0
#define BT_MSG_DELETE	1

typedef struct {
	GObject parent;
} BluetoothMapAgent;

typedef struct {
	GObjectClass parent;
} BluetoothMapAgentClass;

GType bluetooth_map_agent_get_type(void);

#define BLUETOOTH_MAP_TYPE_AGENT (bluetooth_map_agent_get_type())

#define BLUETOOTH_MAP_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_CAST((object), \
	BLUETOOTH_MAP_TYPE_AGENT , BluetoothMapAgent))
#define BLUETOOTH_MAP_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	BLUETOOTH_MAP_TYPE_AGENT , BluetoothMapAgentClass))
#define BLUETOOTH_MAP_IS_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), \
	BLUETOOTH_MAP_TYPE_AGENT))
#define BLUETOOTH_MAP_IS_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), \
	BLUETOOTH_MAP_TYPE_AGENT))
#define BLUETOOTH_MAP_AGENT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
	BLUETOOTH_MAP_TYPE_AGENT , BluetoothMapAgentClass))

G_DEFINE_TYPE(BluetoothMapAgent, bluetooth_map_agent, G_TYPE_OBJECT)

GMainLoop *mainloop = NULL;

static gboolean bluetooth_map_get_folder_tree(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context);
static gboolean bluetooth_map_get_message_list(BluetoothMapAgent *agent,
					gchar *folder_name,
					DBusGMethodInvocation *context);
static gboolean bluetooth_map_get_message(BluetoothMapAgent *agent,
					gchar *message_name,
					DBusGMethodInvocation *context);
static gboolean bluetooth_map_update_message(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context);
static gboolean bluetooth_map_message_status(BluetoothMapAgent *agent,
					gchar *message_name,
					int indicator, int value,
					DBusGMethodInvocation *context);

#include "bluetooth_map_agent_glue.h"

static void bluetooth_map_agent_init(BluetoothMapAgent *obj)
{
	DBG("+\n");

	g_assert(obj != NULL);
}

static void bluetooth_map_agent_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(bluetooth_map_agent_parent_class)->finalize(obj);
}

static void bluetooth_map_agent_class_init(BluetoothMapAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;

	g_assert(klass != NULL);

	object_class->finalize = bluetooth_map_agent_finalize;

	dbus_g_object_type_install_info(BLUETOOTH_MAP_TYPE_AGENT,
					&dbus_glib_bluetooth_map_object_info);
}

static GQuark __bt_map_agent_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

static GError *__bt_map_agent_error(bt_map_agent_error_t error,
				     const char *err_msg)
{
	return g_error_new(BT_MAP_AGENT_ERROR, error, err_msg);
}

static void __bluetooth_map_msg_incoming_status_cb(MSG_HANDLE_T handle,
				msg_message_t msg, void *user_param)
{
	DBusMessage *message = NULL;
	char *message_type = NULL;
	DBusConnection *conn;

	DBG("+\n");

	conn  = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (NULL == conn)
		return;

	message = dbus_message_new_signal(BT_MNS_OBJECT_PATH, BT_MNS_INTERFACE,
					BT_MAP_NEW_MESSAGE);
	if (!message) {
		dbus_connection_unref(conn);
		return;
	}

	switch (msg_get_message_type(msg)) {
	case MSG_TYPE_SMS:
		message_type =  g_strdup("SMS_GSM");
		break;
	case MSG_TYPE_MMS:
		message_type =  g_strdup("MMS");
		break;
	default:
		message_type =  g_strdup("UNKNOWN");
		break;

	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &message_type,
						DBUS_TYPE_INT32, &handle,
						DBUS_TYPE_INVALID);

	dbus_message_set_no_reply(message, TRUE);
	dbus_connection_send(conn, message, NULL);
	dbus_message_unref(message);
	dbus_connection_unref(conn);
	g_free(message_type);
}

static gboolean __bluetooth_map_start_service()
{
	MSG_ERROR_T err = MSG_SUCCESS;
	int email_err = EMF_ERROR_NONE;
	bool msg_ret = TRUE;
	bool email_ret = TRUE;

	err = msg_open_msg_handle(&g_msg_handle);

	if (err != MSG_SUCCESS) {
		ERR("msg_open_msg_handle error = %d\n", err);
		msg_ret = FALSE;
		goto  email;
	}

	err = msg_reg_sms_message_callback(g_msg_handle,
			 __bluetooth_map_msg_incoming_status_cb,
			 0, (void *)BT_MAP_MSG_CB);

	if (err != MSG_SUCCESS) {
		ERR("msg_reg_sms_message_callback error  = %d\n", err);
		msg_ret = FALSE;
	}

email:
	email_err = email_service_begin();

	if (email_err != EMF_ERROR_NONE) {
		ERR("email_service_begin fail  error = %d\n", email_err);
		email_ret = FALSE;
	}

	if (msg_ret || email_ret)
		return TRUE;
	else
		return FALSE;
}

static void __bluetooth_map_stop_service()
{
	if (NULL != g_msg_handle)
		msg_close_msg_handle(&g_msg_handle);

	g_msg_handle = NULL;

	if (EMF_ERROR_NONE != email_service_end())
		ERR("email_service_end fail \n");
	return;
}

static gboolean bluetooth_map_get_folder_tree(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	MSG_FOLDER_LIST_S g_folderList;
	int i = 0;
	char name[BT_MAP_MSG_INFO_MAX] = {0,};
	int vconf_err = 0;
	int account_id = 0;
	emf_mailbox_t *mailbox_list = NULL;
	int mailbox_count = 0;
	bool flag = FALSE;
	int j = 0;
	GValue *value = NULL;
	GError *error = NULL;
	bool msg_ret = TRUE;

	if (__bluetooth_map_start_service() == FALSE)
		goto fail;

	if (g_msg_handle == NULL) {
		msg_ret = FALSE;
		goto email;
	}

	if (msg_get_folder_list(g_msg_handle, &g_folderList) != MSG_SUCCESS) {
		msg_ret = FALSE;
		goto email;
	}

	value = g_new0(GValue, 1);

	for (i = 0; i < g_folderList.nCount; i++) {
		g_strlcpy(name, g_folderList.folderInfo[i].folderName,
						sizeof(name));

		memset(value, 0, sizeof(GValue));
		g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
		g_value_take_boxed(value, dbus_g_type_specialized_construct(
					DBUS_STRUCT_STRING_STRING_UINT));
		dbus_g_type_struct_set(value, 0, name, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(value));
	}

email:
	vconf_err = vconf_get_int(BT_MAP_EMAIL_DEFAULTACCOUNT, &account_id);
	if (vconf_err == -1) {
		if (!msg_ret)
			goto fail;
	}

	if (EMF_ERROR_NONE != email_get_mailbox_list(account_id,
							EMF_MAILBOX_ALL,
							&mailbox_list,
							&mailbox_count)) {
		if (!msg_ret)
			goto fail;
	}

	for (i = 0; i < mailbox_count; i++) {
		flag = FALSE;
		for (j = 0; j < g_folderList.nCount; j++) {
			if (!g_ascii_strncasecmp(
				mailbox_list[i].name,
				g_folderList.folderInfo[j].folderName,
				strlen(mailbox_list[i].name))) {
				flag = TRUE;
				break;
			}
		}
		if (!flag) {
			g_strlcpy(name, mailbox_list[i].name, sizeof(name));
			memset(value, 0, sizeof(GValue));
			g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
			g_value_take_boxed(value,
				dbus_g_type_specialized_construct(
				DBUS_STRUCT_STRING_STRING_UINT));
			dbus_g_type_struct_set(value, 0, name, G_MAXUINT);
			g_ptr_array_add(array, g_value_get_boxed(value));
		}
	}

	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	g_free(value);
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
	return TRUE;

fail:
	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	g_free(value);
	g_ptr_array_free(array, TRUE);
	error = __bt_map_agent_error(BT_MAP_AGENT_ERROR_INTERNAL,
				  "InternalError");
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	return FALSE;
}

static gboolean bluetooth_map_get_message_list(BluetoothMapAgent *agent,
					gchar *folder_name,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	MSG_FOLDER_ID_T folder_id = 0;
	int i = 0;
	MSG_FOLDER_LIST_S g_folderList;
	MSG_SORT_RULE_S sortRule;
	MSG_LIST_S msg_list;
	GValue *value = NULL;
	char msg_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	char msg_type[BT_MAP_MSG_INFO_MAX] = {0,};
	char msg_datetime[BT_MAP_MSG_INFO_MAX] = {0,};
	char *folder = NULL;
	int vconf_err = 0;
	int account_id = 0;
	emf_mailbox_t *mailbox_list = NULL;
	int mailbox_count = 0;
	emf_mail_list_item_t *mail_list = NULL;
	int mail_count = 0;
	emf_mailbox_t mailbox;
	int total = 0;
	int unseen = 0;
	bool msg_ret = TRUE;
	GError *error = NULL;

	if (g_msg_handle == NULL) {
		msg_ret = FALSE;
		goto email;
	}

	value = g_new0(GValue, 1);

	folder = strrchr(folder_name, '/');

	if (NULL == folder)
		folder = folder_name;
	else
		folder++;

	if (msg_get_folder_list(g_msg_handle, &g_folderList) != MSG_SUCCESS) {
		msg_ret = FALSE;
		goto email;
	}

	for (i = 0; i < g_folderList.nCount; i++)
		if (!g_ascii_strncasecmp(folder,
				g_folderList.folderInfo[i].folderName,
				strlen(folder)))
			folder_id = g_folderList.folderInfo[i].folderId;

	if (MSG_SUCCESS != msg_get_folder_view_list(g_msg_handle,
					folder_id, &sortRule, &msg_list)) {
		msg_ret = FALSE;
		goto email;
	}

	for (i = 0; i < msg_list.nCount; i++) {
		time_t *time = NULL;
		struct tm local_time = {0,};

		memset(value, 0, sizeof(GValue));
		g_value_init(value, DBUS_STRUCT_MESSAGE_LIST);
		g_value_take_boxed(value, dbus_g_type_specialized_construct(
				DBUS_STRUCT_MESSAGE_LIST));

		snprintf(msg_handle, sizeof(msg_handle), "%d%s",
				msg_get_message_id(msg_list.msgInfo[i]),
				BT_MAP_SMS);

		time = msg_get_time(msg_list.msgInfo[i]);

		if (NULL != time)
			localtime_r(time, &local_time);

		snprintf(msg_datetime, sizeof(msg_datetime), "%d%d%dT%d%d%d",
				local_time.tm_year, local_time.tm_mon,
				local_time.tm_mday, local_time.tm_hour,
				local_time.tm_min, local_time.tm_sec);

		switch (msg_get_message_type(msg_list.msgInfo[i])) {
		case MSG_TYPE_SMS:
			g_strlcpy(msg_type,  "SMS_GSM", sizeof(msg_type));
			break;

		case MSG_TYPE_MMS:
			g_strlcpy(msg_type,  "MMS", sizeof(msg_type));
			break;

		default:
			g_strlcpy(msg_type,  "UNKNOWN", sizeof(msg_type));
			break;
		}
		dbus_g_type_struct_set(value, 0, msg_handle,
					1, msg_type,
					2, msg_datetime,
					G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(value));
	}

email:
	vconf_err = vconf_get_int(BT_MAP_EMAIL_DEFAULTACCOUNT, &account_id);
	if (vconf_err == -1) {
		if (!msg_ret)
		goto fail;
	}

	if (EMF_ERROR_NONE != email_get_mailbox_list(account_id,
						EMF_MAILBOX_ALL,
						&mailbox_list,
						&mailbox_count)) {
		if (!msg_ret)
		goto fail;
	}

	for (i = 0; i < mailbox_count; i++)
		if (!g_ascii_strncasecmp(mailbox_list[i].name, folder,
			strlen(mailbox_list[i].name)))
			folder_id = mailbox_list[i].account_id;
	memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
	mailbox.account_id = folder_id;
	mailbox.name = strdup(folder);
	if (EMF_ERROR_NONE != email_count_message(&mailbox, &total, &unseen)) {
		if (!msg_ret)
		goto fail;
	}

	if (mailbox.name != NULL)
		free(mailbox.name);

	if (EMF_ERROR_NONE != email_get_mail_list_ex(folder_id, folder,
				EMF_LIST_TYPE_NORMAL,
				0, total - 1, EMF_SORT_DATETIME_HIGH,
				&mail_list, &mail_count)) {
		if (!msg_ret)
		goto fail;
	}

	for (i = 0; i < mail_count; ++i) {
		memset(value, 0, sizeof(GValue));
		g_value_init(value, DBUS_STRUCT_MESSAGE_LIST);
		g_value_take_boxed(value, dbus_g_type_specialized_construct(
			DBUS_STRUCT_MESSAGE_LIST));

		snprintf(msg_handle, sizeof(msg_handle), "%d%s",
					mail_list[i].mail_id,
					BT_MAP_EMAIL);
		g_strlcpy(msg_type,  "EMAIL", sizeof(msg_type));

		/*Dummy for testing purpose*/
		snprintf(msg_datetime, sizeof(msg_datetime), "%dT%d", 2011, 12);
		dbus_g_type_struct_set(value, 0, msg_handle,
					1, msg_type,
					2, msg_datetime, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(value));
	}

	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	if (mail_list != NULL)
		g_free(mail_list);
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
	g_free(value);
	return TRUE;

fail:
	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	if (mail_list != NULL)
		g_free(mail_list);
	g_ptr_array_free(array, TRUE);
	g_free(value);
	error = __bt_map_agent_error(BT_MAP_AGENT_ERROR_INTERNAL,
				  "InternalError");
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	return FALSE;

}

static gboolean bluetooth_map_get_message(BluetoothMapAgent *agent,
					gchar *message_name,
					DBusGMethodInvocation *context)
{
	char *pch = NULL;
	char *last = NULL;
	int message_id = 0;
	FILE *body_file = NULL;
	GValue *value = NULL;
	int vconf_err = 0;
	int account_id = 0;
	GPtrArray *array = g_ptr_array_new();
	emf_mailbox_t mailbox;
	emf_mail_body_t *body = NULL;
	int nread = 0;
	char *buf = NULL;
	long l_size = 0;
	msg_message_t msg;
	MSG_ERROR_T msg_err = MSG_SUCCESS;
	MSG_SENDINGOPT_S sendOpt = { 0 };
	GError *error = NULL;

	if (message_name != NULL) {
		pch = strtok_r(message_name, "_", &last);
		if (pch == NULL)
			goto fail;

		message_id = atoi(pch);
		pch = strtok_r(NULL, "_", &last);
	} else
		goto fail;

	value = g_new0(GValue, 1);

	g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_take_boxed(value, dbus_g_type_specialized_construct(
			DBUS_STRUCT_STRING_STRING_UINT));

	if (!g_ascii_strncasecmp(pch, "s", 1)) {
		if (g_msg_handle == NULL)
			goto fail;

		msg = msg_new_message();
		msg_err = msg_get_message(g_msg_handle,
					(MSG_MESSAGE_ID_T)message_id,
					msg, &sendOpt);
		if (msg_err == MSG_SUCCESS) {
			dbus_g_type_struct_set(value, 0,
						msg_sms_get_message_body(msg),
						G_MAXUINT);
			g_ptr_array_add(array, g_value_get_boxed(value));
		}
		msg_release_message(&msg);
	} else if (!g_ascii_strncasecmp(pch, "e", 1)) {
		vconf_err = vconf_get_int(BT_MAP_EMAIL_DEFAULTACCOUNT,
							&account_id);
		if (vconf_err == -1)
			goto fail;

		memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
		mailbox.account_id = account_id;

		if (EMF_ERROR_NONE == email_get_body_info(&mailbox, message_id,
								&body)) {
			body_file = fopen(body->plain, "r");
			if (body_file == NULL)
				body_file = fopen(body->html, "rb");

			if (body_file != NULL) {
				fseek(body_file , 0, SEEK_END);
				l_size = ftell(body_file);
				rewind(body_file);

				buf = (char *)malloc(sizeof(char) * l_size);
				if (NULL == buf)
					goto fail;

				nread = fread(buf, 1, l_size, body_file);

				if (nread != l_size)
					goto fail;

				dbus_g_type_struct_set(value, 0, buf,
							G_MAXUINT);
				g_ptr_array_add(array,
						g_value_get_boxed(value));
			}
		}
	}

	dbus_g_method_return(context, array);
	g_free(value);
	g_ptr_array_free(array, TRUE);
	if (body_file != NULL)
		fclose(body_file);
	if (buf)
		free(buf);
	if (body)
		email_free_body_info(&body, 1);
	return TRUE;
fail:
	g_free(value);
	g_ptr_array_free(array, TRUE);
	if (body_file != NULL)
		fclose(body_file);
	if (buf)
		free(buf);
	if (body)
		email_free_body_info(&body, 1);
	error = __bt_map_agent_error(BT_MAP_AGENT_ERROR_INTERNAL,
				  "InternalError");
	dbus_g_method_return_error(context, error);
	g_error_free(error);
	return FALSE;
}

static gboolean bluetooth_map_update_message(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context)
{
	unsigned handle = 0;
	int err = EMF_ERROR_NONE;

	err = email_sync_header_for_all_account(&handle);

	if (err == EMF_ERROR_NONE) {
		DBG("Handle to stop download = %d \n", handle);
	} else {
		ERR("Message Update failed \n");
	}

	dbus_g_method_return(context, err);
	return (err == EMF_ERROR_NONE) ? TRUE : FALSE;
}

static gboolean bluetooth_map_message_status(BluetoothMapAgent *agent,
					gchar *message_name,
					int indicator, int value,
					DBusGMethodInvocation *context)
{
	char *pch = NULL;
	char *last = NULL;
	int message_id = 0;
	emf_mailbox_t mailbox;
	emf_mail_t *mail = NULL;
	msg_message_t msg;
	MSG_ERROR_T err = MSG_SUCCESS;
	MSG_SENDINGOPT_S sendOpt = { 0 };
	int ret = 0;
	bool flag = FALSE;
	GError *error = NULL;

	DBG("bluetooth_map_message_status");

	if (message_name != NULL) {
		pch = strtok_r(message_name, "_", &last);
		if (pch == NULL)
			goto done;

		message_id = atoi(pch);
		pch = strtok_r(NULL, "_", &last);
	} else
		goto done;

	DBG("message_id = %d, i = %d, v = %d\n", message_id, indicator, value);

	if (!g_ascii_strncasecmp(pch, "s", 1)) {
		switch (indicator) {
		case BT_MSG_UPDATE:{
			msg = msg_new_message();
			err = msg_get_message(g_msg_handle,
					    (MSG_MESSAGE_ID_T)message_id, msg,
					    &sendOpt);
			if (err != MSG_SUCCESS) {
				msg_release_message(&msg);
				goto done;
			}

			if (!msg_is_read(msg)) {
				DBG(" Message is UNREAD \n");

				ret = msg_update_read_status(
					g_msg_handle, message_id, TRUE);
				if (msg_is_mms(msg)) {
					ret = msg_mms_send_read_report(
						g_msg_handle,
						message_id,
						MSG_READ_REPORT_IS_READ);
				}
			} else {
				DBG("Message is READ \n");
				ret = msg_update_read_status(
					g_msg_handle,
					 message_id, FALSE);

				if (msg_is_mms(msg)) {
					ret = msg_mms_send_read_report(
						g_msg_handle,
						message_id,
						MSG_READ_REPORT_NONE);
				}
			}
			if (ret == MSG_SUCCESS)
				flag = TRUE;
			msg_release_message(&msg);
			break;
		}

		case BT_MSG_DELETE: {
			if (msg_delete_message(g_msg_handle, message_id) ==
						MSG_SUCCESS) {
				DBG("Message delete success");
				flag = TRUE;
			} else {
				ERR("Message delete fail");
				flag = FALSE;
			}
			break;
		}

		default:
			break;
		}
	} else if (!g_ascii_strncasecmp(pch, "e", 1)) {
		switch (indicator) {
		case 0: {
			emf_mail_flag_t newflag;
			memset(&newflag, 0x00, sizeof(emf_mail_flag_t));
			newflag.seen = !newflag.seen;
			newflag.answered = 0;
			newflag.sticky = 1;

			if (email_modify_mail_flag(message_id, newflag,
						1) < 0) {
				ERR("email_modify_mail_flag failed \n");
				flag = FALSE;
			} else {
				DBG("email_modify_mail_flag success \n");
				flag = TRUE;
			}
			break;
		}
		case 1: {
			memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
			if (email_get_mail(&mailbox, message_id, &mail) < 0) {
				ERR("email_get_mail failed\n");
			} else {
				DBG("email_get_mail success\n");
				if (email_delete_message(&mailbox, &message_id,
							1, 1) >= 9) {
					DBG("\n email_delete_message success");
					flag = TRUE;
				} else {
					ERR("\n email_delete_message failed");
					flag = FALSE;
				}
				email_free_mail(&mail, 1);
			}
			break;
		}

		default:
			break;
		}
	}

done:
	if (flag)
		dbus_g_method_return(context, ret);
	else {
		error = __bt_map_agent_error(BT_MAP_AGENT_ERROR_INTERNAL,
				  			"InternalError");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
	}
	return flag;
}

int main(int argc, char **argv)
{
	BluetoothMapAgent *bluetooth_map_obj = NULL;
	static DBusGConnection *connection = NULL;
	DBusGProxy *bus_proxy = NULL;
	guint result = 0;
	GError *error = NULL;

	g_type_init();

	mainloop = g_main_loop_new(NULL, FALSE);

	if (mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);

	if (error != NULL) {
		ERR("Couldn't connect to system bus[%s]\n", error->message);
		g_error_free(error);
		return EXIT_FAILURE;
	}

	bus_proxy = dbus_g_proxy_new_for_name(connection,
					DBUS_SERVICE_DBUS,
					DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (bus_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		goto failure;
	}

	if (!dbus_g_proxy_call(bus_proxy, "RequestName", &error, G_TYPE_STRING,
			BT_MAP_SERVICE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (error != NULL) {
			ERR("RequestName RPC failed[%s]\n", error->message);
			g_error_free(error);
		}
		goto failure;
	}
	DBG("result : %d %d\n", result, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		ERR("Failed to get the primary well-known name.\n");
		goto failure;
	}

	g_object_unref(bus_proxy);
	bus_proxy = NULL;

	bluetooth_map_obj = g_object_new(BLUETOOTH_MAP_TYPE_AGENT, NULL);
	if (bluetooth_map_obj == NULL) {
		ERR("Failed to create one BluetoothMapAgent instance.\n");
		goto failure;
	}

	/* Registering it on the D-Bus */
	dbus_g_connection_register_g_object(connection,
					BT_MAP_SERVICE_OBJECT_PATH,
					G_OBJECT(bluetooth_map_obj));

	g_main_loop_run(mainloop);

 failure:
	DBG("Terminate the bluetooth-map-agent\n");
	if (bus_proxy)
		g_object_unref(bus_proxy);
	if (bluetooth_map_obj)
		g_object_unref(bluetooth_map_obj);
	if (connection)
		dbus_g_connection_unref(connection);

	__bluetooth_map_stop_service();
	return EXIT_FAILURE;
}



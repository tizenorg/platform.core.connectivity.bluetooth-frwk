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
#include <time.h>
#include <errno.h>
#include "vconf.h"
#include "vconf-keys.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*Messaging Header Files*/
#include "MsgTypes.h"
#include "MapiStorage.h"
#include "MapiControl.h"
#include "MapiMessage.h"
#include "MapiTransport.h"

/*Email Header Files*/
#include "Emf_Mapi_Init.h"
#include "Emf_Mapi_Account.h"
#include "Emf_Mapi_Message.h"
#include "Emf_Mapi_Network.h"
#include "Emf_Mapi_Mailbox.h"

#include <bluetooth_map_agent.h>

#define DBUS_STRUCT_STRING_STRING_UINT (dbus_g_type_get_struct("GValueArray", G_TYPE_STRING, \
						G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))

#define DBUS_STRUCT_MESSAGE_LIST (dbus_g_type_get_struct("GValueArray", G_TYPE_STRING, \
						G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))
static MSG_HANDLE_T msgHandle = NULL;
#define BT_MAP_STATUS_CB "sent status callback"
#define BT_MAP_MSG_CB "sms message callback"
#define BT_MAP_EMAIL_DEFAULTACCOUNT "db/email/defaultaccount"
#define BT_MAP_SMS "_s"
#define BT_MAP_EMAIL "_e"
#define BT_MAP_MSG_INFO_MAX 256
#define BT_MAP_MSG_HANDLE_MAX 16

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

static void bluetooth_map_msg_sent_status_cb(MSG_HANDLE_T handle,
				MSG_SENT_STATUS_S *pStatus, void *pUserParam)
{
	if (NULL != pStatus) {
		if (pStatus->status == MSG_NETWORK_SEND_SUCCESS)
			DBG("reqId : %d \n", pStatus->reqId);
		else
			DBG("reqId : %d , status : %d \n",
					pStatus->reqId, pStatus->status);
	}
}

static void bluetooth_map_msg_incoming_status_cb(MSG_HANDLE_T Handle,
				msg_message_t msg, void *pUserParam)
{

}

static void bluetooth_map_start_service()
{
	MSG_ERROR_T err = MSG_SUCCESS;

	err = msg_open_msg_handle(&msgHandle);

	if (err != MSG_SUCCESS) {
		DBG("msg_open_msg_handle error = %d\n", err);
	} else {
		err =  msg_reg_sent_status_callback(msgHandle,
				bluetooth_map_msg_sent_status_cb,
				(void *)BT_MAP_STATUS_CB);

		if (err != MSG_SUCCESS) {
			DBG("msg_reg_sent_status_callback error = %d \n", err);
		} else {
			err = msg_reg_sms_message_callback(msgHandle,
					 bluetooth_map_msg_incoming_status_cb,
					 0, (void *)BT_MAP_MSG_CB);
			if (err != MSG_SUCCESS)
				DBG("msg_reg_sms_message_callback error  = %d\n", err);
		}
	}

	if (email_service_begin() != EMF_ERROR_NONE)
		DBG("email_service_begin fail \n");
	return;
}

static void bluetooth_map_stop_service()
{
	if (NULL != msgHandle)
		msg_close_msg_handle(&msgHandle);
	if (EMF_ERROR_NONE != email_service_end())
		DBG("email_service_end fail \n");
	return;
}

static gboolean bluetooth_map_get_folder_tree(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	int folder_count = 0;
	MSG_FOLDER_LIST_S g_folderList;
	int i = 0;
	char name[BT_MAP_MSG_INFO_MAX] = {0,};
	int vconf_err = 0;
	int account_id = 0;
	emf_mailbox_t *mailbox_list = NULL;
	int mailbox_count = 0;
	bool flag = FALSE;
	int j = 0;
	GValue *value;

	bluetooth_map_start_service();

	if (msg_get_folder_list(msgHandle, &g_folderList) == MSG_SUCCESS) {
		for (i = 0; i < g_folderList.nCount; i++) {
			g_strlcpy(name, g_folderList.folderInfo[i].folderName,
							sizeof(name));

			value = g_new0(GValue, 1);
			g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
			g_value_take_boxed(value,
				dbus_g_type_specialized_construct(
					DBUS_STRUCT_STRING_STRING_UINT));
			dbus_g_type_struct_set(value, 0, name, G_MAXUINT);
			g_ptr_array_add(array, g_value_get_boxed(value));
			g_free(value);
		}
	}

	vconf_err = vconf_get_int(BT_MAP_EMAIL_DEFAULTACCOUNT, &account_id);
	if (vconf_err != -1) {
		if (EMF_ERROR_NONE == email_get_mailbox_list(account_id,
								EMF_MAILBOX_ALL,
								&mailbox_list,
								&mailbox_count)) {
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
					g_strlcpy(name, mailbox_list[i].name,
							sizeof(name));
					value = g_new0(GValue, 1);
					g_value_init(value,
						DBUS_STRUCT_STRING_STRING_UINT);
					g_value_take_boxed(value,
						dbus_g_type_specialized_construct(
						DBUS_STRUCT_STRING_STRING_UINT));
					dbus_g_type_struct_set(value, 0, name, G_MAXUINT);
					g_ptr_array_add(array, g_value_get_boxed(value));
					g_free(value);
				}
			}
		}
	}

	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);

	return TRUE;
}

static gboolean bluetooth_map_get_message_list(BluetoothMapAgent *agent,
					gchar *folder_name,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	MSG_FOLDER_ID_T folder_id = 0;
	int i = 0;
	MSG_FOLDER_LIST_S g_folderList;
	MSG_ERROR_T err = MSG_SUCCESS;
	MSG_SORT_RULE_S sortRule;
	MSG_LIST_S msg_list;
	GValue *value;
	char msg_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	char msg_type[BT_MAP_MSG_INFO_MAX] = {0,};
	char msg_subject[BT_MAP_MSG_INFO_MAX] = {0,};
	char msg_datetime[BT_MAP_MSG_INFO_MAX] = {0,};
	char s_name[BT_MAP_MSG_INFO_MAX] = {0,};
	char s_address[BT_MAP_MSG_INFO_MAX] = {0,};
	char r_2_address[BT_MAP_MSG_INFO_MAX] = {0,};
	char r_name[BT_MAP_MSG_INFO_MAX] = {0,};
	char r_address[BT_MAP_MSG_INFO_MAX] = {0,};
	char recp_status[BT_MAP_MSG_INFO_MAX] = {0,};
	int msg_size = 0;
	int att_size = 0;
	gboolean text;
	gboolean read;
	gboolean sent;
	gboolean protect;
	gboolean priority;
	char *folder;
	int vconf_err = 0;
	int account_id = 0;
	emf_mailbox_t *mailbox_list = NULL;
	int mailbox_count = 0;

	emf_mail_list_item_t *mail_list = NULL;
	int mail_count = 0;
	int err_m;
	emf_mailbox_t mailbox;
	int total = 0;
	int unseen = 0;

	folder = strrchr(folder_name, '/');
	if (NULL == folder)
			folder = folder_name;
		else
			folder++;

	if (msg_get_folder_list(msgHandle, &g_folderList) == MSG_SUCCESS)
		for (i = 0; i < g_folderList.nCount; i++)
			if (!g_ascii_strncasecmp(folder,
					g_folderList.folderInfo[i].folderName,
					strlen(folder)))
				folder_id = g_folderList.folderInfo[i].folderId;

	err = msg_get_folder_view_list(msgHandle, folder_id,
				     &sortRule, &msg_list);
	/*SMS and MMS*/
	if (err == MSG_SUCCESS) {
		for (i = 0; i < msg_list.nCount; i++) {
			value = g_new0(GValue, 1);
			g_value_init(value, DBUS_STRUCT_MESSAGE_LIST);
			g_value_take_boxed(value, dbus_g_type_specialized_construct(
					DBUS_STRUCT_MESSAGE_LIST));
			snprintf(msg_handle, sizeof(msg_handle), "%d%s",
				msg_get_message_id(msg_list.msgInfo[i]),
				BT_MAP_SMS);
			snprintf(msg_datetime, sizeof(msg_datetime), "%dT%d",
				(int)msg_get_time(msg_list.msgInfo[i]));

			DBG("date n time = %s \n ", msg_datetime);

			switch (msg_get_message_type(msg_list.msgInfo[i])) {
			case MSG_TYPE_SMS:
				g_strlcpy(msg_type,  "SMS_GSM",
					sizeof(msg_type));
				break;

			case MSG_TYPE_MMS:
				g_strlcpy(msg_type,  "MMS",
					sizeof(msg_type));
				break;

			default:
				g_strlcpy(msg_type,  "UNKNOWN",
					sizeof(msg_type));
				break;
			}
			dbus_g_type_struct_set(value, 0, msg_handle,
						1, msg_type,
						2, msg_datetime,
						G_MAXUINT);
			g_ptr_array_add(array, g_value_get_boxed(value));
			g_free(value);
		}
	}
	/*Email*/
	vconf_err = vconf_get_int(BT_MAP_EMAIL_DEFAULTACCOUNT, &account_id);
	if (vconf_err != -1) {
		if (EMF_ERROR_NONE == email_get_mailbox_list(account_id,
							EMF_MAILBOX_ALL,
							&mailbox_list,
							&mailbox_count))
			for (i = 0; i < mailbox_count; i++)
				if (!g_ascii_strncasecmp(mailbox_list[i].name, folder,
					strlen(mailbox_list[i].name)))
					folder_id = mailbox_list[i].account_id;
		memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
		mailbox.account_id = folder_id;
		mailbox.name = strdup(folder);
		if (EMF_ERROR_NONE == email_count_message(&mailbox, &total,
							&unseen)) {
			DBG(" Total: %d, Unseen: %d \n", total, unseen);
		}

		if (mailbox.name != NULL)
			free(mailbox.name);

		err_m = email_get_mail_list_ex(folder_id, folder,
					EMF_LIST_TYPE_NORMAL,
					0, total - 1, EMF_SORT_DATETIME_HIGH,
					&mail_list, &mail_count);
		if (err_m == EMF_ERROR_NONE) {
			for (i = 0; i < mail_count; ++i) {
				value = g_new0(GValue, 1);
				g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
				g_value_take_boxed(value, dbus_g_type_specialized_construct(
					DBUS_STRUCT_STRING_STRING_UINT));
				snprintf(msg_handle, sizeof(msg_handle), "%d%s",
							mail_list[i].mail_id,
							BT_MAP_EMAIL);
				g_strlcpy(msg_type,  "EMAIL",
						sizeof(msg_type));
				/*Dummy for testing purpose*/
				snprintf(msg_datetime, sizeof(msg_datetime), "%dT%d",
								12345);
				dbus_g_type_struct_set(value, 0, msg_handle,
							1, msg_type,
							2, msg_datetime, G_MAXUINT);
				g_ptr_array_add(array, g_value_get_boxed(value));
				g_free(value);
			}
		}
	}
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
}

static gboolean bluetooth_map_get_message(BluetoothMapAgent *agent,
					gchar *message_name,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	char *pch, *last;
	int message_id;
	GValue *value;

	if (message_name != NULL) {
		pch = strtok_r(message_name, "_", &last);
		if (pch == NULL)
			return -1;

		message_id = atoi(pch);
		pch = strtok_r(NULL, "_", &last);
	}

	value = g_new0(GValue, 1);
	g_value_init(value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_take_boxed(value, dbus_g_type_specialized_construct(
			DBUS_STRUCT_STRING_STRING_UINT));

	if (!g_ascii_strncasecmp(pch, "s", 1)) {
		msg_message_t msg ;
		MSG_ERROR_T err = MSG_SUCCESS;
		MSG_SENDINGOPT_S sendOpt = { 0 };

		msg = msg_new_message();
		err = msg_get_message(msgHandle, (MSG_MESSAGE_ID_T)message_id,
							msg,
							&sendOpt);
		if (err == MSG_SUCCESS)
			DBG("Body =%s \n", msg_sms_get_message_body(msg));
		dbus_g_type_struct_set(value, 0, msg_sms_get_message_body(msg),
						G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(value));
		g_free(value);

	} else if (!g_ascii_strncasecmp(pch, "e", 1)) {
		emf_mailbox_t mailbox;
		emf_mail_t *mail = NULL;
		emf_mail_body_t *body = NULL;
		FILE *body_file;
		int nread = 0;
		char *buf;
		long lSize;

		memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
		if (EMF_ERROR_NONE ==  email_get_mail(&mailbox, message_id, &mail)) {
			if (EMF_ERROR_NONE ==
					email_get_body_from_mail(mail, &body)) {
				body_file = fopen(body->html, "r");
				if (body_file == NULL)
					body_file = fopen(body->plain, "r");
				if (body_file != NULL) {
					/* obtain file size */
					fseek(body_file , 0 , SEEK_END);
					lSize = ftell(body_file);
					rewind(body_file);

					nread = fread(buf, 1, lSize, body_file);
					if (nread != lSize)
						DBG("Read error email \n");
					else {
						dbus_g_type_struct_set(value, 0,
							buf,
							G_MAXUINT);
						g_ptr_array_add(array, g_value_get_boxed(value));
						g_free(value);
					}
				}
			}
		}
	}
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
}

static gboolean bluetooth_map_update_message(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context)
{
	unsigned handle;
	int err;

	DBG("bluetooth_map_update_message 123");

	err = email_sync_header_for_all_account(&handle);
	if (err == EMF_ERROR_NONE) {
		DBG("Handle to stop download = %d \n", handle);
	} else {
		DBG("Message Update failed \n");
	}
	dbus_g_method_return(context, err);
}

static gboolean bluetooth_map_message_status(BluetoothMapAgent *agent,
					gchar *message_name,
					int indicator, int value,
					DBusGMethodInvocation *context)
{
	char *pch, *last;
	int message_id;
	emf_mailbox_t mailbox;
	emf_mail_t *mail = NULL;
	msg_message_t msg;
	MSG_ERROR_T err = MSG_SUCCESS;
	MSG_SENDINGOPT_S sendOpt = { 0 };
	int ret;

	DBG("bluetooth_map_message_status");

	if (message_name != NULL) {
		pch = strtok_r(message_name, "_", &last);
		if (pch == NULL)
			return -1;

		message_id = atoi(pch);
		pch = strtok_r(NULL, "_", &last);
	}
	DBG("Message handle = %d, i = %d, v = %d\n", message_id, indicator, value);

	if (!g_ascii_strncasecmp(pch, "s", 1)) {
		switch (indicator) {
		case 0:{
			msg = msg_new_message();
			err = msg_get_message(msgHandle,
					    (MSG_MESSAGE_ID_T)message_id, msg,
					    &sendOpt);
			if (err == MSG_SUCCESS) {
				if (!msg_is_read(msg)) {
					DBG(" Message is UNREAD \n");

					ret = msg_update_read_status(msgHandle,
								message_id, TRUE);
					if (msg_is_mms(msg)) {
						ret = msg_mms_send_read_report(
							msgHandle,
							message_id,
							MSG_READ_REPORT_IS_READ);
					}
				} else {
					DBG("Message is READ \n");
					ret = msg_update_read_status(msgHandle,
								   message_id,
								   FALSE);

					if (msg_is_mms(msg)) {
						ret = msg_mms_send_read_report(
							msgHandle,
							message_id,
							MSG_READ_REPORT_NONE);
					}
				}
				msg_release_message(&msg);
			} else {
				DBG("Get message failed %d\n", err);
			}

			break;
		}

		case 1: {
			if (msg_delete_message(msgHandle, message_id) ==  MSG_SUCCESS) {
				DBG("Message delete success");
				ret = TRUE;
			} else {
				DBG("Message delete fail");
				ret = FALSE;
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

			if (email_modify_mail_flag(message_id, newflag, 1) < 0) {
				DBG("email_modify_mail_flag failed \n");
				ret = FALSE;
			} else {
				DBG("email_modify_mail_flag success \n");
				ret = TRUE;
			}
			break;
		}
		case 1: {
			memset(&mailbox, 0x00, sizeof(emf_mailbox_t));
			if (email_get_mail(&mailbox, message_id, &mail) < 0) {
				DBG("email_get_mail failed\n");
			} else {
				DBG("email_get_mail success\n");
				if (email_delete_message(&mailbox, &message_id, 1, 1) >= 9) {
					DBG("\n email_delete_message success");
					ret = TRUE;
				} else {
					DBG("\n email_delete_message failed");
					ret = FALSE;
				}
				email_free_mail(&mail, 1);
			}
			break;
		}

		default:
			break;
		}
	}
	dbus_g_method_return(context, ret);
}

int main(int argc, char **argv)
{
	BluetoothMapAgent *bluetooth_map_obj = NULL;
	DBusGConnection *bus = NULL;
	DBusGProxy *bus_proxy = NULL;
	guint result = 0;
	GError *error = NULL;

	g_type_init();
	DBG("Map Agent\n");
	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		DBG("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		DBG("Couldn't connect to system bus[%s]\n", error->message);
		g_error_free(error);
		return EXIT_FAILURE;
	}

	bus_proxy = dbus_g_proxy_new_for_name(bus, DBUS_SERVICE_DBUS,
					DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (bus_proxy == NULL) {
		DBG("Failed to get a proxy for D-Bus\n");
		goto failure;
	}

	if (!dbus_g_proxy_call(bus_proxy, "RequestName", &error, G_TYPE_STRING,
			BT_MAP_SERVICE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (error != NULL) {
			DBG("RequestName RPC failed[%s]\n", error->message);
			g_error_free(error);
		}
		goto failure;
	}
	DBG("result : %d %d\n", result, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		DBG("Failed to get the primary well-known name.\n");
		goto failure;
	}

	g_object_unref(bus_proxy);
	bus_proxy = NULL;

	bluetooth_map_obj = g_object_new(BLUETOOTH_MAP_TYPE_AGENT, NULL);
	if (bluetooth_map_obj == NULL) {
		DBG("Failed to create one BluetoothMapAgent instance.\n");
		goto failure;
	}

	/* Registering it on the D-Bus */
	dbus_g_connection_register_g_object(bus, BT_MAP_SERVICE_OBJECT_PATH,
						G_OBJECT(bluetooth_map_obj));

	g_main_loop_run(mainloop);

 failure:
	DBG("Terminate the bluetooth-map-agent\n");
	if (bus)
		dbus_g_connection_unref(bus);
	if (bus_proxy)
		g_object_unref(bus_proxy);
	if (bluetooth_map_obj)
		g_object_unref(bluetooth_map_obj);

	return EXIT_FAILURE;
}



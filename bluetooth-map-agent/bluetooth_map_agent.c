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
#include "vconf.h"
#include "vconf-keys.h"

#include <sys/types.h>
#include <fcntl.h>

/*Messaging Header Files*/
#include "msg.h"
#include "msg_storage.h"
#include "msg_storage_types.h"
#include "msg_transport.h"
#include "msg_transport_types.h"
#include "msg_types.h"

/*Email Header Files*/
#include "email-types.h"
#include "email-api-init.h"
#include "email-api-account.h"
#include "email-api-mailbox.h"
#include "email-api-mail.h"
#include "email-api-network.h"

#include <bluetooth_map_agent.h>

#define OBEX_CLIENT_SERVICE "org.openobex.client"
#define OBEX_CLIENT_INTERFACE "org.openobex.Client"
#define OBEX_CLIENT_PATH "/"

#define DBUS_STRUCT_STRING_STRING_UINT (dbus_g_type_get_struct("GValueArray", \
		G_TYPE_STRING, G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))

#define DBUS_STRUCT_MESSAGE_LIST (dbus_g_type_get_struct("GValueArray", \
		G_TYPE_STRING, G_TYPE_STRING,  G_TYPE_STRING, G_TYPE_INVALID))

static msg_handle_t g_msg_handle = NULL;
#define BT_MAP_NEW_MESSAGE "NewMessage"
#define BT_MAP_STATUS_CB "sent status callback"
#define BT_MAP_MSG_CB "sms message callback"
#define BT_MAP_EMAIL_DEFAULTACCOUNT "db/email/defaultaccount"
#define BT_MAP_SMS "_s"
#define BT_MAP_EMAIL "_e"
#define BT_MAP_MSG_INFO_MAX 256
#define BT_MAP_MSG_HANDLE_MAX 16
#define BT_MAP_TIMESTAMP_MAX_LEN 16
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

GMainLoop *g_mainloop = NULL;
static DBusGConnection *g_connection = NULL;
static char *g_mns_path = NULL;

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
static gboolean bluetooth_map_noti_registration(BluetoothMapAgent *agent,
					gchar *remote_addr,
					gboolean status,
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

static void __bluetooth_map_msg_incoming_status_cb(msg_handle_t handle,
				msg_struct_t msg, void *user_param)
{
	DBusMessage *message = NULL;
	char *message_type = NULL;
	DBusConnection *conn;
	int msg_id = 0;
	int msg_type = 0;
	char msg_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	int ret = MSG_SUCCESS;

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


	ret = msg_get_int_value(msg,
			MSG_MESSAGE_ID_INT, &msg_id);
	if (ret != MSG_SUCCESS)
		return;

	snprintf(msg_handle, sizeof(msg_handle), "%d%s",
			msg_id,
			BT_MAP_SMS);

	ret = msg_get_int_value(msg,
			MSG_MESSAGE_TYPE_INT, &msg_type);
	if (ret != MSG_SUCCESS)
		return;

	switch (msg_type) {
	case MSG_TYPE_SMS:
		message_type = g_strdup("SMS_GSM");
		break;
	case MSG_TYPE_MMS:
		message_type = g_strdup("MMS");
		break;
	default:
		message_type = g_strdup("UNKNOWN");
		break;

	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &message_type,
						DBUS_TYPE_INT32, &msg_handle,
						DBUS_TYPE_INVALID);

	dbus_message_set_no_reply(message, TRUE);
	dbus_connection_send(conn, message, NULL);
	dbus_message_unref(message);
	dbus_connection_unref(conn);
	g_free(message_type);
}

static gboolean __bluetooth_map_start_service()
{
	msg_error_t err = MSG_SUCCESS;
	int email_err = EMAIL_ERROR_NONE;
	gboolean msg_ret = TRUE;
	gboolean email_ret = TRUE;

	err = msg_open_msg_handle(&g_msg_handle);
	if (err != MSG_SUCCESS) {
		ERR("msg_open_msg_handle error = %d\n", err);
		msg_ret = FALSE;
		goto email;
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
	if (email_err != EMAIL_ERROR_NONE) {
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

	if (EMAIL_ERROR_NONE != email_service_end())
		ERR("email_service_end fail \n");
	return;
}

static void __get_msg_timestamp(time_t *ltime, char *timestamp)
{
	struct tm local_time;
	int year;
	int month;

	if (!localtime_r(ltime, &local_time))
		return;

	year = local_time.tm_year + 1900; /* years since 1900 */
	month = local_time.tm_mon + 1; /* months since January */
	snprintf(timestamp, 16, "%04d%02d%02dT%02d%02d%02d",
				year, month,
				local_time.tm_mday, local_time.tm_hour,
				local_time.tm_min, local_time.tm_sec);

	return;
}

gboolean static __bt_msg_is_mms(int msg_type)
{
	gboolean result = FALSE;

	switch (msg_type) {
	case MSG_TYPE_MMS_NOTI:
	case MSG_TYPE_MMS_JAVA:
	case MSG_TYPE_MMS:
		result = TRUE;
		break;
	default:
		break;
	}

	return result;
}

static void __bt_mns_client_connect(char *address)
{
	DBusGProxy *mns_proxy;
	GHashTable *hash;
	GValue *addr_value;
	GValue *tgt_value;
	GError *error = NULL;
	const char *session_path = NULL;

	DBG("+ address %s\n", address);

	mns_proxy = dbus_g_proxy_new_for_name(g_connection,
					OBEX_CLIENT_SERVICE,
					OBEX_CLIENT_PATH,
					OBEX_CLIENT_INTERFACE);
	if (mns_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		return;
	}

	hash = g_hash_table_new_full(g_str_hash, g_str_equal,
				     NULL, (GDestroyNotify)g_free);

	addr_value = g_new0(GValue, 1);
	g_value_init(addr_value, G_TYPE_STRING);
	g_value_set_string(addr_value, address);
	g_hash_table_insert(hash, "Destination", addr_value);

	tgt_value = g_new0(GValue, 1);
	g_value_init(tgt_value, G_TYPE_STRING);
	g_value_set_string(tgt_value, "MNS");
	g_hash_table_insert(hash, "Target", tgt_value);

	dbus_g_proxy_call(mns_proxy, "CreateSession", &error,
		dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
		hash, G_TYPE_INVALID,
		DBUS_TYPE_G_OBJECT_PATH, &session_path,
		G_TYPE_INVALID);
	if (error) {
		DBG("Error [%s]", error->message);
		g_error_free(error);
		g_hash_table_destroy(hash);
		g_object_unref(mns_proxy);
		return;
	}

	g_mns_path = g_strdup(session_path);
	DBG("g_mns_path = %s\n", g_mns_path);

	g_hash_table_destroy(hash);
	g_object_unref(mns_proxy);

	DBG("-\n");
	return;
}

static void __bt_mns_client_disconnect()
{
	DBusGProxy *mns_proxy;
	GError *error = NULL;

	if (!g_mns_path)
		return;

	mns_proxy = dbus_g_proxy_new_for_name(g_connection,
					OBEX_CLIENT_SERVICE,
					OBEX_CLIENT_PATH,
					OBEX_CLIENT_INTERFACE);
	if (mns_proxy == NULL) {
		DBG("Failed to get a proxy for D-Bus\n");
		return;
	}

	dbus_g_proxy_call(mns_proxy, "RemoveSession", &error,
		DBUS_TYPE_G_OBJECT_PATH, g_mns_path,
		G_TYPE_INVALID, G_TYPE_INVALID);
	if (error) {
		DBG("Error [%s]", error->message);
		g_error_free(error);
		g_object_unref(mns_proxy);
		return;
	}

	g_free(g_mns_path);
	g_mns_path = NULL;

	g_object_unref(mns_proxy);

	DBG("-\n");
	return;
}

static gboolean bluetooth_map_get_folder_tree(BluetoothMapAgent *agent,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	GValue value;
	GError *error = NULL;

	char name[BT_MAP_MSG_INFO_MAX] = {0,};
	char folder_name[BT_MAP_MSG_INFO_MAX] = {0,};
	int i;
	int j;
	int account_id = 0;
	int mailbox_count = 0;
	int ret = MSG_SUCCESS;
	gboolean flag = FALSE;
	gboolean msg_ret = TRUE;

	msg_struct_list_s g_folderList;
	msg_struct_t p_folder;
	email_mailbox_t *mailbox_list = NULL;

	if (g_msg_handle == NULL) {
		msg_ret = FALSE;
		goto email;
	}

	if (msg_get_folder_list(g_msg_handle, &g_folderList) != MSG_SUCCESS) {
		msg_ret = FALSE;
		goto email;
	}

	for (i = 0; i < g_folderList.nCount; i++) {
		p_folder = g_folderList.msg_struct_info[i];
		memset(folder_name, 0x00, BT_MAP_MSG_INFO_MAX);

		ret = msg_get_str_value(p_folder, MSG_FOLDER_INFO_NAME_STR,
					folder_name, BT_MAP_MSG_INFO_MAX);
		if (ret != MSG_SUCCESS)
			continue;

		g_strlcpy(name, folder_name, sizeof(name));
		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
		g_value_take_boxed(&value, dbus_g_type_specialized_construct(
					DBUS_STRUCT_STRING_STRING_UINT));
		dbus_g_type_struct_set(&value, 0, name, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(&value));
	}

email:
	if (EMAIL_ERROR_NONE != email_load_default_account_id(&account_id))
		goto done;

	if (EMAIL_ERROR_NONE != email_get_mailbox_list(account_id,
							EMAIL_MAILBOX_ALL,
							&mailbox_list,
							&mailbox_count)) {
		goto done;
	}

	msg_ret = TRUE;

	for (i = 0; i < mailbox_count; i++) {
		flag = FALSE;
		for (j = 0; j < g_folderList.nCount; j++) {

			p_folder = g_folderList.msg_struct_info[j];
			memset(folder_name, 0x00, BT_MAP_MSG_INFO_MAX);

			ret = msg_get_str_value(p_folder, MSG_FOLDER_INFO_NAME_STR,
						folder_name, BT_MAP_MSG_INFO_MAX);
			if (ret != MSG_SUCCESS)
				continue;

			if (!g_ascii_strncasecmp(mailbox_list[i].alias,
				folder_name, strlen(mailbox_list[i].alias))) {
				flag = TRUE;
				break;
			}
		}

		if (!flag) {
			g_strlcpy(name, mailbox_list[i].alias, sizeof(name));
			memset(&value, 0, sizeof(GValue));
			g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
			g_value_take_boxed(&value,
				dbus_g_type_specialized_construct(
				DBUS_STRUCT_STRING_STRING_UINT));
			dbus_g_type_struct_set(&value, 0, name, G_MAXUINT);
			g_ptr_array_add(array, g_value_get_boxed(&value));
		}
	}

	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);

done:

	if (msg_ret == FALSE) {
		g_ptr_array_free(array, TRUE);

		error = __bt_map_agent_error(BT_MAP_AGENT_ERROR_INTERNAL,
					"InternalError");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return FALSE;
	} else {
		dbus_g_method_return(context, array);
		g_ptr_array_free(array, TRUE);
		return TRUE;
	}
}

static gboolean bluetooth_map_get_message_list(BluetoothMapAgent *agent,
					gchar *folder_name,
					DBusGMethodInvocation *context)
{
	GPtrArray *array = g_ptr_array_new();
	GValue value;
	GError *error = NULL;

	char msg_handle[BT_MAP_MSG_HANDLE_MAX] = {0,};
	char msg_type[BT_MAP_MSG_INFO_MAX] = {0,};
	char msg_datetime[BT_MAP_TIMESTAMP_MAX_LEN] = {0,};
	char *folder = NULL;
	char *type = NULL;
	int i = 0;
	int account_id = 0;
	int mailbox_count = 0;
	int mail_count = 0;
	int total = 0;
	gboolean msg_ret = TRUE;
	int ret = 0;
	int folder_id = 0;

	msg_struct_list_s g_folderList;
	msg_struct_list_s msg_list;

	email_mailbox_t *mailbox_list = NULL;
	email_mail_list_item_t *mail_list = NULL;
	email_list_filter_t *filter_list = NULL;
	email_list_sorting_rule_t *sorting_rule_list = NULL;

	if (g_msg_handle == NULL) {
		msg_ret = FALSE;
		goto email;
	}

	folder = strrchr(folder_name, '/');
	if (NULL == folder)
		folder = folder_name;
	else
		folder++;

	ret = msg_get_folder_list(g_msg_handle, &g_folderList);
	if (ret  != MSG_SUCCESS) {
		msg_ret = FALSE;
		goto email;
	}

	for (i = 0; i < g_folderList.nCount; i++) {
		msg_struct_t pFolder = g_folderList.msg_struct_info[i];
		char folderName[BT_MAP_MSG_INFO_MAX] = {0, };

		ret = msg_get_str_value(pFolder, MSG_FOLDER_INFO_NAME_STR,
						folderName, BT_MAP_MSG_INFO_MAX);
		if (ret  != MSG_SUCCESS)
			continue;

		if (!g_ascii_strncasecmp(folder, folderName, strlen(folder))) {
			ret = msg_get_int_value(pFolder, MSG_FOLDER_INFO_ID_INT, &folder_id);
			if (ret != MSG_SUCCESS) {
				msg_ret = FALSE;
			} else {
				DBG("folder_id %d \n", folder_id);
			}
			break;
		}
	}

	if (msg_ret == FALSE)
		goto email;

	/* Need to apply filter on the code based on remote request */
	if (MSG_SUCCESS != msg_get_folder_view_list(g_msg_handle,
					folder_id, NULL, &msg_list)) {
		msg_ret = FALSE;
		goto email;
	}

	for (i = 0; i < msg_list.nCount; i++) {
		int dptime;
		int m_id = 0;
		int m_type = 0;

		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, DBUS_STRUCT_MESSAGE_LIST);
		g_value_take_boxed(&value, dbus_g_type_specialized_construct(
				DBUS_STRUCT_MESSAGE_LIST));

		ret = msg_get_int_value(msg_list.msg_struct_info[i],
							MSG_MESSAGE_ID_INT, &m_id);
		if (ret != MSG_SUCCESS)
			continue;

		snprintf(msg_handle, sizeof(msg_handle), "%d%s",
				m_id,
				BT_MAP_SMS);

		ret = msg_get_int_value(msg_list.msg_struct_info[i],
				MSG_MESSAGE_DISPLAY_TIME_INT, &dptime);
		if (ret == MSG_SUCCESS)
			__get_msg_timestamp((time_t *)&dptime, msg_datetime);

		msg_get_int_value(msg_list.msg_struct_info[i],
				MSG_MESSAGE_TYPE_INT, &m_type);

		switch (m_type) {
		case MSG_TYPE_SMS:
			g_strlcpy(msg_type, "SMS_GSM", sizeof(msg_type));
			break;

		case MSG_TYPE_MMS:
			g_strlcpy(msg_type, "MMS", sizeof(msg_type));
			break;

		default:
			g_strlcpy(msg_type, "UNKNOWN", sizeof(msg_type));
			break;
		}

		dbus_g_type_struct_set(&value, 0, msg_handle,
					1, msg_type,
					2, msg_datetime,
					G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(&value));
	}

email:
	if (EMAIL_ERROR_NONE != email_load_default_account_id(&account_id)) {
		if (!msg_ret)
			goto fail;
	}

	if (EMAIL_ERROR_NONE != email_get_mailbox_list(account_id,
						EMAIL_MAILBOX_ALL,
						&mailbox_list,
						&mailbox_count)) {
		if (!msg_ret)
			goto fail;
	}

	if (mailbox_list == NULL)
		goto fail;

	for (i = 0; i < mailbox_count; i++) {
		DBG("mailbox alias = %s \n", mailbox_list[i].alias);
		if (!g_ascii_strncasecmp(mailbox_list[i].alias, folder,
			strlen(mailbox_list[i].alias))) {
			total = mailbox_list[i].total_mail_count_on_server;
			DBG("Total mail on sever : %d \n", total);
			DBG("mailbox name : %s \n", mailbox_list[i].mailbox_name);

			break;
		}

		if (!msg_ret)
			goto fail;
		else
			goto done;
	}

	/* Need to modify the filter code, have to make it dynamic based on remote device request*/
	/* Also to check whether it needs to be done in agent or in obexd */

	filter_list = g_new0(email_list_filter_t, 3);
	filter_list[0].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_RULE;
	filter_list[0].list_filter_item.rule.target_attribute = EMAIL_MAIL_ATTRIBUTE_ACCOUNT_ID;
	filter_list[0].list_filter_item.rule.rule_type = EMAIL_LIST_FILTER_RULE_EQUAL;
	filter_list[0].list_filter_item.rule.key_value.integer_type_value = account_id;

	filter_list[1].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_OPERATOR;
	filter_list[1].list_filter_item.operator_type = EMAIL_LIST_FILTER_OPERATOR_AND;

	filter_list[2].list_filter_item_type = EMAIL_LIST_FILTER_ITEM_RULE;
	filter_list[2].list_filter_item.rule.target_attribute = EMAIL_MAIL_ATTRIBUTE_MAILBOX_NAME;
	filter_list[2].list_filter_item.rule.rule_type = EMAIL_LIST_FILTER_RULE_EQUAL;
	type = g_strdup(mailbox_list[i].mailbox_name);
	filter_list[2].list_filter_item.rule.key_value.string_type_value = type;
	filter_list[2].list_filter_item.rule.case_sensitivity = true;

	sorting_rule_list = g_new0(email_list_sorting_rule_t, 1);
	sorting_rule_list->target_attribute = EMAIL_MAIL_ATTRIBUTE_DATE_TIME;
	sorting_rule_list->sort_order = EMAIL_SORT_ORDER_ASCEND;

	ret = email_get_mail_list_ex(filter_list, 3,
				sorting_rule_list, 1, 0, total - 1,
				&mail_list, &mail_count);

	DBG("email API ret %d  \n", ret);
	if (ret != EMAIL_ERROR_NONE) {
		if (!msg_ret) {
			g_free(type);
			g_free(filter_list);
			g_free(sorting_rule_list);
			goto fail;
		} else
			goto done;
	}

	for (i = 0; i < mail_count; ++i) {
		time_t time = {0,};
		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, DBUS_STRUCT_MESSAGE_LIST);
		g_value_take_boxed(&value, dbus_g_type_specialized_construct(
			DBUS_STRUCT_MESSAGE_LIST));

		snprintf(msg_handle, sizeof(msg_handle), "%d%s",
					mail_list[i].mail_id,
					BT_MAP_EMAIL);
		g_strlcpy(msg_type,  "EMAIL", sizeof(msg_type));

		time = mail_list[i].date_time;
		__get_msg_timestamp(&time, msg_datetime);

		dbus_g_type_struct_set(&value, 0, msg_handle,
					1, msg_type,
					2, msg_datetime, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(&value));
	}

done:
	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	if (mail_list != NULL)
		g_free(mail_list);
	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
	g_free(type);
	g_free(filter_list);
	g_free(sorting_rule_list);
	return TRUE;

fail:
	if (mailbox_list != NULL)
		 email_free_mailbox(&mailbox_list, mailbox_count);
	if (mail_list != NULL)
		g_free(mail_list);
	g_ptr_array_free(array, TRUE);
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
	GValue value = { 0, };
	int account_id = 0;
	GPtrArray *array = g_ptr_array_new();
	email_mail_data_t *mail_data = NULL;
	int nread = 0;
	char *buf = NULL;
	long l_size = 0;

	GError *error = NULL;

	if (message_name != NULL) {
		pch = strtok_r(message_name, "_", &last);
		if (pch == NULL)
			goto fail;

		message_id = atoi(pch);
		DBG("message_id %d \n", message_id);
		pch = strtok_r(NULL, "_", &last);
	} else
		goto fail;

	g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_take_boxed(&value, dbus_g_type_specialized_construct(
			DBUS_STRUCT_STRING_STRING_UINT));

	if (!g_ascii_strncasecmp(pch, "s", 1)) {
		if (g_msg_handle == NULL)
			goto fail;

		int msg_size = 0;
		msg_error_t msg_err = MSG_SUCCESS;
		msg_struct_t msg = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
		msg_struct_t send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);

		msg_err = msg_get_message(g_msg_handle,
					(msg_message_id_t)message_id, msg, send_opt);
		if (msg_err != MSG_SUCCESS)
			goto fail;

		msg_err = msg_get_int_value(msg,
					MSG_MESSAGE_DATA_SIZE_INT, &msg_size);
		if (msg_err != MSG_SUCCESS) {
			msg_release_struct(&msg);
			goto fail;
		}

		buf = (char *)calloc(msg_size, sizeof(char));
		if (NULL == buf)
			goto fail;

		msg_err = msg_get_str_value(msg, MSG_MESSAGE_SMS_DATA_STR,
						buf, msg_size);
		if (msg_err != MSG_SUCCESS) {
			msg_release_struct(&msg);
			goto fail;
		}

		dbus_g_type_struct_set(&value, 0,
					buf, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(&value));

		msg_release_struct(&msg);
	} else if (!g_ascii_strncasecmp(pch, "e", 1)) {
		if (EMAIL_ERROR_NONE != email_load_default_account_id(&account_id))
			goto fail;

		if (EMAIL_ERROR_NONE == email_get_mail_data(message_id, &mail_data)) {
			body_file = fopen(mail_data->file_path_plain, "r");
			if (body_file == NULL)
				body_file = fopen(mail_data->file_path_html, "rb");

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

				dbus_g_type_struct_set(&value, 0, buf,
							G_MAXUINT);
				g_ptr_array_add(array,
						g_value_get_boxed(&value));
			}
		}
	}

	dbus_g_method_return(context, array);
	g_ptr_array_free(array, TRUE);
	if (body_file != NULL)
		fclose(body_file);
	if (buf)
		free(buf);
	if (mail_data)
		email_free_mail_data(&mail_data, 1);
	return TRUE;
fail:
	g_ptr_array_free(array, TRUE);
	if (body_file != NULL)
		fclose(body_file);
	if (buf)
		free(buf);
	if (mail_data)
		email_free_mail_data(&mail_data, 1);

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
	int err;

	err = email_sync_header_for_all_account(&handle);

	if (err == EMAIL_ERROR_NONE) {
		DBG("Handle to stop download = %d \n", handle);
	} else {
		ERR("Message Update failed \n");
	}

	dbus_g_method_return(context, err);
	return (err == EMAIL_ERROR_NONE) ? TRUE : FALSE;
}

static gboolean bluetooth_map_message_status(BluetoothMapAgent *agent,
					gchar *message_name,
					int indicator, int value,
					DBusGMethodInvocation *context)
{
	char *pch = NULL;
	char *last = NULL;
	int message_id = 0;
	email_mail_data_t *mail_data = NULL;
	int ret = 0;
	gboolean flag = FALSE;
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
			msg_error_t msg_err = MSG_SUCCESS;
			msg_struct_t msg = msg_create_struct(MSG_STRUCT_MESSAGE_INFO);
			msg_struct_t send_opt = msg_create_struct(MSG_STRUCT_SENDOPT);
			int msg_type = 0;
			bool read_status = true;


			msg_err = msg_get_message(g_msg_handle,
						(msg_message_id_t)message_id, msg,
						send_opt);
			if (msg_err != MSG_SUCCESS) {
				msg_release_struct(&msg);
				goto done;
			}

			msg_err = msg_get_bool_value(msg, MSG_MESSAGE_READ_BOOL,
							&read_status);
			if (msg_err != MSG_SUCCESS) {
				msg_release_struct(&msg);
				goto done;
			}

			msg_err = msg_get_int_value(msg, MSG_MESSAGE_TYPE_INT,
							&msg_type);
			if (msg_err != MSG_SUCCESS) {
				msg_release_struct(&msg);
				goto done;
			}


			if (read_status == false) {
				DBG(" Message is UNREAD \n");

				ret = msg_update_read_status(
					g_msg_handle, message_id, TRUE);
				if (__bt_msg_is_mms(msg_type)) {
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

				if (__bt_msg_is_mms(msg_type)) {
					ret = msg_mms_send_read_report(
						g_msg_handle,
						message_id,
						MSG_READ_REPORT_NONE);
				}
			}

			if (ret == MSG_SUCCESS)
				flag = TRUE;

			msg_release_struct(&msg);
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
			if (email_get_mail_data(message_id, &mail_data) != EMAIL_ERROR_NONE) {
				ERR("email_get_mail_data failed\n");
				flag = FALSE;
				break;
			}

			if (email_set_flags_field(mail_data->account_id, &message_id, 1,
				EMAIL_FLAGS_SEEN_FIELD, 1, 0) != EMAIL_ERROR_NONE) {

				ERR("email_set_flags_field failed \n");
				flag = FALSE;
			} else {
				DBG("email_set_flags_field success \n");
				flag = TRUE;
			}
			break;
		}
		case 1: {
			if (email_get_mail_data(message_id, &mail_data) != EMAIL_ERROR_NONE) {
				ERR("email_get_mail failed\n");
			} else {
				DBG("email_get_mail success\n");
				if (email_delete_mail(mail_data->mailbox_id, &message_id,
							1, 1) == EMAIL_ERROR_NONE) {
					DBG("\n email_delete_mail success");
					flag = TRUE;
				} else {
					ERR("\n email_delete_mail failed");
					flag = FALSE;
				}
				email_free_mail_data(&mail_data, 1);
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

static gboolean bluetooth_map_noti_registration(BluetoothMapAgent *agent,
					gchar *remote_addr,
					gboolean status,
					DBusGMethodInvocation *context)
{
	DBG("remote_addr = %s \n", remote_addr);

	if (status == TRUE)
		__bt_mns_client_connect(remote_addr);
	else
		__bt_mns_client_disconnect();

	return TRUE;
}

int main(int argc, char **argv)
{
	BluetoothMapAgent *bluetooth_map_obj = NULL;
	DBusGProxy *bus_proxy = NULL;
	guint result = 0;
	GError *error = NULL;

	g_type_init();

	g_mainloop = g_main_loop_new(NULL, FALSE);

	if (g_mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	g_connection = dbus_g_bus_get(DBUS_BUS_SESSION, &error);

	if (error != NULL) {
		ERR("Couldn't connect to system bus[%s]\n", error->message);
		g_error_free(error);
		return EXIT_FAILURE;
	}

	bus_proxy = dbus_g_proxy_new_for_name(g_connection,
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
	dbus_g_connection_register_g_object(g_connection,
					BT_MAP_SERVICE_OBJECT_PATH,
					G_OBJECT(bluetooth_map_obj));

	if (__bluetooth_map_start_service() == FALSE)
		goto failure;

	g_main_loop_run(g_mainloop);

 failure:
	DBG("Terminate the bluetooth-map-agent\n");
	if (g_mns_path)
		__bt_mns_client_disconnect();
	if (bus_proxy)
		g_object_unref(bus_proxy);
	if (bluetooth_map_obj)
		g_object_unref(bluetooth_map_obj);
	if (g_connection)
		dbus_g_connection_unref(g_connection);


	__bluetooth_map_stop_service();
	return EXIT_FAILURE;
}

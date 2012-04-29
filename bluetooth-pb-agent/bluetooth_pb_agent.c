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
#include <contacts-svc.h>

#include "vconf.h"
#include "vconf-keys.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bluetooth_pb_agent.h"

#define CALL_LOG_VCARD  "BEGIN:VCARD\r\n" \
					"VERSION:2.1\r\n" \
					"N:%s;%s\r\n" \
					"TEL:%s\r\n" \
					"X-IRMC-CALL-DATETIME;%s:%s\r\n" \
					"END:VCARD\r\n"

#define PBAP_OWNER_VCARD  "BEGIN:VCARD\r\n" \
					"VERSION:2.1\r\n" \
					"TEL:%s\r\n" \
					"END:VCARD\r\n"

#define PBAP_EMPTY_VCARD  "BEGIN:VCARD\r\n" \
					"VERSION:2.1\r\n" \
					"END:VCARD\r\n"

#define VCARD_NO_NAME  "Noname"
#define MAX_CONTACT_NAME_LEN  256
#define MAX_CONTACT_NUM_LEN  20
#define PBAP_OWNER_VCARD_MAX_LEN  255
#define VCARD_MAX_LEN	3000

#define DBUS_STRUCT_STRING_STRING_UINT (dbus_g_type_get_struct("GValueArray", G_TYPE_STRING, \
							G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID))

enum PhoneBookObject {
	TELECOM_NONE = 0,
	TELECOM_PB,
	TELECOM_ICH,
	TELECOM_OCH,
	TELECOM_MCH,
	TELECOM_CCH,
};

typedef struct {
	GObject parent;
} BluetoothPbAgent;

typedef struct {
	GObjectClass parent;
} BluetoothPbAgentClass;

GType bluetooth_pb_agent_get_type(void);

#define BLUETOOTH_PB_TYPE_AGENT (bluetooth_pb_agent_get_type())

#define BLUETOOTH_PB_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_CAST((object), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgent))
#define BLUETOOTH_PB_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgentClass))
#define BLUETOOTH_PB_IS_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), \
	BLUETOOTH_PB_TYPE_AGENT))
#define BLUETOOTH_PB_IS_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), \
	BLUETOOTH_PB_TYPE_AGENT))
#define BLUETOOTH_PB_AGENT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgentClass))

G_DEFINE_TYPE(BluetoothPbAgent, bluetooth_pb_agent, G_TYPE_OBJECT)

GMainLoop *mainloop = NULL;

static gboolean bluetooth_pb_get_phonebook(BluetoothPbAgent *agent,
					gushort max_list,
					gushort offset,
					DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_calls(BluetoothPbAgent *agent,
				gushort max_list,
				gushort offset,
				gchar *call_type,
				DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_size(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_total_object_count(BluetoothPbAgent *agent,
						gchar *path,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_list(BluetoothPbAgent *agent,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_calls_list(BluetoothPbAgent *agent,
					gchar *call_type,
					    DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_entry(BluetoothPbAgent *agent,
						gchar *id,
						 DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_calls_entry(BluetoothPbAgent *agent,
					gchar *id,
					     DBusGMethodInvocation *context);

static gboolean bluetooth_pb_add_contact (BluetoothPbAgent *agent,
					const char *filename,
					 GError **error);


static unsigned int __bluetooth_pb_get_call_size(const enum PhoneBookObject pb_oject);

#include "bluetooth_pb_agent_glue.h"

static void bluetooth_pb_agent_init(BluetoothPbAgent *obj)
{
	DBG("+\n");
	g_assert(obj != NULL);
}

static void bluetooth_pb_agent_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(bluetooth_pb_agent_parent_class)->finalize(obj);
}

static void bluetooth_pb_agent_class_init(BluetoothPbAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;

	g_assert(klass != NULL);

	object_class->finalize = bluetooth_pb_agent_finalize;

	dbus_g_object_type_install_info(BLUETOOTH_PB_TYPE_AGENT,
					&dbus_glib_bluetooth_pb_object_info);
}

static gboolean bluetooth_pb_get_phonebook_size(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context)
{
	unsigned int phonebook_size = 0;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	if (name == NULL) {
		GError *error = NULL;
		GQuark quark;

		quark = g_type_qname(bluetooth_pb_agent_get_type());
		error = g_error_new(quark, -1, "No name defined");

		DBG("no name defined\n");

		dbus_g_method_return_error(context, error);

		g_error_free(error);

		return FALSE;
	}

	if (g_strcmp0(name, "/telecom/pb.vcf") == 0) {
		contacts_svc_connect();

		phonebook_size = contacts_svc_count(CTS_GET_ALL_CONTACT);
		DBG("Number of contacts is %d\n", phonebook_size);

		contacts_svc_disconnect();

		/* add count for owner (0.vcf) */
		phonebook_size++;
	} else if (g_strcmp0(name, "/telecom/ich.vcf") == 0) {
		phonebook_size = __bluetooth_pb_get_call_size(TELECOM_ICH);
	} else if (g_strcmp0(name, "/telecom/och.vcf") == 0) {
		phonebook_size = __bluetooth_pb_get_call_size(TELECOM_OCH);
	} else if (g_strcmp0(name, "/telecom/mch.vcf") == 0) {
		phonebook_size = __bluetooth_pb_get_call_size(TELECOM_MCH);
	} else if (g_strcmp0(name, "/telecom/cch.vcf") == 0) {
		phonebook_size = __bluetooth_pb_get_call_size(TELECOM_CCH);
	}

	dbus_g_method_return(context, phonebook_size);

	return TRUE;
}


static int __bluetooth_get_calllog_type(int call_type)
{
	int val = CTS_PLOG_TYPE_NONE;
	switch (call_type) {
	case CTS_PLOG_TYPE_VOICE_INCOMMING:
	case CTS_PLOG_TYPE_VIDEO_INCOMMING:
		val = CTS_PLOG_TYPE_VOICE_INCOMMING;
		break;

	case CTS_PLOG_TYPE_VOICE_OUTGOING:
	case CTS_PLOG_TYPE_VIDEO_OUTGOING:
		val = CTS_PLOG_TYPE_VOICE_OUTGOING;
		break;

	case CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN:
	case CTS_PLOG_TYPE_VOICE_INCOMMING_SEEN:
	case CTS_PLOG_TYPE_VIDEO_INCOMMING_UNSEEN:
	case CTS_PLOG_TYPE_VIDEO_INCOMMING_SEEN:
		val = CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN;
		break;

	default:
		break;
	}

	return val;
}

static unsigned int __get_call_log_count(unsigned int call_log_type)
{
	CTSiter *iter = NULL;
	unsigned int count = 0;

	contacts_svc_get_list(CTS_LIST_GROUPING_PLOG, &iter);
	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
		CTSvalue *plog = NULL;

		plog = contacts_svc_iter_get_info(iter);
		if (plog) {
			int type = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_LOG_TYPE_INT);
			DBG("type: %d\n", type);
			int log_type = __bluetooth_get_calllog_type(type);

			if ((call_log_type == 0xFF || call_log_type == log_type) &&
								(log_type != CTS_PLOG_TYPE_NONE)) {
				count++;
			}
		}
	}
	return count;
}
static gboolean bluetooth_pb_get_total_object_count(BluetoothPbAgent *agent,
					gchar *path, DBusGMethodInvocation *context)
{
	unsigned int nr_contact = 0;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);
	contacts_svc_connect();

	if ((g_strcmp0(path, "SM") == 0) || (g_strcmp0(path, "ME") == 0)) {
		nr_contact = contacts_svc_count(CTS_GET_ALL_CONTACT);
	} else if (g_strcmp0(path, "DC") == 0) {
		nr_contact = __get_call_log_count(CTS_PLOG_TYPE_VOICE_OUTGOING);
	} else if (g_strcmp0(path, "MC") == 0) {
		nr_contact = __get_call_log_count(CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN);
	} else if (g_strcmp0(path, "RC") == 0) {
		nr_contact = __get_call_log_count(CTS_PLOG_TYPE_VOICE_INCOMMING);
	}
	DBG("Number of contacts is %d\n", nr_contact);

	contacts_svc_disconnect();

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	dbus_g_method_return(context, nr_contact);

	return TRUE;
}

static void __get_vcard_from_contact(int id, int *vcard_total_len, char **vcard)
{
	int ret;
	int vcard_len;
	char *vcard_stream;
	CTSstruct *contact = NULL;

	contacts_svc_get_contact(id, &contact);

	ret = contacts_svc_get_vcard_from_contact(contact, &vcard_stream);
	if (CTS_SUCCESS == ret) {
		vcard_len = strlen(vcard_stream);
		*vcard_total_len += vcard_len;
		DBG("len:%d total:%d\n", vcard_len, *vcard_total_len);
		*vcard = strdup(vcard_stream);
		free(vcard_stream);
	}

	contacts_svc_struct_free(contact);
}

static gboolean bluetooth_pb_get_phonebook(BluetoothPbAgent *agent,
					gushort max_list, gushort offset,
					DBusGMethodInvocation *context)
{
	int i = 0;
	int nr_contact = 0;
	int vcard_total_len = 0;

	CTSiter *iter = NULL;
	static int *contact_id = NULL;
	static int index = 0;
	int last_part = 0;

	char **vcard;

	DBG("max_list:%d offset:%d\n", max_list, offset);

	contacts_svc_connect();

	nr_contact = contacts_svc_count(CTS_GET_ALL_CONTACT);
	DBG("Number of contacts is %d\n", nr_contact);

	vcard = g_new0(char *, nr_contact + 1);

	/* first request */
	if (!contact_id) {
		contact_id = (int *)malloc(nr_contact * sizeof(int));
		if (!contact_id) {
			DBG("malloc error\n");
			contacts_svc_disconnect();
			g_strfreev(vcard);

			return FALSE;
		}

                contacts_svc_get_list(CTS_LIST_ALL_CONTACT, &iter);

                while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
			CTSvalue *row_info = NULL;
			int id;

			row_info = contacts_svc_iter_get_info(iter);
			id = contacts_svc_value_get_int(row_info,
							CTS_LIST_CONTACT_ID_INT);
			contact_id[i] = id;

			if (vcard_total_len < VCARD_MAX_LEN) {
				__get_vcard_from_contact(id, &vcard_total_len,
								&vcard[i]);
				DBG("vcard:%s\n", vcard[i]);
                                index++;

				if (index >= max_list) {
					DBG("Over max list%d\n", max_list);
					break;
				}
			}

                        contacts_svc_value_free(row_info);
			i++;
		}
		if( NULL != iter ) {
			contacts_svc_iter_remove(iter);
		}
        } else { /* subsequent request */
                while (vcard_total_len < VCARD_MAX_LEN) {
			__get_vcard_from_contact(contact_id[index],
						&vcard_total_len, &vcard[i]);
			DBG("vcard:%s\n", vcard[i]);

                        index++;
			i++;

			if (index >= nr_contact || index >= max_list) {
				DBG("Complete\n");
				break;
			}
                }
        }
	contacts_svc_disconnect();

	if (index >= nr_contact || index >= max_list) {
		free(contact_id);
		contact_id = NULL;
		index = 0;
		last_part = 1;
	}

	dbus_g_method_return(context, last_part, vcard);

	g_strfreev(vcard);

        return TRUE;
}

static gboolean bluetooth_pb_get_calls(BluetoothPbAgent *agent, gushort max_list, gushort offset,
				       gchar *call_type, DBusGMethodInvocation *context)
{
	int call_log_type;
	int i = 0;
	char **vcard;
	char vcard_buffer[256] = {0,};
	CTSiter *iter = NULL;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);
	contacts_svc_connect();

	if (strncmp(call_type, "incoming", 8) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_INCOMMING;
	else if (strncmp(call_type, "outgoing", 8) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_OUTGOING;
	else if (strncmp(call_type, "missed", 6) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN;
	else
		call_log_type = 0xFF;

	vcard = g_new0(char *, max_list + 1);

	contacts_svc_get_list(CTS_LIST_GROUPING_PLOG, &iter);

	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
		CTSvalue *plog = NULL;

		plog = contacts_svc_iter_get_info(iter);
		if (plog) {
			struct tm timeinfo;
			char log_time_stamp[32] = {0,};
			char calllog_type[10] = {0,};
			int type = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_LOG_TYPE_INT);
			DBG("type: %d\n", type);
			int log_type = __bluetooth_get_calllog_type(type);

			const char *number = contacts_svc_value_get_str(plog,
									CTS_LIST_PLOG_NUMBER_STR);
			const char *first_name = contacts_svc_value_get_str(plog,
									CTS_LIST_PLOG_FIRST_NAME_STR);
			const char *last_name = contacts_svc_value_get_str(plog,
									CTS_LIST_PLOG_LAST_NAME_STR);

			time_t time = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_LOG_TIME_INT);

			if (!number) {
				contacts_svc_value_free(plog);
				continue;
			}
			if (!first_name)
				first_name = "";
			if (!last_name)
				last_name = "";

			localtime_r(&time, &timeinfo);

			strftime(log_time_stamp, sizeof(log_time_stamp),
						"%Y%m%dT%H%M%S", &timeinfo);

			if (log_type == CTS_PLOG_TYPE_VOICE_INCOMMING)
				strncpy(calllog_type, "RECEIVED", strlen("RECEIVED"));
			 else if (log_type == CTS_PLOG_TYPE_VOICE_OUTGOING)
				strncpy(calllog_type, "DIALED", strlen("DIALED"));
			else if (log_type == CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN)
				strncpy(calllog_type, "MISSED", strlen("MISSED"));
			 else {
				DBG("no log type found \n");
			}

			if ((call_log_type == 0xFF || call_log_type == log_type) &&
								(log_type != CTS_PLOG_TYPE_NONE)) {

				snprintf(vcard_buffer, sizeof(vcard_buffer), CALL_LOG_VCARD,
							 last_name, first_name, number, calllog_type, log_time_stamp);

				vcard[i] = strdup((char *)vcard_buffer);
				DBG("%s() %d [%d] %s\n", __FUNCTION__, __LINE__, i, vcard[i]);
				i++;
			}

			contacts_svc_value_free(plog);

			if (i >= max_list) {
				DBG("Over max list count %d\n", max_list);
				break;
			}
		}
	}

	if( NULL != iter ) {
		contacts_svc_iter_remove(iter);
	}
	contacts_svc_disconnect();

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	dbus_g_method_return(context, vcard);

	g_strfreev(vcard);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_list(BluetoothPbAgent *agent,
						DBusGMethodInvocation *context)
{
	unsigned int nr_contact = 0;
	guint ret = 0;
	CTSiter *iter = NULL;
	GPtrArray *array = g_ptr_array_new();
	char *subscriber_number = NULL;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	GValue owner_value = {0, };

	/* owner's vcard 0.vcf */
	g_value_init(&owner_value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_take_boxed(&owner_value,
		dbus_g_type_specialized_construct(DBUS_STRUCT_STRING_STRING_UINT));

	subscriber_number = vconf_get_str(VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER);
	if (NULL == subscriber_number) {
		DBG("vconf_get_int failed for VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER \n");

		dbus_g_type_struct_set(&owner_value, 0, " ", 1, " ", 2, 0, G_MAXUINT);
	} else {
		dbus_g_type_struct_set(&owner_value, 0, subscriber_number, 1,
					subscriber_number, 2, 0, G_MAXUINT);
	}

	g_ptr_array_add(array, g_value_get_boxed(&owner_value));

	if (subscriber_number)
		free(subscriber_number);

	contacts_svc_connect();

	nr_contact = contacts_svc_count(CTS_GET_ALL_CONTACT);
	DBG("Number of contacts is %d\n", nr_contact);

	contacts_svc_get_list(CTS_LIST_ALL_CONTACT, &iter);

	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
		int index_num;
		char name[MAX_CONTACT_NAME_LEN + 2] = { 0 };
		const char *first = NULL;
		const char *last = NULL;
		const char *default_num = NULL;

		CTSvalue *row_info = NULL;
		CTSvalue *number = NULL;
		GValue value = {0, };

		row_info = contacts_svc_iter_get_info(iter);

		if (!row_info) {
			DBG("contacts_svc_iter_get_info failed \n");
			break;
		}

		first = contacts_svc_value_get_str(row_info, CTS_LIST_CONTACT_FIRST_STR);
		last = contacts_svc_value_get_str(row_info, CTS_LIST_CONTACT_LAST_STR);

		if (first && last) {
			g_strlcpy(name, last, sizeof(name) / 2);
			g_strlcat(name, ";", sizeof(name));
			g_strlcat(name, first, sizeof(name));
		} else if (first) {
			g_strlcpy(name, first, sizeof(name));
		} else if (last)  {
			g_strlcpy(name, last, sizeof(name));
		} else {
			g_strlcpy(name, VCARD_NO_NAME, sizeof(name));
		}

		index_num = contacts_svc_value_get_int(row_info, CTS_LIST_CONTACT_ID_INT);

		ret = contacts_svc_get_contact_value(CTS_GET_DEFAULT_NUMBER_VALUE, index_num,
							&number);

		if (CTS_SUCCESS != ret) {
			DBG("contacts_svc_get_contact_value() Failed(%d)\n", ret);
		} else {
			default_num = contacts_svc_value_get_str(number, CTS_NUM_VAL_NUMBER_STR);
			DBG("The default Number is %s\n", default_num);
		}

		g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
		g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_STRING_STRING_UINT));
		dbus_g_type_struct_set(&value, 0, name, 1, default_num, 2, index_num, G_MAXUINT);
		g_ptr_array_add(array, g_value_get_boxed(&value));

		if (number)
			contacts_svc_value_free(number);

		if (row_info)
			contacts_svc_value_free(row_info);

	}

	if( NULL != iter ) {
		contacts_svc_iter_remove(iter);
	}

	contacts_svc_disconnect();

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	dbus_g_method_return(context, array);

	g_ptr_array_foreach(array, (GFunc)g_value_array_free, NULL);
	g_ptr_array_free(array, TRUE);

	return TRUE;
}

static gboolean bluetooth_pb_get_calls_list(BluetoothPbAgent *agent, gchar *call_type,
					    DBusGMethodInvocation *context)
{
	int call_log_type;
	char name[256] = {0,};
	GPtrArray *array = g_ptr_array_new();

	CTSiter *iter = NULL;

	DBG("%s() %d call_type:%s\n", __FUNCTION__, __LINE__, call_type);

	if (strncmp(call_type, "incoming", 8) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_INCOMMING;
	else if (strncmp(call_type, "outgoing", 8) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_OUTGOING;
	else if (strncmp(call_type, "missed", 6) == 0)
		call_log_type = CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN;
	else
		call_log_type = 0xFF;

	contacts_svc_connect();

	contacts_svc_get_list(CTS_LIST_GROUPING_PLOG, &iter);

	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
		CTSvalue *plog = NULL;

		plog = contacts_svc_iter_get_info(iter);
		if (plog) {
			int index = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_ID_INT);
			int type = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_LOG_TYPE_INT);
			int log_type = __bluetooth_get_calllog_type(type);
			const char *number = contacts_svc_value_get_str(plog,
									CTS_LIST_PLOG_NUMBER_STR);
			const char *first_name = contacts_svc_value_get_str(plog,
								CTS_LIST_PLOG_FIRST_NAME_STR);
			const char *last_name = contacts_svc_value_get_str(plog,
								CTS_LIST_PLOG_LAST_NAME_STR);

			if (!number) {
				DBG("number is NULL\n");
				contacts_svc_value_free(plog);
				continue;
			}
			DBG("number: %s\n", number);

			if (first_name && last_name)
				snprintf(name, sizeof(name), "%s;%s;", last_name, first_name);
			else if (first_name)
				snprintf(name, sizeof(name), ";%s", first_name);
			else if (last_name)
				snprintf(name, sizeof(name), "%s;", last_name);
			else
				strncpy(name, number, sizeof(name) - 1);

			if ((call_log_type == 0xFF || call_log_type == log_type) &&
					(log_type != CTS_PLOG_TYPE_NONE)) {

				GValue value = {0, };
				g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
				g_value_take_boxed(&value,
					dbus_g_type_specialized_construct(DBUS_STRUCT_STRING_STRING_UINT));
				dbus_g_type_struct_set(&value, 0, name, 1, number, 2, (guint) index,
						       G_MAXUINT);
				g_ptr_array_add(array, g_value_get_boxed(&value));
			}

			contacts_svc_value_free(plog);
		}
	}

	if( NULL != iter ) {
		contacts_svc_iter_remove(iter);
	}

	contacts_svc_disconnect();

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	dbus_g_method_return(context, array);

	g_ptr_array_foreach(array, (GFunc)g_value_array_free, NULL);
	g_ptr_array_free(array, TRUE);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_entry(BluetoothPbAgent *agent, gchar *id,
						 DBusGMethodInvocation *context)
{

	int ret = -1;
	int index;
	CTSstruct *contact = NULL;
	char *phonebook_entry = NULL;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	if (sscanf(id, "%d.vcf", &index) != 1) {
		DBG("Failed to get index\n");
		return FALSE;
	}

	if (index != 0) {
		contacts_svc_connect();

		DBG("Get %dth phonebook entry\n", index);
		ret = contacts_svc_get_contact(index, &contact);
		if (CTS_SUCCESS == ret) {
			ret = contacts_svc_get_vcard_from_contact(contact, &phonebook_entry);
			if (CTS_SUCCESS == ret) {
				DBG("[%s]\n", phonebook_entry);

				dbus_g_method_return(context, phonebook_entry);
			}
			contacts_svc_struct_free(contact);
		}
		contacts_svc_disconnect();
	}

	if (index == 0 || ret != CTS_SUCCESS) {
		DBG("Get owner vcard\n");
		char *subscriber_number = NULL;

		subscriber_number = vconf_get_str(VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER);
		if (NULL == subscriber_number) {
			DBG("vconf_get_int failed for VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER \n");

			phonebook_entry = strdup(PBAP_EMPTY_VCARD);
			dbus_g_method_return(context, phonebook_entry);
		} else {
			char vcard_buffer[PBAP_OWNER_VCARD_MAX_LEN + 1] = {0,};

			if (strlen(subscriber_number) > MAX_CONTACT_NUM_LEN) {
				char temp[MAX_CONTACT_NUM_LEN + 1] = {0,};
				strncpy(temp, subscriber_number, MAX_CONTACT_NUM_LEN);
				snprintf(vcard_buffer, sizeof(vcard_buffer), PBAP_OWNER_VCARD,
						temp);
			} else {
				snprintf(vcard_buffer, sizeof(vcard_buffer), PBAP_OWNER_VCARD,
							subscriber_number);
				DBG(" Owner vcard \n %s  \n", vcard_buffer);
			}

			dbus_g_method_return(context, vcard_buffer);

			free(subscriber_number);
		}
	}

	if (phonebook_entry)
		free(phonebook_entry);

	return TRUE;
}

static gboolean bluetooth_pb_get_calls_entry(BluetoothPbAgent *agent, gchar *id,
					     DBusGMethodInvocation *context)
{
	int calls_index;
	char *calls_entry;
	char vcard_buffer[256];
	CTSiter *iter = NULL;

	DBG("%s() %d\n", __FUNCTION__, __LINE__);
	contacts_svc_connect();

	if (sscanf(id, "%d.vcf", &calls_index) != 1) {
		DBG("Failed to get index\n");
		return FALSE;
	}

	contacts_svc_get_list(CTS_LIST_GROUPING_PLOG, &iter);

	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {
		CTSvalue *plog = NULL;

		plog = contacts_svc_iter_get_info(iter);
		if (plog) {
			int index = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_ID_INT);
			const char *number = contacts_svc_value_get_str(plog,
									CTS_LIST_PLOG_NUMBER_STR);
			const char *first_name = contacts_svc_value_get_str(plog,
								CTS_LIST_PLOG_FIRST_NAME_STR);
			const char *last_name = contacts_svc_value_get_str(plog,
								CTS_LIST_PLOG_LAST_NAME_STR);
			const char *display_name = contacts_svc_value_get_str(plog,
								CTS_LIST_PLOG_DISPLAY_NAME_STR);

			if (!number)
				number = "";
			if (!first_name)
				first_name = "";
			if (!last_name)
				last_name = "";
			if (display_name) {
				DBG("display_name: %s\n", display_name);
			}

			if (calls_index == index) {
				snprintf(vcard_buffer, sizeof(vcard_buffer), CALL_LOG_VCARD,
					 last_name, first_name, number);
				calls_entry = vcard_buffer;
			}

			contacts_svc_value_free(plog);
		}
	}

	if( NULL != iter ) {
		contacts_svc_iter_remove(iter);
	}

	contacts_svc_disconnect();

	DBG("%s() %d\n", __FUNCTION__, __LINE__);

	dbus_g_method_return(context, calls_entry);

	return TRUE;
}

static int __bluetooth_pb_agent_read_file(const char *file_path, char **stream)
{
	FILE *fp = NULL;
	int read_len = -1;
	int received_file_size = 0;
	struct stat file_attr;

	if (file_path == NULL || stream == NULL) {
		DBG("Invalid data \n");
		return -1;
	}

	DBG("file_path = %s\n", file_path);

	if ((fp = fopen(file_path, "r+")) == NULL) {
		DBG("Cannot open %s\n", file_path);
		return -1;
	}

	if (fstat(fileno(fp), &file_attr) == 0) {
		received_file_size = file_attr.st_size;
		DBG("file_attr.st_size = %d, size = %d\n", file_attr.st_size, received_file_size);

		if (received_file_size <= 0) {
			DBG("Some problem in the file size [%s]  \n", file_path);
			fclose(fp);
			fp = NULL;
			return -1;
		}

		*stream = (char *)malloc(sizeof(char) * received_file_size);
		if (NULL == *stream) {
			fclose(fp);
			fp = NULL;
			return -1;
		}
	} else {
		DBG("Some problem in the file [%s]  \n", file_path);
		fclose(fp);
		fp = NULL;
		return -1;
	}

	read_len = fread(*stream, 1, received_file_size, fp);

	if (read_len == 0) {
		if (fp != NULL) {
			fclose(fp);
			fp = NULL;
		}
		DBG("Cannot open %s\n", file_path);
		return -1;
	}

	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	return 0;
}

static gboolean bluetooth_pb_add_contact(BluetoothPbAgent *agent, const char *filename,
					 GError **error)
{
	CTSstruct *contact_record = NULL;
	GSList *numbers_list = NULL, *cursor;
	int is_success = 0;
	int is_duplicated = 0;
	int err = 0;
	char *stream = NULL;

	DBG("file_path = %s\n", filename);

	err = contacts_svc_connect();
	DBG("contact_db_service_connect fucntion call [error] = %d \n", err);

	err = __bluetooth_pb_agent_read_file(filename, &stream);

	if (err != 0) {
		contacts_svc_disconnect();
		DBG("contacts_svc_disconnect fucntion call [error] = %d \n", err);

		if (NULL != stream) {
			free(stream);
			stream = NULL;
		}
		return FALSE;
	}

	is_success = contacts_svc_get_contact_from_vcard((const void *)stream, &contact_record);

	DBG("contacts_svc_get_contact_from_vcard fucntion call [is_success] = %d \n", is_success);

	if (0 == is_success) {
		contacts_svc_struct_get_list(contact_record, CTS_CF_NUMBER_LIST, &numbers_list);
		cursor = numbers_list;

		for (; cursor; cursor = g_slist_next(cursor)) {
			if (contacts_svc_find_contact_by(CTS_FIND_BY_NUMBER,
							contacts_svc_value_get_str(cursor->data,
								CTS_NUM_VAL_NUMBER_STR)) > 0) {
				DBG("is_duplicated\n");
				is_duplicated = TRUE;
			}
		}

		if (is_duplicated == FALSE) {
			contacts_svc_insert_contact(0, contact_record);
		}
	} else {
		DBG("Fail \n");
	}

	err = contacts_svc_disconnect();
	DBG("contacts_svc_disconnect fucntion call [error] = %d \n", err);

	if (NULL != stream) {
		free(stream);
		stream = NULL;
	}

	return TRUE;
}


static unsigned int __bluetooth_pb_get_call_size(const enum PhoneBookObject pb_object)
{
	CTSiter *iter = NULL;
	unsigned int call_size = 0;

	int err = 0;

	err = contacts_svc_connect();
	if (err != CTS_SUCCESS) {
		DBG("contacts_svc_connect fucntion call [error] = %d \n", err);
		return call_size;
	}

	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	while (CTS_SUCCESS == contacts_svc_iter_next(iter)) {

		CTSvalue *value = NULL;
		int type = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		type = contacts_svc_value_get_int(value, CTS_LIST_PLOG_LOG_TYPE_INT);

		DBG("type : %d\n", type);

		switch (pb_object) {
		case TELECOM_ICH:
			if (CTS_PLOG_TYPE_VOICE_INCOMMING == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING == type) {
				call_size++;
			}
			break;
		case TELECOM_OCH:
			if (CTS_PLOG_TYPE_VOICE_OUTGOING == type ||
				CTS_PLOG_TYPE_VIDEO_OUTGOING == type) {
				call_size++;
			}
			break;
		case TELECOM_MCH:
			if (CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN == type ||
				CTS_PLOG_TYPE_VOICE_INCOMMING_SEEN == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING_UNSEEN == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING_SEEN) {
				call_size++;
			}
			break;
		case TELECOM_CCH:
			if (CTS_PLOG_TYPE_VOICE_INCOMMING == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING == type ||
				CTS_PLOG_TYPE_VOICE_OUTGOING == type ||
				CTS_PLOG_TYPE_VIDEO_OUTGOING == type ||
				CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN == type ||
				CTS_PLOG_TYPE_VOICE_INCOMMING_SEEN == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING_UNSEEN == type ||
				CTS_PLOG_TYPE_VIDEO_INCOMMING_SEEN) {
				call_size++;
			}
			break;
		default:
			break;
		}
	}

	if (iter)
		contacts_svc_iter_remove(iter);

	err = contacts_svc_disconnect();
	if (err != CTS_SUCCESS)
		DBG("contacts_svc_disconnect fucntion call [error] = %d \n", err);

	return call_size;
}


int main(int argc, char **argv)
{
	BluetoothPbAgent *bluetooth_pb_obj = NULL;
	DBusGConnection *bus = NULL;
	DBusGProxy *bus_proxy = NULL;
	guint result = 0;
	GError *error = NULL;

	g_type_init();

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		DBG("Couldn't create GMainLoop\n");
		return EXIT_FAILURE;
	}

	bus = dbus_g_bus_get(DBUS_BUS_SESSION, &error);
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
			BT_PB_SERVICE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
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

	bluetooth_pb_obj = g_object_new(BLUETOOTH_PB_TYPE_AGENT, NULL);
	if (bluetooth_pb_obj == NULL) {
		DBG("Failed to create one BluetoothPbAgent instance.\n");
		goto failure;
	}

	/* Registering it on the D-Bus */
	dbus_g_connection_register_g_object(bus, BT_PB_SERVICE_OBJECT_PATH,
						G_OBJECT(bluetooth_pb_obj));

	g_main_loop_run(mainloop);

 failure:
	DBG("Terminate the bluetooth-pb-agent\n");
	if (bluetooth_pb_obj)
		g_object_unref(bluetooth_pb_obj);

	if (bus_proxy)
		g_object_unref(bus_proxy);

	if (bus)
		dbus_g_connection_unref(bus);

	return EXIT_FAILURE;
}

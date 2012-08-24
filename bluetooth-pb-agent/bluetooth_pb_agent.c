/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *		 Jaekyun Lee <jkyun.leek@samsung.com>
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
#include <signal.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <contacts-svc.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bluetooth_pb_agent.h"
#include "bluetooth_pb_vcard.h"

typedef enum {
	TELECOM_NONE = 0,
	TELECOM_PB,
	TELECOM_ICH,
	TELECOM_OCH,
	TELECOM_MCH,
	TELECOM_CCH
} PhoneBookType;

typedef struct {
	GObject parent;
} BluetoothPbAgent;

typedef struct {
	GObjectClass parent;

	void (*clear) (BluetoothPbAgent *agent);
} BluetoothPbAgentClass;


enum {
	CLEAR,
	LAST_SIGNAL
};

GType bluetooth_pb_agent_get_type(void);

#define BLUETOOTH_PB_TYPE_AGENT (bluetooth_pb_agent_get_type())

#define BLUETOOTH_PB_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_CAST((object), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgent))
#define BLUETOOTH_PB_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgentClass))
#define BLUETOOTH_IS_PB_AGENT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), \
	BLUETOOTH_PB_TYPE_AGENT))
#define BLUETOOTH_IS_PB_AGENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), \
	BLUETOOTH_PB_TYPE_AGENT))
#define BLUETOOTH_PB_AGENT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), \
	BLUETOOTH_PB_TYPE_AGENT , BluetoothPbAgentClass))

G_DEFINE_TYPE(BluetoothPbAgent, bluetooth_pb_agent, G_TYPE_OBJECT)

#define DBUS_STRUCT_STRING_STRING_UINT (dbus_g_type_get_struct("GValueArray", G_TYPE_STRING, \
							G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID))

static guint signals[LAST_SIGNAL] = { 0 };

static GMainLoop *mainloop = NULL;

static GHashTable *contact_list_hash = NULL;

static PhoneBookType g_current_pb_type = TELECOM_NONE;

static void bluetooth_pb_agent_finalize(GObject *obj);

static void bluetooth_pb_agent_clear(BluetoothPbAgent *agent);

/* Dbus messages */
static gboolean bluetooth_pb_get_phonebook(BluetoothPbAgent *agent,
					const char *name,
					guint64 filter,
					guint8 format,
					guint16 max_list_count,
					guint16 list_start_offset,
					DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_size(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_list(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_entry(BluetoothPbAgent *agent,
						const gchar *folder,
						const gchar *id,
						guint64 filter,
						guint8 format,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_size_at(BluetoothPbAgent *agent,
					const gchar *command,
					DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_entries_at(BluetoothPbAgent *agent,
					const gchar *command,
					gint32 start_index,
					gint32 end_index,
					DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_phonebook_entries_find_at(BluetoothPbAgent *agent,
							const gchar *command,
							const gchar *find_text,
							DBusGMethodInvocation *context);

static gboolean bluetooth_pb_get_total_object_count(BluetoothPbAgent *agent,
						gchar *path,
						DBusGMethodInvocation *context);

static gboolean bluetooth_pb_add_contact (BluetoothPbAgent *agent,
					const char *filename,
					GError **error);

static void __bluetooth_pb_dbus_return_error(DBusGMethodInvocation *context,
					gint code,
					const gchar *message);

static PhoneBookType __bluetooth_pb_get_pb_type(const char *name);

static PhoneBookType __bluetooth_pb_get_storage_pb_type(const char *name);

static unsigned int __bluetooth_pb_get_contact_size(void);

static unsigned int __bluetooth_pb_get_incoming_call_size(void);

static unsigned int __bluetooth_pb_get_outgoing_call_size(void);

static unsigned int __bluetooth_pb_get_missed_call_size(void);

static unsigned int __bluetooth_pb_get_combined_call_size(void);


static GPtrArray *__bluetooth_pb_get_contact_vcards(BluetoothPbAgent *agent,
						guint64 filter,
						guint8 format,
						guint16 max_list_count,
						guint16 list_start_offset);

static GPtrArray *__bluetooth_pb_get_incoming_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset);

static GPtrArray *__bluetooth_pb_get_outgoing_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset);

static GPtrArray *__bluetooth_pb_get_missed_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset);

static GPtrArray *__bluetooth_pb_get_combined_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset);

static void __bluetooth_pb_create_contact_index(PhoneBookType pb_type);

static void __bluetooth_pb_create_call_index(PhoneBookType pb_type);

static void __bluetooth_pb_get_contact_list(PhoneBookType pb_type,
					GPtrArray *ptr_array,
					gint start_index,
					gint end_index,
					gboolean formatted_name);

static void __bluetooth_pb_get_call_list(PhoneBookType pb_type,
					GPtrArray *ptr_array,
					gint start_index,
					gint end_index,
					gboolean formatted_name);

static void __bluetooth_pb_get_contact_list_by_name(PhoneBookType pb_type,
						GPtrArray *ptr_array,
						const gchar *find_text,
						gboolean formatted_name,
						gboolean owner);

static void __bluetooth_pb_get_call_list_by_name(PhoneBookType pb_type,
						GPtrArray *ptr_array,
						const gchar *find_text,
						gboolean formatted_name);

static int __bluetooth_get_calllog_type(int call_type);

static unsigned int __get_call_log_count(unsigned int call_log_type);


static void __bluetooth_pb_list_hash_reset(void);

static gboolean __bluetooth_pb_list_hash_insert(gint handle,
						gint id);

static gint __bluetooth_pb_list_hash_lookup_id(gint handle);

static guint __bluetooth_pb_list_hash_size(void);


static void __bluetooth_pb_list_ptr_array_add(GPtrArray *ptr_array,
						const gchar *name,
						const gchar *number,
						gint handle);

static void __bluetooth_pb_list_ptr_array_free(gpointer data);

static void __bluetooth_pb_agent_signal_handler(int signum);

static void __bluetooth_pb_contact_changed(void *user_data);

static void __bluetooth_pb_call_changed(void *user_data);


#include "bluetooth_pb_agent_glue.h"

static void bluetooth_pb_agent_init(BluetoothPbAgent *obj)
{
}

static void bluetooth_pb_agent_class_init(BluetoothPbAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;

	klass->clear = bluetooth_pb_agent_clear;

	object_class->finalize = bluetooth_pb_agent_finalize;

	signals[CLEAR] = g_signal_new("clear",
			G_TYPE_FROM_CLASS(klass),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET(BluetoothPbAgentClass, clear),
			NULL, NULL,
			g_cclosure_marshal_VOID__VOID,
			G_TYPE_NONE, 0);

	dbus_g_object_type_install_info(BLUETOOTH_PB_TYPE_AGENT,
					&dbus_glib_bluetooth_pb_object_info);
}

static void bluetooth_pb_agent_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(bluetooth_pb_agent_parent_class)->finalize(obj);
}

static void bluetooth_pb_agent_clear(BluetoothPbAgent *agent)
{
	DBG("+\n");

	if (contact_list_hash) {
		g_hash_table_destroy(contact_list_hash);
		contact_list_hash = NULL;
	}

	g_current_pb_type = TELECOM_NONE;
}

static gboolean bluetooth_pb_get_phonebook(BluetoothPbAgent *agent,
					const char *name,
					guint64 filter,
					guint8 format,
					guint16 max_list_count,
					guint16 list_start_offset,
					DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;
	GPtrArray *vcards = NULL;
	gchar **vcards_str = NULL;

	gint new_missed_calls = 0;

	DBG("\n");

	pb_type = __bluetooth_pb_get_pb_type(name);

	switch (pb_type) {
	case TELECOM_PB:
		vcards = __bluetooth_pb_get_contact_vcards(agent,
				filter, format,
				max_list_count, list_start_offset);
		break;
	case TELECOM_ICH:
		vcards = __bluetooth_pb_get_incoming_call_vcards(agent,
				filter, format,
				max_list_count, list_start_offset);
		break;
	case TELECOM_OCH:
		vcards = __bluetooth_pb_get_outgoing_call_vcards(agent,
				filter, format,
				max_list_count, list_start_offset);
		break;
	case TELECOM_MCH:
		vcards = __bluetooth_pb_get_missed_call_vcards(agent,
				filter, format,
				max_list_count, list_start_offset);
		break;
	case TELECOM_CCH:
		vcards = __bluetooth_pb_get_combined_call_vcards(agent,
				filter, format,
				max_list_count, list_start_offset);
		break;
	default: {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	}

	if (vcards)
		vcards_str = (gchar **) g_ptr_array_free(vcards, FALSE);

	/* TODO : new_missed_calls need to implement */
	dbus_g_method_return(context, vcards_str, new_missed_calls);

	g_strfreev(vcards_str);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_size(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;
	unsigned int phonebook_size = 0;

	DBG("\n");

	pb_type = __bluetooth_pb_get_pb_type(name);

	switch (pb_type) {
	case TELECOM_PB:
		phonebook_size = __bluetooth_pb_get_contact_size();
		break;
	case TELECOM_ICH:
		phonebook_size = __bluetooth_pb_get_incoming_call_size();
		break;
	case TELECOM_OCH:
		phonebook_size = __bluetooth_pb_get_outgoing_call_size();
		break;
	case TELECOM_MCH:
		phonebook_size = __bluetooth_pb_get_missed_call_size();
		break;
	case TELECOM_CCH:
		phonebook_size = __bluetooth_pb_get_combined_call_size();
		break;
	default: {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	}


	dbus_g_method_return(context, phonebook_size);

	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_list(BluetoothPbAgent *agent,
						const char *name,
						DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;

	GPtrArray *ptr_array;

	DBG("\n");

	pb_type = __bluetooth_pb_get_pb_type(name);

	if (pb_type == TELECOM_NONE) {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	ptr_array = g_ptr_array_new_with_free_func(__bluetooth_pb_list_ptr_array_free);

	if (pb_type == TELECOM_PB)
		__bluetooth_pb_get_contact_list(pb_type, ptr_array, 0, G_MAXINT, FALSE);
	else
		__bluetooth_pb_get_call_list(pb_type, ptr_array, 0, G_MAXINT, FALSE);

	dbus_g_method_return(context, ptr_array);

	if (ptr_array)
		g_ptr_array_free(ptr_array, TRUE);

	return TRUE;
}


static gboolean bluetooth_pb_get_phonebook_entry(BluetoothPbAgent *agent,
						const gchar *folder,
						const gchar *id,
						guint64 filter,
						guint8 format,
						DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;

	gint handle = 0;
	gint cid = -1;
	gchar *str = NULL;

	DBG("\n");

	if (!g_str_has_suffix(id, ".vcf")) {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"invalid vcf file");
		return FALSE;
	}

	handle = (gint)g_ascii_strtoll(id, NULL, 10);
	cid = __bluetooth_pb_list_hash_lookup_id(handle);

	DBG("id %s handle%d, cid %d\n", id, handle, cid );

	pb_type = __bluetooth_pb_get_pb_type(folder);
	switch (pb_type) {
	case TELECOM_PB:
		__bluetooth_pb_create_contact_index(pb_type);
		str = _bluetooth_pb_vcard_contact(cid, filter, format);
		break;
	case TELECOM_ICH:
		__bluetooth_pb_create_call_index(pb_type);
		str = _bluetooth_pb_vcard_call(cid, filter, format, "RECEIVED");
		break;
	case TELECOM_OCH:
		__bluetooth_pb_create_call_index(pb_type);
		str = _bluetooth_pb_vcard_call(cid, filter, format, "DIALED");
		break;
	case TELECOM_MCH:
		__bluetooth_pb_create_call_index(pb_type);
		str = _bluetooth_pb_vcard_call(cid, filter, format, "MISSED");
		break;
	case TELECOM_CCH: {
		char *attr = NULL;

		if (_bluetooth_pb_is_incoming_call(cid))
			attr = "RECEIVED";
		else if (_bluetooth_pb_is_outgoing_call(cid))
			attr = "DIALED";
		else if (_bluetooth_pb_is_missed_call(cid))
			attr = "MISSED";

		__bluetooth_pb_create_call_index(pb_type);
		str = _bluetooth_pb_vcard_call(cid, filter, format, attr);

		break;
	}
	default: {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	}

	dbus_g_method_return(context, str);
	g_free(str);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_size_at(BluetoothPbAgent *agent,
					const gchar *command,
					DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;
	unsigned int phonebook_size = 0;

	DBG("\n");

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	switch (pb_type) {
	case TELECOM_PB:
		phonebook_size = __bluetooth_pb_get_contact_size();
		break;
	case TELECOM_ICH:
		phonebook_size = __bluetooth_pb_get_incoming_call_size();
		break;
	case TELECOM_OCH:
		phonebook_size = __bluetooth_pb_get_outgoing_call_size();
		break;
	case TELECOM_MCH:
		phonebook_size = __bluetooth_pb_get_missed_call_size();
		break;
	default: {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	}

	dbus_g_method_return(context, phonebook_size);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_entries_at(BluetoothPbAgent *agent,
					const gchar *command,
					gint start_index,
					gint end_index,
					DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;

	GPtrArray *ptr_array = NULL;

	DBG("command %s, start_index %d, end_index %d %s %d\n",
			command, start_index, end_index, __FILE__, __LINE__);

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	ptr_array = g_ptr_array_new_with_free_func(__bluetooth_pb_list_ptr_array_free);

	if (pb_type == TELECOM_PB)
		__bluetooth_pb_get_contact_list(pb_type, ptr_array, start_index, end_index, TRUE);
	else
		__bluetooth_pb_get_call_list(pb_type, ptr_array, start_index, end_index, TRUE);

	dbus_g_method_return(context, ptr_array);

	if (ptr_array)
		g_ptr_array_free(ptr_array, TRUE);

	return TRUE;
}

static gboolean bluetooth_pb_get_phonebook_entries_find_at(BluetoothPbAgent *agent,
							const gchar *command,
							const gchar *find_text,
							DBusGMethodInvocation *context)
{
	PhoneBookType pb_type = TELECOM_NONE;

	GPtrArray *ptr_array = NULL;

	pb_type = __bluetooth_pb_get_storage_pb_type(command);

	if (pb_type == TELECOM_NONE || pb_type == TELECOM_CCH) {
		__bluetooth_pb_dbus_return_error(context,
					G_FILE_ERROR_INVAL,
					"unsupported name defined");
		return FALSE;
	}

	ptr_array = g_ptr_array_new_with_free_func(__bluetooth_pb_list_ptr_array_free);

	if (pb_type == TELECOM_PB)
		__bluetooth_pb_get_contact_list_by_name(pb_type, ptr_array, find_text, TRUE, FALSE);
	else
		__bluetooth_pb_get_call_list_by_name(pb_type, ptr_array, find_text, TRUE);

	dbus_g_method_return(context, ptr_array);

	if (ptr_array)
		g_ptr_array_free(ptr_array, TRUE);

	return TRUE;
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

static void __bluetooth_pb_dbus_return_error(DBusGMethodInvocation *context,
					gint code,
					const gchar *message)
{
	GQuark quark;
	GError *error = NULL;

	quark = g_type_qname(bluetooth_pb_agent_get_type());
	error = g_error_new_literal(quark, code, message);

	dbus_g_method_return_error(context, error);
	g_error_free(error);
}

static PhoneBookType __bluetooth_pb_get_pb_type(const char *name)
{
	gchar *suffix = ".vcf";
	gint len;

	if (name == NULL)
		return TELECOM_NONE;

	len = strlen(name);

	if (g_str_has_suffix(name, suffix))
		len -= strlen(suffix);

	if (len < 0)
		return TELECOM_NONE;

	if (strncmp(name, "/telecom/pb", len) == 0)
		return TELECOM_PB;

	if (strncmp(name, "/telecom/ich", len) == 0)
		return TELECOM_ICH;

	if (strncmp(name, "/telecom/och", len) == 0)
		return TELECOM_OCH;

	if (strncmp(name, "/telecom/mch", len) == 0)
		return TELECOM_MCH;

	if (strncmp(name, "/telecom/cch", len) == 0)
		return TELECOM_CCH;

	return TELECOM_NONE;
}

static PhoneBookType __bluetooth_pb_get_storage_pb_type(const char *name)
{
	if (name == NULL)
		return TELECOM_NONE;

	if (g_strcmp0(name, "\"ME\"") == 0 )
		return TELECOM_PB;

	if (g_strcmp0(name, "\"RC\"") == 0)
		return TELECOM_ICH;

	if (g_strcmp0(name, "\"DC\"") == 0)
		return TELECOM_OCH;

	if (g_strcmp0(name, "\"MC\"") == 0)
		return TELECOM_MCH;

	return TELECOM_NONE;
}

static unsigned int __bluetooth_pb_get_contact_size(void)
{
	unsigned int phonebook_size = 0;

	phonebook_size = contacts_svc_count(CTS_GET_ALL_CONTACT);
	DBG("Number of contacts is %d\n", phonebook_size);

	/* add count for owner (0.vcf) */
	phonebook_size++;

	return phonebook_size;
}

static unsigned int __bluetooth_pb_get_incoming_call_size(void)
{
	CTSiter *iter = NULL;

	unsigned int call_size = 0;

	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	while (contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_incoming_call(phonelog_id))
			call_size++;

		contacts_svc_value_free(value);
	}

	if (iter)
		contacts_svc_iter_remove(iter);

	return call_size;
}

static unsigned int __bluetooth_pb_get_outgoing_call_size(void)
{
	CTSiter *iter = NULL;

	unsigned int call_size = 0;

	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	while (contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_outgoing_call(phonelog_id))
			call_size++;

		contacts_svc_value_free(value);
	}

	if (iter)
		contacts_svc_iter_remove(iter);

	return call_size;
}

static unsigned int __bluetooth_pb_get_missed_call_size(void)
{
	CTSiter *iter = NULL;

	unsigned int call_size = 0;

	contacts_svc_get_list(CTS_LIST_ALL_MISSED_CALL, &iter);

	while (contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		call_size++;
	}

	if (iter)
		contacts_svc_iter_remove(iter);

	return call_size;
}

static unsigned int __bluetooth_pb_get_combined_call_size(void)
{
	CTSiter *iter = NULL;

	unsigned int call_size = 0;

	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	while (contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_incoming_call(phonelog_id) ||
					_bluetooth_pb_is_outgoing_call(phonelog_id) ||
					_bluetooth_pb_is_missed_call(phonelog_id))
			call_size++;

		contacts_svc_value_free(value);
	}

	if (iter)
		contacts_svc_iter_remove(iter);

	return call_size;
}

static GPtrArray *__bluetooth_pb_get_contact_vcards(BluetoothPbAgent *agent,
						guint64 filter,
						guint8 format,
						guint16 max_list_count,
						guint16 list_start_offset)
{
	GPtrArray *vcards = NULL;

	gint i = 1;
	gboolean unrestricted = FALSE;

	CTSiter *iter = NULL;

	vcards = g_ptr_array_new();

	if (max_list_count == 65535)
		unrestricted = TRUE;

	/* for owner */
	if (list_start_offset == 0) {
		gchar *vcard = NULL;
		vcard = _bluetooth_pb_vcard_contact(0, filter, format);

		g_ptr_array_add(vcards, vcard);
	}

	contacts_svc_get_list(CTS_LIST_ALL_CONTACT, &iter);
	while ((contacts_svc_iter_next(iter) == CTS_SUCCESS) &&
			(unrestricted || (i < list_start_offset + max_list_count))) {
		CTSvalue *value = NULL;
		gchar *vcard = NULL;
		gint id = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		id = contacts_svc_value_get_int(value, CTS_LIST_CONTACT_ID_INT);
		vcard = _bluetooth_pb_vcard_contact(id, filter, format);

		contacts_svc_value_free(value);

		if (vcard == NULL)
			continue;

		if ( i >= list_start_offset)
			g_ptr_array_add(vcards, vcard);

		i++;
	}

	g_ptr_array_add(vcards, NULL);

	if (iter)
		contacts_svc_iter_remove(iter);

	return vcards;
}

static GPtrArray *__bluetooth_pb_get_incoming_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset)
{
	GPtrArray *vcards = NULL;

	gint i = 1;
	guint16 offset = list_start_offset;

	gboolean unrestricted = FALSE;

	CTSiter *iter = NULL;

	vcards = g_ptr_array_new();
	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	if (max_list_count == 65535)
		unrestricted = TRUE;

	if (offset == 0)
		offset = 1;

	DBG("i %d offset %d max_list_count %d\n", i, offset, max_list_count);

	while ((contacts_svc_iter_next(iter) == CTS_SUCCESS) &&
			(unrestricted || (i < offset + max_list_count))) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;
		gchar *vcard = NULL;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_incoming_call(phonelog_id)) {
			vcard = _bluetooth_pb_vcard_call(phonelog_id, filter, format,
					"RECEIVED");

			if (vcard == NULL)
				continue;

			if ( i >= offset)
				g_ptr_array_add(vcards, vcard);
			i++;
		}

		contacts_svc_value_free(value);
	}

	g_ptr_array_add(vcards, NULL);

	if (iter)
		contacts_svc_iter_remove(iter);

	return vcards;
}

static GPtrArray *__bluetooth_pb_get_outgoing_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset)
{
	GPtrArray *vcards = NULL;

	gint i = 1;
	guint16 offset = list_start_offset;

	gboolean unrestricted = FALSE;

	CTSiter *iter = NULL;

	vcards = g_ptr_array_new();
	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	if (max_list_count == 65535)
		unrestricted = TRUE;

	if (offset == 0)
		offset = 1;

	while ((contacts_svc_iter_next(iter) == CTS_SUCCESS) &&
			(unrestricted || (i < offset + max_list_count))) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;
		gchar *vcard = NULL;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_outgoing_call(phonelog_id)) {
			vcard = _bluetooth_pb_vcard_call(phonelog_id, filter, format,
					"DIALED");

			if (vcard == NULL)
				continue;

			if (i >= offset)
				g_ptr_array_add(vcards, vcard);
			i++;
		}

		contacts_svc_value_free(value);
	}

	g_ptr_array_add(vcards, NULL);

	if (iter)
		contacts_svc_iter_remove(iter);

	return vcards;
}

static GPtrArray *__bluetooth_pb_get_missed_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset)
{
	GPtrArray *vcards = NULL;

	gint i = 1;
	guint16 offset = list_start_offset;

	gboolean unrestricted = FALSE;

	CTSiter *iter = NULL;

	vcards = g_ptr_array_new();
	contacts_svc_get_list(CTS_LIST_ALL_MISSED_CALL, &iter);

	if (max_list_count == 65535)
		unrestricted = TRUE;

	if (offset == 0)
		offset = 1;

	while ((contacts_svc_iter_next(iter) == CTS_SUCCESS) &&
			(unrestricted || (i < offset + max_list_count))) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;
		gchar *vcard = NULL;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_missed_call(phonelog_id)) {
			vcard = _bluetooth_pb_vcard_call(phonelog_id, filter, format,
					"MISSED");

			if (vcard == NULL)
				continue;

			if (i >= offset)
				g_ptr_array_add(vcards, vcard);
			i++;
		}

		contacts_svc_value_free(value);
	}

	g_ptr_array_add(vcards, NULL);

	if (iter)
		contacts_svc_iter_remove(iter);

	return vcards;
}

static GPtrArray *__bluetooth_pb_get_combined_call_vcards(BluetoothPbAgent *agent,
							guint64 filter,
							guint8 format,
							guint16 max_list_count,
							guint16 list_start_offset)
{
	GPtrArray *vcards = NULL;

	gint i = 1;
	guint16 offset = list_start_offset;

	gboolean unrestricted = FALSE;

	CTSiter *iter = NULL;

	vcards = g_ptr_array_new();
	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	if (max_list_count == 65535)
		unrestricted = TRUE;

	if (offset == 0)
		offset = 1;

	while ((contacts_svc_iter_next(iter) == CTS_SUCCESS) &&
			(unrestricted || (i < offset + max_list_count))) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;
		gchar *vcard = NULL;

		gchar *attr = NULL;

		value = contacts_svc_iter_get_info(iter);
		if(value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		if (_bluetooth_pb_is_incoming_call(phonelog_id))
			attr = "RECEIVED";
		else if (_bluetooth_pb_is_outgoing_call(phonelog_id))
			attr = "DIALED";
		else if (_bluetooth_pb_is_missed_call(phonelog_id))
			attr = "MISSED";

		vcard = _bluetooth_pb_vcard_call(phonelog_id, filter, format,
				attr);

		if (vcard == NULL)
			continue;

		if (i >= offset)
			g_ptr_array_add(vcards, vcard);
		i++;

		contacts_svc_value_free(value);
	}

	g_ptr_array_add(vcards, NULL);

	if (iter)
		contacts_svc_iter_remove(iter);

	return vcards;
}

static void __bluetooth_pb_create_contact_index(PhoneBookType pb_type)
{
	CTSiter *iter = NULL;
	gint i = 1;


	if (g_current_pb_type == pb_type)
		return;

	/* create cache */
	g_current_pb_type = pb_type;
	__bluetooth_pb_list_hash_reset();

	contacts_svc_get_list(CTS_LIST_ALL_CONTACT, &iter);

	while (contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		CTSvalue *value = NULL;
		gint contact_id = 0;

		value = contacts_svc_iter_get_info(iter);
		if (value == NULL)
			continue;

		contact_id = contacts_svc_value_get_int(value, CTS_LIST_CONTACT_ID_INT);
		__bluetooth_pb_list_hash_insert(i, contact_id);


		i++;
	}
}

static void __bluetooth_pb_create_call_index(PhoneBookType pb_type)
{
	CTSiter *iter = NULL;
	gint i = 1;

	if (g_current_pb_type == pb_type)
		return;

	/* create cache */
	g_current_pb_type = pb_type;
	__bluetooth_pb_list_hash_reset();

	contacts_svc_get_list(CTS_LIST_ALL_PLOG, &iter);

	while(contacts_svc_iter_next(iter) == CTS_SUCCESS) {
		CTSvalue *value = NULL;
		gint phonelog_id = 0;

		value = contacts_svc_iter_get_info(iter);
		if(value == NULL)
			continue;

		phonelog_id = contacts_svc_value_get_int(value, CTS_LIST_PLOG_ID_INT);

		switch (pb_type) {
		case TELECOM_ICH: {
			if(_bluetooth_pb_is_incoming_call(phonelog_id)) {
				__bluetooth_pb_list_hash_insert(i, phonelog_id);
				i++;
			}
		}
			break;
		case TELECOM_OCH: {
			if(_bluetooth_pb_is_outgoing_call(phonelog_id)) {
				__bluetooth_pb_list_hash_insert(i, phonelog_id);
				i++;
			}
		}
			break;
		case TELECOM_MCH: {
			if(_bluetooth_pb_is_missed_call(phonelog_id)) {
				__bluetooth_pb_list_hash_insert(i, phonelog_id);
				i++;
			}
		}
			break;
		case TELECOM_CCH: {
			if(_bluetooth_pb_is_incoming_call(phonelog_id) ||
					_bluetooth_pb_is_outgoing_call(phonelog_id) ||
					_bluetooth_pb_is_missed_call(phonelog_id)) {
				__bluetooth_pb_list_hash_insert(i, phonelog_id);
				i++;
			}
		}
			break;
		default :
			return;
		}

		contacts_svc_value_free(value);
	}
}


static void __bluetooth_pb_get_contact_list(PhoneBookType pb_type,
					GPtrArray *ptr_array,
					gint start_index,
					gint end_index,
					gboolean formatted_name)
{
	gint i;
	guint hash_size;

	if (ptr_array == NULL)
		return;

	__bluetooth_pb_create_contact_index(pb_type);

	if (end_index < 0 || end_index < start_index)
		end_index = start_index;

	if (start_index <= 0) {
		/* owner */
		gchar *name = NULL;
		gchar *number = NULL;

		if (formatted_name)
			name = _bluetooth_pb_name_owner();
		else
			name = _bluetooth_pb_fn_owner();

		number = _bluetooth_pb_number_owner();

		__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, 0);

		g_free(name);
		g_free(number);

		start_index = 1;
	}

	hash_size = __bluetooth_pb_list_hash_size();
	if (hash_size < end_index)
		end_index = hash_size;

	for (i = start_index; i <= end_index; i++) {
		gint contact_id;

		gchar *name = NULL;
		gchar *number = NULL;

		contact_id = __bluetooth_pb_list_hash_lookup_id(i);

		if (formatted_name)
			name = _bluetooth_pb_fn_from_contact_id(contact_id);
		else
			name = _bluetooth_pb_name_from_contact_id(contact_id);

		number = _bluetooth_pb_number_from_contact_id(contact_id);

		__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, i);

		g_free(name);
		g_free(number);
	}
}

static void __bluetooth_pb_get_call_list(PhoneBookType pb_type,
					GPtrArray *ptr_array,
					gint start_index,
					gint end_index,
					gboolean formatted_name)
{
	gint i;
	guint hash_size;

	if (ptr_array == NULL)
		return;

	__bluetooth_pb_create_call_index(pb_type);

	if (end_index < 0 || end_index < start_index)
		end_index = start_index;

	if (start_index <= 0)
		start_index = 1;

	hash_size = __bluetooth_pb_list_hash_size();
	if (hash_size < end_index)
		end_index = hash_size;

	DBG("start_index: %d end_index %d\n", start_index, end_index);

	for (i = start_index; i <= end_index; i++) {
		gint phonelog_id;

		gchar *name = NULL;
		gchar *number = NULL;

		phonelog_id = __bluetooth_pb_list_hash_lookup_id(i);

		if (formatted_name)
			name = _bluetooth_pb_fn_from_phonelog_id(phonelog_id);
		else
			name = _bluetooth_pb_name_from_phonelog_id(phonelog_id);

		number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);

		__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, i);

		g_free(name);
		g_free(number);
	}
}

static void __bluetooth_pb_get_contact_list_by_name(PhoneBookType pb_type,
						GPtrArray *ptr_array,
						const gchar *find_text,
						gboolean formatted_name,
						gboolean owner)
{
	DBG("%s %d\n", __FILE__, __LINE__);
	guint i;
	guint hash_size;

	if (ptr_array == NULL)
		return;

	__bluetooth_pb_create_contact_index(pb_type);

	if (owner) {
		/* owner */
		gchar *name;

		if (formatted_name)
			name = _bluetooth_pb_name_owner();
		else
			name = _bluetooth_pb_fn_owner();

		if (g_str_has_prefix(name, find_text)) {
			gchar *number;

			number = _bluetooth_pb_number_owner();

			__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, 0);

			g_free(number);
		}

		g_free(name);
	}

	hash_size = __bluetooth_pb_list_hash_size();

	for (i = 1; i <= hash_size; i++) {
		gint contact_id;
		gchar *name;

		contact_id = __bluetooth_pb_list_hash_lookup_id(i);

		if (formatted_name)
			name = _bluetooth_pb_fn_from_contact_id(contact_id);
		else
			name = _bluetooth_pb_name_from_contact_id(contact_id);

		if(g_str_has_prefix(name , find_text)) {
			gchar *number;

			number = _bluetooth_pb_number_from_contact_id(contact_id);

			__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, i);

			g_free(number);
		}

		g_free(name);
	}
}

static void __bluetooth_pb_get_call_list_by_name(PhoneBookType pb_type,
						GPtrArray *ptr_array,
						const gchar *find_text,
						gboolean formatted_name)
{
	guint i;
	guint hash_size;

	if (ptr_array == NULL)
		return;

	__bluetooth_pb_create_call_index(pb_type);

	hash_size = __bluetooth_pb_list_hash_size();

	for (i = 1; i <= hash_size; i++) {
		gint phonelog_id;
		gchar *name;

		phonelog_id = __bluetooth_pb_list_hash_lookup_id(i);

		if (formatted_name)
			name = _bluetooth_pb_fn_from_phonelog_id(phonelog_id);
		else
			name = _bluetooth_pb_name_from_phonelog_id(phonelog_id);

		if(g_str_has_prefix(name , find_text)) {
			gchar *number;

			number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);

			__bluetooth_pb_list_ptr_array_add(ptr_array, name, number, i);

			g_free(number);
		}

		g_free(name);
	}
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
		if(plog == NULL)
			continue;

		int type = contacts_svc_value_get_int(plog, CTS_LIST_PLOG_LOG_TYPE_INT);
		DBG("type: %d\n", type);
		int log_type = __bluetooth_get_calllog_type(type);

		if ((call_log_type == 0xFF || call_log_type == log_type) &&
				(log_type != CTS_PLOG_TYPE_NONE)) {
			count++;
		}
	}
	return count;
}

static void __bluetooth_pb_list_hash_reset(void)
{
	if (contact_list_hash)
		g_hash_table_destroy(contact_list_hash);

	contact_list_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static gboolean __bluetooth_pb_list_hash_insert(gint handle,
						gint id)
{
	if (contact_list_hash == NULL)
		return FALSE;

	g_hash_table_insert(contact_list_hash,
			GINT_TO_POINTER(handle), GINT_TO_POINTER(id));

	return TRUE;
}

static gint __bluetooth_pb_list_hash_lookup_id(gint handle)
{
	gint id;
	if (contact_list_hash == NULL)
		return 0;

	id = GPOINTER_TO_INT(g_hash_table_lookup(contact_list_hash,
				GINT_TO_POINTER(handle)));

	return id;
}

static guint __bluetooth_pb_list_hash_size (void)
{
	if (contact_list_hash == NULL)
		return 0;

	return g_hash_table_size(contact_list_hash);
}

static void __bluetooth_pb_list_ptr_array_add(GPtrArray *ptr_array,
						const gchar *name,
						const gchar *number,
						gint handle)
{
	GValue value = { 0, };

	g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_STRING_STRING_UINT));

	dbus_g_type_struct_set(&value,
				0, g_strdup(name),
				1, g_strdup(number),
				2, handle,
				G_MAXUINT);

	g_ptr_array_add(ptr_array, g_value_get_boxed(&value));
}

static void __bluetooth_pb_list_ptr_array_free(gpointer data)
{
	GValue value = { 0, };

	gchar *name = NULL;
	gchar *number = NULL;

	if(data == NULL)
		return;

	g_value_init(&value, DBUS_STRUCT_STRING_STRING_UINT);
	g_value_set_boxed(&value, data);

	dbus_g_type_struct_get(&value,
			0, &name,
			1, &number,
			G_MAXUINT);

	g_free(name);
	g_free(number);
}

static void __bluetooth_pb_agent_signal_handler(int signum)
{
	if (mainloop)
		g_main_loop_quit(mainloop);
	else
		exit(0);
}

static void __bluetooth_pb_contact_changed(void *user_data)
{
	BluetoothPbAgent *agent;

	g_return_if_fail(BLUETOOTH_IS_PB_AGENT(user_data));
	agent = BLUETOOTH_PB_AGENT(user_data);

	g_signal_emit(agent, signals[CLEAR], 0);
}

static void __bluetooth_pb_call_changed(void *user_data)
{
	BluetoothPbAgent *agent;

	g_return_if_fail(BLUETOOTH_IS_PB_AGENT(user_data));
	agent = BLUETOOTH_PB_AGENT(user_data);

	g_signal_emit(agent, signals[CLEAR], 0);
}

int main(int argc, char **argv)
{
	BluetoothPbAgent *bluetooth_pb_obj = NULL;

	DBusGConnection *bus = NULL;
	DBusGProxy *bus_proxy = NULL;

	guint result = 0;

	gint ret = EXIT_SUCCESS;
	struct sigaction sa;

	GError *error = NULL;

	cts_error status;

	g_type_init();

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
		ret = EXIT_FAILURE;
		goto failure;
	}

	if (!dbus_g_proxy_call(bus_proxy, "RequestName", &error, G_TYPE_STRING,
			BT_PB_SERVICE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (error != NULL) {
			DBG("RequestName RPC failed[%s]\n", error->message);
			g_error_free(error);
		}
		ret = EXIT_FAILURE;
		goto failure;
	}
	DBG("result : %d %d\n", result, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		DBG("Failed to get the primary well-known name.\n");
		ret = EXIT_FAILURE;
		goto failure;
	}

	g_object_unref(bus_proxy);
	bus_proxy = NULL;

	bluetooth_pb_obj = g_object_new(BLUETOOTH_PB_TYPE_AGENT, NULL);
	if (bluetooth_pb_obj == NULL) {
		DBG("Failed to create one BluetoothPbAgent instance.\n");
		ret = EXIT_FAILURE;
		goto failure;
	}

	/* Registering it on the D-Bus */
	dbus_g_connection_register_g_object(bus, BT_PB_SERVICE_OBJECT_PATH,
						G_OBJECT(bluetooth_pb_obj));

	/* connect contact */
	status = (cts_error)contacts_svc_connect();
	if (status != CTS_SUCCESS) {
		DBG("Can not connect contacts server\n");
		ret = EXIT_FAILURE;
		goto failure;
	}

	contacts_svc_subscribe_change(CTS_SUBSCRIBE_CONTACT_CHANGE,
				__bluetooth_pb_contact_changed,
				bluetooth_pb_obj);
	contacts_svc_subscribe_change(CTS_SUBSCRIBE_PLOG_CHANGE,
				__bluetooth_pb_call_changed,
				bluetooth_pb_obj);

	/* set signal */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __bluetooth_pb_agent_signal_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	g_main_loop_run(mainloop);

 failure:
	DBG("Terminate the bluetooth-pb-agent\n");

	/* disconnect contact */
	contacts_svc_unsubscribe_change(CTS_SUBSCRIBE_CONTACT_CHANGE,
				__bluetooth_pb_contact_changed);
	contacts_svc_unsubscribe_change(CTS_SUBSCRIBE_PLOG_CHANGE,
				__bluetooth_pb_call_changed);

	contacts_svc_disconnect();

	g_signal_emit(bluetooth_pb_obj, signals[CLEAR], 0);

	if (bluetooth_pb_obj)
		g_object_unref(bluetooth_pb_obj);

	if (bus_proxy)
		g_object_unref(bus_proxy);

	if (bus)
		dbus_g_connection_unref(bus);

	return ret;
}

/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *		 Jaekyun Lee <jkyun.lee@samsung.com>
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
#include <time.h>
#include <string.h>
#include <stdarg.h>


#include <glib.h>
#include <dbus/dbus-glib.h>

#include <dlog.h>
#include <contacts-svc-struct.h>

#include "vconf.h"
#include "vconf-keys.h"

#include "bluetooth_pb_vcard.h"

#define BT_PB_AGENT	"BT_PB_AGENT"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_PB_AGENT, "%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_PB_AGENT, "%s():%d "fmt, __func__, __LINE__, ##args)

#define VCARD_FORMAT_2_1 0x0
#define VCARD_FORMAT_3_0 0x1

#define VCARD_VERSION	(0x1)
#define VCARD_FN	(0x1 << 1)	/* CTS_CF_NAME_VALUE: NAME_VALUE - CTS_NAME_VAL_DISPLAY_STR */
#define VCARD_N		(0x1 << 2)	/* CTS_CF_NAME_VALUE: NAME_VALUE -
					CTS_NAME_VAL_FIRST_STR, CTS_NAME_VAL_LAST_STR,
					CTS_NAME_VAL_ADDITION_STR, CTS_NAME_VAL_SUFFIX_STR,
					CTS_NAME_VAL_PREFIX_STR */
#define VCARD_PHOTO	(0x1 << 3)	/* CTS_CF_BASE_INFO_VALUE: BASEVALUE - CTS_BASE_VAL_IMG_PATH_STR*/
#define VCARD_BDAY	(0x1 << 4)	/* CTS_CF_EVENT_LIST: EVENTTYPE - CTS_EVENT_TYPE_BIRTH */
#define VCARD_ADR	(0x1 << 5)	/* CTS_CF_POSTAL_ADDR_LIST: */
#define VCARD_LABEL	(0x1 << 6)	/* not supported */
#define VCARD_TEL	(0x1 << 7)	/* CTS_CF_NUMBER_LIST: */
#define VCARD_EMAIL	(0x1 << 8)	/* CTS_CF_EMAIL_LIST: */
#define VCARD_MAILER	(0x1 << 9)	/* not supported */
#define VCARD_TZ	(0x1 << 10)	/* not supported */
#define VCARD_GEO	(0x1 << 11)	/* not supported */
#define VCARD_TITLE	(0x1 << 12)	/* CTS_CF_COMPANY_VALUE: COMPANYVALUE - CTS_COMPANY_VAL_JOB_TITLE_STR */
#define VCARD_ROLE	(0x1 << 13)	/* CTS_CF_COMPANY_VALUE: COMPANYVALUE - CTS_COMPANY_VAL_ROLE_STR */
#define VCARD_LOGO	(0x1 << 14)	/* not supported */
#define VCARD_AGENT	(0x1 << 15)	/* not supported */
#define VCARD_ORG	(0x1 << 16)	/* CTS_CF_COMPANY_VALUE: COMAPNYVALUE - CTS_COMPANY_VAL_NAME_STR */
#define VCARD_NOTE	(0x1 << 17)	/* CTS_CF_BASE_INFO_VALUE: BASEVALUE - CTS_BASE_VAL_NOTE_STR */
#define VCARD_REV	(0x1 << 18)	/* CTS_CF_BASE_INFO_VALUE: BASEVALUE - CTS_BASE_VAL_CHANGED_TIME_INT */
#define VCARD_SOUND	(0x1 << 19)	/* not supported */
#define VCARD_URL	(0x1 << 20)	/* CTS_CF_WEB_ADDR_LIST: */
#define VCARD_UID	(0x1 << 21)	/* CTS_CF_BASE_INFO_VALUE: BASEVALUE - CTS_BASE_VAL_UID_STR */
#define VCARD_KEY	(0x1 << 22)	/* not supported */
#define VCARD_NICKNAME	(0x1 << 23)	/* CTS_CF_NICKNAME_LIST: */
#define VCARD_CATEGORIES	(0x1 << 24)	/* not supported */
#define VCARD_PROID	(0x1 << 25)	/* not supported */
#define VCARD_CLASS	(0x1 << 26)	/* not supported */
#define VCARD_SORT_STRING	(0x1 << 27)	/* not supported */

#define VCARD_X_IRMC_CALL_DATETIME	(0x1 << 28)

#define QP_ENC_LEN	3
#define LINEBREAK_LEN	75


static gchar *__bluetooth_pb_vcard_escape(const gchar *str);

static gchar *__bluetooth_pb_vcard_strv_concat(gchar **strv,
					const gchar *delimeter);


static gboolean __bluetooth_pb_vcard_qp_encode_check(const gchar *str);

static gint __bluetooth_pb_vcard_qp_encode_strlen(const gchar *str,
						gint len);

static void __bluetooth_pb_vcard_qp_encode_append_to_hex(GString *string,
							const gchar *str,
							gint len,
							gint *line_pos);

static void __bluetooth_pb_vcard_qp_encode_append_printable_c(GString *string,
							gchar ch,
							gint *line_pos);

static void __bluetooth_pb_vcard_qp_encode_append(GString *string,
						const gchar *str,
						gint len,
						gint *line_pos);

static gchar *__bluetooth_pb_vcard_qp_encode(const gchar *str);

static gchar *__bluetooth_pb_vcard_owner(guint64 filter,
					guint8 format);

static void __bluetooth_pb_vcard_append_param_v21(GString *string,
						 const gchar *param);

static void __bluetooth_pb_vcard_append_qp_encode_v21(GString *string,
					const gchar *name,
					const gchar *param,
					const gchar *value);

static void __bluetooth_pb_vcard_append_base64_encode_v21(GString *string,
							const gchar *name,
							const gchar *param,
							const gchar *value,
							gsize len,
							gboolean folding);

static void __bluetooth_pb_vcard_append_n_v21(GString *string,
					CTSstruct *contact);

static void __bluetooth_pb_vcard_append_tel_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_fn_v21(GString *string,
					CTSstruct *contact);

static void __bluetooth_pb_vcard_append_photo_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_bday_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_adr_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_email_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_title_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_role_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_org_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_note_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_rev_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_url_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_uid_v21(GString *string,
						CTSstruct *contact);

static void __bluetooth_pb_vcard_append_v30(GString *string,
					const gchar *name,
					const gchar *param,
					const gchar *value);

static void __bluetooth_pb_vcard_remove_v30(GString *string,
					const gchar *property_name);

static gchar *__bluetooth_pb_vcard_filter_v30(const gchar *vcard,
					guint64 filter);

static gchar *__bluetooth_pb_vcard_real_contact_valist_v21(gint contact_id,
							gint phonelog_id,
							guint64 filter,
							const gchar *first_name,
							va_list args);

static gchar *__bluetooth_pb_vcard_real_contact_valist_v30(gint contact_id,
							gint phonelog_id,
							guint64 filter,
							const gchar *first_name,
							va_list args);

static gchar *__bluetooth_pb_vcard_real_contact_with_properties(gint contact_id,
								gint phonelog_id,
								guint64 filter,
								guint8 format,
								const gchar *first_name,
								...);

static gchar *__bluetooth_pb_vcard_real_call_v21(gint phonelog_id,
						guint filter,
						const gchar *attr);

static gchar *__bluetooth_pb_vcard_real_call_v30(gint phonelog_id,
						guint filter,
						const gchar *attr);

static gchar *__bluetooth_pb_vcard_real_call(gint phonelog_id,
					guint filter,
					guint8 format,
					const gchar *attr);

static gchar **__bluetooth_pb_contact_add_field_str(CTSvalue *value,
						int *field,
						gint field_size);

static gchar **__bluetooth_pb_contact_tel_param(CTSvalue *value);

static gchar *__bluetooth_pb_contact_photo_type(const gchar *filename);

static gchar **__bluetooth_pb_contact_addr(CTSvalue *value);

static gchar **__bluetooth_pb_contact_addr_param(CTSvalue *value);

static gchar *__bluetooth_pb_phonelog_datetime(gint phonelog_id);

static gchar *__bluetooth_pb_fn_from_contact(CTSstruct *contact);

static gchar *__bluetooth_pb_name_from_contact(CTSstruct *contact);

static gchar *__bluetooth_pb_number_from_contact(CTSstruct *contact);

static gint __bluetooth_pb_contact_id_from_phonelog_id(gint phonelog_id);

static gchar *__bluetooth_pb_vcard_escape(const gchar *str)
{
	GString *escaped;

	gchar *st = NULL;
	gchar *pos = NULL;

	if (str == NULL)
		return NULL;

	escaped = g_string_new(NULL);

	st = (gchar *)str;
	pos = st;

	while (*pos != '\0') {
		if (*pos == ';') {
			g_string_append_len(escaped, st, (pos - st));
			g_string_append(escaped, "\\;");

			pos++;
			st = pos;
		}
		else {
			pos++;
		}
	}

	g_string_append_len(escaped, st, (pos - st));
	return g_string_free(escaped, FALSE);
}

static gchar *__bluetooth_pb_vcard_strv_concat(gchar **strv,
					const gchar *separator)
{
	GString *string = g_string_new(NULL);
	gint i;

	for (i = 0; strv[i] != NULL; i++) {
		if (i > 0)
			g_string_append(string, ";");

		g_string_append(string, strv[i]);
	}

	return g_string_free(string, FALSE);
}

static gboolean __bluetooth_pb_vcard_qp_encode_check(const gchar *str)
{
	gchar *pos = NULL;

	if (str == NULL)
		return FALSE;

	pos = (gchar *)str;
	while (*pos != '\0') {
		/* ascii code  ' ' : 32, '~' : 126 */
		if ((guchar)*pos < ' ' || (guchar)*pos > '~')
			return TRUE;

		pos++;
	}
	return FALSE;
}

/* get string length, which convert to quoted-printable encoding */
static gint __bluetooth_pb_vcard_qp_encode_strlen(const gchar *str,
						gint len)
{
	gchar *pos;

	gint count = 0;
	gint length = len;

	if (str == NULL)
		return 0;

	if (strlen(str) < len )
		length = -1;

	pos = (gchar *)str;

	while (*pos != '\0' && (((pos - str) < length) || length < 0)) {
		if ((guchar)*pos == '\t') {
			count++;
			pos++;
			continue;
		}

		if ((guchar)*pos < ' ' || (guchar)*pos == '=') {
			count += QP_ENC_LEN;
			pos++;
			continue;
		}

		/* check no-ascii utf-8 character */
		if ((guchar)*pos > '~') {

			gchar *next;

			next = g_utf8_next_char(pos);

			count += QP_ENC_LEN * (next - pos);
			pos = next;
			continue;
		}

		pos++;
		count++;
	}

	return count;
}

/* convert to quoted printable code */
static void __bluetooth_pb_vcard_qp_encode_append_to_hex(GString *string,
							const gchar *str,
							gint len,
							gint *line_pos)
{
	int i;

	if (str == NULL || len == 0)
		return;

	/* add soft linebreak when it exceed */
	if ((*line_pos + (QP_ENC_LEN * len) > LINEBREAK_LEN)) {
		g_string_append(string, "=\r\n");
		*line_pos = 0;
	}

	for (i = 0; i < len; i++) {
		g_string_append_printf(string, "=%02X", (guchar)*(str+i));
		*line_pos += QP_ENC_LEN;
	}
}

/* append plain visiable ascii character */
static void __bluetooth_pb_vcard_qp_encode_append_printable_c(GString *string,
							gchar ch,
							gint *line_pos)
{
	/* add soft linebreak when it exceed */
	if (*line_pos + 1 > LINEBREAK_LEN) {
		g_string_append(string, "=\r\n");
		*line_pos = 0;
	}
	g_string_append_c(string, ch);
	(*line_pos)++;
}

static void __bluetooth_pb_vcard_qp_encode_append(GString *string,
						const gchar *str,
						gint len,
						gint *line_pos)
{
	gint length;
	gint encode_len;

	gint i = 0;

	if (string == NULL)
		return;

	encode_len = __bluetooth_pb_vcard_qp_encode_strlen(str, len);

	/* add soft linebreak when it exceed */
	if (((*line_pos + encode_len) > LINEBREAK_LEN) && (*line_pos > 1)) {
		g_string_append(string, "=\r\n");
		*line_pos = 0;
	}

	length = strlen(str);
	if (length > len)
		length = len;

	while (i < len) {
		gchar *pos;

		pos = ((gchar *)str) + i;

		/* converts invisiable character and escape character '=' to quoted-printable */
		if ((guchar)*pos != '\t' &&
				((guchar)*pos < ' ' || (guchar)*pos == '=')) {
			__bluetooth_pb_vcard_qp_encode_append_to_hex(string, pos,
					1, line_pos);
			i++;

			continue;
		}

		/* converts non-ascii utf-8 character to quoted-printable */
		if ((guchar)*pos > '~') {
			gchar *next;
			int ch_len;

			next = g_utf8_next_char(pos);

			ch_len = next - pos;
			__bluetooth_pb_vcard_qp_encode_append_to_hex(string, pos,
					ch_len, line_pos);
			i += ch_len;

			continue;
		}

		__bluetooth_pb_vcard_qp_encode_append_printable_c(string, *pos, line_pos);
		i++;
	}
}

static gchar* __bluetooth_pb_vcard_qp_encode(const gchar *str)
{
	GString *enc;

	gchar *st_pos;
	gchar *pos;

	gint line_pos = 0;

	if (str == NULL)
		return NULL;

	enc = g_string_new(NULL);

	st_pos = (gchar *)str;
	pos = (gchar *)str;

	while (*pos != '\0') {
		/* split string with given delimeter  ' ' or  '\t' */
		if (*pos == ' '  || *pos == '\t') {
			__bluetooth_pb_vcard_qp_encode_append(enc, st_pos,
					(pos - st_pos), &line_pos);

			st_pos = pos;
			pos++;

			continue;
		}

		/* split string with given delimeter '\r', '\n' or '\r\n' - newline */
		if (*pos == '\r' || *pos == '\n' ) {
			__bluetooth_pb_vcard_qp_encode_append(enc, st_pos,
					(pos - st_pos), &line_pos);

			/* convers newline to qp_encode with soft linebreak
			 for example, converts \r\n to  =0D=0A=\r\n */
			__bluetooth_pb_vcard_qp_encode_append_to_hex(enc, "\r\n",
					2, &line_pos);
			g_string_append(enc, "=\r\n ");

			line_pos = 1;

			if (*pos == '\r' && *(pos + 1) == '\n')
				pos += 2;
			else
				pos++;

			st_pos = pos;

			continue;
		}

		pos++;
	}

	__bluetooth_pb_vcard_qp_encode_append(enc, st_pos,
			(pos - st_pos), &line_pos);

	return g_string_free(enc, FALSE);
}


/* FIXME: only telephony number we have, filter does not support yet */
static gchar *__bluetooth_pb_vcard_owner(guint64 filter,
				guint8 format)
{
	GString *str = g_string_new("BEGIN:VCARD\r\n");
	gchar *number;

	number = _bluetooth_pb_number_owner();

	if (number == NULL)
		ERR("can not get vconf value from VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER\n");

	switch (format) {
	case VCARD_FORMAT_3_0:
		g_string_append(str, "VERSION:3.0\r\n");
		__bluetooth_pb_vcard_append_v30(str, "TEL", "TYPE=CELL", number);
		break;
	case VCARD_FORMAT_2_1:
	default :
		g_string_append(str, "VERSION:2.1\r\n");
		__bluetooth_pb_vcard_append_qp_encode_v21(str, "TEL", "CELL", number);
		break;

	}

	g_string_append(str, "END:VCARD\r\n");
	g_free(number);

	return g_string_free(str, FALSE);
}

static void __bluetooth_pb_vcard_append_param_v21(GString *string,
						 const gchar *param)
{
	gchar *pos = NULL;

	if (param == NULL)
		return;

	pos = (gchar *)param;

	while (*pos != '\0') {
		if (*pos != ';')
			break;

		pos++;
	}

	if (*pos != '\0')
		g_string_append_printf(string, ";%s", pos);
}

static void __bluetooth_pb_vcard_append_qp_encode_v21(GString *string,
						const gchar *name,
						const gchar *param,
						const gchar *value)
{
	GString *property = NULL;

	if (name == NULL)
		return;

	property = g_string_new(name);
	__bluetooth_pb_vcard_append_param_v21(property, param);

	if (__bluetooth_pb_vcard_qp_encode_check(value)) {
		gchar *enc = NULL;

		__bluetooth_pb_vcard_append_param_v21(property,
				"ENCODING=QUOTED-PRINTABLE");
		__bluetooth_pb_vcard_append_param_v21(property,
				"CHARSET=utf-8");
		g_string_append(property, ":");

		enc = __bluetooth_pb_vcard_qp_encode(value);

		if (enc) {
			g_string_append(property, enc);
			g_free(enc);
		}
	} else {
		g_string_append(property, ":");
		if (value)
			g_string_append(property , value);
	}

	g_string_append_printf(string, "%s\r\n", property->str);

	g_string_free(property, TRUE);
}


static void __bluetooth_pb_vcard_append_base64_encode_v21(GString *string,
							const gchar *name,
							const gchar *param,
							const gchar *value,
							gsize len,
							gboolean folding)
{
	gchar *enc = NULL;

	if (name == NULL)
		return;

	g_string_append(string, name);

	__bluetooth_pb_vcard_append_param_v21(string, param);
	__bluetooth_pb_vcard_append_param_v21(string, "ENCODING=BASE64");

	g_string_append(string, ":");

	if (value  == NULL)
		return;

	enc = g_base64_encode((const guchar *)value, len);


	if (folding == FALSE) {
		g_string_append(string, enc);
	} else {
		gint enc_len = strlen(enc);
		gint i = 0;

		/* count ' ' size for folding */
		gint fline_len = LINEBREAK_LEN -1;

		for (i = 0; (i * fline_len) < enc_len; i++) {
			g_string_append(string, "\r\n ");
			if ((i * fline_len) + fline_len >  enc_len)
				g_string_append(string, enc + (i * fline_len));
			else
				g_string_append_len(string, enc + (i * fline_len), fline_len);
		}

		/* some application requires more \r\n */
		g_string_append(string, "\r\n");
	}
	g_string_append(string, "\r\n");

	g_free(enc);
}

static void __bluetooth_pb_vcard_append_n_v21(GString *string,
					CTSstruct *contact)
{
	gchar *str;

	str = __bluetooth_pb_name_from_contact(contact);
	__bluetooth_pb_vcard_append_qp_encode_v21(string, "N", NULL, str);

	g_free(str);
}

static void __bluetooth_pb_vcard_append_tel_v21(GString *string,
						CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	contacts_svc_struct_get_list(contact, CTS_CF_NUMBER_LIST, &list);

	for (pos = list; pos != NULL; pos = pos->next) {
		CTSvalue *value = (CTSvalue *)(pos->data);

		gchar **paramv = NULL;
		gchar *param = NULL;

		const gchar *tel = NULL;
		gchar *escaped = NULL;

		tel  = contacts_svc_value_get_str(value, CTS_NUM_VAL_NUMBER_STR);
		escaped = __bluetooth_pb_vcard_escape(tel);

		paramv = __bluetooth_pb_contact_tel_param(value);
		param = __bluetooth_pb_vcard_strv_concat(paramv, ";");

		g_strfreev(paramv);

		__bluetooth_pb_vcard_append_qp_encode_v21(string, "TEL", param, escaped);

		g_free(escaped);
		g_free(param);
	}
}

static void __bluetooth_pb_vcard_append_fn_v21(GString *string,
					CTSstruct *contact)
{
	CTSvalue *value = NULL;

	gchar *fn = NULL;
	gchar *tmp = NULL;

	contacts_svc_struct_get_value(contact, CTS_CF_NAME_VALUE, &value);

	tmp = __bluetooth_pb_fn_from_contact(contact);
	fn = __bluetooth_pb_vcard_escape(tmp);

	__bluetooth_pb_vcard_append_qp_encode_v21(string, "FN", NULL, fn);

	g_free(tmp);
	g_free(fn);
}

static void __bluetooth_pb_vcard_append_photo_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	const gchar *filename = NULL;

	gchar *type = NULL;
	gchar *param = NULL;
	gchar *contents = NULL;

	gsize len = 0;

	contacts_svc_struct_get_value(contact, CTS_CF_BASE_INFO_VALUE, &value);
	filename = contacts_svc_value_get_str(value, CTS_BASE_VAL_IMG_PATH_STR);

	if (filename == NULL) {
		return;
	}

	type = __bluetooth_pb_contact_photo_type(filename);

	if (type) {
		param = g_strdup_printf("TYPE=%s", type);
		g_free(type);
	}

	if (g_file_get_contents(filename, &contents, &len, NULL) == FALSE) {
		ERR("can not read file contents:%s\n", filename);
		return;
	}

	__bluetooth_pb_vcard_append_base64_encode_v21(string,
			"PHOTO", param, contents, len, TRUE);

	g_free(param);
	g_free(contents);
}

static void __bluetooth_pb_vcard_append_bday_v21(GString *string,
						CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	contacts_svc_struct_get_list(contact, CTS_CF_EVENT_LIST, &list);

	for (pos = list; pos != NULL; pos = pos->next) {
		enum EVENTTYPE  event_type;
		gint date;
		CTSvalue *value = (CTSvalue *) (pos->data);

		event_type = contacts_svc_value_get_int(value, CTS_EVENT_VAL_TYPE_INT);
		if (event_type != CTS_EVENT_TYPE_BIRTH)
			continue;

		date = contacts_svc_value_get_int(value, CTS_EVENT_VAL_DATE_INT);
		if (date > 0) {
			gchar *bday = NULL;

			bday = g_strdup_printf("%04d-%02d-%02d",
					(date/10000), (date/100)%100, date%100);
			__bluetooth_pb_vcard_append_qp_encode_v21(string, "BDAY",
					NULL, bday);
			g_free(bday);
		}
	}
}

static void __bluetooth_pb_vcard_append_adr_v21(GString *string,
						CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	contacts_svc_struct_get_list(contact, CTS_CF_POSTAL_ADDR_LIST, &list);

	for (pos = list; pos != NULL; pos = pos->next) {
		CTSvalue *value = (CTSvalue *) (pos->data);

		gchar **addrv;
		gchar **paramv;

		gchar *addr;
		gchar *param;

		if (value == NULL)
			continue;

		addrv = __bluetooth_pb_contact_addr(value);

		if (addrv == NULL)
			continue;

		addr = __bluetooth_pb_vcard_strv_concat(addrv, ";");
		g_strfreev(addrv);

		paramv = __bluetooth_pb_contact_addr_param(value);
		param = __bluetooth_pb_vcard_strv_concat(paramv, ";");
		g_strfreev(paramv);

		__bluetooth_pb_vcard_append_qp_encode_v21(string, "ADR",
				param, addr);

		g_free(param);
		g_free(addr);
	}
}

static void __bluetooth_pb_vcard_append_email_v21(GString *string,
						CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	contacts_svc_struct_get_list(contact, CTS_CF_EMAIL_LIST, &list);

	for (pos = list; pos != NULL; pos = pos->next) {
		CTSvalue *value = (CTSvalue *)(pos->data);

		const gchar *email;
		gchar *escaped;

		if (value == NULL)
			continue;

		email = contacts_svc_value_get_str(value, CTS_EMAIL_VAL_ADDR_STR);
		if (email == NULL)
			continue;

		escaped = __bluetooth_pb_vcard_escape(email);
		__bluetooth_pb_vcard_append_qp_encode_v21(string, "EMAIL", NULL, escaped);

		g_free(escaped);
	}

}

static void __bluetooth_pb_vcard_append_title_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	const gchar *title;
	gchar *escaped;

	contacts_svc_struct_get_value(contact, CTS_CF_COMPANY_VALUE, &value);

	if (value == NULL)
		return;

	title = contacts_svc_value_get_str(value, CTS_COMPANY_VAL_JOB_TITLE_STR);

	if (title == NULL)
		return;

	escaped = __bluetooth_pb_vcard_escape(title);
	__bluetooth_pb_vcard_append_qp_encode_v21(string, "TITLE", NULL, escaped);

	g_free(escaped);
}

static void __bluetooth_pb_vcard_append_role_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;
	const gchar *role;
	gchar *escaped;

	contacts_svc_struct_get_value(contact, CTS_CF_COMPANY_VALUE, &value);

	if (value == NULL)
		return;

	role = contacts_svc_value_get_str(value, CTS_COMPANY_VAL_ROLE_STR);

	if (role == NULL)
		return;

	escaped = __bluetooth_pb_vcard_escape(role);
	__bluetooth_pb_vcard_append_qp_encode_v21(string, "ROLE", NULL, escaped);

	g_free(escaped);
}

static void __bluetooth_pb_vcard_append_org_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	GString *org = NULL;

	const gchar *name;
	const gchar *department;

	contacts_svc_struct_get_value(contact, CTS_CF_COMPANY_VALUE, &value);

	name = contacts_svc_value_get_str(value, CTS_COMPANY_VAL_NAME_STR);
	department = contacts_svc_value_get_str(value, CTS_COMPANY_VAL_DEPARTMENT_STR);

	if (name == NULL && department == NULL)
		return;

	org = g_string_new(NULL);

	if (name) {
		gchar *escaped;

		escaped = __bluetooth_pb_vcard_escape(name);
		g_string_append(org, escaped);
		g_free(escaped);
	}

	g_string_append(org, ";");

	if (department) {
		gchar *escaped;

		escaped = __bluetooth_pb_vcard_escape(department);
		g_string_append(org, escaped);
		g_free(escaped);
	}

	__bluetooth_pb_vcard_append_qp_encode_v21(string, "ORG", NULL, org->str);

	g_string_free(org, TRUE);
}

static void __bluetooth_pb_vcard_append_note_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	const gchar *note;
	gchar *escaped;

	contacts_svc_struct_get_value(contact, CTS_CF_BASE_INFO_VALUE, &value);

	if (value == NULL)
		return;

	note = contacts_svc_value_get_str(value, CTS_BASE_VAL_NOTE_STR);

	if (note == NULL)
		return;

	escaped = __bluetooth_pb_vcard_escape(note);
	__bluetooth_pb_vcard_append_qp_encode_v21(string, "NOTE", NULL, escaped);

	g_free(escaped);
}

static void __bluetooth_pb_vcard_append_rev_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	gint time;
	gchar *rev;

	struct tm result;

	contacts_svc_struct_get_value(contact, CTS_CF_BASE_INFO_VALUE, &value);

	if (value == NULL)
		return;

	time = contacts_svc_value_get_int(value, CTS_BASE_VAL_CHANGED_TIME_INT);

	if (time <= 0)
		return;

	gmtime_r((const time_t*)(&time), &result);

	rev = g_strdup_printf("%04d-%02d-%02dT%02d:%02d:%02dZ",
			(1900 + result.tm_year), (1 + result.tm_mon), result.tm_mday,
			result.tm_hour, result.tm_min, result.tm_sec);

	__bluetooth_pb_vcard_append_qp_encode_v21(string, "REV", NULL, rev);

	g_free(rev);
}

static void __bluetooth_pb_vcard_append_url_v21(GString *string,
						CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	contacts_svc_struct_get_list(contact, CTS_CF_WEB_ADDR_LIST, &list);

	for (pos = list; pos != NULL; pos = pos->next) {
		CTSvalue *value = (CTSvalue *)(pos->data);

		const gchar *url;
		gchar *escaped;

		if (value == NULL)
			continue;

		url = contacts_svc_value_get_str(value, CTS_WEB_VAL_ADDR_STR);

		if (url == NULL)
			continue;

		escaped = __bluetooth_pb_vcard_escape(url);
		__bluetooth_pb_vcard_append_qp_encode_v21(string, "URL", NULL, escaped);

		g_free(escaped);
	}
}

static void __bluetooth_pb_vcard_append_uid_v21(GString *string,
						CTSstruct *contact)
{
	CTSvalue *value = NULL;

	const gchar *uid;
	gchar *escaped;

	contacts_svc_struct_get_value(contact, CTS_CF_BASE_INFO_VALUE, &value);

	if (value == NULL)
		return;

	uid = contacts_svc_value_get_str(value, CTS_BASE_VAL_UID_STR);

	if (uid == NULL)
		return;

	escaped = __bluetooth_pb_vcard_escape(uid);
	__bluetooth_pb_vcard_append_qp_encode_v21(string, "UID", NULL, escaped);

	g_free(escaped);
}

static void __bluetooth_pb_vcard_append_v30(GString *string,
					const gchar *name,
					const gchar *param,
					const gchar *value)
{
	if (string == NULL)
		return;
	if (name == NULL)
		return;

	g_string_append(string, name);

	if (param)
		g_string_append_printf(string, ";%s", param);

	g_string_append(string, ":");

	if (value)
		g_string_append(string, value);

	g_string_append(string, "\r\n");
}

static void __bluetooth_pb_vcard_remove_v30(GString *string,
					const gchar *property_name)
{
	gchar *pos = NULL;
	gchar *st_pos = NULL;

	gboolean matched = FALSE;

	if(string == NULL || property_name == NULL)
		return;

	pos = string->str;

	while(*pos != '\0') {
		if (matched == FALSE) {
			if (g_ascii_strncasecmp(pos, "\r\n", 2) == 0) {
				gint attrlen = 0;

				st_pos = pos;
				pos += 2;

				attrlen = strlen(property_name);
				if (g_ascii_strncasecmp(pos, property_name, attrlen) == 0) {
					pos += attrlen;

					if (*pos == ':' || *pos == ';') {
						matched = TRUE;
						pos++;
					}
				}
				continue;
			}
		}
		else {
			if (g_ascii_strncasecmp(pos, "\r\n", 2) == 0) {
				pos += 2;

				if (*pos != ' ' && *pos != '\t') {
					/* +2 means move over \r\n */
					g_string_erase(string, (st_pos+2)-(string->str), pos-(st_pos +2));
					pos = st_pos;
					matched = FALSE;
				}
				continue;
			}
		}

		pos++;
	}
}

static gchar *__bluetooth_pb_vcard_filter_v30(const gchar *vcard,
					guint64 filter)
{
	GString *string = NULL;

	if (vcard == NULL)
		return NULL;

	string = g_string_new(vcard);

	if ((filter & VCARD_PHOTO) == 0)
		__bluetooth_pb_vcard_remove_v30(string, "PHOTO");

	if ((filter & VCARD_BDAY) == 0)
		__bluetooth_pb_vcard_remove_v30(string, "BDAY");

	if ((filter & VCARD_ADR) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "ADR");

	if ((filter & VCARD_EMAIL) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "EMAIL");

	if ((filter & VCARD_TITLE) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "TITLE");

	if ((filter & VCARD_ROLE) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "ROLE");

	if ((filter & VCARD_ORG) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "ORG");

	if ((filter & VCARD_NOTE) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "NOTE");

	if ((filter & VCARD_REV) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "REV");

	if ((filter & VCARD_URL) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "URL");

	if ((filter & VCARD_UID) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "UID");

	if ((filter & VCARD_NICKNAME) == 0 )
		__bluetooth_pb_vcard_remove_v30(string, "NICKNAME");

	return g_string_free(string, FALSE);
}

static gchar *__bluetooth_pb_vcard_real_contact_valist_v21(gint contact_id,
							gint phonelog_id,
							guint64 filter,
							const gchar *first_name,
							va_list args)
{
	CTSstruct *contact = NULL;
	gint ret = 0;
	guint64 f = filter;

	const gchar *name = first_name;

	GString *str = NULL;

	ret = contacts_svc_get_person(contact_id, &contact);
	if (ret < 0)
		return NULL;

	if (f == 0)
		f = ~f;

	str = g_string_new("BEGIN:VCARD\r\nVERSION:2.1\r\n");

	/* N, TEL is default */
	__bluetooth_pb_vcard_append_n_v21(str, contact);

	if (phonelog_id > 0) {
		gchar *number;

		number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);
		__bluetooth_pb_vcard_append_qp_encode_v21(str, "TEL", "X-0", number);
		g_free(number);


	} else {
		__bluetooth_pb_vcard_append_tel_v21(str, contact);
	}

	if (f & VCARD_FN)
		__bluetooth_pb_vcard_append_fn_v21(str, contact);
	if (f & VCARD_PHOTO)
		__bluetooth_pb_vcard_append_photo_v21(str, contact);
	if (f & VCARD_BDAY)
		__bluetooth_pb_vcard_append_bday_v21(str, contact);
	if (f & VCARD_ADR)
		__bluetooth_pb_vcard_append_adr_v21(str, contact);
	if (f & VCARD_EMAIL)
		__bluetooth_pb_vcard_append_email_v21(str, contact);
	if (f & VCARD_TITLE)
		__bluetooth_pb_vcard_append_title_v21(str, contact);
	if (f & VCARD_ROLE)
		__bluetooth_pb_vcard_append_role_v21(str, contact);
	if (f & VCARD_ORG)
		__bluetooth_pb_vcard_append_org_v21(str, contact);
	if (f & VCARD_NOTE)
		__bluetooth_pb_vcard_append_note_v21(str, contact);
	if (f & VCARD_REV)
		__bluetooth_pb_vcard_append_rev_v21(str, contact);
	if (f & VCARD_URL)
		__bluetooth_pb_vcard_append_url_v21(str, contact);
	if (f & VCARD_UID)
		__bluetooth_pb_vcard_append_uid_v21(str, contact);

	while (name) {
		const gchar *param = va_arg(args, const gchar *);
		const gchar *value = va_arg(args, const gchar *);

		if (value) {
			gchar *escaped = NULL;

			escaped = __bluetooth_pb_vcard_escape(value);
			__bluetooth_pb_vcard_append_qp_encode_v21(str, name, param, escaped);

			g_free(escaped);
		}

		name = va_arg(args, const gchar *);
	}

	g_string_append(str, "END:VCARD\r\n");

	return g_string_free(str, FALSE);
}


static gchar *__bluetooth_pb_vcard_real_contact_valist_v30(gint contact_id,
							gint phonelog_id,
							guint64 filter,
							const gchar *first_name,
							va_list args)
{
	CTSstruct *contact = NULL;

	gint ret = 0;

	const gchar *name = first_name;
	gchar *vcard = NULL;

	ret = contacts_svc_get_person(contact_id, &contact);
	if (ret < 0)
		return NULL;

	ret = contacts_svc_get_vcard_from_contact(contact, &vcard);

	if(vcard == NULL)
		return NULL;

	/* append contents on vcard */
	while (name) {
		const gchar *param = va_arg(args, const gchar *);
		const gchar *value = va_arg(args, const gchar *);
		const gchar *local_value = NULL;

		gchar *new_vcard = NULL;

		GString *content = g_string_new(name);

		if (param)
			g_string_append_printf(content, ";%s", param);

		if (value)
			local_value = value;
		else
			local_value = "";

		new_vcard = contacts_svc_vcard_put_content(vcard, content->str, local_value);

		if(new_vcard) {
			g_free(vcard);
			vcard = new_vcard;
		}

		g_string_free(content, TRUE);

		name = va_arg(args, const gchar *);
	}

	/* temporary fixed for some application crash */
	if (filter == 0)
		filter = ~VCARD_NOTE;

	if (filter) {
		gchar *new_vcard = NULL;

		new_vcard = __bluetooth_pb_vcard_filter_v30(vcard, filter);

		if (new_vcard) {
			g_free(vcard);
			vcard = new_vcard;
		}
	}

	/* if phonelog_id exist, we shall show only the phone number that was used for that call */
	if (phonelog_id > 0) {
		GString *string = g_string_new(vcard);

		gchar *new_vcard ;
		gchar *number;

		__bluetooth_pb_vcard_remove_v30(string , "TEL");

		number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);
		new_vcard = contacts_svc_vcard_put_content(string->str, "TEL", number);
		g_free(number);

		if (new_vcard) {
			g_free(vcard);
			vcard = new_vcard;
		}

		g_string_free(string, TRUE);
	}

	return vcard;
}


static gchar *__bluetooth_pb_vcard_real_contact_with_properties(gint contact_id,
								gint phonelog_id,
								guint64 filter,
								guint8 format,
								const gchar *first_name,
								...)
{
	DBG("\n");
	gchar *vcard = NULL;
	va_list args;

	va_start(args, first_name);

	switch(format) {
	case VCARD_FORMAT_3_0:
		vcard = __bluetooth_pb_vcard_real_contact_valist_v30(contact_id,
				phonelog_id, filter,
				first_name, args);
		break;
	case VCARD_FORMAT_2_1:
	default:
		vcard = __bluetooth_pb_vcard_real_contact_valist_v21(contact_id,
				phonelog_id, filter,
				first_name, args);
		break;
	}

	va_end(args);

	return vcard;
}

static gchar *__bluetooth_pb_vcard_real_call_v21(gint phonelog_id,
						guint filter,
						const char *attr)
{
	GString *str;
	gchar *number;

	str = g_string_new("BEGIN:VCARD\r\nVERSION:2.1\r\n");

	__bluetooth_pb_vcard_append_qp_encode_v21(str, "N", NULL, NULL);

	number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);
	__bluetooth_pb_vcard_append_qp_encode_v21(str, "TEL", "X-0", number);
	g_free(number);

	if (((filter == 0) || (filter | VCARD_X_IRMC_CALL_DATETIME))
			&& attr) {
		gchar *datetime = NULL;

		datetime = __bluetooth_pb_phonelog_datetime(phonelog_id);
		__bluetooth_pb_vcard_append_qp_encode_v21(str, "X-IRMC-CALL-DATETIME",
				attr, datetime);
		g_free(datetime);
	}

	g_string_append(str, "END:VCARD\r\n");

	return g_string_free(str, FALSE);
}

static gchar *__bluetooth_pb_vcard_real_call_v30(gint phonelog_id,
						guint filter,
						const gchar *attr)
{
	GString *str;
	gchar *number;

	str = g_string_new("BEGIN:VCARD\r\nVERSION:3.0\r\n");

	__bluetooth_pb_vcard_append_v30(str, "N", NULL, NULL);
	__bluetooth_pb_vcard_append_v30(str, "FN", NULL, NULL);

	number = _bluetooth_pb_number_from_phonelog_id(phonelog_id);
	__bluetooth_pb_vcard_append_v30(str, "TEL", NULL, number);
	g_free(number);

	if (((filter == 0) || (filter | VCARD_X_IRMC_CALL_DATETIME))
			&& attr) {
		gchar *datetime = NULL;

		datetime = __bluetooth_pb_phonelog_datetime(phonelog_id);
		__bluetooth_pb_vcard_append_v30(str,
				"X-IRMC-CALL-DATETIME", attr, datetime);
		g_free(datetime);
	}

	g_string_append(str, "END:VCARD\r\n");

	return g_string_free(str, FALSE);
}

static gchar *__bluetooth_pb_vcard_real_call(gint phonelog_id,
					guint filter,
					guint8 format,
					const gchar *attr)
{
	DBG("\n");
	gchar *vcard = NULL;

	switch(format) {
	case VCARD_FORMAT_3_0:
		vcard = __bluetooth_pb_vcard_real_call_v30(phonelog_id,
				filter, attr);
		break;
	case VCARD_FORMAT_2_1:
	default:
		vcard = __bluetooth_pb_vcard_real_call_v21(phonelog_id,
				filter, attr);
		break;
	}

	return vcard;
}

static gchar **__bluetooth_pb_contact_add_field_str(CTSvalue *value,
						int *field,
						gint field_size)
{
	gchar **strv;
	gint i;

	gboolean valid = FALSE;

	/* check empty field */
	for (i = 0; i < field_size; i++) {
		const gchar *tmp;
		tmp = contacts_svc_value_get_str(value, field[i]);
		if (tmp) {
			valid = TRUE;
			break;
		}

	}

	if (valid == FALSE)
		return NULL;

	strv = g_new0(gchar *, field_size + 1);

	for (i = 0; i < field_size; i++) {
		const gchar *tmp;

		tmp = contacts_svc_value_get_str(value, field[i]);
		if (tmp == NULL)
			strv[i] = g_strdup("");
		else
			strv[i] = __bluetooth_pb_vcard_escape(tmp);
	}

	return strv;
}

static gchar **__bluetooth_pb_contact_tel_param(CTSvalue *value)
{
	const gint TEL_PARAM_LEN = 13;
	gchar **strv = NULL;
	enum NUMBERTYPE type;

	gint i = 0;

	strv = g_new0(char *, TEL_PARAM_LEN + 1);	/* tel param max size is 13 */

	if (contacts_svc_value_get_bool(value, CTS_NUM_VAL_DEFAULT_BOOL)) {
		strv[i] = g_strdup("PREF");
		i++;
	}

	type = contacts_svc_value_get_int(value, CTS_NUM_VAL_TYPE_INT);

	if (type & CTS_NUM_TYPE_HOME) {
		strv[i] = g_strdup("HOME");
		i++;
	}

	if (type & CTS_NUM_TYPE_WORK) {
		strv[i] = g_strdup("WORK");
		i++;
	}

	if (type & CTS_NUM_TYPE_VOICE) {
		strv[i] = g_strdup("VOICE");
		i++;
	}

	if (type & CTS_NUM_TYPE_FAX) {
		strv[i] = g_strdup("FAX");
		i++;
	}

	if (type & CTS_NUM_TYPE_MSG) {
		strv[i] = g_strdup("MSG");
		i++;
	}

	if (type & CTS_NUM_TYPE_CELL) {
		strv[i] = g_strdup("CELL");
		i++;
	}

	if (type & CTS_NUM_TYPE_PAGER) {
		strv[i] = g_strdup("PAGER");
		i++;
	}

	if (type & CTS_NUM_TYPE_BBS) {
		strv[i] = g_strdup("BBS");
		i++;
	}

	if (type & CTS_NUM_TYPE_MODEM) {
		strv[i] = g_strdup("MODEM");
		i++;
	}

	if (type & CTS_NUM_TYPE_CAR) {
		strv[i] = g_strdup("CAR");
		i++;
	}

	if (type & CTS_NUM_TYPE_ISDN) {
		strv[i] = g_strdup("ISDN");
		i++;
	}

	if (type & CTS_NUM_TYPE_VIDEO) {
		strv[i] = g_strdup("VIDEO");
		i++;
	}

	/* CTS_NUM_TYPE_PCS is not part of vcard2.1 */

	return strv;
}


static gchar *__bluetooth_pb_contact_photo_type(const gchar *filename)
{
	gchar *filetype = NULL;
	gchar *ext = NULL;

	if (g_file_test(filename, G_FILE_TEST_IS_REGULAR) == FALSE) {
		ERR("file does not regular:%s\n", filename);
		return NULL;
	}

	ext = strrchr(filename, '.');
	if (ext == NULL) {
		ERR("file doesn't have extension\n");
		return NULL;
	}

	ext++;

	if (g_ascii_strcasecmp(ext, "gif") == 0)
		filetype = "GIF";
	else if (g_ascii_strcasecmp(ext, "cgm") == 0)
		filetype = "CGM";
	else if (g_ascii_strcasecmp(ext, "wmf") == 0)
		filetype = "WMF";
	else if (g_ascii_strcasecmp(ext, "bmp") == 0)
		filetype = "BMP";
	else if (g_ascii_strcasecmp(ext, "met") == 0)
		filetype = "MET";
	else if (g_ascii_strcasecmp(ext, "dib") == 0)
		filetype = "DIB";
	else if (g_ascii_strcasecmp(ext, "pict") == 0 || g_ascii_strcasecmp(ext, "pct") == 0 ||
			g_ascii_strcasecmp(ext, "pic") == 0)
		filetype = "PICT";
	else if (g_ascii_strcasecmp(ext, "tiff") == 0 || g_ascii_strcasecmp(ext, "tif") == 0)
		filetype = "TIFF";
	else if (g_ascii_strcasecmp(ext, "ps") == 0)
		filetype = "PS";
	else if (g_ascii_strcasecmp(ext, "pdf") == 0)
		filetype = "PDF";
	else if (g_ascii_strcasecmp(ext, "jpeg") == 0 || g_ascii_strcasecmp(ext, "jpg") == 0 ||
			g_ascii_strcasecmp(ext, "jpe") == 0)
		filetype = "JPEG";
	else if (g_ascii_strcasecmp(ext, "mpeg") == 0 || g_ascii_strcasecmp(ext, "mpg") == 0)
		filetype = "MPEG";
	else if (g_ascii_strcasecmp(ext, "m2v") == 0)
		filetype = "MPEG2";
	else if (g_ascii_strcasecmp(ext, "avi") == 0)
		filetype = "AVI";
	else if (g_ascii_strcasecmp(ext, "mov") == 0)
		filetype = "QTIME";
	else if (g_ascii_strcasecmp(ext, "png") == 0)
		filetype = "PNG";

	return g_strdup(filetype);
}

static gchar **__bluetooth_pb_contact_addr(CTSvalue *value)
{
	const gint ADDR_LEN = 7;

	gchar **strv = NULL;

	gint addr[] = { CTS_POSTAL_VAL_POBOX_STR,
			CTS_POSTAL_VAL_EXTENDED_STR,
			CTS_POSTAL_VAL_STREET_STR,
			CTS_POSTAL_VAL_LOCALITY_STR,
			CTS_POSTAL_VAL_REGION_STR,
			CTS_POSTAL_VAL_POSTALCODE_STR,
			CTS_POSTAL_VAL_COUNTRY_STR };

	strv = __bluetooth_pb_contact_add_field_str(value, addr, ADDR_LEN);
	return strv;
}

static gchar **__bluetooth_pb_contact_addr_param(CTSvalue *value)
{
	gchar **strv = NULL;
	enum ADDRESSTYPE type;

	gint i = 0;

	strv = g_new0(gchar *, 7);	/* ADDR param max size is 6 */

	type = contacts_svc_value_get_int(value, CTS_POSTAL_VAL_TYPE_INT);

	if (type & CTS_ADDR_TYPE_HOME) {
		strv[i] = g_strdup("HOME");
		i++;
	}
	if (type & CTS_ADDR_TYPE_WORK) {
		strv[i] = g_strdup("WORK");
		i++;
	}
	if (type & CTS_ADDR_TYPE_DOM) {
		strv[i] = g_strdup("DOM");
		i++;
	}
	if (type & CTS_ADDR_TYPE_INTL) {
		strv[i] = g_strdup("INTL");
		i++;
	}
	if (type & CTS_ADDR_TYPE_POSTAL) {
		strv[i] = g_strdup("POSTAL");
		i++;
	}
	if (type & CTS_ADDR_TYPE_PARCEL) {
		strv[i] = g_strdup("PARCEL");
		i++;
	}
	return strv;
}

static gchar *__bluetooth_pb_phonelog_datetime(gint phonelog_id)
{
	CTSvalue *value = NULL;
	char time_str[32] = {0,};

	time_t log_time;
	struct tm time_info;

	gint status = 0;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		DBG("can not get phonelog from id\n");
		return NULL;
	}

	log_time = contacts_svc_value_get_int(value, CTS_PLOG_VAL_LOG_TIME_INT);
	localtime_r(&log_time, &time_info);

	strftime(time_str, sizeof(time_str),
			"%Y%m%dT%H%M%S", &time_info);

	contacts_svc_value_free(value);

	return g_strdup(time_str);
}

static gchar *__bluetooth_pb_fn_from_contact(CTSstruct *contact)
{
	CTSvalue *value = NULL;

	GString *string = NULL;
	const gchar *str = NULL;

	gint name_size = 5;
	gint name[] = { CTS_NAME_VAL_PREFIX_STR,
		CTS_NAME_VAL_FIRST_STR,
		CTS_NAME_VAL_ADDITION_STR,
		CTS_NAME_VAL_LAST_STR,
		CTS_NAME_VAL_SUFFIX_STR };

	gint i = 0;

	contacts_svc_struct_get_value(contact, CTS_CF_NAME_VALUE, &value);

	str = contacts_svc_value_get_str(value, CTS_NAME_VAL_DISPLAY_STR);
	if (str)
		return g_strdup(str);

	string = g_string_new(NULL);

	for (i = 0; i < name_size; i++) {
		const gchar *tmp = NULL;

		tmp = contacts_svc_value_get_str(value, name[i]);
		if (tmp) {
			if (string->len > 0) {
				if (name[i] == CTS_NAME_VAL_SUFFIX_STR)
					g_string_append_c(string, ',');

				g_string_append_c(string, ' ');
			}
			g_string_append(string, tmp);
		}
	}

	return g_string_free(string, FALSE);
}

static gchar *__bluetooth_pb_name_from_contact(CTSstruct *contact)
{
	CTSvalue *value = NULL;
	GString *string = g_string_new(NULL);

	gint name_size = 5;
	gint name[] = { CTS_NAME_VAL_LAST_STR,
		CTS_NAME_VAL_FIRST_STR,
		CTS_NAME_VAL_ADDITION_STR,
		CTS_NAME_VAL_PREFIX_STR,
		CTS_NAME_VAL_SUFFIX_STR };

	gint i = 0;

	contacts_svc_struct_get_value(contact, CTS_CF_NAME_VALUE, &value);

	for (i = 0; i < name_size; i++) {
		const gchar *tmp = NULL;

		if (i > 0)
			g_string_append_c(string, ';');

		tmp = contacts_svc_value_get_str(value, name[i]);
		if (tmp) {
			gchar *escape = NULL;

			escape = __bluetooth_pb_vcard_escape(tmp);
			g_string_append(string, escape);

			g_free(escape);
		}
	}

	return g_string_free(string, FALSE);
}

static gchar *__bluetooth_pb_number_from_contact(CTSstruct *contact)
{
	GSList *list = NULL;
	GSList *pos = NULL;

	gboolean has_default = FALSE;

	contacts_svc_struct_get_list(contact, CTS_CF_NUMBER_LIST, &list);

	for (pos = list;pos != NULL;pos = pos->next) {
		has_default = contacts_svc_value_get_bool((CTSvalue *)(pos->data),
							CTS_NUM_VAL_DEFAULT_BOOL);

		if (has_default)
			break;
	}

	if (has_default == FALSE)
		pos = list;

	return g_strdup(contacts_svc_value_get_str((CTSvalue *)(pos->data),
						CTS_NUM_VAL_NUMBER_STR));
}

static gint __bluetooth_pb_contact_id_from_phonelog_id(gint phonelog_id)
{
	CTSvalue *value = NULL;

	gint contact_id = 0;
	gint status = 0;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		DBG("can not get phonelog from id\n");
		return 0;
	}

	contact_id = contacts_svc_value_get_int(value,
			CTS_PLOG_VAL_RELATED_ID_INT);

	if (contact_id == 0) {
		/* CTS_PLOG_VAL_RELATEED_ID_INT can be 0,
		   when phonelog is added on existing contacts,
		   with this case, trying to contact by phone number */
		const gchar *number = NULL;

		number = contacts_svc_value_get_str(value, CTS_PLOG_VAL_NUMBER_STR);
		if (number) {
			gint ret = 0;

			ret = contacts_svc_find_contact_by(CTS_FIND_BY_NUMBER,
					number);
			if (ret > 0)
				contact_id = ret;
		}
	}

	return contact_id;
}

/* API for vcard */
gboolean _bluetooth_pb_is_incoming_call(gint phonelog_id)
{
	CTSvalue *value = NULL;

	gint status;
	gint type = 0;

	gboolean retval = FALSE;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		DBG("can not get phonelog from id\n");
		return FALSE;
	}

	type = contacts_svc_value_get_int(value, CTS_PLOG_VAL_LOG_TYPE_INT);
	if (CTS_PLOG_TYPE_VOICE_INCOMMING == type ||
			CTS_PLOG_TYPE_VIDEO_INCOMMING == type) {
		retval = TRUE;
	}
	contacts_svc_value_free(value);

	return retval;
}

gboolean _bluetooth_pb_is_outgoing_call(gint phonelog_id)
{
	CTSvalue *value = NULL;

	gint status;
	gint type = 0;

	gboolean retval = FALSE;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		DBG("can not get phonelog from id\n");
		return FALSE;
	}

	type = contacts_svc_value_get_int(value, CTS_PLOG_VAL_LOG_TYPE_INT);
	if (CTS_PLOG_TYPE_VOICE_OUTGOING == type ||
			CTS_PLOG_TYPE_VIDEO_OUTGOING == type) {
		retval = TRUE;
	}
	contacts_svc_value_free(value);

	return retval;
}

gboolean _bluetooth_pb_is_missed_call(gint phonelog_id)
{
	CTSvalue *value = NULL;

	gint status;
	gint type = 0;

	gboolean retval = FALSE;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		DBG("can not get phonelog from id\n");
		return FALSE;
	}

	type = contacts_svc_value_get_int(value, CTS_PLOG_VAL_LOG_TYPE_INT);
	if (CTS_PLOG_TYPE_VOICE_INCOMMING_UNSEEN == type ||
			CTS_PLOG_TYPE_VOICE_INCOMMING_SEEN == type ||
			CTS_PLOG_TYPE_VIDEO_INCOMMING_UNSEEN == type ||
			CTS_PLOG_TYPE_VIDEO_INCOMMING_SEEN == type) {
		retval = TRUE;
	}
	contacts_svc_value_free(value);

	return retval;
}

gchar *_bluetooth_pb_vcard_contact(gint contact_id,
				guint64 filter,
				guint8 format)
{
	gchar *str = NULL;

	if (contact_id < 0)
		return NULL;

	/* owner */
	if (contact_id == 0) {
		str = __bluetooth_pb_vcard_owner(filter, format);
		return str;
	}

	str = __bluetooth_pb_vcard_real_contact_with_properties(contact_id, 0,
			filter, format,
			NULL);
	return str;
}

gchar *_bluetooth_pb_vcard_call(gint phonelog_id,
				guint64 filter,
				guint8 format,
				const gchar *attr)
{
	gint contact_id = 0;

	gchar *str = NULL;

	if (attr == NULL) {
		DBG("Unknown attribute type ignored\n");
		return NULL;
	}

	contact_id = __bluetooth_pb_contact_id_from_phonelog_id(phonelog_id);

	if (contact_id) {
		if (filter == 0 || (filter & VCARD_X_IRMC_CALL_DATETIME)) {
			gchar *datetime = NULL;

			datetime = __bluetooth_pb_phonelog_datetime(phonelog_id);

			str = __bluetooth_pb_vcard_real_contact_with_properties(contact_id,
					phonelog_id,
					filter, format,
					"X-IRMC-CALL-DATETIME", attr, datetime,
					NULL);

			if(datetime)
				g_free(datetime);
		}
		else {
			str = __bluetooth_pb_vcard_real_contact_with_properties(contact_id,
					phonelog_id,
					filter, format,
					NULL);
		}
	}
	else
		str = __bluetooth_pb_vcard_real_call(phonelog_id, filter, format, attr);

	return str;
}

gchar *_bluetooth_pb_fn_from_contact_id(gint contact_id)
{
	CTSstruct *contact = NULL;
	gchar *str = NULL;

	contacts_svc_get_person(contact_id, &contact);

	str = __bluetooth_pb_fn_from_contact(contact);

	contacts_svc_struct_free(contact);

	return str;
}

gchar *_bluetooth_pb_name_from_contact_id(gint contact_id)
{
	CTSstruct *contact = NULL;
	gchar *str = NULL;

	contacts_svc_get_person(contact_id, &contact);

	str = __bluetooth_pb_name_from_contact(contact);

	contacts_svc_struct_free(contact);

	return str;
}

gchar *_bluetooth_pb_number_from_contact_id(gint contact_id)
{
	CTSstruct *contact = NULL;
	gchar *str = NULL;

	contacts_svc_get_person(contact_id, &contact);

	str = __bluetooth_pb_number_from_contact(contact);

	contacts_svc_struct_free(contact);

	return str;
}

gchar *_bluetooth_pb_fn_from_phonelog_id(gint phonelog_id)
{
	gint contact_id = 0;
	gchar *str = NULL;

	contact_id = __bluetooth_pb_contact_id_from_phonelog_id(phonelog_id);

	if (contact_id > 0)
		str = _bluetooth_pb_fn_from_contact_id(contact_id);
	else
		str = _bluetooth_pb_number_from_phonelog_id(phonelog_id);

	return str;
}

gchar *_bluetooth_pb_name_from_phonelog_id(gint phonelog_id)
{
	gint contact_id = 0;
	gchar *str = NULL;

	contact_id = __bluetooth_pb_contact_id_from_phonelog_id(phonelog_id);

	if (contact_id > 0)
		str = _bluetooth_pb_name_from_contact_id(contact_id);
	else {
		gchar *tmp;

		tmp = _bluetooth_pb_number_from_phonelog_id(phonelog_id);
		str = g_strdup_printf("%s;;;;", tmp);

		g_free(tmp);
	}

	return str;
}

gchar *_bluetooth_pb_number_from_phonelog_id(gint phonelog_id)
{
	CTSvalue *value = NULL;
	gint status;
	gchar *str;

	status = contacts_svc_get_phonelog(phonelog_id, &value);
	if (status != CTS_SUCCESS) {
		return NULL;
	}

	str = g_strdup(contacts_svc_value_get_str(value,
				CTS_PLOG_VAL_NUMBER_STR));

	contacts_svc_value_free(value);

	return str;
}

gchar *_bluetooth_pb_fn_owner(void)
{
	return _bluetooth_pb_number_owner();
}

gchar *_bluetooth_pb_name_owner(void)
{
	gchar *name;
	gchar *number;

	number = _bluetooth_pb_number_owner();
	name = g_strdup_printf("%s;;;;", number);

	g_free(number);

	return name;
}

gchar *_bluetooth_pb_number_owner(void)
{
	return vconf_get_str(VCONFKEY_TELEPHONY_SUBSCRIBER_NUMBER);
}

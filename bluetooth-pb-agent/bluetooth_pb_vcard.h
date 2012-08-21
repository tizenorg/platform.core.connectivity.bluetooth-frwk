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

#ifndef __DEF_BT_PB_VCARD_H_
#define __DEF_BT_PB_VCARD_H_

#include <glib.h>
#include <contacts-svc.h>

gboolean _bluetooth_pb_is_incoming_call(gint phonelog_id);

gboolean _bluetooth_pb_is_outgoing_call(gint phonelog_id);

gboolean _bluetooth_pb_is_missed_call(gint phonelog_id);

/* vcard */
gchar *_bluetooth_pb_vcard_contact(gint contact_id,
				guint64 filter,
				guint8 format);

gchar *_bluetooth_pb_vcard_call(gint phonelog_id,
				guint64 filter,
				guint8 format,
				const gchar *attr);

/* get list entry*/
GPtrArray *_bluetooth_pb_list_new(void);

void _bluetooth_pb_list_contact_append(GPtrArray *ptr_array,
				gint handle,
				gint contact_id);

void _bluetooth_pb_list_call_append(GPtrArray *ptr_array,
				gint handle,
				gint phonelog_id);

gint _bluetooth_pb_list_get_id(gint handle);

void _bluetooth_pb_list_free(GPtrArray *ptr_array,
			gboolean hash_table);

gchar *_bluetooth_pb_fn_from_contact_id(gint contact_id);

gchar *_bluetooth_pb_name_from_contact_id(gint contact_id);

gchar *_bluetooth_pb_number_from_contact_id(gint contact_id);

gchar *_bluetooth_pb_fn_from_phonelog_id(gint phonelog_id);

gchar *_bluetooth_pb_name_from_phonelog_id(gint phonelog_id);

gchar *_bluetooth_pb_number_from_phonelog_id(gint phonelog_id);

gchar *_bluetooth_pb_fn_owner(void);

gchar *_bluetooth_pb_name_owner(void);

gchar *_bluetooth_pb_number_owner(void);

#endif

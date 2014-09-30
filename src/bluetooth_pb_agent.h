/*
 * Bluetooth-agent
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

#ifndef __DEF_BT_PB_AGENT_H_
#define __DEF_BT_PB_AGENT_H_

#ifdef TIZEN_2_MOBILE

#include <unistd.h>
#include <dlog.h>

#include <stdio.h>

#include "gdbus.h"

#define BT_PB_SERVICE_OBJECT_PATH	"/org/bluez/pb_agent"
#define BT_PB_SERVICE_NAME		"org.bluez.pb_agent"
#define BT_PB_SERVICE_INTERFACE		"org.bluez.PbAgent"

#undef LOG_TAG
#define LOG_TAG "BLUETOOTH_AGENT_PB"
#define INFO(fmt, args...) SLOGI(fmt, ##args)
#undef DBG
#define DBG(fmt, args...) SLOGD(fmt, ##args)
#define ERR(fmt, args...) SLOGE(fmt, ##args)

#define DBG_SECURE(fmt, args...) SECURE_SLOGD(fmt, ##args)
#define ERR_SECURE(fmt, args...) SECURE_SLOGE(fmt, ##args)

#define FUCNTION_CALLS
#ifdef FUCNTION_CALLS
#define FN_START	DBG("ENTER==>")
#define FN_END		DBG("EXIT===>")
#else
#define FN_START
#define FN_END
#endif
void pb_agent_init(void);
gboolean bluetooth_pb_get_phonebook_folder_list(GDBusMethodInvocation *invocation);
gboolean bluetooth_pb_get_phonebook(const char *name,
					guint64 filter,
					guint8 format,
					guint16 max_list_count,
					guint16 list_start_offset,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_size(const char *name,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_list(const char *name,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_entry(const gchar *folder,
					const gchar *id,
					guint64 filter,
					guint8 format,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_total_object_count(gchar *path,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_add_contact(const char *filename,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_add_contact(const char *filename,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_size_at(const gchar *command,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_entries_at(const gchar *command,
					gint start_index,
					gint end_index,
					GDBusMethodInvocation *context);
gboolean bluetooth_pb_get_phonebook_entries_find_at(const gchar *command,
					const gchar *find_text,
					GDBusMethodInvocation *context);
#endif /* #ifdef TIZEN_2_MOBILE */
#endif /* __DEF_BT_PB_AGENT_H_ */

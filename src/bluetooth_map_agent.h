/*
 * Bluetooth-Frwk-NG
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
 * Copyright (c) 2013-2014 Intel Corporation.
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

#ifndef __DEF_BT_PB_AGENT_H_
#define __DEF_BT_PB_AGENT_H_

#include <gio/gio.h>
#include "bluez.h"

gboolean bluetooth_map_get_folder_tree(GDBusMethodInvocation *context);
gboolean bluetooth_map_get_message_list(gchar *folder_name, guint16 max,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_get_message(gchar *message_name,
					gboolean attach, gboolean transcode,
					gboolean first_request,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_push_message(gboolean save_copy,
					gboolean retry_send,
					gboolean native,
					gchar *folder_name,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_push_message_data(gchar *bmsg,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_update_message(GDBusMethodInvocation *context);
gboolean bluetooth_map_set_read_status(gchar *handle, gboolean read_status,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_set_delete_status(gchar *handle, gboolean delete_status,
					GDBusMethodInvocation *context);
gboolean bluetooth_map_noti_registration(gchar *remote_addr,
					gboolean status,
					GDBusMethodInvocation *context);

#endif /* __DEF_BT_AGENT_H_ */

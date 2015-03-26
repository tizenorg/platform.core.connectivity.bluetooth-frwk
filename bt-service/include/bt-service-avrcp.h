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


#ifndef _BT_SERVICE_AVRCP_H_
#define _BT_SERVICE_AVRCP_H_

#include <glib.h>
#include <sys/types.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "bluetooth-api.h"
#include "bluetooth-media-control.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BT_MEDIA_OBJECT_PATH "/Musicplayer"

#define BT_MEDIA_CONTROL_PATH "%s/player0"

int _bt_register_media_player(void);

int _bt_unregister_media_player(void);

int _bt_avrcp_set_track_info(media_metadata_attributes_t *meta_data);

int _bt_avrcp_set_properties(media_player_settings_t *properties);

int _bt_avrcp_set_property(int type, unsigned int value);

int _bt_avrcp_control_cmd(int type);

int _bt_avrcp_control_set_property(int type, unsigned int value);

int _bt_avrcp_control_get_property(int type, unsigned int *value);

int _bt_avrcp_control_get_track_info(media_metadata_attributes_t *metadata);

void _bt_handle_avrcp_control_event(DBusMessageIter *msg_iter, const char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_AVRCP_H_*/


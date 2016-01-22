/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include "bluetooth-api.h"
#include "bluetooth-media-control.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BT_MEDIA_OBJECT_PATH "/Musicplayer"

#define BT_AVRCP_ERROR (__bt_avrcp_error_quark())

#define BT_ERROR_INTERNAL "InternalError"
#define BT_ERROR_INVALID_PARAM "InvalidParameters"
#define BT_ERROR_INVALID_INTERFACE "InvalidInterface"

typedef enum {
	BT_AVRCP_ERROR_NONE,
	BT_AVRCP_ERROR_INTERNAL,
	BT_AVRCP_ERROR_INVALID_PARAM,
	BT_AVRCP_ERROR_NOT_SUPPORTED,
	BT_AVRCP_ERROR_INVALID_INTERFACE
} bt_avrcp_error_t;

int _bt_register_media_player(void);

int _bt_unregister_media_player(void);

int _bt_avrcp_set_track_info(media_metadata_attributes_t *meta_data);

int _bt_avrcp_set_properties(media_player_settings_t *properties);

int _bt_avrcp_set_property(int type, unsigned int value);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_AVRCP_H_*/


/*
 *   bluetooth-media-control
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 *		Girishashok Joshi <girish.joshi@samsung.com>
 *		Chanyeol Park <chanyeol.park@samsung.com>
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BLUETOOTH_CONTROL_API_H_
#define _BLUETOOTH_CONTROL_API_H_

#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <glib.h>
#include <dlog.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define BT_MEDIA_PLAYER_DBUS_INTERFACE	"org.tizen.player"
#define BT_MEDIA_PLAYER_OBJECT_PATH	"/Tizen/Control"


/* defines*/
#define MEDIA_OBJECT_PATH_LENGTH	50

#define BLUETOOTH_CONTROL_ERROR	-1
#define BLUETOOTH_CONTROL_SUCCESS	0

typedef enum {
	EQUILIZER = 0x00,
	REPEAT,
	SHUFFLE,
	SCAN,
	STATUS,
	POSITION
} media_player_property_type;

typedef enum {
	EQUILIZER_OFF = 0x00,
	EQUILIZER_ON,
	EQUILIZER_INVALID,
} media_player_equilizer_status;

typedef enum {
	REPEAT_MODE_OFF = 0x00,
	REPEAT_SINGLE_TRACK,
	REPEAT_ALL_TRACK,
	REPEAT_GROUP,
	REPEAT_INVALID,
} media_player_repeat_status;

typedef enum {
	SHUFFLE_MODE_OFF = 0x00,
	SHUFFLE_ALL_TRACK,
	SHUFFLE_GROUP,
	SHUFFLE_INVALID,
} media_player_shuffle_status;

typedef enum {
	SCAN_MODE_OFF = 0x00,
	SCAN_ALL_TRACK,
	SCAN_GROUP,
	SCAN_INVALID,
} media_player_scan_status;

typedef enum {
	STATUS_PLAYING  = 0x00,
	STATUS_STOPPED,
	STATUS_PAUSED,
	STATUS_FORWARD_SEEK,
	STATUS_REVERSE_SEEK,
	STATUS_ERROR,
	STATUS_INVALID
} media_player_status;

typedef struct {
	media_player_equilizer_status equilizer;
	media_player_repeat_status  repeat;
	media_player_shuffle_status  shuffle;
	media_player_scan_status scan;
	media_player_status status;
	unsigned int position;
} media_player_settings_t;

typedef struct {
	const char *title;
	const char *artist;
	const char *album;
	const char *genre;
	unsigned int total_tracks;
	unsigned int number;
	unsigned int duration;
} media_metadata_attributes_t;

/**
 * @fn int bluetooth_media_init(void)
 * @brief Initializes the Media interface to media service
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return   0  - Success \n
 *          -1 - On Failure\n
 *
 * @exception   None
 * @param[in]  None.
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_init(void);

/**
 * @fn int bluetooth_media_register_player(media_player_settings_t player_settings,
 *					media_metadata_attributes_t metadata )
 * @brief Registers the Music player with its player settings and media attributes
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return   0  - Success \n
 *          -1 - On Failure\n
 *
 * @exception   None
 * @param[in]   player_settings - Music player application settings,
 *			 metadata -Meida attributes
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_register_player(void);

/**
 * @fn int bluetooth_media_unregister_player(void )
 * @brief Un-registers the Music player
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return   0  - Success \n
 *          -1 - On Failure\n
 *
 * @exception   None
 * @param[in]   None
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_unregister_player(void);

/**
 * @fn int bluetooth_media_deinit(void)
 * @brief deinitializes the Media interface to media service
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return   0  - Success \n
 *          -1 - On Failure\n
 *
 * @exception   None
 * @param[in]  None.
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_deinit(void);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*_BLUETOOTH_CONTROL_API_H_*/

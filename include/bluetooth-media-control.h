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

#ifndef _BT_MP_CONTROL_H_
#define _BT_MP_CONTROL_H_

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#define BT_MEDIA_ERROR_NONE ((int)0)

#define BT_MEDIA_ERROR_BASE ((int)0)
#define BT_MEDIA_ERROR_INTERNAL ((int)BT_MEDIA_ERROR_BASE - 0x01)
#define BT_MEDIA_ERROR_ALREADY_INITIALIZED ((int)BT_MEDIA_ERROR_BASE - 0x02)
#define BT_MEDIA_ERROR_NOT_CONNECTED ((int)BT_MEDIA_ERROR_BASE - 0x15)

typedef enum {
	EQUALIZER = 0x01,
	REPEAT,
	SHUFFLE,
	SCAN,
	POSITION,
	METADATA,
	STATUS
} media_player_property_type;

typedef enum {
	EQUALIZER_OFF = 0x01,
	EQUALIZER_ON,
	EQUALIZER_INVALID,
} media_player_equalizer_status;

typedef enum {
	REPEAT_MODE_OFF = 0x01,
	REPEAT_SINGLE_TRACK,
	REPEAT_ALL_TRACK,
	REPEAT_GROUP,
	REPEAT_INVALID,
} media_player_repeat_status;

typedef enum {
	STATUS_STOPPED = 0x00,
	STATUS_PLAYING,
	STATUS_PAUSED,
	STATUS_FORWARD_SEEK,
	STATUS_REVERSE_SEEK,
	STATUS_ERROR,
	STATUS_INVALID
} media_player_status;

typedef enum {
	SHUFFLE_MODE_OFF = 0x01,
	SHUFFLE_ALL_TRACK,
	SHUFFLE_GROUP,
	SHUFFLE_INVALID,
} media_player_shuffle_status;

/* bluez 4.101 */
typedef enum {
	SCAN_MODE_OFF = 0x01,
	SCAN_ALL_TRACK,
	SCAN_GROUP,
	SCAN_INVALID,
} media_player_scan_status;

typedef enum {
	PLAY = 0x01,
	PAUSE,
	STOP,
	NEXT,
	PREVIOUS,
	FAST_FORWARD,
	REWIND
} media_player_control_cmd;

typedef struct {
	const char *title;
	const char *artist;
	const char *album;
	const char *genre;
	unsigned int total_tracks;
	unsigned int number;
	int64_t duration;
} media_metadata_attributes_t;

typedef struct {
	media_player_equalizer_status equalizer;
	media_player_repeat_status  repeat;
	media_player_shuffle_status  shuffle;
	media_player_scan_status scan;
	media_player_status status;
	unsigned int position;
	media_metadata_attributes_t metadata;
} media_player_settings_t;

typedef struct {
	int event;
	int result;
	void *param_data;
	void *user_data;
} media_event_param_t;

typedef void (*media_cb_func_ptr)(int, media_event_param_t*, void*);


/**
 * @fn int bluetooth_media_player_init(media_cb_func_ptr callback_ptr, void *user_data)
 * @brief Initialize AVRCP service and register the callback
 *
 * This function is a synchronous call.
 *
 * @param[in]   callback_ptr - Callback function (A2DP connected / Disconnected)
 * @param[in]   user_data - User data
 *
 * @return  BT_MEDIA_ERROR_NONE  - Success \n
 *              BT_MEDIA_ERROR_ALREADY_INITIALIZED   - Already initialized \n
 *              BT_MEDIA_ERROR_INTERNAL  - Internal error \n
 *
 * @remark      None
 *
 */
int bluetooth_media_player_init(media_cb_func_ptr callback_ptr,
					void *user_data);

/**
 * @fn int bluetooth_media_player_deinit(void)
 * @brief Deinitialize AVRCP service and register the callback
 *
 * This function is a synchronous call.
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @remark      None
 *
 */
int bluetooth_media_player_deinit(void);

/**
 * @fn int bluetooth_media_player_set_properties(media_player_settings_t *setting)
 * @brief Notifies the remote bluetooth headset with change in music player settings
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in]   setting - The music player properties
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_player_set_properties(
			media_player_settings_t *setting);

/**
 * @fn int bluetooth_media_player_change_property(media_player_property_type type,
 *				unsigned int value);
 * @brief Notifies the remote bluetooth headset with change in music player settings
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in]   type - Type of the music player property
 *			 value - Value of the property which is changed
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_player_change_property(
			media_player_property_type type,
			unsigned int value);

/**
 * @fn int bluetooth_media_player_change_track(media_metadata_attributes_t metadata)
 * @briefNotifies the remote bluetooth headset with change in media attributes of the track
 *
 * This function is a asynchronous call.
 * No event for this api..
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in] 	  metadata -Meida attributes
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_player_change_track(
			media_metadata_attributes_t *metadata);

/**
 * @fn int bluetooth_media_control_init(media_cb_func_ptr callback_ptr, void *user_data)
 * @brief Initialize AVRCP control and register the callback
 *
 * This function is a synchronous call.
 *
 * @param[in]   callback_ptr - Callback function (AVRCP connected / Disconnected)
 * @param[in]   user_data - User data
 *
 * @return  BT_MEDIA_ERROR_NONE  - Success \n
 *              BT_MEDIA_ERROR_ALREADY_INITIALIZED   - Already initialized \n
 *              BT_MEDIA_ERROR_INTERNAL  - Internal error \n
 *
 * @remark      None
 *
 */
int bluetooth_media_control_init(media_cb_func_ptr callback_ptr,
						void *user_data);

/**
 * @fn int bluetooth_media_control_deinit(void)
 * @brief Deinitialize AVRCP Control and deregister callback
 *
 * This function is a synchronous call.
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @remark      None
 *
 */
 int bluetooth_media_control_deinit(void);

/**
 * @brief	The function bluetooth_media_control_connect is called to establish an AVRCP
 *	control role connection with  the specified device.
 *
 * @param[in]	remote_address	Bluetooth device address.
 * @return	int	Zero on Success or reason for error if any.
 *
 */
int bluetooth_media_control_connect(bluetooth_device_address_t *remote_address);

/**
 * @brief	The function bluetooth_media_control_disconnect is called to disconnect an
 *	existing AVRCP Control role connection with the specified device.
 *
 * @param[in]	remote_address	Bluetooth device address.
 * @return	int	Zero on Success or reason for error if any.
 *
 */
int bluetooth_media_control_disconnect(bluetooth_device_address_t *remote_address);

/**
 * @brief	The function bluetooth_media_control_command is called to send
 *	the  AVRCP Control command like Play, Pause, FF, Rewind to the target device.
 *
 * @param[in]	type 	media_player_control_cmd.
 * @return	int	Zero on Success or reason for error if any.
 *
 */
int bluetooth_media_control_command(media_player_control_cmd type);

/**
 * @fn int bluetooth_media_control_set_property(media_player_property_type type, unsigned int value)
 * @brief Notifies the remote bluetooth target with change in music control settings
 *
 * This function is a asynchronous call.
 * No event for this api.
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in]   setting - The music control properties
 *
 * @remark       None
 * @see    	 None
 */
 int bluetooth_media_control_set_property(media_player_property_type type, unsigned int value);

/**
 * @fn int bluetooth_media_control_get_property(media_player_property_type type, unsigned int *value)
 * @brief reads the setting of the remote bluetooth target with change in music control settings
 *
 * This function is a asynchronous call.
 * No event for this api.
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in]   setting - The music control properties
 *
 * @remark       None
 * @see    	 None
 */
int bluetooth_media_control_get_property(media_player_property_type type, unsigned int *value);

/**
 * @fn int bluetooth_media_control_get_track_info(media_metadata_attributes_t *metadata)
 * @brief reads the track metadata from the remote target player.
 *
 * This function is a asynchronous call.
 * No event for this api.
 *
 * @return  BT_MEDIA_CONTROL_SUCCESS  - Success \n
 *              BT_MEDIA_CONTROL_ERROR - Error \n
 *
 * @exception   None
 * @param[in]   metadata - The music meta data information.
 *
 * @remark       None
 * @see    	 None
 */
 int bluetooth_media_control_get_track_info(media_metadata_attributes_t *metadata);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*_BT_MP_CONTROL_H_*/

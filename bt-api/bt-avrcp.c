/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#include <string.h>

#include "bluetooth-api.h"
#include "bluetooth-media-control.h"
#include "bt-internal-types.h"

#include "bt-common.h"
#include "bt-request-sender.h"
#include "bt-event-handler.h"

BT_EXPORT_API int bluetooth_media_player_init(media_cb_func_ptr callback_ptr,
						void *user_data)
{
	int ret;

	/* Register AVRCP events */
	ret = _bt_register_event(BT_AVRCP_EVENT , (void *)callback_ptr, user_data);

	if (ret != BLUETOOTH_ERROR_NONE &&
	     ret != BLUETOOTH_ERROR_ALREADY_INITIALIZED) {
		BT_ERR("Fail to init the event handler");
		return ret;
	}

	_bt_set_user_data(BT_AVRCP, (void *)callback_ptr, user_data);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_media_player_deinit(void)
{
	int ret;

	ret = _bt_unregister_event(BT_AVRCP_EVENT);

	if (ret != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Fail to deinit the event handler");
		return ret;
	}

	_bt_set_user_data(BT_AVRCP, NULL, NULL);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_media_player_change_property(
			media_player_property_type type,
			unsigned int value)
{
	int result;

	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, &type, sizeof(int));
	g_array_append_vals(in_param2, &value, sizeof(unsigned int));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_AVRCP_SET_PROPERTY,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_media_player_set_properties(
			media_player_settings_t *setting)
{
	int result;

	BT_CHECK_PARAMETER(setting, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	g_array_append_vals(in_param1, setting, sizeof(media_player_settings_t));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_AVRCP_SET_PROPERTIES,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

BT_EXPORT_API int bluetooth_media_player_change_track(
		media_metadata_attributes_t *metadata)
{
	int result;
	media_metadata_t meta_data;

	BT_CHECK_PARAMETER(metadata, return);
	BT_CHECK_ENABLED(return);

	BT_INIT_PARAMS();
	BT_ALLOC_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	memset(&meta_data, 0x00, sizeof(media_metadata_t));

	if (_bt_copy_utf8_string(meta_data.title, metadata->title, BT_NAME_MAX))
		BT_DBG("Error in copying Title\n");
	if (_bt_copy_utf8_string(meta_data.artist, metadata->artist[0], BT_NAME_MAX))
		BT_DBG("Error in copying Artist\n");
	if (_bt_copy_utf8_string(meta_data.album, metadata->album, BT_NAME_MAX))
		BT_DBG("Error in copying Album\n");
	if (_bt_copy_utf8_string(meta_data.genre, metadata->genre[0], BT_NAME_MAX))
		BT_DBG("Error in copying Genre\n");

	meta_data.number = metadata->tracknumber;
	meta_data.duration = metadata->duration;

	g_array_append_vals(in_param1, &meta_data, sizeof(media_metadata_t));

	result = _bt_send_request(BT_BLUEZ_SERVICE, BT_AVRCP_SET_TRACK_INFO,
		in_param1, in_param2, in_param3, in_param4, &out_param);

	BT_FREE_PARAMS(in_param1, in_param2, in_param3, in_param4, out_param);

	return result;
}

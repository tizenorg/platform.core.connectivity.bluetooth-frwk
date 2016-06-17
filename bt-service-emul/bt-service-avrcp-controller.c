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

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-avrcp-controller.h"
#include "bt-service-event.h"

int _bt_avrcp_control_cmd(int type)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_avrcp_control_get_property(int type, unsigned int *value)
{
	BT_CHECK_PARAMETER(value, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_avrcp_control_set_property(int type, unsigned int value)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_avrcp_control_get_track_info(media_metadata_attributes_t *metadata)
{
	retv_if(metadata == NULL, BLUETOOTH_ERROR_INTERNAL);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

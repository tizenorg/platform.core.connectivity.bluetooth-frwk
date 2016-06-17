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

#include <glib.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-util.h"
#include "bt-service-rfcomm-client.h"

int _bt_rfcomm_connect_using_uuid(int request_id,
			bluetooth_device_address_t *device_address,
			char *remote_uuid)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

/* Range of the Channel : 0 <= channel <= 30 */
int _bt_rfcomm_connect_using_channel(int request_id,
			bluetooth_device_address_t *device_address,
			char *channel)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

/* Be used in RFCOMM client /server */
int _bt_rfcomm_disconnect(int socket_fd)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

/* Be used in RFCOMM client /server */
int _bt_rfcomm_write(int socket_fd, char *buf, int length)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_rfcomm_cancel_connect(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_rfcomm_is_connected(gboolean *connected)
{
	BT_CHECK_PARAMETER(connected, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_rfcomm_is_device_connected(bluetooth_device_address_t *device_address,
					gboolean *connected)
{
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_PARAMETER(connected, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}


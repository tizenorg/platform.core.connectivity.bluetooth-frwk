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
#include <string.h>
#include <stdio.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"
#include "bt-service-network.h"
#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-util.h"

int _bt_network_activate(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_network_deactivate(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_network_connect(int request_id, int role,
		bluetooth_device_address_t *device_address)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_network_disconnect(int request_id,
		bluetooth_device_address_t *device_address)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_network_server_disconnect(int request_id,
		bluetooth_device_address_t *device_address)
{
	BT_CHECK_PARAMETER(device_address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}
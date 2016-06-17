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

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-util.h"
#include "bt-service-opp-client.h"

int _bt_opp_client_push_files(int request_id, GDBusMethodInvocation *context,
				bluetooth_device_address_t *remote_address,
				char **file_path, int file_count)
{
	BT_CHECK_PARAMETER(remote_address, return);
	BT_CHECK_PARAMETER(file_path, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_opp_client_cancel_push(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_opp_client_cancel_all_transfers(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_opp_client_is_sending(gboolean *sending)
{
	BT_CHECK_PARAMETER(sending, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}


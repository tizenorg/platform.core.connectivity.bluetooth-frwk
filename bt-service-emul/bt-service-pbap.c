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
#include <unistd.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-pbap.h"

int _bt_pbap_connect(const bluetooth_device_address_t *address)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_pbap_disconnect(const bluetooth_device_address_t *address)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_pbap_get_phonebook_size(const bluetooth_device_address_t *address,
		int source, int type)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_pbap_get_phonebook(const bluetooth_device_address_t *address,
		int source, int type, bt_pbap_pull_parameters_t *app_param)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_pbap_get_list(const bluetooth_device_address_t *address, int source,
		int type,  bt_pbap_list_parameters_t *app_param)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}


int _bt_pbap_pull_vcard(const bluetooth_device_address_t *address,
		int source, int type, bt_pbap_pull_vcard_parameters_t *app_param)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_pbap_phonebook_search(const bluetooth_device_address_t *address,
		int source, int type, bt_pbap_search_parameters_t *app_param)
{
	BT_CHECK_PARAMETER(address, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}


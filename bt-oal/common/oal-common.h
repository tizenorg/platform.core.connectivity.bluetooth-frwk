/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*			   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#ifndef _OAL_COMMON_H_
#define _OAL_COMMON_H_

#include <stdint.h>
#include <sys/types.h>

#include <bluetooth.h>

#ifdef __cplusplus
extern "C" {
#endif
void parse_device_properties(int num_properties, bt_property_t *properties,
				remote_device_t *dev_info, ble_adv_data_t * adv_info);
oal_status_t convert_to_oal_status(bt_status_t status);

const char * status2string(bt_status_t status);

int check_duplicate_uuid(oal_uuid_t *table, oal_uuid_t toMatch, int table_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_COMMON_H_*/

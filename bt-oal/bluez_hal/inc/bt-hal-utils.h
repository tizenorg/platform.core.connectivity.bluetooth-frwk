/*
 * Copyright (C) 2013 Intel Corporation
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

#ifndef _BT_HAL_UTILS_H_
#define _BT_HAL_UTILS_H_

#include <endian.h>

#include <hardware/bluetooth.h>

#define MAX_UUID_STR_LEN	37
#define HAL_UUID_LEN		16
#define MAX_ADDR_STR_LEN	18

static const char BT_BASE_UUID[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb
};

const char *bt_uuid_t2str(const uint8_t *uuid, char *buf);
const char *btuuid2str(const uint8_t *uuid);
const char *bt_bdaddr_t2str(const bt_bdaddr_t *bd_addr, char *buf);
void str2bt_bdaddr_t(const char *str, bt_bdaddr_t *bd_addr);
void str2bt_uuid_t(const char *str, bt_uuid_t *uuid);
const char *btproperty2str(const bt_property_t *property);
const char *bdaddr2str(const bt_bdaddr_t *bd_addr);

const char* bt_property_type_t2str(bt_property_type_t prop_type);
const char* bt_device_type_t2str(bt_device_type_t device_type);

struct int2str {
	int val;		/* int value */
	const char *str;	/* corresponding string */
};

int int2str_findint(int v, const struct int2str m[]);
int int2str_findstr(const char *str, const struct int2str m[]);
const char *enum_defines(void *v, int i);
const char *enum_strings(void *v, int i);
const char *enum_one_string(void *v, int i);

#endif //_BT_HAL_UTILS_H_

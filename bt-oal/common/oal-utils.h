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

#ifndef _OAL_UTILS_H_
#define _OAL_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include "oal-internal.h"


#define MENU_PRINT_ERROR(format, arg...) MENUPRINT(RED(format), ##arg)

#define RED(text) "\033[31m"text"\033[0m"
#define BLUE(text) "\033[34m"text"\033[0m"
#define YELLOW(text) "\033[33m"text"\033[0m"
#define GREEN(text) "\033[32m"text"\033[0m"
#define MAGENTA(text) "\033[35m"text"\033[0m"
#define CYAN(text) "\033[36m"text"\033[0m"

typedef char bdstr_t[18];

/* Common/util functions */
char* bdt_bd2str(const bt_address_t *bdaddr, bdstr_t *bdstr);
char* bdaddr_2_str(const bt_bdaddr_t *bd_addr);
void string_to_uuid(char *str, service_uuid_t *p_uuid);
void uuid_to_string(service_uuid_t *p_uuid, char *str);
void oal_print_device_address_t(const bt_address_t *addr);
void oal_convert_addr_string_to_type(unsigned char *addr, const char *address);
int oal_is_address_zero(unsigned char *addr1);
void print_bt_properties(int num_properties, bt_property_t *properties);

void convert_str_2_hex(char out[],char in[]);
void convert_hex_2_str(char * hex, int len, char * str_out);
char* convert_bt_property_2_str(const bt_property_t *property);
char* convert_property_type_2_str(bt_property_type_t prop_type);
char* convert_scan_mode_2_str(bt_scan_mode_t scan_mode);
char* convert_device_type_2_str(bt_device_type_t device_type);
char* convert_bdaddr_2_str(const bt_bdaddr_t *bd_addr, char *buf);

void local_le_feat_2_string(char *str, const bt_local_le_features_t *f);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_UTILS_H_*/

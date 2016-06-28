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

#include <stdlib.h>
#include <stdio.h>

#include <dlog.h>
#include <string.h>
#include <bluetooth.h>
#include "oal-utils.h"

char *bdt_bd2str(const bt_address_t *bdaddr, bdstr_t *bdstr)
{
	const uint8_t *addr = bdaddr->addr;

	if(bdaddr == NULL) {
		*bdstr[0] = 0;
		return *bdstr;
	}

	snprintf(*bdstr, sizeof(bdstr_t), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);
	return *bdstr;
}

void string_to_uuid(char *str, service_uuid_t *p_uuid)
{
	uint32_t uuid0, uuid4;
	uint16_t uuid1, uuid2, uuid3, uuid5;

	sscanf(str, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
			&uuid0, &uuid1, &uuid2, &uuid3, &uuid4, &uuid5);

	uuid0 = htonl(uuid0);
	uuid1 = htons(uuid1);
	uuid2 = htons(uuid2);
	uuid3 = htons(uuid3);
	uuid4 = htonl(uuid4);
	uuid5 = htons(uuid5);

	memcpy(&(p_uuid->uuid[0]), &uuid0, 4);
	memcpy(&(p_uuid->uuid[4]), &uuid1, 2);
	memcpy(&(p_uuid->uuid[6]), &uuid2, 2);
	memcpy(&(p_uuid->uuid[8]), &uuid3, 2);
	memcpy(&(p_uuid->uuid[10]), &uuid4, 4);
	memcpy(&(p_uuid->uuid[14]), &uuid5, 2);

	return;
}

void oal_print_device_address_t(const bt_address_t *addr)
{
	BT_INFO("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", addr->addr[0], addr->addr[1], addr->addr[2],
			addr->addr[3], addr->addr[4], addr->addr[5]);
}

void oal_convert_addr_string_to_type(unsigned char *addr,
		const char *address)
{
	int i;
	char *ptr = NULL;

	for (i = 0; i < BT_ADDRESS_BYTES_NUM; i++) {
		addr[i] = strtol(address, &ptr, 16);
		if (ptr != NULL) {
			if (ptr[0] != ':')
				return;
			address = ptr + 1;
		}
	}
}

int oal_is_address_zero(unsigned char *addr1)
{
	int i;
	for(i = 0; i < BT_ADDRESS_BYTES_NUM; i++) {
		if(addr1[i] == 0){
			continue;
		}
		break;
	}
	if(i == BT_ADDRESS_BYTES_NUM)
		return 1;
	else
		return 0;
}

void uuid_to_string(service_uuid_t *p_uuid, char *str)
{
	uint32_t uuid0, uuid4;
	uint16_t uuid1, uuid2, uuid3, uuid5;

	memcpy(&uuid0, &(p_uuid->uuid[0]), 4);
	memcpy(&uuid1, &(p_uuid->uuid[4]), 2);
	memcpy(&uuid2, &(p_uuid->uuid[6]), 2);
	memcpy(&uuid3, &(p_uuid->uuid[8]), 2);
	memcpy(&uuid4, &(p_uuid->uuid[10]), 4);
	memcpy(&uuid5, &(p_uuid->uuid[14]), 2);

	snprintf((char *)str, BT_UUID_STRING_MAX, "%.8x-%.4x-%.4x-%.4x-%.8x%.4x",
			ntohl(uuid0), ntohs(uuid1),
			ntohs(uuid2), ntohs(uuid3),
			ntohl(uuid4), ntohs(uuid5));
}


static int hex2bin( const char *s )
{
	int ret=0;
	int i;
	for( i=0; i<2; i++ )
	{
		char c = *s++;
		int n=0;
		if( '0'<=c && c<='9' )
			n = c-'0';
		else if( 'a'<=c && c<='f' )
			n = 10 + c-'a';
		else if( 'A'<=c && c<='F' )
			n = 10 + c-'A';
		ret = n + ret*16;
	}
	return ret;
}

void convert_str_2_hex(char out[],char in[])
{
	int i=0;
	for(i=0; i<62; i++) {
		out[i] = hex2bin( in ); \
			 in += 2; \
	}
}

void convert_hex_2_str(char * hex, int len, char * str_out)
{
	int i = 0;

	for(i=0;i<len;i++) {
		snprintf(str_out + (i * 3),3*(len - i),"%02x ", hex[i]);
	}
	str_out[3*len] = 0;
}

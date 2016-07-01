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

char* convert_bdaddr_2_str(const bt_bdaddr_t *bd_addr, char *buf)
{
	const uint8_t *p;

	if (!bd_addr)
		return strcpy(buf, "NULL");
	p = bd_addr->address;

	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			p[0], p[1], p[2], p[3], p[4], p[5]);

	return buf;
}

char *bdaddr_2_str(const bt_bdaddr_t *bd_addr)
{
        static char buf[18];
        return convert_bdaddr_2_str(bd_addr, buf);
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

int hex2bin( const char *s )
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

void print_bt_properties(int num_properties, bt_property_t *properties)
{
	int i;
	for (i = 0; i < num_properties; i++) {
		bt_property_t prop;
		memcpy(&prop, properties + i, sizeof(prop));
		BT_INFO("prop: %s\n", convert_bt_property_2_str(&prop));
	}
}

char* convert_scan_mode_2_str(bt_scan_mode_t scan_mode)
{
	switch(scan_mode) {
		case BT_SCAN_MODE_NONE:
			return "Non Scannable";
		case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
			return "Connectable And Discoverable";
		case BT_SCAN_MODE_CONNECTABLE:
			return "Connectable";
		default:
			return "Unknown Scan Mode";
	}

}

char* convert_device_type_2_str(bt_device_type_t device_type)
{
	switch (device_type) {
		case BT_DEVICE_DEVTYPE_BREDR:
			return "BREDR Device";
		case BT_DEVICE_DEVTYPE_BLE:
			return "BLE Device";
		case BT_DEVICE_DEVTYPE_DUAL:
			return "Dual Device";
		default:
			return "Unknown Device Type";
	}
}

char *convert_bt_property_2_str(const bt_property_t *property)
{
	static char buf[4096];
	char *p;

	p = buf + sprintf(buf, "type=%s len=%d val=",
			convert_property_type_2_str(property->type),
			property->len);

	switch (property->type) {
		case BT_PROPERTY_BDNAME:
		case BT_PROPERTY_REMOTE_FRIENDLY_NAME:
			snprintf(p, property->len + 1, "%s",
					((bt_bdname_t *) property->val)->name);
			break;
		case BT_PROPERTY_BDADDR:
			sprintf(p, "%s", bdaddr_2_str((bt_bdaddr_t *) property->val));
			break;
		case BT_PROPERTY_CLASS_OF_DEVICE:
			sprintf(p, "%06x", *((unsigned int *) property->val));
			break;
		case BT_PROPERTY_TYPE_OF_DEVICE:
			sprintf(p, "%s", convert_device_type_2_str(
						*((bt_device_type_t *) property->val)));
			break;
		case BT_PROPERTY_REMOTE_RSSI:
			sprintf(p, "%d", *((char *) property->val));
			break;
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
			sprintf(p, "%d", *((unsigned int *) property->val));
			break;
		case BT_PROPERTY_ADAPTER_SCAN_MODE:
			sprintf(p, "%s",
					convert_scan_mode_2_str(*((bt_scan_mode_t *) property->val)));
			break;
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
			break;
		case BT_PROPERTY_UUIDS:
			break;
		case BT_PROPERTY_SERVICE_RECORD:
			break;
			/* Tizen BlueZ specific Device properties */
		case BT_PROPERTY_REMOTE_PAIRED:
			sprintf(p, "%d", *((bool *) property->val));
			break;
		case BT_PROPERTY_REMOTE_CONNECTED:
			sprintf(p, "%d", *((unsigned int *) property->val));
			break;
		case BT_PROPERTY_REMOTE_TRUST:
			sprintf(p, "%d", *((bool *) property->val));
			break;
		case BT_PROPERTY_PAIRABLE:
			sprintf(p, "%d", *((bool *) property->val));
			break;
		case BT_PROPERTY_VERSION:
			snprintf(p, property->len + 1, "%s",
					((char *) property->val));
			break;
		case BT_PROPERTY_LOCAL_LE_FEATURES:
			local_le_feat_2_string(p, property->val);
			break;
		case BT_PROPERTY_PAIRABLE_TIMEOUT:
			sprintf(p, "%d", *((unsigned int *) property->val));
			break;
		case BT_PROPERTY_IPSP_INITIALIZED:
			sprintf(p, "%d", *((bool *) property->val));
			break;
		case BT_PROPERTY_MODALIAS:
			snprintf(p, property->len + 1, "%s",
					((char *) property->val));
			break;
		case BT_PROPERTY_REMOTE_DEVICE_MANUFACTURER_DATA_LEN:
			sprintf(p, "%d", *((unsigned int *) property->val));
			break;
		case BT_PROPERTY_REMOTE_DEVICE_MANUFACTURER_DATA:
			{
				int indx;
				char *pppp = property->val;
				for (indx = 0; indx < property->len; indx++)
					p += sprintf(p, " %2.2X", pppp[indx]);
				break;
			}
		case BT_PROPERTY_REMOTE_BLE_ADV_DATA:
			{
				int indx;
				char *pppp = property->val;
				for (indx = 0; indx < property->len; indx++)
					p += sprintf(p, " %2.2X", pppp[indx]);
				break;
			}
			/* End of Tizen BlueZ specific device propeties */
		case BT_PROPERTY_REMOTE_VERSION_INFO:
		case BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP:
		default:
			sprintf(p, "%p", property->val);
			break;
	}
	return buf;
}

void local_le_feat_2_string(char *str, const bt_local_le_features_t *f)
{
	uint16_t scan_num;

	str += sprintf(str, "{\n");

	str += sprintf(str, "Privacy supported: %s,\n",
			f->local_privacy_enabled ? "TRUE" : "FALSE");

	str += sprintf(str, "Num of advertising instances: %u,\n",
			f->max_adv_instance);

	str += sprintf(str, "PRA offloading support: %s,\n",
			f->rpa_offload_supported ? "TRUE" : "FALSE");

	str += sprintf(str, "Num of offloaded IRKs: %u,\n",
			f->max_irk_list_size);

	str += sprintf(str, "Num of offloaded scan filters: %u,\n",
			f->max_adv_filter_supported);

	scan_num = (f->scan_result_storage_size_hibyte << 8) +
		f->scan_result_storage_size_lobyte;

	str += sprintf(str, "Num of offloaded scan results: %u,\n", scan_num);

	str += sprintf(str, "Activity & energy report support: %s\n",
			f->activity_energy_info_supported ? "TRUE" : "FALSE");

	sprintf(str, "}");
}

char* convert_property_type_2_str(bt_property_type_t prop_type)
{
	switch (prop_type) {
		case BT_PROPERTY_BDNAME:
			return "[Bluetooth Name]";
		case BT_PROPERTY_BDADDR:
			return "[Bluetooth Address]";
		case BT_PROPERTY_UUIDS:
			return "[UUIDS]";
		case BT_PROPERTY_CLASS_OF_DEVICE:
			return "[Class of Device]";
		case BT_PROPERTY_TYPE_OF_DEVICE:
			return "[Bluetooth Type of Device]";
		case BT_PROPERTY_SERVICE_RECORD:
			return "[Bluetooth Service record]";
		case BT_PROPERTY_ADAPTER_SCAN_MODE:
			return "[Bluetooth Adapter Scan Mode]";
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
			return "[Bluetooth Bonded Devices]";
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
			return "[Bluetooth Adapter Discovery Timeout]";
		case BT_PROPERTY_REMOTE_FRIENDLY_NAME:
			return "[Bluetooth Friendly Name]";
		case BT_PROPERTY_REMOTE_RSSI:
			return "[Bluetooth Rmote RSSI]";
		case BT_PROPERTY_REMOTE_VERSION_INFO:
			return "[Bluetooth Version Info]";
		case BT_PROPERTY_LOCAL_LE_FEATURES:
			return "[Bluetooth LE Features]";
		case BT_PROPERTY_REMOTE_PAIRED:
			return "[Bluetooth Remote Paired]";
		case BT_PROPERTY_REMOTE_CONNECTED:
			return "[Bluetooth Remote Connected]";
		case BT_PROPERTY_REMOTE_TRUST:
			return "[Bluetooth Remote TRUST]";
		case BT_PROPERTY_PAIRABLE:
			return "[Bluetooth Pairable]";
		case BT_PROPERTY_PAIRABLE_TIMEOUT:
			return "[Bluetooth Pairable Timeout]";
		case BT_PROPERTY_VERSION:
			return "[Bluetooth Version]";
		case BT_PROPERTY_IPSP_INITIALIZED:
			return "[Bluetooth IPSP Initialized]";
		case BT_PROPERTY_MODALIAS:
			return "[Bluetooth ModAlias]";
		case BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP:
			return "[Bluetooth Remote Device Timestamp]";
		case BT_PROPERTY_REMOTE_DEVICE_MANUFACTURER_DATA_LEN:
			return "[Bluetooth Remote Device Manufacturer Data Len]";
		case BT_PROPERTY_REMOTE_DEVICE_MANUFACTURER_DATA:
			return "[Bluetooth Remote Device Manufacturer Data]";
		case BT_PROPERTY_REMOTE_BLE_ADV_DATA:
			return "[Bluetooth Remote Device LE Advertising Data]";
		default:
			return "[Default Property]";
	}
}


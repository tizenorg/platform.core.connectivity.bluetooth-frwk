/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
*
* Contact: Anupam Roy <anupam.r@samsung.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bluetooth.h>
#include "oal-internal.h"
#include "oal-common.h"

#define BT_UUID_STRING_SIZE 37
#define BT_UUID_LENGTH_MAX 16

void parse_device_properties(int num_properties, bt_property_t *properties,
		remote_device_t *dev_info, ble_adv_data_t * adv_info)
{
	int i = 0;
	int uuid_count = 0, table_len = 0;
	int tmp_uuid_cnt = 0;
	int chk = 0;
	char lcl_uuid[BT_UUID_STRING_MAX];

	bt_bdaddr_t * addr = {0};
	bt_bdname_t *name = {0};
	service_uuid_t *uuids;
	bt_device_type_t dev_type;

	BT_DBG("num_properties: %d", num_properties);

	for(i=0; i<num_properties; i++) {
		BT_DBG("===>Prop type: %d, Len: %d<===", properties[i].type, properties[i].len);

		switch (properties[i].type) {
		case BT_PROPERTY_BDADDR: {
			addr = (bt_bdaddr_t *)properties[i].val;
				memcpy(dev_info->address.addr, addr->address, 6);
			BT_DBG("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					dev_info->address.addr[0], dev_info->address.addr[1],
					dev_info->address.addr[2], dev_info->address.addr[3],
					dev_info->address.addr[4], dev_info->address.addr[5]);
			break;
		}
		case BT_PROPERTY_CLASS_OF_DEVICE: {
			dev_info->cod = *((int *)properties[i].val);
			BT_DBG("CLASS: 0x%06x", dev_info->cod);
			break;
		}
		case BT_PROPERTY_BDNAME: {
			name = properties[i].val;

			g_strlcpy(dev_info->name, (const gchar *)name->name, BT_DEVICE_NAME_LENGTH_MAX);
			BT_DBG("NAME: %s", dev_info->name);
			break;
		}
		case  BT_PROPERTY_REMOTE_FRIENDLY_NAME: {
			bt_bdname_t *name = properties[i].val;
			if (NULL != name && (0 != properties[i].len))
				g_strlcpy(dev_info->name, (const gchar *)name->name, BT_DEVICE_NAME_LENGTH_MAX);
			BT_DBG("FRIENDLY NAME: [%s]", dev_info->name);
			break;
		}
		case BT_PROPERTY_REMOTE_PAIRED: {
			dev_info->is_bonded = *((gboolean*)properties[i].val);
			BT_DBG("BONDED [%d]", dev_info->is_bonded);
			break;
		}
		case BT_PROPERTY_REMOTE_CONNECTED: {
			dev_info->is_connected = *((int*)properties[i].val);
			BT_DBG("CONNECTED [%d]", dev_info->is_connected);
			break;
		}
		case BT_PROPERTY_REMOTE_TRUST: {
			dev_info->is_trusted = *((gboolean*)properties[i].val);
			BT_DBG("TRUSTED [%d]", dev_info->is_trusted);
			break;
		}
		case BT_PROPERTY_REMOTE_RSSI: {
			dev_info->rssi = *((int *)properties[i].val);
			BT_DBG("RSSI: %d", dev_info->rssi);
			break;
		}
		case BT_PROPERTY_UUIDS: {
			uuids  = (service_uuid_t *)properties[i].val;
			BT_DBG("Length of properties from HAL [%d]", properties[i].len);
			uuid_count = properties[i].len/sizeof(bt_uuid_t);
			table_len += uuid_count;
			for(; tmp_uuid_cnt < table_len; tmp_uuid_cnt++) {
				uuid_to_string(&uuids[tmp_uuid_cnt], lcl_uuid);
				chk = check_duplicate_uuid(dev_info->uuid,
					uuids[tmp_uuid_cnt], dev_info->uuid_count);
				if(chk != 0) {
					memcpy(&dev_info->uuid[dev_info->uuid_count++].uuid,
							&uuids[tmp_uuid_cnt].uuid, 16);
				} else {
					BT_DBG("Duplicate UUID found:%s\n", lcl_uuid);
				}
				BT_DBG("%d.BT_PROPERTY_UUIDS:%s", dev_info->uuid_count, lcl_uuid);
			}
			break;
		}
		case BT_PROPERTY_TYPE_OF_DEVICE: {
			dev_type = *((bt_device_type_t *)properties[i].val);
			if(dev_type == BT_DEVICE_DEVTYPE_BLE)
				BT_DBG("Single mode BLE Device");
			else if(dev_type == BT_DEVICE_DEVTYPE_DUAL)
				BT_DBG("Dual mode BLE Device");
			dev_info->type = dev_type - 1;//OAL enum starts with 0 and Bluedroid with 1
			break;
		}
		case BT_PROPERTY_REMOTE_BLE_ADV_DATA: {
			if(adv_info) {
				adv_info->adv_data = properties[i].val;
				adv_info->len = properties[i].len;
			}
			BT_DBG("----Advertising Data Length: %d",properties[i].len);
			break;
		}
		case BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP: {
			BT_INFO("BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP: Not Handled!!");
			break;
		}
		case BT_PROPERTY_SERVICE_RECORD: {
			BT_INFO("BT_PROPERTY_SERVICE_RECORD: Not Handled!!");
			break;
		}
		default:
			BT_WARN("Property not handled");
			break;
		}
	}
}

oal_status_t convert_to_oal_status(bt_status_t status)
{
	oal_status_t ret = OAL_STATUS_INTERNAL_ERROR;

	switch(status) {
		case BT_STATUS_SUCCESS:
	case BT_STATUS_DONE:
		ret = OAL_STATUS_SUCCESS;
		break;
	case BT_STATUS_NOT_READY:
		ret = OAL_STATUS_NOT_READY;
		break;
	case BT_STATUS_BUSY:
		ret = OAL_STATUS_BUSY;
		break;
	case BT_STATUS_PARM_INVALID:
		ret = OAL_STATUS_INVALID_PARAM;
		break;
	case BT_STATUS_RMT_DEV_DOWN:
		ret = OAL_STATUS_RMT_DEVICE_DOWN;
		break;
	case BT_STATUS_AUTH_FAILURE:
		ret = OAL_STATUS_AUTH_FAILED;
		break;
	case BT_STATUS_UNSUPPORTED:
		ret = OAL_STATUS_NOT_SUPPORT;
		break;
	case BT_STATUS_UNHANDLED:
	case BT_STATUS_FAIL:
	case BT_STATUS_NOMEM:
	default:
		ret = OAL_STATUS_INTERNAL_ERROR;
		break;
	}
	return ret;
}

static const char * status_str[] = {
    "BT_STATUS_SUCCESS",
    "BT_STATUS_FAIL",
    "BT_STATUS_NOT_READY",
    "BT_STATUS_NOMEM",
    "BT_STATUS_BUSY",
    "BT_STATUS_DONE",
    "BT_STATUS_UNSUPPORTED",
    "BT_STATUS_PARM_INVALID",
    "BT_STATUS_UNHANDLED",
    "BT_STATUS_AUTH_FAILURE",
    "BT_STATUS_RMT_DEV_DOWN"
};

int check_duplicate_uuid(oal_uuid_t *table, oal_uuid_t toMatch, int table_len)
{
	int i;
	int ret = 1;

	for (i = 0; i < table_len; i++)	{
		ret = memcmp(table[i].uuid, toMatch.uuid, 16);
		if (ret == 0)
			break;
	}
	return ret;
}

const char* status2string(bt_status_t status)
{
	if(status >= BT_STATUS_SUCCESS && status <= BT_STATUS_RMT_DEV_DOWN)
		return status_str[status];
	else {
		BT_ERR("Invalid BT status from stack");
		return "BT_STATUS_UNKNOWN";
	}
}

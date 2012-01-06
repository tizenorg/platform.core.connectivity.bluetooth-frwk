/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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

#include "uts_bluetooth_get_bonded_device_list.h"

bluetooth_device_address_t searched_device = {{0}};

#define TC_TIMEOUT	30000

#define BT_DEFAULT_DEV_NAME "SLP-BT-TEST-TARGET"
#define DISCOVER_TIMEOUT 20
#define DISCOVER_CANCEL_INTERVAL 3

#define TC_FAIL 0
#define TC_PASS 1
#define TC_PRT tet_printf
//#define tc_result tet_result

void startup()
{
	tet_printf("bluetooth framework TC startup");

	if(!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	dbus_g_thread_init();

	g_type_init();
}


void cleanup()
{
	tet_printf("bluetooth framework TC cleanup");
}

void utc_bluetooth_get_bonded_device_list_1(void)
{

	int 	return_15;
	int ret_val;

	GPtrArray *devinfo = NULL;

	devinfo = g_ptr_array_new();

	ret_val = bluetooth_check_adapter();
	if (ret_val < BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
		//tc_result(TC_FAIL, 3);
	}
	else
	{
		TC_PRT("BT state [0x%04x]", ret_val);
		//tc_result(TC_PASS, 3);
	}

	return_15=bluetooth_get_bonded_device_list(&devinfo);
	if(return_15<BLUETOOTH_ERROR_NONE)
	{
		tet_printf("Api failed");
		tet_result(TET_FAIL);
	}
	else
	{
		int i;
		bluetooth_paired_device_info_t *ptr;
		for(i=0; i<devinfo->len;i++)
		{
			ptr = g_ptr_array_index(devinfo, i);
			if(ptr != NULL)
			{
				TC_PRT("Name [%s]", ptr->device_name.name);
				TC_PRT("Major Class [%d]", ptr->device_class.major_class);
				TC_PRT("Minor Class [%d]", ptr->device_class.minor_class);
				TC_PRT("Service Class [%d]", ptr->device_class.service_class);
				TC_PRT("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", ptr->device_address.addr[0], ptr->device_address.addr[1], ptr->device_address.addr[2], ptr->device_address.addr[3], ptr->device_address.addr[4], ptr->device_address.addr[5]);
				TC_PRT("\n");
			}
		}
		tet_printf("Api passed");
		tet_result(TET_PASS);
	}

	g_ptr_array_free(devinfo, TRUE);
}

void utc_bluetooth_get_bonded_device_list_2(void)
{
	int 	return_15;
	int ret_val;

	ret_val = bluetooth_check_adapter();
	if (ret_val < BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
		//tc_result(TC_FAIL, 3);
	}
	else
	{
		TC_PRT("BT state [0x%04x]", ret_val);
		//tc_result(TC_PASS, 3);
	}

	return_15=bluetooth_get_bonded_device_list(NULL);
	if(return_15==BLUETOOTH_ERROR_INVALID_PARAM)
	{
		tet_printf("Api failed");
		tet_result(TET_PASS);
	}
	else
	{
		tet_printf("Api passed");
		tet_result(TET_FAIL);
	}
}

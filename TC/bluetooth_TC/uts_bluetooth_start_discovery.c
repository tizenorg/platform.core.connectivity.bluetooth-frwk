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

#include "uts_bluetooth_start_discovery.h"

bluetooth_device_address_t searched_device = {{0}};

#define TC_TIMEOUT	30000

#define BT_DEFAULT_DEV_NAME "SLP-BT-TEST-TARGET"
#define DISCOVER_TIMEOUT 20
#define DISCOVER_CANCEL_INTERVAL 3

#define TC_FAIL 0
#define TC_PASS 1
#define TC_PRT tet_printf
//#define tc_result tet_result

GMainLoop *main_loop = NULL;
static int timeout_status = 0;

void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data);

void startup()
{
	tet_printf("bluetooth framework TC startup");

	if(!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	dbus_g_thread_init();

	g_type_init();
	//main_loop = g_main_loop_new(NULL, FALSE);
}


void cleanup()
{

	//g_main_loop_run(main_loop);
	tet_printf("bluetooth framework TC cleanup");
	//if( main_loop!= NULL)
	{
	//	g_main_loop_unref(main_loop);
	}
}

void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data)
{
	TC_PRT("bt event callback 0x%04x", event);
	switch(event)
	{
		case BLUETOOTH_EVENT_ENABLED:
			TC_PRT("BLUETOOTH_EVENT_ENABLED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				//tc_result(TC_PASS, 1);
			}
			else
			{
				//tc_result(TC_FAIL, 1);
			}
			break;

		case BLUETOOTH_EVENT_DISABLED:
			TC_PRT("BLUETOOTH_EVENT_DISABLED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				//tc_result(TC_PASS, 2);
			}
			else
			{
				//tc_result(TC_FAIL, 2);
			}
			break;

		case BLUETOOTH_EVENT_LOCAL_NAME_CHANGED:
			TC_PRT("BLUETOOTH_EVENT_LOCAL_NAME_CHANGED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_name_t *local_name = (bluetooth_device_name_t *)param->param_data;
				//tc_result(TC_PASS, 6);
				TC_PRT("Changed Name : [%s]", local_name->name);
			}
			else
			{
				//tc_result(TC_FAIL, 6);
			}
			break;


		case BLUETOOTH_EVENT_DISCOVERY_STARTED:
			TC_PRT("BLUETOOTH_EVENT_DISCOVERY_STARTED, result [0x%04x]", param->result);
			break;

		case BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND:
		{
			bluetooth_device_info_t *device_info = NULL;
			TC_PRT("BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND, result [0x%04x]", param->result);
			device_info  = (bluetooth_device_info_t *)param->param_data;
			memcpy(&searched_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			TC_PRT("dev [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", \
				device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
				device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5]);
			break;
		}

		case BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED:
		{
			bluetooth_device_info_t *device_info = NULL;
			TC_PRT("BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED, result [0x%04x]", param->result);
			device_info  = (bluetooth_device_info_t *)param->param_data;
			memcpy(&searched_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			TC_PRT("dev [%s] [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", device_info->device_name.name, \
				device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
				device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5]);
			break;
		}

		case BLUETOOTH_EVENT_DISCOVERY_FINISHED:
			TC_PRT("BLUETOOTH_EVENT_DISCOVERY_FINISHED, result [0x%04x]", param->result);
			//tc_result(TC_PASS, 9);
			break;


		case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				//tc_result(TC_PASS, 12);
				device_info  = (bluetooth_device_info_t *)param->param_data;
				TC_PRT("dev [%s] [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X] mjr[%#x] min[%#x] srv[%#x]", device_info->device_name.name, \
					device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
					device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5], \
					device_info->device_class.major_class, device_info->device_class.minor_class, device_info->device_class.service_class);
			}
			else
			{
				//tc_result(TC_FAIL, 12);
			}
			break;
		}

		default:
			TC_PRT("received event [0x%04x]", event);
			break;
	}
}




void utc_bluetooth_start_discovery_1(void)
{
	unsigned max_response;
	unsigned discovery_duration;
	unsigned classOfDeviceMask;
	int return_9;
	int ret_val;

	ret_val = bluetooth_register_callback(bt_event_callback, NULL);

	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		tet_printf("bluetooth_register_callback returned Success");
	//	tc_result(TC_PASS, 0);
	}
	else
	{
		tet_printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
	//	tc_result(TC_FAIL, 0);
		return 0;
	}

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

	bluetooth_cancel_discovery();

	max_response =0;
	discovery_duration =0;
	classOfDeviceMask =0;
	return_9=bluetooth_start_discovery(max_response,discovery_duration,classOfDeviceMask);
	if(	return_9<0)
	{
	tet_printf("Api failed: %d", return_9);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}



void utc_bluetooth_start_discovery_2(void)
{
	unsigned short max_response;
	unsigned short discovery_duration;
	unsigned  classOfDeviceMask;
	int return_9;
	int ret_val;

	ret_val = bluetooth_register_callback(bt_event_callback, NULL);

	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		tet_printf("bluetooth_register_callback returned Success");
	//	tc_result(TC_PASS, 0);
	}
	else
	{
		tet_printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
	//	tc_result(TC_FAIL, 0);
		return 0;
	}

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
	max_response =0;//assign value over here
	discovery_duration =0;//assign value over here
	classOfDeviceMask=0x800001;//0x001000;
	return_9=bluetooth_start_discovery(max_response,discovery_duration,classOfDeviceMask);
	if(	return_9>=0)
	{
	tet_printf("Api failed=%d\n",return_9);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}


// Not proper case!!
// The API parameter types is unsigned!
#if 0
void utc_bluetooth_start_discovery_3(void)
{
	unsigned max_response;
	unsigned discovery_duration;
	unsigned classOfDeviceMask;
	int 	return_9;
		int ret_val;
		ret_val = bluetooth_register_callback(bt_event_callback);
	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		tet_printf("bluetooth_register_callback returned Success");
	//	tc_result(TC_PASS, 0);
	}
	else
	{
		tet_printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
	//	tc_result(TC_FAIL, 0);
		return 0;
	}

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
	max_response =0;//assign value over here
	discovery_duration=-1;
	classOfDeviceMask=0;
	return_9=bluetooth_start_discovery(max_response,discovery_duration,classOfDeviceMask);
	if(	return_9>=0)
	{
	tet_printf("Api failed=%d\n",return_9);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}

void utc_bluetooth_start_discovery_4(void)
{
	unsigned max_response;
	unsigned discovery_duration;
	unsigned classOfDeviceMask;
	int 	return_9;
		int ret_val;
		ret_val = bluetooth_register_callback(bt_event_callback);
	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		tet_printf("bluetooth_register_callback returned Success");
	//	tc_result(TC_PASS, 0);
	}
	else
	{
		tet_printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
	//	tc_result(TC_FAIL, 0);
		return 0;
	}

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
	max_response=0;
	discovery_duration=0;
	classOfDeviceMask=-1;
	return_9=bluetooth_start_discovery(max_response,discovery_duration,classOfDeviceMask);
	if(	return_9>=0)
	{
	tet_printf("Api failed=%d\n",return_9);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}
#endif

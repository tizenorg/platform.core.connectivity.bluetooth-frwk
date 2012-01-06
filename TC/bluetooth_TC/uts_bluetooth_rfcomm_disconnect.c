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

#include "uts_bluetooth_rfcomm_disconnect.h"

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

const char * rfcomm_test_uuid_spp ="00001101-0000-1000-8000-00805F9B34FB";
int g_ret_client_fd1 = 0;

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
//	main_loop = g_main_loop_new(NULL, FALSE);
}


void cleanup()
{

	//g_main_loop_run(main_loop);
	tet_printf("bluetooth framework TC cleanup");
	if( main_loop!= NULL)
	{
		g_main_loop_unref(main_loop);
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
		case BLUETOOTH_EVENT_RFCOMM_CONNECTED:
		{
			int 	return_22;
			bluetooth_rfcomm_connection_t *con_ind = (bluetooth_rfcomm_connection_t *)param->param_data;
			TC_PRT("BLUETOOTH_EVENT_RFCOMM_CONNECTED, result [0x%04x], fd = %d, device add = 0x%X:%X:%X:%X:%X:%X, Role = %s", param->result,
								con_ind->socket_fd,
								con_ind->device_addr.addr[0], con_ind->device_addr.addr[1], con_ind->device_addr.addr[2],
								con_ind->device_addr.addr[3], con_ind->device_addr.addr[4], con_ind->device_addr.addr[5],
								(con_ind->device_role == RFCOMM_ROLE_SERVER)? "SERVER":"CLIENT");
			//tc_result(TC_PASS, 22);
			tet_printf("g_ret_client_fd1=%d\nconn_ind->socket_fd %d\n",g_ret_client_fd1,con_ind->socket_fd);
			tet_printf("con_ind->device_role=%d\n",con_ind->device_role);
			if(con_ind->device_role == RFCOMM_ROLE_CLIENT)
				g_ret_client_fd1 = con_ind->socket_fd;

			return_22=bluetooth_rfcomm_disconnect( g_ret_client_fd1);
			if(	return_22<0)
			{
			tet_printf("BLUETOOTH_EVENT_RFCOMM_CONNECTED Api failed, return_22=%d\n",return_22);
			tet_result(TET_FAIL);
			}
			else
			{
			tet_printf("Api passed");
			tet_result(TET_PASS);
			}

			 g_main_loop_quit (main_loop);
//			if( main_loop!= NULL)
//			{
//				g_main_loop_unref(main_loop);
//			}
			break;
		}

		default:
			TC_PRT("received event [0x%04x]", event);
			break;
	}
}



#if 0
void uts_bluetooth_rfcomm_disconnect_1(void)
{
	int sk;
	int max_pending_connection;
	int 	return_22;
	int ret_val;
        //Replace the below BD address with the remote device BD address
	const bluetooth_device_address_t remote_address={{0x00,0x80,0x98,0xE7,0x34,0x82}};
	ret_val = bluetooth_register_callback(bt_event_callback);
//	main_loop = g_main_loop_new(NULL, FALSE);
	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		tet_printf("bluetooth_register_callback returned Success");
	//	tc_result(TC_PASS, 0);
	}
	else
	{
		tet_printf("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
	//	tc_result(TC_FAIL, 0);
		return ;
	}

	ret_val = bluetooth_check_adapter();
	if (ret_val < BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
		//tc_result(TC_FAIL, 3);
	}
//	remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x80; remote_address.addr[2] = 0x98;
//	remote_address.addr[3]= 0xE7; remote_address.addr[4] = 0x34;  remote_address.addr[5]= 0x82;

	return_22= bluetooth_rfcomm_connect(&remote_address, rfcomm_test_uuid_spp);
	tet_printf(" bluetooth_rfcomm_connectApi , return_22=%d\n",return_22);

	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
}
#endif

void uts_bluetooth_rfcomm_disconnect_1(void)
{
	int sk;
	int max_pending_connection;
	int return_22;
	int ret_val;
	 //Replace the below BD address with the remote device BD address
	const bluetooth_device_address_t remote_address={{0x00,0x80,0x98,0xE7,0x34,0x82}};

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
		return ;
	}

	ret_val = bluetooth_check_adapter();
	if (ret_val < BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
		//tc_result(TC_FAIL, 3);
	}
/*Mention bd address of device to which you want to connect*/
//	remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x80; remote_address.addr[2] = 0x98;
//	remote_address.addr[3]= 0xE7; remote_address.addr[4] = 0x34;  remote_address.addr[5]= 0x82;

	//bluetooth_rfcomm_connect(&remote_address, rfcomm_test_uuid_spp);

	return_22=bluetooth_rfcomm_disconnect( -1);
	printf("sk=%x\n",sk);
	if(	return_22>0)
	{
	tet_printf("Api failed,=%d\n",return_22);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}




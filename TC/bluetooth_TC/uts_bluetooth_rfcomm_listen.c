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

#include "uts_bluetooth_rfcomm_listen.h"

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
		case BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED:
		{
			TC_PRT("BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED, result [0x%04x]", param->result);
			bluetooth_rfcomm_received_data_t *rx_data = param->param_data;
			printf("\n FD = %d \nBuffer len = %d ", rx_data->socket_fd, rx_data->buffer_size);

			printf("received data=%s\n",rx_data);
			tet_printf("Api passed");
			tet_result(TET_PASS);
			//tc_result(TC_PASS, 21);


			 g_main_loop_quit (main_loop);
			break;
		}

		default:
			TC_PRT("received event [0x%04x]", event);
			break;
	}
}




void utc_bluetooth_rfcomm_listen_1(void)
{
	int sk;
	int max_pending_connection;
	int  return_22;
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
	sk=bluetooth_rfcomm_create_socket(rfcomm_test_uuid_spp);
	printf("sk=%x\n",sk);
//	return_22=bluetooth_rfcomm_listen(sk,max_pending_connection);
	return_22= bluetooth_rfcomm_listen_and_accept(sk,1);
	if(	return_22<0)
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

void utc_bluetooth_rfcomm_listen_2(void)
{
	int sk;
	int max_pending_connection;
	int return_22;
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
	sk=-1;
	max_pending_connection=1000000;

	return_22= bluetooth_rfcomm_listen_and_accept(sk,max_pending_connection);

	if(	return_22>=0)
	{
	tet_printf("Api failed result_22=%d\n",return_22);
	tet_result(TET_FAIL);
	}
	else
	{
	tet_printf("Api passed");
	tet_result(TET_PASS);
	}
}

#if 0
void utc_bluetooth_rfcomm_listen_3(void)
{
	int sk;
	int max_pending_connection;
	int 	return_22;
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
	sk=bluetooth_rfcomm_create_socket(rfcomm_test_uuid_spp);
	printf("sk=%x\n",sk);
//	return_22=bluetooth_rfcomm_listen(sk,max_pending_connection);
	return_22= bluetooth_rfcomm_listen_and_accept(sk,1);

	main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(main_loop);
}
#endif

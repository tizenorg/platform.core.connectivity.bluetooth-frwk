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

/**
 * @file       bluetooth-frwk-test.c
 * @brief      This is the source file for bluetooth framework test suite.
 */

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <pthread.h>

#include "bluetooth-api.h"


bluetooth_device_address_t searched_device = {{0}};

#define TC_TIMEOUT	30000

#define BT_DEFAULT_DEV_NAME "SLP-BT-TEST-TARGET"
#define DISCOVER_TIMEOUT 20
#define DISCOVER_CANCEL_INTERVAL 3

#define PRT(format, args...) printf("%s:%d() "format, __FUNCTION__, __LINE__, ##args)
#define TC_PRT(format, args...) PRT(format"\n", ##args)

#define TC_PASS 1
#define TC_FAIL 0
int g_tmp = 0;
int g_ret_client_fd1 = -1, g_ret_client_fd2 = -1;
const char *g_hdp_app_handle1 =  NULL;
const char *g_hdp_app_handle2 =  NULL;
int selection;
int hdp_manual_mode =  1;
const char * rfcomm_test_uuid_spp ="00001101-0000-1000-8000-00805F9B34FB";
const char * rfcomm_test_uuid_dun = "00001103-0000-1000-8000-00805F9B34FB";

GMainLoop *main_loop = NULL;
static int timeout_status = 0;

typedef struct
{
	const char *tc_name;
	int tc_code;
} tc_table_t;

tc_table_t tc_table[] =
{
	{"bluetooth_register_callback"		, 0x0001},
	{"bluetooth_enable_adapter"			, 0x0002},
	{"bluetooth_disable_adapter"		, 0x0003},
	{"bluetooth_check_adapter"			, 0x0004},
	{"bluetooth_get_local_address"		, 0x0005},
	{"bluetooth_get_local_name"			, 0x0006},
	{"bluetooth_set_local_name"			, 0x0007},
	{"bluetooth_get_discoverable_mode"	, 0x0008},
	{"bluetooth_set_discoverable_mode"	, 0x0009},
	{"bluetooth_start_discovery"		, 0x000a},
	{"bluetooth_cancel_discovery"		, 0x000b},
	{"bluetooth_is_discovering"			, 0x000c},
	{"bluetooth_bond_device"			, 0x000d},
	{"bluetooth_cancel_bonding"			, 0x000e},
	{"bluetooth_unbond_device"			, 0x000f},
	{"bluetooth_get_bonded_device_list"	, 0x0010},
	{"bluetooth_get_remote_device"		, 0x0011},
	{"bluetooth_authorize_device"		, 0x0012},
	{"bluetooth_search_service"			, 0x0013},
	{"bluetooth_set_alias"				, 0x0014},
	/*Rfcomm related*/
	{"bluetooth_rfcomm_create_socket"	, 0x0020},
	{"bluetooth_rfcomm_listen_and_accept"	, 0x0021},
	{"bluetooth_rfcomm_remove_socket"	, 0x0022},

	{"bluetooth_rfcomm_connect"	, 0x0023},
	{"bluetooth_rfcomm_disconnect"	, 0x0024},
	{"bluetooth_rfcomm_write"	, 0x0025},
	{"bluetooth_network_activate_server"	, 0x0026},
	{"bluetooth_network_deactivate_server"	, 0x0027},
	{"bluetooth_network_connect"	, 0x0028},
	{"bluetooth_network_disconnect"	, 0x0029},

	{"bluetooth_hdp_activate"	, 0x0030},
	{"bluetooth_hdp_deactivate"	, 0x0031},
	{"bluetooth_hdp_connect"	, 0x0032},
	{"bluetooth_hdp_disconnect"	, 0x0033},
	{"bluetooth_hdp_send_data"	, 0x0034},

	{"bluetooth_opc_init"		, 0x0035},
	{"bluetooth_opc_push_file"	, 0x0036},
	{"bluetooth_opc_cancel_push"	, 0x0037},
	{"bluetooth_opc_deinit"		, 0x0038},
	/* -----------------------------------------*/
	{"Finish"							, 0x00ff},
	{NULL								, 0x0000},

};

#define tc_result(success, tc_index) \
	TC_PRT("Test case [%d - %s] %s", tc_table[tc_index].tc_code, tc_table[tc_index].tc_name, ((success == TC_PASS)?"Success":"Failed"));

bluetooth_device_info_t bond_dev;
int is_bond_device = FALSE;

void tc_usage_print(void)
{
	int i = 0;

	while (tc_table[i].tc_name && tc_table[i].tc_code)
	{
		if (tc_table[i].tc_code != 0x00ff)
		{
			TC_PRT("Key %d : usage %s", i, tc_table[i].tc_name);
		}
		else
		{
			TC_PRT("Key %d : usage %s\n\n", 0x00ff, tc_table[i].tc_name);
		}

		i++;
	}

}

int test_input_callback(void *data)
{
	int ret = 0;
	int test_id = (int)data;

	switch (test_id)
	{
		case 0x00ff:
			TC_PRT("Finished");
			g_main_loop_quit(main_loop);
			break;

		case 1:
			TC_PRT("TC : %s", tc_table[1].tc_name);
			ret = bluetooth_enable_adapter();
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[1].tc_name, ret);
				tc_result(TC_FAIL, 1);
			}
			break;

		case 2:
			TC_PRT("TC : %s", tc_table[2].tc_name);
			ret = bluetooth_disable_adapter();
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[2].tc_name, ret);
				tc_result(TC_FAIL, 2);
			}
			break;

		case 3:
			TC_PRT("TC : %s", tc_table[3].tc_name);
			ret = bluetooth_check_adapter();
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[3].tc_name, ret);
				tc_result(TC_FAIL, 3);
			}
			else
			{
				TC_PRT("BT state [0x%04x]", ret);
				tc_result(TC_PASS, 3);
			}
			break;

		case 4:
		{
			bluetooth_device_address_t local_address = {{0}};

			TC_PRT("TC : %s", tc_table[4].tc_name);
			ret = bluetooth_get_local_address(&local_address);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[4].tc_name, ret);
				tc_result(TC_FAIL, 4);
			}
			else
			{
				TC_PRT("BT local address[%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", \
					local_address.addr[0], local_address.addr[1], local_address.addr[2], \
					local_address.addr[3], local_address.addr[4], local_address.addr[5]);
				tc_result(TC_PASS, 4);
			}
			break;
		}

		case 5:
		{
			bluetooth_device_name_t local_name = {{0}};

			TC_PRT("TC : %s", tc_table[5].tc_name);
			ret = bluetooth_get_local_name(&local_name);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[5].tc_name, ret);
				tc_result(TC_FAIL, 5);
			}
			else
			{
				TC_PRT("BT local name [%s]", \
					local_name.name);
				tc_result(TC_PASS, 5);
			}
			break;
		}

		case 6:
		{
			bluetooth_device_name_t local_name = {{0}};
			snprintf(local_name.name, sizeof(local_name.name),
					"bt-frwk-pid-%d", getpid());

			TC_PRT("TC : %s", tc_table[6].tc_name);
			ret = bluetooth_set_local_name(&local_name);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[6].tc_name, ret);
				tc_result(TC_FAIL, 6);
			}
			break;
		}

	        case 7:
		{
			bluetooth_discoverable_mode_t mode;
			TC_PRT("TC : %s", tc_table[7].tc_name);
			ret = bluetooth_get_discoverable_mode(&mode);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[7].tc_name, ret);
				tc_result(TC_FAIL, 7);
			}
			else
			{
				TC_PRT("BT Get Discoverable mode [%d]", \
					mode);
				tc_result(TC_PASS, 7);
			}
			break;
		}

	        case 8:
		{
			bluetooth_discoverable_mode_t mode = 3;
			TC_PRT("TC : %s", tc_table[8].tc_name);
			ret = bluetooth_set_discoverable_mode(mode, 180);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[8].tc_name, ret);
				tc_result(TC_FAIL, 8);
			}
			else
			{
				TC_PRT("BT Set Discoverable mode [%d]", \
					mode);
				tc_result(TC_PASS, 8);
			}
			break;
		}

		case 9:
			TC_PRT("TC : %s", tc_table[9].tc_name);
			ret = bluetooth_start_discovery(0,0,0);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[9].tc_name, ret);
				tc_result(TC_FAIL, 9);
			}
			break;

		case 10:
			TC_PRT("TC : %s", tc_table[10].tc_name);
			ret = bluetooth_cancel_discovery();
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[10].tc_name, ret);
				tc_result(TC_FAIL, 10);
			}
			break;

		case 11:
		{
			TC_PRT("TC : %s", tc_table[11].tc_name);
			ret = bluetooth_is_discovering();
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[11].tc_name, ret);
				tc_result(TC_FAIL, 11);
			}
			else
			{
				TC_PRT("Discovering [%d]", ret);
				tc_result(TC_PASS, 11);
			}
			break;
		}

		case 12:
		{
			if (searched_device.addr[0] || searched_device.addr[1] || searched_device.addr[2] \
				|| searched_device.addr[3] || searched_device.addr[4] || searched_device.addr[5])
			{
				TC_PRT("TC : %s", tc_table[12].tc_name);

				TC_PRT("dev [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", \
					searched_device.addr[0], searched_device.addr[1], searched_device.addr[2], \
					searched_device.addr[3], searched_device.addr[4], searched_device.addr[5]);

				ret = bluetooth_bond_device(&searched_device);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[12].tc_name, ret);
					tc_result(TC_FAIL, 12);
				}
			}
			else
			{
				TC_PRT("Do search first");
			}
			break;
		}

		case 13: /*Cancel bonding */
		{

				TC_PRT("TC : %s", tc_table[13].tc_name);
				ret = bluetooth_cancel_bonding();
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[13].tc_name, ret);
					tc_result(TC_FAIL, 13);
				}

			break;
		}

		case 14: /*Get paired device */
		{
				bluetooth_device_info_t devinfo = {0};
				bluetooth_device_address_t device_address={{0x00,0x1C,0x43,0x2B,0x1A,0xE5}};

				ret = bluetooth_get_bonded_device(&device_address, &devinfo);
				if (ret != BLUETOOTH_ERROR_NONE)
				{
					TC_PRT("bluetooth_get_bonded_device failed with [%d]",ret);
				}
				else
				{
					TC_PRT("Name [%s]", devinfo.device_name.name);
					TC_PRT("Major Class [%d]", devinfo.device_class.major_class);
					TC_PRT("Minor Class [%d]", devinfo.device_class.minor_class);
					TC_PRT("Service Class [%d]", devinfo.device_class.service_class);
					TC_PRT("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", devinfo.device_address.addr[0], devinfo.device_address.addr[1], devinfo.device_address.addr[2], devinfo.device_address.addr[3], devinfo.device_address.addr[4], devinfo.device_address.addr[5]);
				}

			break;
		}

		case 15: /*Get paired device list */
		{

				TC_PRT("TC : %s", tc_table[15].tc_name);
//				bluetooth_device_address_t remote_address = {{0}};

				GPtrArray *devinfo = NULL;
				devinfo = g_ptr_array_new();
				TC_PRT("g pointer arrary count : [%d]", devinfo->len);

				ret = bluetooth_get_bonded_device_list(&devinfo);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[19].tc_name, ret);
					tc_result(TC_FAIL, 15);
				}
				else
				{
					int i;
					bluetooth_device_info_t *ptr;
					TC_PRT("g pointer arrary count : [%d]", devinfo->len);

					if(devinfo->len >=1)
					{
						ptr = g_ptr_array_index(devinfo, 0);
						memcpy(&bond_dev, ptr, sizeof(bluetooth_device_info_t));
						is_bond_device = TRUE;
					}
					else
						is_bond_device = FALSE;

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
					tc_result(TC_PASS, 15);
				}
				g_ptr_array_free(devinfo, TRUE);

			break;
		}
		case 18: /*service search */
		{

				TC_PRT("TC : %s", tc_table[18].tc_name);
				bluetooth_device_address_t remote_address = {{0}};

				TC_PRT("Selected Choi Dongle\n");
				/*Syam PC Dongle choi*/
				remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x03; remote_address.addr[2] = 0x7A;
				remote_address.addr[3]= 0x2D; remote_address.addr[4] = 0xC9;  remote_address.addr[5]= 0x9D;

				ret = bluetooth_search_service(&remote_address);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[18].tc_name, ret);
					tc_result(TC_FAIL, 18);
				}


			break;
		}
		case 19: /*set alias for bonded device */
		{
				char buff[100] = {0,};
				TC_PRT("TC : %s", tc_table[19].tc_name);

				TC_PRT("TC : Input the alias = ");
				scanf("%s", buff);

				if(!strcmp(buff, "NULL"))
				{
					memset(buff, 0, 100);
					TC_PRT("There is no alias");
				}
				else
					TC_PRT("ALIAS is %s", buff);

				if(is_bond_device)
				{
					ret = bluetooth_set_alias(&bond_dev.device_address, buff);
					if (ret < 0)
					{
						TC_PRT("%s failed with [0x%04x]", tc_table[19].tc_name, ret);
						tc_result(TC_FAIL, 19);
					}
					else
					{
						tc_result(TC_PASS, 19);
					}
				}
				else
				{
					TC_PRT("Please get bonded device list calling  bluetooth_get_bonded_device_list");
				}
			break;
		}

		/*Rfcomm */
		case 20: /*Create server socket */
		{
				TC_PRT("TC : %s", tc_table[20].tc_name);
				ret = bluetooth_rfcomm_create_socket(rfcomm_test_uuid_spp);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[20].tc_name, ret);
					tc_result(TC_FAIL, 20);
				}
				TC_PRT("\nReturned FD = %d\n", ret);
				g_tmp = ret;
			break;
		}
		case 21: /*Listen and accept */
		{

				TC_PRT("TC : %s", tc_table[21].tc_name);
				ret = bluetooth_rfcomm_listen_and_accept(g_tmp,1);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[21].tc_name, ret);
					tc_result(TC_FAIL, 21);
				}
				TC_PRT("\nListining status(True/False) = %d\n", ret);
			break;
		}
		case 22: /*Server remove */
		{

				TC_PRT("TC : %s", tc_table[22].tc_name);
				ret = bluetooth_rfcomm_remove_socket(g_tmp, rfcomm_test_uuid_spp);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[22].tc_name, ret);
					tc_result(TC_FAIL, 22);
				}

			break;
		}
		case 23: /*connect */
		{
				bluetooth_device_address_t remote_address = {{0}};
				TC_PRT("Enter connect device 1 or 2:");
				scanf("%d", &selection);
				if(selection == 1)
				{
#if 1
					TC_PRT("Selected Choi Dongle\n");
					/*Syam PC Dongle choi*/
					remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x0A; remote_address.addr[2] = 0x3A;
					remote_address.addr[3]= 0x54; remote_address.addr[4] = 0x19;  remote_address.addr[5]= 0x36;
#else
					TC_PRT("Selected Grey Dongle\n");
					/*Syam PC Dongle Grey BT*/
					remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x0D; remote_address.addr[2] = 0x18;
					remote_address.addr[3]= 0x01; remote_address.addr[4] = 0x24;  remote_address.addr[5]= 0x47;
#endif
				}
				else
				{
					/*Syam Mob 00:21:D1:0B:45:22*/
					remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x21; remote_address.addr[2] = 0xD1;
					remote_address.addr[3]= 0x0B; remote_address.addr[4] = 0x45;  remote_address.addr[5]= 0x22;

				}

				TC_PRT("TC : %s", tc_table[23].tc_name);

				ret = bluetooth_rfcomm_connect(&remote_address, rfcomm_test_uuid_spp);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[23].tc_name, ret);
					tc_result(TC_FAIL, 23);
				}
				else
				{
					TC_PRT("\n Returned value = %d\n", ret);
				}
			break;
		}

		case 24: /*disconnect */
		{
//				bluetooth_device_address_t remote_address = {{0}};
				int no, fd_dis;
				TC_PRT("Enter Disconnect device 1 or 2:");
				scanf("%d", &no);

				if(no == 1)
				{
					fd_dis = g_ret_client_fd1;
				}
				else
				{
					fd_dis = g_ret_client_fd2;
				}

				TC_PRT("TC : %s", tc_table[24].tc_name);

				ret = bluetooth_rfcomm_disconnect(fd_dis);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[24].tc_name, ret);
					tc_result(TC_FAIL, 24);
				}
				TC_PRT("\n Disconnect result for fd %d is = %d\n", fd_dis, ret);
			break;
		}

		case 25: /*write */
		{
//				bluetooth_device_address_t remote_address = {{0}};
				char *buff = "abcdefghijklmnopqrstuvwxyz";
				int fd_channel;
				TC_PRT("TC : %s", tc_table[25].tc_name);
				TC_PRT("\n Enter the channel: ");
				scanf("%d", &fd_channel);
				ret = bluetooth_rfcomm_write(fd_channel, buff, 26);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[25].tc_name, ret);
					tc_result(TC_FAIL, 25);
				}
			break;
		}

		case 26: /*bluetooth_network_activate_server */
		{
			bluetooth_network_activate_server();
			break;
		}

		case 27: /*bluetooth_network_deactivate_server */
		{
			bluetooth_network_deactivate_server();
			break;
		}

		case 28: /*bluetooth_network_connect */
		{
			bluetooth_device_address_t device_address={{0x00,0x02,0x10,0x54,0x90,0x27}};
			bluetooth_network_connect(&device_address, BLUETOOTH_NETWORK_NAP_ROLE, NULL);
			break;
		}

		case 29: /*bluetooth_network_disconnect */
		{
			bluetooth_device_address_t device_address={{0x00,0x02,0x10,0x54,0x90,0x27}};
			bluetooth_network_disconnect(&device_address);
			break;
		}


		case 30: /*HDP Activate*/
		{
			if(hdp_manual_mode == 1)
			{
				int d_type;
				TC_PRT("Enter the device type value\n");
				TC_PRT("eg: 4100(pulse), 4103(Blood pressure), 4104(thermometer), 4111(weight), 4113(Glucose)\n");
				scanf("%d", &d_type);
				ret = bluetooth_hdp_activate(d_type, HDP_ROLE_SINK, HDP_QOS_ANY);
				TC_PRT("Act Done\n");
				break;
			}

				ret = bluetooth_hdp_activate(4100, HDP_ROLE_SINK, HDP_QOS_ANY);

				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[30].tc_name, ret);
					tc_result(TC_FAIL, 30);
				}
			TC_PRT("Done, Res = %d\n", ret);
			break;
		}
		case 31: /*HDP DeActivate*/
		{

			if(hdp_manual_mode == 1)
			{
				if(NULL == g_hdp_app_handle2)
				{
					ret = bluetooth_hdp_deactivate(g_hdp_app_handle1);
					g_hdp_app_handle1 = NULL;
				}
				else
				{
					ret = bluetooth_hdp_deactivate(g_hdp_app_handle2);
					g_hdp_app_handle2 = NULL;
				}
				TC_PRT("Done, Res = %d\n", ret);
				break;
			}
			ret = bluetooth_hdp_deactivate(g_hdp_app_handle1);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[31].tc_name, ret);
				tc_result(TC_FAIL, 31);
			}
			TC_PRT("Done, Res = %d\n", ret);
			break;
		}
		case 32: /*HDP Connect*/
		{
			bluetooth_device_address_t remote_address = {{0}};
			TC_PRT("Warning!!! Make sure that you have changed the BD address \n");
			/*PTS Dongle 1*/
			remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x80; remote_address.addr[2] = 0x98;
			remote_address.addr[3]= 0xE7; remote_address.addr[4] = 0x34;  remote_address.addr[5]= 0x07;
			if(hdp_manual_mode)
			{
				if(g_hdp_app_handle2 != NULL) /**/
				{
					ret = bluetooth_hdp_connect(g_hdp_app_handle2, HDP_QOS_ANY, &remote_address);
					g_hdp_app_handle2 = NULL;
				}
				else
				{
					ret = bluetooth_hdp_connect(g_hdp_app_handle1, HDP_QOS_ANY, &remote_address);
					g_hdp_app_handle1 = NULL;
				}
				TC_PRT("Done, Res = %d\n", ret);
				break;
			}


			ret = bluetooth_hdp_connect(g_hdp_app_handle1, HDP_QOS_ANY, &remote_address);
			if (ret < 0)
			{
				TC_PRT("%s failed with [0x%04x]", tc_table[32].tc_name, ret);
				tc_result(TC_FAIL, 32);
			}
			TC_PRT("Done, Res = %d\n", ret);
			break;
		}

		case 33: /*HDP Disconnect*/
		{
				bluetooth_device_address_t remote_address = {{0}};
				TC_PRT("Warning!!! Make sure that you have changed the BD address \n");
				/*PTS Dongle 1*/
				remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x80; remote_address.addr[2] = 0x98;
				remote_address.addr[3]= 0xE7; remote_address.addr[4] = 0x34;  remote_address.addr[5]= 0x07;
				if(hdp_manual_mode)
				{
					int d_type;
					TC_PRT("Enter the channel id (fd):\n");
					scanf("%d", &d_type);
					ret = bluetooth_hdp_disconnect(d_type, &remote_address);
					TC_PRT("Done, Res = %d\n", ret);
					break;
				}
				ret = bluetooth_hdp_disconnect(g_ret_client_fd1, &remote_address);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[33].tc_name, ret);
					tc_result(TC_FAIL, 33);
				}
				close(g_ret_client_fd1);
				TC_PRT("Done..\n");
			break;
		}


		case 34: /*HDP Send Data*/
		{
				char *buff = "abcdefghijklmnopqrstuvwxyz";

				ret = bluetooth_hdp_send_data(g_ret_client_fd1, buff, 26);
				if (ret < 0)
				{
					TC_PRT("%s failed with [0x%04x]", tc_table[34].tc_name, ret);
					tc_result(TC_FAIL, 34);
				}
				TC_PRT("Done, Res = %d\n", ret);
			break;
		}

		case 35:
		{
			bluetooth_opc_init();
			break;
		}

		case 36:
		{
			bluetooth_device_address_t remote_address = {{0}};
			TC_PRT("Warning!!! Make sure that you have changed the BD address \n");
#if 0
			/*PTS Dongle 1*/
			remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x80; remote_address.addr[2] = 0x98;
			remote_address.addr[3]= 0xE7; remote_address.addr[4] = 0x34;  remote_address.addr[5]= 0x07;
#endif
			/* Grey dongle */
			remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x19; remote_address.addr[2] = 0x0E;
			remote_address.addr[3]= 0x01; remote_address.addr[4] = 0x61;  remote_address.addr[5]= 0x17;
			char *files[5] = {NULL};
			files[0] = "/opt/media/photo1.jpg";
			files[1] = "/opt/media/photo2.jpg";
			files[2] = "/opt/media/photo3.jpg";
//			files[3] = "/opt/media/Downloads/4_photo_41.jpg";
			bluetooth_opc_push_files(&remote_address,files);
			break;
		}

		case 37:
		{
			bluetooth_device_address_t remote_address = {{0}};
			/* Grey dongle */
			remote_address.addr[0] = 0x00; remote_address.addr[1] = 0x03; remote_address.addr[2] = 0x7A;
			remote_address.addr[3]= 0x2D; remote_address.addr[4] = 0xC9;  remote_address.addr[5]= 0x9D;

			char *files[5] = {NULL};
			files[0] = "/opt/media/photo1.jpg";
			files[1] = "/opt/media/photo2.jpg";
			files[2] = "/opt/media/photo3.jpg";
			bluetooth_opc_push_files(&remote_address,files);
			break;
		}

		case 38:
		{
			bluetooth_opc_deinit();
			break;
		}

		case 39:
		{
			bluetooth_obex_server_init("/opt/media/Downloads");
			break;
		}

		case 40:
		{
			bluetooth_obex_server_deinit();
			break;
		}

		case 41:
		{
			bluetooth_obex_server_accept_authorize("abc");
			break;
		}

		case 42:
		{
			bluetooth_obex_server_reject_authorize();
			break;
		}

		case 43:
		{
			bluetooth_is_supported();
			break;
		}

		case 44:
		{
			bluetooth_allow_service(TRUE);
			break;
		}

		case 45:
		{
			bluetooth_allow_service(FALSE);
			break;
		}

		case 46:
		{
			bluetooth_opc_sessioin_is_exist();
			break;
		}

		case 47:
		{
			bluetooth_obex_server_is_activated();
			break;
		}

		default:
			break;
	}

	return 0;
}

void startup()
{
	TC_PRT("bluetooth framework TC startup");

	if(!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	dbus_g_thread_init();

	g_type_init();
	main_loop = g_main_loop_new(NULL, FALSE);
}

void cleanup()
{
	TC_PRT("bluetooth framework TC cleanup");
	if( main_loop!= NULL)
	{
		g_main_loop_unref(main_loop);
	}
}

int timeout_callback(void *data)
{
	TC_PRT("timeout callback");
	timeout_status = -1;

	g_main_loop_quit(main_loop);

	return FALSE;
}

void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data)
{
	TC_PRT(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
	TC_PRT("bt event callback 0x%04x", event);
	switch(event)
	{
		case BLUETOOTH_EVENT_ENABLED:
			TC_PRT("BLUETOOTH_EVENT_ENABLED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				tc_result(TC_PASS, 1);
			}
			else
			{
				tc_result(TC_FAIL, 1);
			}
			break;

		case BLUETOOTH_EVENT_DISABLED:
			TC_PRT("BLUETOOTH_EVENT_DISABLED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				tc_result(TC_PASS, 2);
			}
			else
			{
				tc_result(TC_FAIL, 2);
			}
			break;

		case BLUETOOTH_EVENT_LOCAL_NAME_CHANGED:
			TC_PRT("BLUETOOTH_EVENT_LOCAL_NAME_CHANGED, result [0x%04x]", param->result);
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_name_t *local_name = (bluetooth_device_name_t *)param->param_data;
				tc_result(TC_PASS, 6);
				TC_PRT("Changed Name : [%s]", local_name->name);
			}
			else
			{
				tc_result(TC_FAIL, 6);
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
			tc_result(TC_PASS, 9);
			break;


		case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				tc_result(TC_PASS, 12);
				device_info  = (bluetooth_device_info_t *)param->param_data;
				TC_PRT("dev [%s] [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X] mjr[%#x] min[%#x] srv[%#x]", device_info->device_name.name, \
					device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
					device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5], \
					device_info->device_class.major_class, device_info->device_class.minor_class, device_info->device_class.service_class);
			}
			else
			{
				tc_result(TC_FAIL, 12);
			}
			break;
		}

		case BLUETOOTH_EVENT_BONDED_DEVICE_FOUND:
		{
			// bluetooth_get_bonded_device_list is changed as synchronous API. This event is not used any more.
			// 2011.01.06
#if 0
//			int i = 0;
			TC_PRT("BLUETOOTH_EVENT_BONDED_DEVICE_FOUND, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				///tc_result(TC_PASS, 15);
				bluetooth_device_info_t * bt_dev_info= (bluetooth_device_info_t*)param->param_data;

				TC_PRT("Dev Name = %s, Dev add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X, COD (major,minor,service)= 0x%x:%x:%x\n", bt_dev_info->device_name.name,
					bt_dev_info->device_address.addr[0], bt_dev_info->device_address.addr[1], bt_dev_info->device_address.addr[2], \
					bt_dev_info->device_address.addr[3], bt_dev_info->device_address.addr[4], bt_dev_info->device_address.addr[5], \
					bt_dev_info->device_class.major_class, bt_dev_info->device_class.minor_class, bt_dev_info->device_class.service_class);

			}
			else
			if(param->result == BLUETOOTH_ERROR_END_OF_DEVICE_LIST) /*End of the Device found indication*/
			{
				tc_result(TC_PASS, 15);
				TC_PRT("*****<<No more BLUETOOTH_EVENT_BONDED_DEVICE_FOUND indication>>***** ");
			}
			else
			{
				tc_result(TC_FAIL, 15);
				TC_PRT("*****API failed ***** ");
			}
			break;
#endif
		}
		case BLUETOOTH_EVENT_SERVICE_SEARCHED:
		{
			int i = 0;
			TC_PRT("BLUETOOTH_EVENT_SERVICE_SEARCHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				tc_result(TC_PASS, 18);
				bt_sdp_info_t * bt_sdp_info=param->param_data;

				TC_PRT("Dev add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					bt_sdp_info->device_addr.addr[0], bt_sdp_info->device_addr.addr[1], bt_sdp_info->device_addr.addr[2], \
					bt_sdp_info->device_addr.addr[3], bt_sdp_info->device_addr.addr[4], bt_sdp_info->device_addr.addr[5]);

					TC_PRT("Supported service list:\n");
					for(i=0; i<bt_sdp_info->service_index; i++)
						TC_PRT("[%#x]\n", bt_sdp_info->service_list_array[i]);

			}
			else
			{
				tc_result(TC_FAIL, 18);
			}
			break;
		}
		case BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED:
		{
			TC_PRT("BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED, result [0x%04x]", param->result);
			bluetooth_rfcomm_received_data_t *rx_data = param->param_data;
			printf("\n FD = %d \nBuffer len = %d ", rx_data->socket_fd, rx_data->buffer_size);
			//tc_result(TC_PASS, 21);
			break;
		}
		case BLUETOOTH_EVENT_RFCOMM_CONNECTED:
		{
			bluetooth_rfcomm_connection_t *con_ind = (bluetooth_rfcomm_connection_t *)param->param_data;
			TC_PRT("BLUETOOTH_EVENT_RFCOMM_CONNECTED, result [0x%04x], fd = %d, device add = 0x%X:%X:%X:%X:%X:%X, Role = %s", param->result,
								con_ind->socket_fd,
								con_ind->device_addr.addr[0], con_ind->device_addr.addr[1], con_ind->device_addr.addr[2],
								con_ind->device_addr.addr[3], con_ind->device_addr.addr[4], con_ind->device_addr.addr[5],
								(con_ind->device_role == RFCOMM_ROLE_SERVER)? "SERVER":"CLIENT");
			//tc_result(TC_PASS, 22);
			if((con_ind->device_role == RFCOMM_ROLE_CLIENT) && (con_ind->socket_fd > 0))
			{
				if(selection == 1)
					g_ret_client_fd1 = con_ind->socket_fd;
				else
					g_ret_client_fd2 = con_ind->socket_fd;
			}

			break;
		}
		case BLUETOOTH_EVENT_RFCOMM_DISCONNECTED:
		{
			bluetooth_rfcomm_disconnection_t *disconnection_ind = (bluetooth_rfcomm_disconnection_t *)param->param_data;;
			TC_PRT("BLUETOOTH_EVENT_RFCOMM_DISCONNECTED, result [0x%04x] Fd = %d, device add = 0x%X:%X:%X:%X:%X:%X\n", param->result, disconnection_ind->socket_fd,
														disconnection_ind->device_addr.addr[0], disconnection_ind->device_addr.addr[1], disconnection_ind->device_addr.addr[2],
														disconnection_ind->device_addr.addr[3], disconnection_ind->device_addr.addr[4], disconnection_ind->device_addr.addr[5] );
			//tc_result(TC_PASS, 22);
			break;
		}
		case BLUETOOTH_EVENT_NETWORK_SERVER_CONNECTED:
		{
			bluetooth_network_device_info_t *dev_info = (bluetooth_network_device_info_t *)param->param_data;

			TC_PRT("BLUETOOTH_EVENT_RFCOMM_DISCONNECTED, result [0x%04x]", param->result);
			TC_PRT("interface name: %s", dev_info->interface_name);

			TC_PRT("device add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
								dev_info->device_address.addr[0], dev_info->device_address.addr[1], dev_info->device_address.addr[2],
								dev_info->device_address.addr[3], dev_info->device_address.addr[4], dev_info->device_address.addr[5] );
			break;
		}
		case BLUETOOTH_EVENT_NETWORK_SERVER_DISCONNECTED:
		{
			bluetooth_network_device_info_t *dev_info = (bluetooth_network_device_info_t *)param->param_data;

			TC_PRT("BLUETOOTH_EVENT_RFCOMM_DISCONNECTED, result [0x%04x]", param->result);
			TC_PRT("interface name: %s", dev_info->interface_name);

			TC_PRT("device add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
								dev_info->device_address.addr[0], dev_info->device_address.addr[1], dev_info->device_address.addr[2],
								dev_info->device_address.addr[3], dev_info->device_address.addr[4], dev_info->device_address.addr[5] );
			break;
		}


		case BLUETOOTH_EVENT_HDP_ACTIVATED:
		{

			TC_PRT("BLUETOOTH_EVENT_HDP_ACTIVATED, Result = %s\n", (param->result == 0)? "BLUETOOTH_ERROR_NONE": "BLUETOOTH_ERROR_XXXX");
			bt_hdp_activate_t *act_cfm =  (bt_hdp_activate_t *)param->param_data;
			TC_PRT("App handler = %s\n", act_cfm->app_handle);
			if(hdp_manual_mode == 1)
			{
				if(NULL == g_hdp_app_handle1)
					g_hdp_app_handle1 =  act_cfm->app_handle; /*1st time */
				else
					g_hdp_app_handle2 =  act_cfm->app_handle; /*2nd time */

				break;
			}
			g_hdp_app_handle1 =  act_cfm->app_handle;
			break;
		}

		case BLUETOOTH_EVENT_HDP_DEACTIVATED:
		{

			TC_PRT("BLUETOOTH_EVENT_HDP_DEACTIVATED, Result = %s\n", (param->result == 0)? "BLUETOOTH_ERROR_NONE": "BLUETOOTH_ERROR_XXXX");
			bt_hdp_deactivate_t *deact_cfm =  (bt_hdp_deactivate_t *)param->param_data;
			TC_PRT("App handler = %s\n", deact_cfm->app_handle);
			break;
		}

		case BLUETOOTH_EVENT_HDP_CONNECTED:
		{
			bt_hdp_connected_t *conn_ind = (bt_hdp_connected_t *)param->param_data;

			TC_PRT("BLUETOOTH_EVENT_HDP_CONNECTED, Result = %s\n", (param->result == 0)? "BLUETOOTH_ERROR_NONE": "BLUETOOTH_ERROR_XXXX");
			TC_PRT("App handler = %s, channel id = %d, type = %s", conn_ind->app_handle, conn_ind->channel_id, (conn_ind->type == HDP_QOS_RELIABLE)? "Reliable":"Streaming");
			TC_PRT("device add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
								conn_ind->device_address.addr[0], conn_ind->device_address.addr[1], conn_ind->device_address.addr[2],
								conn_ind->device_address.addr[3], conn_ind->device_address.addr[4], conn_ind->device_address.addr[5] );

			g_ret_client_fd1 = conn_ind->channel_id;
			break;
		}

		case BLUETOOTH_EVENT_HDP_DISCONNECTED:
		{
			bt_hdp_disconnected_t *dis_ind = (bt_hdp_disconnected_t *)param->param_data;

			TC_PRT("BLUETOOTH_EVENT_HDP_DISCONNECTED, Result = %s\n", (param->result == 0)? "BLUETOOTH_ERROR_NONE": "BLUETOOTH_ERROR_XXXX");
			TC_PRT("Channel = %d, Add = device add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", dis_ind->channel_id,
								dis_ind->device_address.addr[0], dis_ind->device_address.addr[1], dis_ind->device_address.addr[2],
								dis_ind->device_address.addr[3], dis_ind->device_address.addr[4], dis_ind->device_address.addr[5]);
			break;
		}

		case BLUETOOTH_EVENT_HDP_DATA_RECEIVED:
		{
			bt_hdp_data_ind_t *data_ind = (bt_hdp_data_ind_t *)param->param_data;

			TC_PRT("BLUETOOTH_EVENT_HDP_DATA_RECEIVED, Result = %s\n", (param->result == 0)? "BLUETOOTH_ERROR_NONE": "BLUETOOTH_ERROR_XXXX");
			TC_PRT("Data received from channel id = %d and  size =%d, buff =[%s]\n",  data_ind->channel_id, data_ind->size, data_ind->buffer);

			break;
		}

		case BLUETOOTH_EVENT_OPC_CONNECTED:
			TC_PRT("BLUETOOTH_EVENT_OPC_CONNECTED");
			break;

		case BLUETOOTH_EVENT_OPC_DISCONNECTED:
			TC_PRT("BLUETOOTH_EVENT_OPC_DISCONNECTED");
			break;
		case BLUETOOTH_EVENT_OPC_TRANSFER_STARTED:
		{
			TC_PRT("BLUETOOTH_EVENT_OPC_TRANSFER_STARTED");
			if (param->param_data) {
				bt_opc_transfer_info_t *info = param->param_data;
				TC_PRT("file %s", info->filename);
				TC_PRT("size %d", info->size);
			}
			break;
		}
		case BLUETOOTH_EVENT_OPC_TRANSFER_PROGRESS:
		{
			TC_PRT("BLUETOOTH_EVENT_OPC_TRANSFER_PROGRESS");
			break;
		}
		case BLUETOOTH_EVENT_OPC_TRANSFER_COMPLETE:
		{
			TC_PRT("BLUETOOTH_EVENT_OPC_TRANSFER_COMPLETE");
			bt_opc_transfer_info_t *info = param->param_data;
			TC_PRT("file %s", info->filename);
			TC_PRT("size %d", info->size);
			break;
		}

		case BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_AUTHORIZE:
			TC_PRT("BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_AUTHORIZE");
			break;

		case BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_STARTED:
			TC_PRT("BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_STARTED");
			break;

		case BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_PROGRESS:
			TC_PRT("BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_PROGRESS");
			break;

		case BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_COMPLETED:
			TC_PRT("BLUETOOTH_EVENT_OBEX_SERVER_TRANSFER_COMPLETED");
			break;

		default:
			TC_PRT("received event [0x%04x]", event);
			break;
	}
	TC_PRT("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
}

#ifdef __THREAD__
static void* input_thread( void* arg )
{
	char test_code[8000];
	int test_id;

	while (1==1)
	{

		tc_usage_print();
		printf("Input test ID : ");
		gets(test_code);
		test_id = atoi(test_code);
		if (test_id)
			g_idle_add(test_input_callback, (void*)test_id);
	}

	return NULL;
}
#endif

static gboolean key_event_cb(GIOChannel * chan, GIOCondition cond , gpointer data)
{
	char buf[10] = {0};

	unsigned int len=0;
	int test_id;
	memset(buf, 0, sizeof(buf));

	if(g_io_channel_read(chan, buf, sizeof(buf), &len) !=G_IO_ERROR_NONE) {

		printf("IO Channel read error");
		return FALSE;

	}
	printf("%s\n",buf);
	tc_usage_print();

	test_id=atoi(buf);

	if(test_id)
		g_idle_add(test_input_callback, (void*)test_id);

	return TRUE;
}

int main()
{
	int ret_val;

	startup();

	// Register callback function
	TC_PRT("TC : %s", tc_table[0].tc_name);
	ret_val = bluetooth_register_callback(bt_event_callback, NULL);
	if (ret_val >= BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_register_callback returned Success");
		tc_result(TC_PASS, 0);
	}
	else
	{
		TC_PRT("bluetooth_register_callback returned failiure [0x%04x]", ret_val);
		tc_result(TC_FAIL, 0);
		return 0;
	}

	ret_val = bluetooth_check_adapter();
	if (ret_val < BLUETOOTH_ERROR_NONE)
	{
		TC_PRT("bluetooth_check_adapter returned failiure [0x%04x]", ret_val);
		tc_result(TC_FAIL, 3);
	}
	else
	{
		TC_PRT("BT state [0x%04x]", ret_val);
		tc_result(TC_PASS, 3);
	}

#ifdef __THREAD__
	{
		pthread_t thread;
		pthread_attr_t tattr = {{0}};

		ret_val = pthread_attr_init(&tattr);
		ret_val = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize(&tattr, 128*1024);
		ret_val = pthread_create(&thread, &tattr, input_thread, NULL);
		pthread_attr_destroy(&tattr);
	}
#else
	{
		GIOChannel *key_io;
		key_io=g_io_channel_unix_new(fileno(stdin));

		g_io_add_watch(key_io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				key_event_cb, NULL);
		g_io_channel_unref(key_io);
	}
#endif

	g_main_loop_run(main_loop);

	cleanup();
	return 0;
}


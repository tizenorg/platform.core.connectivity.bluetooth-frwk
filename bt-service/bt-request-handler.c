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

#include <string.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>
#include <dlog.h>
#include <security-server.h>

#include "bluetooth-api.h"
#include "bt-service-common.h"
#include "bt-service-util.h"
#include "bt-service-event.h"
#include "bt-service-adapter.h"
#include "bt-service-adapter-le.h"
#include "bt-service-device.h"
#include "bt-service-hid.h"
#include "bt-service-network.h"
#include "bt-service-audio.h"
#include "bt-service-oob.h"
#include "bt-service-avrcp.h"
#include "bt-service-opp-client.h"
#include "bt-service-obex-server.h"
#include "bt-service-rfcomm-client.h"
#include "bt-service-rfcomm-server.h"
#include "bt-request-handler.h"
#include "bt-service-pbap.h"

/* auto generated header by bt-request-service.xml*/
#include "bt-service-method.h"

DBusGConnection *bt_service_conn;
BtService *service_object;

GType bt_service_get_type(void);

G_DEFINE_TYPE(BtService, bt_service, G_TYPE_OBJECT);

/*This is part of platform provided code skeleton for client server model*/
static void bt_service_class_init(BtServiceClass *service_class)
{
	dbus_g_object_type_install_info(G_TYPE_FROM_CLASS(service_class),
					&dbus_glib_bt_object_info);
}

/*This is part of platform provided code skeleton for client server model*/
static void bt_service_init(BtService *service)
{
}

static int __bt_bluez_request(int function_name,
		int request_type,
		int request_id,
		DBusGMethodInvocation *context,
		GArray *in_param1,
		GArray *in_param2,
		GArray *in_param3,
		GArray *in_param4,
		GArray **out_param1)
{
	int result = BLUETOOTH_ERROR_NONE;

	switch (function_name) {
	case BT_ENABLE_ADAPTER:
		result = _bt_enable_adapter();
		break;
	case BT_DISABLE_ADAPTER:
		result = _bt_disable_adapter();
		break;
	case BT_RECOVER_ADAPTER:
		result = _bt_recover_adapter();
		break;
	case BT_ENABLE_ADAPTER_LE:
		result = _bt_enable_adapter_le();
		break;
	case BT_DISABLE_ADAPTER_LE:
		result = _bt_disable_adapter_le();
		break;
	case BT_RESET_ADAPTER:
		result = _bt_reset_adapter();
		break;
	case BT_CHECK_ADAPTER: {
		int enabled = BT_ADAPTER_DISABLED;

		result = _bt_check_adapter(&enabled);

		g_array_append_vals(*out_param1, &enabled,
				sizeof(int));
		break;
	}
	case BT_GET_LOCAL_ADDRESS: {
		bluetooth_device_address_t local_address = { {0} };
		result = _bt_get_local_address(&local_address);

		g_array_append_vals(*out_param1, &local_address,
				sizeof(bluetooth_device_address_t));
		break;
	}
	case BT_GET_LOCAL_VERSION: {
		bluetooth_version_t ver = { {0} };
		result = _bt_get_local_version(&ver);

		g_array_append_vals(*out_param1, &ver,
				sizeof(bluetooth_version_t));
		break;
	}
	case BT_GET_LOCAL_NAME: {
		bluetooth_device_name_t local_name = { {0} };
		result = _bt_get_local_name(&local_name);

		g_array_append_vals(*out_param1, &local_name,
				sizeof(bluetooth_device_name_t));

		break;
	}
	case BT_SET_LOCAL_NAME: {
		bluetooth_device_name_t local_name = { {0} };

		local_name = g_array_index(in_param1,
				bluetooth_device_name_t, 0);

		result = _bt_set_local_name(local_name.name);

		break;
	}
	case BT_IS_SERVICE_USED: {
		char *uuid;
		gboolean used = FALSE;

		uuid = &g_array_index(in_param1, char, 0);

		result = _bt_is_service_used(uuid, &used);

		if (result == BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &used,
						sizeof(gboolean));
		}
		break;
	}
	case BT_GET_DISCOVERABLE_MODE: {
		int mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;

		result = _bt_get_discoverable_mode(&mode);

		g_array_append_vals(*out_param1, &mode, sizeof(int));
		break;
	}
	case BT_SET_DISCOVERABLE_MODE: {
		int mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		int time = 0;

		mode = g_array_index(in_param1, int, 0);
		time = g_array_index(in_param2, int, 0);

		result = _bt_set_discoverable_mode(mode, time);
		break;
	}
	case BT_GET_DISCOVERABLE_TIME: {
		int timeout = 0;

		result = _bt_get_timeout_value(&timeout);

		g_array_append_vals(*out_param1, &timeout, sizeof(int));
		break;
	}
	case BT_START_DISCOVERY:
		result = _bt_start_discovery();

		break;
	case BT_START_CUSTOM_DISCOVERY: {
		bt_discovery_role_type_t role;
		role = g_array_index(in_param1, bt_discovery_role_type_t, 0);

		result = _bt_start_custom_discovery(role);
		break;
	}
	case BT_CANCEL_DISCOVERY:
		result = _bt_cancel_discovery();
		break;
	case BT_START_LE_DISCOVERY:
		result = _bt_start_le_discovery();
		break;
	case BT_STOP_LE_DISCOVERY:
		result = _bt_stop_le_discovery();
		break;
	case BT_IS_DISCOVERYING: {
		gboolean discovering = FALSE;
		discovering = _bt_is_discovering();
		g_array_append_vals(*out_param1, &discovering, sizeof(gboolean));
		break;
	}
	case BT_IS_LE_DISCOVERYING: {
		gboolean le_discovering = FALSE;
		le_discovering = _bt_is_le_discovering();
		g_array_append_vals(*out_param1, &le_discovering, sizeof(gboolean));
		break;
	}
	case BT_ENABLE_RSSI: {
		bluetooth_device_address_t bd_addr;
		int link_type;
		bt_rssi_threshold_t rssi_threshold;
		int low_threshold;
		int in_range_threshold;
		int high_threshold;
		BT_DBG("Enable RSSI");

		bd_addr = g_array_index(in_param1, bluetooth_device_address_t, 0);
		link_type = g_array_index(in_param2, int, 0);
		rssi_threshold = g_array_index(in_param3, bt_rssi_threshold_t, 0);

		low_threshold = rssi_threshold.low_threshold;
		in_range_threshold = rssi_threshold.in_range_threshold;
		high_threshold = rssi_threshold.high_threshold;

		result = _bt_enable_rssi(&bd_addr, link_type ,low_threshold,
				in_range_threshold, high_threshold);
		break;
	}
	case BT_GET_RSSI: {
		int link_type;
		bluetooth_device_address_t bd_addr;

		BT_DBG("Get RSSI Strength");

		bd_addr = g_array_index(in_param1, bluetooth_device_address_t, 0);
		link_type = g_array_index(in_param2, int, 0);
		result = _bt_get_rssi_strength(&bd_addr, link_type);
		break;
	}
	case BT_IS_CONNECTABLE: {
		gboolean is_connectable;

		is_connectable = _bt_is_connectable();
		g_array_append_vals(*out_param1, &is_connectable, sizeof(gboolean));
		break;
	}
	case BT_SET_CONNECTABLE: {
		gboolean is_connectable;

		is_connectable = g_array_index(in_param1, gboolean, 0);

		result = _bt_set_connectable(is_connectable);
		break;
	}
	case BT_SET_ADVERTISING: {
		gboolean enable = FALSE;
		char *sender = NULL;
		gboolean use_reserved_slot = FALSE;

		enable = g_array_index(in_param1, gboolean, 0);
		use_reserved_slot = g_array_index(in_param2, gboolean, 0);
		sender = dbus_g_method_get_sender(context);
		result = _bt_set_advertising(enable, sender, use_reserved_slot);
		g_free(sender);
		break;
	}
	case BT_SET_CUSTOM_ADVERTISING: {
		gboolean enable = FALSE;
		bluetooth_advertising_params_t adv_params;
		char *sender = NULL;
		gboolean use_reserved_slot = FALSE;

		enable = g_array_index(in_param1, gboolean, 0);
		adv_params = g_array_index(in_param2,
					bluetooth_advertising_params_t, 0);
		use_reserved_slot = g_array_index(in_param3, gboolean, 0);
		sender = dbus_g_method_get_sender(context);

		BT_DBG("bluetooth_advertising_params_t [%f %f %d %d]",
				adv_params.interval_min, adv_params.interval_max,
				adv_params.filter_policy, adv_params.type);
		result = _bt_set_custom_advertising(enable, &adv_params, sender, use_reserved_slot);
		g_free(sender);
		break;
	}
	case BT_GET_ADVERTISING_DATA: {
		bluetooth_advertising_data_t adv = { {0} };
		int length = 0;

		result = _bt_get_advertising_data(&adv, &length);
		if (result == BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, adv.data, length);
		}

		break;
	}
	case BT_SET_ADVERTISING_DATA: {
		bluetooth_advertising_data_t adv = { {0} };
		int length;
		char *sender = NULL;
		gboolean use_reserved_slot = FALSE;

		sender = dbus_g_method_get_sender(context);

		adv = g_array_index(in_param1,
				bluetooth_advertising_data_t, 0);
		length = g_array_index(in_param2, int, 0);
		use_reserved_slot = g_array_index(in_param3, gboolean, 0);

		result = _bt_set_advertising_data(&adv, length, sender, use_reserved_slot);

		g_free(sender);
		break;
	}
	case BT_GET_SCAN_RESPONSE_DATA: {
		bluetooth_scan_resp_data_t rsp = { {0} };
		int length = 0;

		result = _bt_get_scan_response_data(&rsp, &length);
		if (result == BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, rsp.data, length);
		}

		break;
	}
	case BT_SET_SCAN_RESPONSE_DATA: {
		bluetooth_scan_resp_data_t rsp = { {0} };
		int length;
		char *sender = NULL;
		gboolean use_reserved_slot = FALSE;

		sender = dbus_g_method_get_sender(context);

		rsp = g_array_index(in_param1,
				bluetooth_scan_resp_data_t, 0);
		length = g_array_index(in_param2, int, 0);
		use_reserved_slot = g_array_index(in_param3, gboolean, 0);

		result = _bt_set_scan_response_data(&rsp, length, sender, use_reserved_slot);

		g_free(sender);
		break;
	}
	case BT_SET_MANUFACTURER_DATA: {
		bluetooth_manufacturer_data_t m_data = { 0 };

		m_data = g_array_index(in_param1,
				bluetooth_manufacturer_data_t, 0);

		result = _bt_set_manufacturer_data(&m_data);
		break;
	}
	case BT_SET_SCAN_PARAMETERS: {
		bluetooth_le_scan_params_t scan_params;

		scan_params = g_array_index(in_param1,
					bluetooth_le_scan_params_t, 0);

		BT_DBG("bluetooth_le_scan_params_t [%f %f %d]",
				scan_params.interval, scan_params.window,
				scan_params.type);

		result = _bt_set_scan_parameters(&scan_params);
		break;
	}
	case BT_LE_CONN_UPDATE: {
		bluetooth_device_address_t local_address = { {0} };
		bluetooth_le_conn_update_t parameters = {0};

		local_address = g_array_index(in_param1,
					bluetooth_device_address_t, 0);
		parameters = g_array_index(in_param2,
					bluetooth_le_conn_update_t, 0);

		result =  _bt_le_conn_update(local_address.addr,
					parameters.interval_min,
					parameters.interval_max,
					parameters.latency,
					parameters.time_out);
		break;
	}
	case BT_IS_ADVERTISING: {
		gboolean advertising = FALSE;
		advertising = _bt_is_advertising();

		g_array_append_vals(*out_param1, &advertising, sizeof(gboolean));
		break;
	}
	case BT_ADD_WHITE_LIST: {
		bluetooth_device_address_t address = { {0} };
		int addr_type = 0;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);
		addr_type = g_array_index(in_param2, int, 0);

		result = _bt_add_white_list(&address, addr_type);
		break;
	}
	case BT_REMOVE_WHITE_LIST: {
		bluetooth_device_address_t address = { {0} };
		int addr_type = 0;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);
		addr_type = g_array_index(in_param2, int, 0);

		result = _bt_remove_white_list(&address, addr_type);
		break;
	}
	case BT_CLEAR_WHITE_LIST: {
		result = _bt_clear_white_list();
		break;
	}
	case BT_GET_BONDED_DEVICES:
		result = _bt_get_bonded_devices(out_param1);
		break;

	case BT_GET_BONDED_DEVICE: {
		bluetooth_device_address_t address = { {0} };
		bluetooth_device_info_t dev_info;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));
		result = _bt_get_bonded_device_info(&address, &dev_info);

		if (result == BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &dev_info,
					sizeof(bluetooth_device_info_t));
		}
		break;
	}
	case BT_BOND_DEVICE: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_bond_device(request_id, &address,
				BLUETOOTH_DEV_CONN_DEFAULT, out_param1);
		break;
	}
	case BT_BOND_DEVICE_BY_TYPE: {
		bluetooth_device_address_t address = { {0} };
		unsigned short conn_type = 0;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		conn_type = g_array_index(in_param2,
				unsigned short, 0);

		result = _bt_bond_device(request_id, &address,
				conn_type, out_param1);
		break;
	}
	case BT_CANCEL_BONDING: {
		result = _bt_cancel_bonding();
		break;
	}
	case BT_UNBOND_DEVICE: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_unbond_device(request_id, &address, out_param1);

		break;
	}
	case BT_SET_ALIAS: {
		bluetooth_device_address_t address = { {0} };
		const char *local_name;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		local_name = &g_array_index(in_param2, char, 0);

		result = _bt_set_alias(&address, local_name);
		break;
	}
	case BT_SEARCH_SERVICE: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_search_device(request_id, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}
	case BT_CANCEL_SEARCH_SERVICE: {
		result = _bt_cancel_search_device();
		break;
	}
	case BT_SET_AUTHORIZATION: {
		bluetooth_device_address_t address = { {0} };
		gboolean authorize;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		authorize = g_array_index(in_param2, gboolean, 0);

		result = _bt_set_authorization(&address, authorize);
		break;
	}
	case BT_IS_DEVICE_CONNECTED: {
		bluetooth_device_address_t address = { {0} };
		int type;
		gboolean connected = FALSE;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		type = g_array_index(in_param2, int, 0);

		result = _bt_is_device_connected(&address, type, &connected);

		if (result == BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &connected,
						sizeof(gboolean));
		}

		break;
	}
	case BT_HID_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_hid_connect(request_id, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}
	case BT_HID_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_hid_disconnect(request_id, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}
	case BT_NETWORK_ACTIVATE:
		result = _bt_network_activate();
		break;
	case BT_NETWORK_DEACTIVATE:
		result = _bt_network_deactivate();
		break;
	case BT_NETWORK_CONNECT: {
		bluetooth_device_address_t address = { {0} };
		int role;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		role = g_array_index(in_param2, int, 0);

		result = _bt_network_connect(request_id, role, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}
	case BT_NETWORK_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_network_disconnect(request_id, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}
	case BT_NETWORK_SERVER_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_network_server_disconnect(request_id, &address);
		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
		break;
	}

	case BT_AUDIO_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_connect(request_id, BT_AUDIO_ALL,
					&address, out_param1);
		break;
	}
	case BT_AUDIO_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_disconnect(request_id, BT_AUDIO_ALL,
					&address, out_param1);
		break;
	}
	case BT_AG_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_connect(request_id, BT_AUDIO_HSP,
					&address, out_param1);
		break;
	}
	case BT_AG_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_disconnect(request_id, BT_AUDIO_HSP,
					&address, out_param1);
		break;
	}
	case BT_AV_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_connect(request_id, BT_AUDIO_A2DP,
					&address, out_param1);
		break;
	}
	case BT_AV_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_disconnect(request_id, BT_AUDIO_A2DP,
					&address, out_param1);
		break;
	}
	case BT_AVRCP_CONTROL_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_connect(request_id, BT_AVRCP,
					&address, out_param1);
		break;
	}
	case BT_AVRCP_CONTROL_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_audio_disconnect(request_id, BT_AVRCP,
					&address, out_param1);
		break;
	}
	case BT_HF_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_hf_connect(request_id, &address, out_param1);
		break;
	}
	case BT_HF_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_hf_disconnect(request_id, &address, out_param1);
		break;
	}
	case BT_GET_SPEAKER_GAIN: {
		unsigned int volume;

		result = _bt_audio_get_speaker_gain(&volume);

		g_array_append_vals(*out_param1, &volume,
				sizeof(unsigned int));
		break;
	}
	case BT_SET_SPEAKER_GAIN: {
		unsigned int volume;

		volume = g_array_index(in_param1,
				unsigned int, 0);

		result = _bt_audio_set_speaker_gain(volume);

		break;
	}
	case BT_SET_CONTENT_PROTECT: {
		gboolean status;

		status = g_array_index(in_param1, gboolean, 0);

		result = _bt_audio_set_content_protect(status);

		break;
	}
	case BT_OOB_READ_LOCAL_DATA: {
		bt_oob_data_t local_oob_data;

		memset(&local_oob_data, 0x00, sizeof(bt_oob_data_t));
		result = _bt_oob_read_local_data(&local_oob_data);

		g_array_append_vals(*out_param1, &local_oob_data,
				sizeof(bt_oob_data_t));

		break;
	}
	case BT_OOB_ADD_REMOTE_DATA: {
		bluetooth_device_address_t address = { {0} };
		bt_oob_data_t local_oob_data;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		local_oob_data = g_array_index(in_param2,
				bt_oob_data_t, 0);

		result = _bt_oob_add_remote_data(&address, &local_oob_data);

		break;
	}
	case BT_OOB_REMOVE_REMOTE_DATA: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_oob_remove_remote_data(&address);

		break;
	}
	case BT_AVRCP_SET_TRACK_INFO: {
		media_metadata_t data;
		media_metadata_attributes_t meta_data;

		memset(&data, 0x00, sizeof(media_metadata_t));
		memset(&meta_data, 0x00, sizeof(media_metadata_attributes_t));

		data = g_array_index(in_param1,
				media_metadata_t, 0);

		meta_data.title = g_strdup(data.title);
		meta_data.artist = g_strdup(data.artist);
		meta_data.album = g_strdup(data.album);
		meta_data.genre = g_strdup(data.genre);
		meta_data.total_tracks = data.total_tracks;
		meta_data.number = data.number;
		meta_data.duration = (int64_t) data.duration;

		result = _bt_avrcp_set_track_info(&meta_data);

		g_free((gpointer)meta_data.title);
		g_free((gpointer)meta_data.artist);
		g_free((gpointer)meta_data.album);
		g_free((gpointer)meta_data.genre);

		break;
	}
	case BT_AVRCP_SET_PROPERTY: {
		int type;
		unsigned int value;

		type = g_array_index(in_param1, int, 0);
		value = g_array_index(in_param2, unsigned int, 0);

		result = _bt_avrcp_set_property(type, value);

		break;
	}
	case BT_AVRCP_SET_PROPERTIES: {
		media_player_settings_t properties;

		memset(&properties, 0x00, sizeof(media_player_settings_t));

		properties = g_array_index(in_param1,
				media_player_settings_t, 0);

		result = _bt_avrcp_set_properties(&properties);

		break;
	}
	case BT_AVRCP_HANDLE_CONTROL: {
		int type;

		type = g_array_index(in_param1,
				int, 0);

		result = _bt_avrcp_control_cmd(type);

		break;
	}
	case BT_AVRCP_CONTROL_SET_PROPERTY: {
		int type;
		unsigned int value;

		type = g_array_index(in_param1, int, 0);
		value = g_array_index(in_param2, unsigned int, 0);

		result = _bt_avrcp_control_set_property(type, value);

		break;
	}
	case BT_AVRCP_CONTROL_GET_PROPERTY: {
		int type;
		unsigned int value;

		type = g_array_index(in_param1,
				int, 0);

		result = _bt_avrcp_control_get_property(type, &value);
		g_array_append_vals(*out_param1, &value, sizeof(int));

		break;
	}
	case BT_AVRCP_GET_TRACK_INFO: {
		media_metadata_t meta_data;
		media_metadata_attributes_t metadata;

		memset(&meta_data, 0x00, sizeof(media_metadata_t));
		memset(&metadata, 0x00, sizeof(media_metadata_attributes_t));

		result = _bt_avrcp_control_get_track_info(&metadata);

		if (BLUETOOTH_ERROR_NONE != result)
			break;

		if (_bt_copy_utf8_string(meta_data.title, metadata.title,
							BT_META_DATA_MAX_LEN))
			BT_ERR("Error in copying Title\n");
		if (_bt_copy_utf8_string(meta_data.artist, metadata.artist,
							BT_META_DATA_MAX_LEN))
			BT_ERR("Error in copying Artist\n");
		if (_bt_copy_utf8_string(meta_data.album, metadata.album,
							BT_META_DATA_MAX_LEN))
			BT_ERR("Error in copying Album\n");
		if (_bt_copy_utf8_string(meta_data.genre, metadata.genre,
							BT_META_DATA_MAX_LEN))
			BT_ERR("Error in copying Genre\n");

		if (_bt_utf8_validate(meta_data.title) == FALSE)
			meta_data.title[0] = '\0';

		if (_bt_utf8_validate(meta_data.artist) == FALSE)
			meta_data.artist[0] = '\0';

		if (_bt_utf8_validate(meta_data.album) == FALSE)
			meta_data.album[0] = '\0';

		if (_bt_utf8_validate(meta_data.genre) == FALSE)
			meta_data.genre[0] = '\0';

		meta_data.total_tracks = metadata.total_tracks;
		meta_data.number = metadata.number;
		meta_data.duration = metadata.duration;

		g_free((gpointer)metadata.title);
		g_free((gpointer)metadata.artist);
		g_free((gpointer)metadata.album);
		g_free((gpointer)metadata.genre);

		g_array_append_vals(*out_param1, &meta_data,
					sizeof(media_metadata_t));
		break;
	}
	case BT_RFCOMM_CLIENT_CONNECT: {
#ifdef RFCOMM_DIRECT
		result = BLUETOOTH_ERROR_NONE;
#else
		bluetooth_device_address_t address = { {0} };
		char *input_string;
		int connect_type;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		input_string = &g_array_index(in_param2, char, 0);

		connect_type = g_array_index(in_param3, int, 0);

		if (connect_type == BT_RFCOMM_UUID) {
			result = _bt_rfcomm_connect_using_uuid(request_id,
							&address, input_string);
		} else {
			result = _bt_rfcomm_connect_using_channel(request_id,
							&address, input_string);
		}

		if (result != BLUETOOTH_ERROR_NONE) {
			g_array_append_vals(*out_param1, &address,
					sizeof(bluetooth_device_address_t));
		}
#endif
		break;
	}
	case BT_RFCOMM_CLIENT_CANCEL_CONNECT:
		result = _bt_rfcomm_cancel_connect();
		break;
	case BT_RFCOMM_CLIENT_IS_CONNECTED: {
		gboolean connected = FALSE;
		result = _bt_rfcomm_is_connected(&connected);

		g_array_append_vals(*out_param1, &connected, sizeof(gboolean));
		break;
	}
	case BT_RFCOMM_SOCKET_DISCONNECT: {
#ifdef RFCOMM_DIRECT
		result = BLUETOOTH_ERROR_NONE;
#else
		int socket_fd;

		socket_fd = g_array_index(in_param1, int, 0);

		result = _bt_rfcomm_disconnect(socket_fd);
#endif
		break;
	}
	case BT_RFCOMM_SOCKET_WRITE: {
#ifdef RFCOMM_DIRECT
		result = BLUETOOTH_ERROR_NONE;
#else
		int socket_fd;
		int length;
		char *buffer;

		socket_fd = g_array_index(in_param1, int, 0);
		length = g_array_index(in_param2, int, 0);
		buffer = &g_array_index(in_param3, char, 0);

		result = _bt_rfcomm_write(socket_fd, buffer, length);
#endif
		break;
	}
	case BT_RFCOMM_CREATE_SOCKET: {
#ifdef RFCOMM_DIRECT
		result = BLUETOOTH_ERROR_NONE;
#else
		char *sender;
		char *uuid;
		int socket_fd = -1;

		sender = dbus_g_method_get_sender(context);
		uuid = &g_array_index(in_param1, char, 0);

		result = _bt_rfcomm_create_socket(sender, uuid);

		if (result > 0) {
			socket_fd = result;
			result = BLUETOOTH_ERROR_NONE;
		}

		g_array_append_vals(*out_param1, &socket_fd, sizeof(int));

		g_free(sender);
#endif
		break;
	}
	case BT_RFCOMM_REMOVE_SOCKET: {
#ifdef RFCOMM_DIRECT
		result = BLUETOOTH_ERROR_NONE;
#else
		int socket_fd;

		socket_fd = g_array_index(in_param1, int, 0);

		result = _bt_rfcomm_remove_socket(socket_fd);
#endif
		break;
	}
	case BT_RFCOMM_LISTEN: {
		int socket_fd;
		int pending;
		gboolean is_native;

		socket_fd = g_array_index(in_param1, int, 0);
		pending = g_array_index(in_param2, int, 0);
		is_native = g_array_index(in_param3, gboolean, 0);

		result = _bt_rfcomm_listen(socket_fd, pending, is_native);
		break;
	}
	case BT_RFCOMM_IS_UUID_AVAILABLE: {
		gboolean available = TRUE;
		char *uuid;

		uuid = &g_array_index(in_param1, char, 0);

		result = _bt_rfcomm_is_uuid_available(uuid, &available);

		g_array_append_vals(*out_param1, &available, sizeof(gboolean));
		break;
	}
	case BT_RFCOMM_ACCEPT_CONNECTION: {
		int socket_fd;

		socket_fd = g_array_index(in_param1, int, 0);
		BT_DBG(" socket fd %d", socket_fd);
		result = _bt_rfcomm_accept_connection();
		break;
	}
	case BT_RFCOMM_REJECT_CONNECTION: {
		int socket_fd;

		socket_fd = g_array_index(in_param1, int, 0);
		BT_DBG(" socket fd %d", socket_fd);
		result = _bt_rfcomm_reject_connection();
		break;
	}
	case BT_CONNECT_LE: {
		bluetooth_device_address_t address = { {0} };
		gboolean auto_connect;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		auto_connect = g_array_index(in_param2,
				gboolean, 0);

		result = _bt_connect_le_device(&address, auto_connect);

		break;
	}
	case BT_DISCONNECT_LE: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_disconnect_le_device(&address);

		break;
	}
	case BT_SET_LE_PRIVACY: {
		gboolean set_privacy;

		set_privacy = g_array_index(in_param1, gboolean, 0);

		result = _bt_set_le_privacy(set_privacy);

		break;
	}
	case BT_HDP_CONNECT:
	case BT_HDP_DISCONNECT:
	case BT_HDP_SEND_DATA:

	case BT_GATT_GET_PRIMARY_SERVICES:
	case BT_GATT_DISCOVER_CHARACTERISTICS:
	case BT_GATT_SET_PROPERTY_REQUEST:
	case BT_GATT_READ_CHARACTERISTIC:
	case BT_GATT_DISCOVER_CHARACTERISTICS_DESCRIPTOR:
		/* Just call to check the privilege */
		break;
	default:
		result = BLUETOOTH_ERROR_INTERNAL;
		break;
	}

	return result;
}

static int __bt_obexd_request(int function_name,
		int request_type,
		int request_id,
		DBusGMethodInvocation *context,
		GArray *in_param1,
		GArray *in_param2,
		GArray *in_param3,
		GArray *in_param4,
		GArray **out_param1)
{
	BT_DBG("+");

	int result;

	BT_DBG("function_name : %x", function_name);

	switch (function_name) {
	case BT_OPP_PUSH_FILES: {
		BT_DBG("BT_OPP_PUSH_FILES");
		int i;
		bluetooth_device_address_t address = { {0} };
		bt_file_path_t path;
		char **file_path;
		int file_count;

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		file_count = g_array_index(in_param3, int, 0);

		file_path = g_new0(char *, file_count + 1);

		for (i = 0; i < file_count; i++) {
			path = g_array_index(in_param2,
					bt_file_path_t, i);

			file_path[i] = g_strdup(path.path);
		}
		BT_DBG("_bt_opp_client_push_files");
		result = _bt_opp_client_push_files(request_id, context,
						&address, file_path,
						file_count);

		for (i = 0; i < file_count; i++) {
			g_free(file_path[i]);
		}

		g_free(file_path);

		break;
	}
	case BT_OPP_CANCEL_PUSH: {
		result = _bt_opp_client_cancel_push();

		break;
	}
	case BT_OPP_IS_PUSHING_FILES: {
		gboolean is_sending = FALSE;

		result = _bt_opp_client_is_sending(&is_sending);

		g_array_append_vals(*out_param1, &is_sending,
				sizeof(gboolean));
		break;
	}
	case BT_OBEX_SERVER_ALLOCATE: {
		int app_pid;
		gboolean is_native;
		char *path;
		char *sender;

		sender = dbus_g_method_get_sender(context);
		path = &g_array_index(in_param1, char, 0);
		is_native = g_array_index(in_param2, gboolean, 0);
		app_pid = g_array_index(in_param3, int, 0);

		result = _bt_obex_server_allocate(sender, path, app_pid, is_native);

		g_free(sender);
		break;
	}
	case BT_OBEX_SERVER_DEALLOCATE: {
		int app_pid;
		gboolean is_native;

		is_native = g_array_index(in_param1, gboolean, 0);
		app_pid = g_array_index(in_param2, int, 0);

		result = _bt_obex_server_deallocate(app_pid, is_native);
		break;
	}
	case BT_OBEX_SERVER_IS_ACTIVATED: {
		gboolean is_activated = FALSE;

		result = _bt_obex_server_is_activated(&is_activated);

		g_array_append_vals(*out_param1, &is_activated,
				sizeof(gboolean));

		break;
	}
	case BT_OBEX_SERVER_ACCEPT_CONNECTION: {
		result = _bt_obex_server_accept_connection(request_id);

		break;
	}
	case BT_OBEX_SERVER_REJECT_CONNECTION: {
		result = _bt_obex_server_reject_connection();

		break;
	}
	case BT_OBEX_SERVER_ACCEPT_FILE: {
		char *file_name;

		file_name = &g_array_index(in_param1, char, 0);

		result = _bt_obex_server_accept_authorize(file_name, TRUE);

		break;
	}
	case BT_OBEX_SERVER_REJECT_FILE: {
		result = _bt_obex_server_reject_authorize();

		break;
	}
	case BT_OBEX_SERVER_SET_PATH: {
		gboolean is_native;
		char *destination_path;

		destination_path = &g_array_index(in_param1, char, 0);
		is_native = g_array_index(in_param2, gboolean, 0);

		result = _bt_obex_server_set_destination_path(destination_path,
							is_native);

		break;
	}
	case BT_OBEX_SERVER_SET_ROOT: {
		char *root;

		root = &g_array_index(in_param1, char, 0);

		result = _bt_obex_server_set_root(root);

		break;
	}
	case BT_OBEX_SERVER_CANCEL_TRANSFER: {
		int transfer_id;

		transfer_id = g_array_index(in_param1, int, 0);

		result = _bt_obex_server_cancel_transfer(transfer_id);

		break;
	}
	case BT_OBEX_SERVER_CANCEL_ALL_TRANSFERS: {
		result = _bt_obex_server_cancel_all_transfers();

		break;
	}
	case BT_OBEX_SERVER_IS_RECEIVING: {
		gboolean is_receiving = FALSE;

		result = _bt_obex_server_is_receiving(&is_receiving);

		g_array_append_vals(*out_param1, &is_receiving,
				sizeof(gboolean));
		break;
	}
	case BT_PBAP_CONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_pbap_connect(&address);
		break;
	}
	case BT_PBAP_DISCONNECT: {
		bluetooth_device_address_t address = { {0} };

		address = g_array_index(in_param1,
				bluetooth_device_address_t, 0);

		result = _bt_pbap_disconnect(&address);
		break;
	}
	case BT_PBAP_GET_PHONEBOOK_SIZE: {
		bluetooth_device_address_t address = { {0} };
		bt_pbap_folder_t folder = { 0, };

		address = g_array_index(in_param1, bluetooth_device_address_t, 0);
		folder = g_array_index(in_param2, bt_pbap_folder_t, 0);

		result = _bt_pbap_get_phonebook_size(&address, folder.addressbook,
					folder.folder_type);
		break;
	}
	case BT_PBAP_GET_PHONEBOOK: {
		bluetooth_device_address_t address = { {0} };
		bt_pbap_folder_t folder = { 0, };
		bt_pbap_pull_parameters_t app_param = { 0, };

		address = g_array_index(in_param1, bluetooth_device_address_t, 0);
		folder = g_array_index(in_param2, bt_pbap_folder_t, 0);
		app_param = g_array_index(in_param3, bt_pbap_pull_parameters_t, 0);

		result = _bt_pbap_get_phonebook(&address, folder.addressbook,
				folder.folder_type, &app_param);
		break;
	}
	case BT_PBAP_GET_LIST: {
		bluetooth_device_address_t address = { {0} };
		bt_pbap_folder_t folder = { 0, };
		bt_pbap_list_parameters_t app_param = { 0, };

		address = g_array_index(in_param1, bluetooth_device_address_t, 0);
		folder = g_array_index(in_param2, bt_pbap_folder_t, 0);
		app_param = g_array_index(in_param3, bt_pbap_list_parameters_t, 0);

		result = _bt_pbap_get_list(&address, folder.addressbook,
				folder.folder_type, &app_param);
		break;
	}
	case BT_PBAP_PULL_VCARD: {
		bluetooth_device_address_t address = { {0} };
		bt_pbap_folder_t folder = { 0, };
		bt_pbap_pull_vcard_parameters_t app_param = { 0, };

		address = g_array_index(in_param1, bluetooth_device_address_t, 0);
		folder = g_array_index(in_param2, bt_pbap_folder_t, 0);
		app_param = g_array_index(in_param3, bt_pbap_pull_vcard_parameters_t, 0);

		result = _bt_pbap_pull_vcard(&address, folder.addressbook,
				folder.folder_type, &app_param);
		break;
	}
	case BT_PBAP_PHONEBOOK_SEARCH: {
		bluetooth_device_address_t address = { {0} };
		bt_pbap_folder_t folder = { 0, };
		bt_pbap_search_parameters_t app_param = { 0, };

		address = g_array_index(in_param1, bluetooth_device_address_t, 0);
		folder = g_array_index(in_param2, bt_pbap_folder_t, 0);
		app_param = g_array_index(in_param3, bt_pbap_search_parameters_t, 0);

		result = _bt_pbap_phonebook_search(&address, folder.addressbook,
				folder.folder_type, &app_param);
		break;
	}

	default:
		BT_ERR("Unknown function!");
		result = BLUETOOTH_ERROR_INTERNAL;
		break;
	}

	BT_DBG("-");

	return result;
}

static int __bt_agent_request(int function_name,
		int request_type,
		int request_id,
		DBusGMethodInvocation *context,
		GArray *in_param1,
		GArray *in_param2,
		GArray *in_param3,
		GArray *in_param4,
		GArray **out_param1)
{
	int result;
	switch(function_name) {
	case BT_SET_AUTHORIZATION: {
		int type;
		char *uuid;
		char *path;
		int fd;

		type = g_array_index(in_param1, int, 0);
		uuid = &g_array_index(in_param2, char, 0);
		path = &g_array_index(in_param3, char, 0);
		fd = g_array_index(in_param4, int, 0);
		result = _bt_register_osp_server_in_agent(type, uuid, path, fd);
		break;
	}
	case BT_UNSET_AUTHORIZATION: {
		int type;
		char *uuid;
		type = g_array_index(in_param1, int, 0);
		uuid = &g_array_index(in_param2, char, 0);
		result = _bt_unregister_osp_server_in_agent(type, uuid);
		break;
	}
	default:
		BT_ERR("Unknown function!");
		result = BLUETOOTH_ERROR_INTERNAL;
		break;
	}

	return result;
}

static int __bt_core_request(int function_name,
		int request_type,
		int request_id,
		DBusGMethodInvocation *context,
		GArray *in_param1)
{
	int result;

	switch (function_name) {
	case BT_ENABLE_ADAPTER:
	{
		bt_status_t status;

		status = _bt_adapter_get_status();

		if (status == BT_ACTIVATING) {
			BT_DBG("Enabling in progress");
			result = BLUETOOTH_ERROR_IN_PROGRESS;
		} else if (status == BT_ACTIVATED) {
			BT_DBG("Already enabled");
			result = BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
		} else {
			_bt_adapter_set_status(BT_ACTIVATING);
			_bt_adapter_start_enable_timer();
			result = BLUETOOTH_ERROR_NONE;
		}

		break;
	}
	case BT_DISABLE_ADAPTER:
	{
		bt_status_t status;

		status = _bt_adapter_get_status();
		if (status == BT_DEACTIVATING) {
				BT_DBG("Disabling in progress");
				result = BLUETOOTH_ERROR_IN_PROGRESS;
		}
		else if (status == BT_DEACTIVATED) {
				BT_DBG("Already disabled");
				result = BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
		}
		else
		{
			_bt_adapter_set_status(BT_DEACTIVATING);
			result = BLUETOOTH_ERROR_NONE;
		}

		break;
	}
	case BT_ENABLE_ADAPTER_LE:
	{
		bt_le_status_t le_status;

		le_status = _bt_adapter_get_le_status();
		if (le_status == BT_LE_ACTIVATING) {
			BT_DBG("Enabling in progress");
			result = BLUETOOTH_ERROR_IN_PROGRESS;
		}
		else if (le_status == BT_LE_ACTIVATED) {
			BT_DBG("Already enabled");
			result = BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
		} else {
			_bt_adapter_set_le_status(BT_LE_ACTIVATING);
			_bt_adapter_start_le_enable_timer();
			result = BLUETOOTH_ERROR_NONE;
		}

		break;
	}
	case BT_DISABLE_ADAPTER_LE:
	{
		bt_le_status_t le_status;

		le_status = _bt_adapter_get_le_status();
		if (le_status == BT_LE_DEACTIVATING) {
				BT_DBG("Disabling in progress");
				result = BLUETOOTH_ERROR_IN_PROGRESS;
		}
		else if (le_status == BT_LE_DEACTIVATED) {
				BT_DBG("Already disabled");
				result = BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
		}
		else
		{
			_bt_adapter_set_le_status(BT_LE_DEACTIVATING);
			result = BLUETOOTH_ERROR_NONE;
		}

		break;
	}
	default:
		BT_ERR("Unknown function!");
		result = BLUETOOTH_ERROR_INTERNAL;
		break;
	}

	return result;
}

gboolean __bt_service_check_privilege(int function_name,
					int service_type,
					GArray *in_param5)
{
	const char *cookie;
	int ret_val;
	gboolean result = TRUE;

	cookie = (const char *)&g_array_index(in_param5, char, 0);

	retv_if(cookie == NULL, FALSE);

	switch (function_name) {
	case BT_SET_LOCAL_NAME:
	case BT_START_DISCOVERY:
	case BT_START_CUSTOM_DISCOVERY:
	case BT_CANCEL_DISCOVERY:
	case BT_OOB_ADD_REMOTE_DATA:
	case BT_OOB_REMOVE_REMOTE_DATA:
	case BT_SET_ADVERTISING:
	case BT_SET_CUSTOM_ADVERTISING:
	case BT_START_LE_DISCOVERY:
	case BT_STOP_LE_DISCOVERY:

	case BT_BOND_DEVICE:
	case BT_CANCEL_BONDING:
	case BT_UNBOND_DEVICE:
	case BT_SET_ALIAS:
	case BT_SET_AUTHORIZATION:
	case BT_UNSET_AUTHORIZATION:
	case BT_SEARCH_SERVICE:

	case BT_RFCOMM_CLIENT_CONNECT:
	case BT_RFCOMM_CLIENT_CANCEL_CONNECT:
	case BT_RFCOMM_SOCKET_DISCONNECT:
	case BT_RFCOMM_SOCKET_WRITE:
	case BT_RFCOMM_CREATE_SOCKET:
	case BT_RFCOMM_REMOVE_SOCKET:

	case BT_OPP_PUSH_FILES:
	case BT_OPP_CANCEL_PUSH:

	case BT_OBEX_SERVER_ACCEPT_CONNECTION:
	case BT_OBEX_SERVER_REJECT_CONNECTION:
	case BT_OBEX_SERVER_ACCEPT_FILE:
	case BT_OBEX_SERVER_REJECT_FILE:
	case BT_OBEX_SERVER_SET_PATH:
	case BT_OBEX_SERVER_SET_ROOT:
	case BT_OBEX_SERVER_CANCEL_TRANSFER:
	case BT_OBEX_SERVER_CANCEL_ALL_TRANSFERS:

	case BT_AUDIO_CONNECT:
	case BT_AUDIO_DISCONNECT:
	case BT_AG_CONNECT:
	case BT_AG_DISCONNECT:
	case BT_AV_CONNECT:
	case BT_AV_DISCONNECT:
	case BT_AVRCP_CONTROL_CONNECT:
	case BT_AVRCP_CONTROL_DISCONNECT:
	case BT_HF_CONNECT:
	case BT_HF_DISCONNECT:

	case BT_HID_CONNECT:
	case BT_HID_DISCONNECT:

	case BT_CONNECT_LE:
	case BT_DISCONNECT_LE:

	case BT_SET_ADVERTISING_DATA:
	case BT_SET_SCAN_RESPONSE_DATA:

	case BT_HDP_CONNECT:
	case BT_HDP_DISCONNECT:
	case BT_HDP_SEND_DATA:

	case BT_NETWORK_ACTIVATE:
	case BT_NETWORK_DEACTIVATE:
	case BT_NETWORK_CONNECT:
	case BT_NETWORK_DISCONNECT:
	case BT_NETWORK_SERVER_DISCONNECT:

	case BT_GATT_GET_PRIMARY_SERVICES:
	case BT_GATT_DISCOVER_CHARACTERISTICS:
	case BT_GATT_SET_PROPERTY_REQUEST:
	case BT_GATT_READ_CHARACTERISTIC:
	case BT_GATT_DISCOVER_CHARACTERISTICS_DESCRIPTOR:

		ret_val = security_server_check_privilege_by_cookie(cookie,
						BT_PRIVILEGE_PUBLIC, "w");
		if (ret_val == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
			BT_ERR("[SMACK] Fail to access: %s", BT_PRIVILEGE_PUBLIC);
			result = FALSE;
		}
	break;

	case BT_ENABLE_ADAPTER:
	case BT_DISABLE_ADAPTER:
	case BT_RESET_ADAPTER:
	case BT_RECOVER_ADAPTER:
	case BT_ENABLE_ADAPTER_LE:
	case BT_DISABLE_ADAPTER_LE:
	case BT_SET_CONNECTABLE:
	case BT_SET_DISCOVERABLE_MODE:
	case BT_ADD_WHITE_LIST:
	case BT_REMOVE_WHITE_LIST:
	case BT_CLEAR_WHITE_LIST:
	case BT_SET_MANUFACTURER_DATA:
	case BT_SET_SCAN_PARAMETERS:

	case BT_CANCEL_SEARCH_SERVICE:
	case BT_ENABLE_RSSI:

	case BT_RFCOMM_ACCEPT_CONNECTION:
	case BT_RFCOMM_REJECT_CONNECTION:
	case BT_RFCOMM_LISTEN:

	case BT_AVRCP_SET_TRACK_INFO:
	case BT_AVRCP_SET_PROPERTY:
	case BT_AVRCP_SET_PROPERTIES:
	case BT_AVRCP_HANDLE_CONTROL:
	case BT_AVRCP_CONTROL_SET_PROPERTY:
	case BT_AVRCP_CONTROL_GET_PROPERTY:
	case BT_AVRCP_GET_TRACK_INFO:

	case BT_SET_CONTENT_PROTECT:
	case BT_BOND_DEVICE_BY_TYPE:
	case BT_SET_LE_PRIVACY:
	case BT_LE_CONN_UPDATE:

		ret_val = security_server_check_privilege_by_cookie(cookie,
						BT_PRIVILEGE_PLATFORM, "w");

		if (ret_val == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
			BT_ERR("[SMACK] Fail to access: %s", BT_PRIVILEGE_PLATFORM);
			result = FALSE;
		}
	break;

	case BT_CHECK_ADAPTER:
	case BT_GET_RSSI:

	case BT_GET_LOCAL_NAME:
	case BT_GET_LOCAL_ADDRESS:
	case BT_GET_LOCAL_VERSION:
	case BT_IS_SERVICE_USED:
	case BT_GET_DISCOVERABLE_MODE:
	case BT_GET_DISCOVERABLE_TIME:
	case BT_IS_DISCOVERYING:
	case BT_IS_LE_DISCOVERYING:
	case BT_IS_CONNECTABLE:
	case BT_GET_BONDED_DEVICES:
	case BT_GET_BONDED_DEVICE:
	case BT_IS_DEVICE_CONNECTED:
	case BT_GET_SPEAKER_GAIN:
	case BT_SET_SPEAKER_GAIN:
	case BT_OOB_READ_LOCAL_DATA:
	case BT_RFCOMM_CLIENT_IS_CONNECTED:
	case BT_RFCOMM_IS_UUID_AVAILABLE:
	case BT_GET_ADVERTISING_DATA:
	case BT_GET_SCAN_RESPONSE_DATA:
	case BT_IS_ADVERTISING:

	case BT_OBEX_SERVER_ALLOCATE:
	case BT_OBEX_SERVER_DEALLOCATE:

		/* Non-privilege control */
		break;
	default:
		BT_ERR("Unknown function!");
		result = FALSE;
		break;
	}

	return result;
}

gboolean bt_service_request(
		BtService *service,
		int service_type,
		int service_function,
		int request_type,
		GArray *in_param1,
		GArray *in_param2,
		GArray *in_param3,
		GArray *in_param4,
		GArray *in_param5,
		DBusGMethodInvocation *context)
{
	BT_DBG("+");

	int result;
	int request_id = -1;
	GArray *out_param1 = NULL;
	GArray *out_param2 = NULL;

	out_param1 = g_array_new(FALSE, FALSE, sizeof(gchar));
	out_param2 = g_array_new(FALSE, FALSE, sizeof(gchar));

	if (service_type == BT_CORE_SERVICE) {
		BT_DBG("No need to check privilege from bt-core");
	}
	else if (__bt_service_check_privilege(service_function,
				service_type, in_param5) == FALSE) {
		result = BLUETOOTH_ERROR_PERMISSION_DEINED;
		goto fail;
	}

	if (request_type == BT_ASYNC_REQ
	     || service_function == BT_OBEX_SERVER_ACCEPT_CONNECTION) {
		/* Set the timer */
		request_id = _bt_assign_request_id();
		BT_DBG("Request ID: %d", request_id);

		if (request_id < 0) {
			BT_ERR("Fail to assign the request id");
			result = BLUETOOTH_ERROR_INTERNAL;
			goto fail;
		}
	}

	BT_DBG("SERVICE TYPE %d", service_type);

	switch (service_type) {
	case BT_BLUEZ_SERVICE:
		result = __bt_bluez_request(service_function, request_type,
					request_id, context, in_param1, in_param2,
					in_param3, in_param4, &out_param1);
		break;
	case BT_OBEX_SERVICE:
		result = __bt_obexd_request(service_function, request_type,
					request_id, context, in_param1,
					in_param2, in_param3,
					in_param4, &out_param1);
		break;
	case BT_AGENT_SERVICE:
		result = __bt_agent_request(service_function, request_type,
					request_id, context, in_param1,
					in_param2, in_param3,
					in_param4, &out_param1);
		break;
	case BT_CORE_SERVICE:
		result = __bt_core_request(service_function, request_type,
					request_id, context, in_param1);
		break;
	case BT_CHECK_PRIVILEGE:
		result = BLUETOOTH_ERROR_NONE;
		break;
	default:
		BT_ERR("Unknown service type");
		result = BLUETOOTH_ERROR_INTERNAL;
		goto fail;
	}

	if (result != BLUETOOTH_ERROR_NONE) {
		goto fail;
	}

	g_array_append_vals(out_param2, &result, sizeof(int));

	if ((request_type == BT_ASYNC_REQ ||
		service_function == BT_OBEX_SERVER_ACCEPT_CONNECTION) &&
		service_function != BT_OPP_PUSH_FILES) {
		_bt_insert_request_list(request_id, service_function,
					NULL, context);
	} else {
		/* Return result */
		if (service_type == BT_CHECK_PRIVILEGE ||
			service_function != BT_OPP_PUSH_FILES)
			dbus_g_method_return(context, out_param1, out_param2);
	}

	g_array_free(out_param1, TRUE);
	g_array_free(out_param2, TRUE);

	return TRUE;
fail:
	BT_ERR_C("Request is failed [%s] [%x]", _bt_convert_error_to_string(result), result);
	g_array_append_vals(out_param2, &result, sizeof(int));
	dbus_g_method_return(context, out_param1, out_param2);

	g_array_free(out_param1, TRUE);
	g_array_free(out_param2, TRUE);

	if (request_type == BT_ASYNC_REQ)
		_bt_delete_request_id(request_id);

	BT_DBG("-");

	return FALSE;
}

int _bt_service_register(void)
{
	BtService *bt_service;
	DBusGConnection *conn;
	DBusGProxy *proxy;
	GError *err = NULL;
	guint result = 0;

	conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	proxy = dbus_g_proxy_new_for_name(conn, DBUS_SERVICE_DBUS,
				DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);

	if (proxy == NULL) {
		BT_ERR("proxy is NULL");
		goto fail;
	}

	if (!dbus_g_proxy_call(proxy, "RequestName", &err, G_TYPE_STRING,
			BT_SERVICE_NAME, G_TYPE_UINT, 0, G_TYPE_INVALID,
			G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("RequestName RPC failed[%s]\n", err->message);
			g_error_free(err);
		}
		g_object_unref(proxy);

		goto fail;
	}

	g_object_unref(proxy);

	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		BT_ERR("Failed to get the primary well-known name.\n");
		goto fail;
	}

	bt_service = g_object_new(BT_SERVICE_TYPE, NULL);

	dbus_g_connection_register_g_object(conn, BT_SERVICE_PATH,
					G_OBJECT(bt_service));

	service_object = bt_service;
	bt_service_conn = conn;

	return BLUETOOTH_ERROR_NONE;

fail:
	if (bt_service_conn) {
		dbus_g_connection_unref(bt_service_conn);
		bt_service_conn = NULL;
	}

	return BLUETOOTH_ERROR_INTERNAL;
}

void _bt_service_unregister(void)
{
	if (bt_service_conn) {
		if (service_object) {
			dbus_g_connection_unregister_g_object(bt_service_conn,
						G_OBJECT(service_object));
			g_object_unref(service_object);
			service_object = NULL;
		}

		dbus_g_connection_unref(bt_service_conn);
		bt_service_conn = NULL;
	}
}


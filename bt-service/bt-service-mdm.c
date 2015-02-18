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

#ifdef TIZEN_MDM_ENABLE
#include <syspopup_caller.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-main.h"
#include "bt-service-mdm.h"
#include "bt-service-opp-client.h"
#include "bt-service-obex-server.h"
#include "bt-service-rfcomm-client.h"
#include "bt-service-rfcomm-server.h"
#include "bt-service-adapter.h"
#include "bt-service-device.h"
#include "bt-service-network.h"
#include "bt-service-pbap.h"

policy_receiver_handle mdm_handle;

static int __bt_mdm_is_profile_connected(bluetooth_device_address_t *device_address,
		char *profile_uuid, gboolean *is_connected)
{
	char *object_path = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	DBusGProxy *device_proxy = NULL;
	DBusGProxy *adapter_proxy = NULL;
	DBusGConnection *conn;
	GError *error = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	dbus_bool_t val = FALSE;

	retv_if(device_address == NULL, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(profile_uuid == NULL, BLUETOOTH_ERROR_INVALID_PARAM);
	retv_if(is_connected == NULL, BLUETOOTH_ERROR_INVALID_PARAM);

	*is_connected = FALSE;

	if (g_strcmp0(profile_uuid, RFCOMM_UUID_STR) == 0)
		return _bt_rfcomm_is_device_connected(device_address,
						      is_connected);
	else if (g_strcmp0(profile_uuid, GATT_UUID) == 0)
		return _bt_is_gatt_connected(device_address, is_connected);

	adapter_proxy = _bt_get_adapter_proxy();
	retv_if(adapter_proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	conn = _bt_get_system_gconn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	_bt_convert_addr_type_to_string(address, device_address->addr);

	if (g_strcmp0(profile_uuid, NAP_UUID) == 0) {
		object_path = _bt_get_adapter_path();
		device_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				object_path, BT_NETWORK_SERVER_INTERFACE);
		g_free(object_path);
		if (device_proxy == NULL) {
			BT_DBG("Device don't have this service");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		dbus_g_proxy_call(device_proxy, "GetProperties", NULL,
				G_TYPE_STRING, address,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable",
					G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);
		if (hash != NULL) {
			value = g_hash_table_lookup(hash, "Connected");
			*is_connected = value ? g_value_get_boolean(value) : FALSE;
			g_hash_table_destroy(hash);
		}
	} else if (g_strcmp0(profile_uuid, PANU_UUID) == 0)
		return _bt_is_network_connected(_bt_get_net_conn(),
				device_address->addr, is_connected);
	else {
		object_path = _bt_get_device_object_path(address);
		retv_if(object_path == NULL, BLUETOOTH_ERROR_NOT_PAIRED);

		device_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				object_path, BT_DEVICE_INTERFACE);
		g_free(object_path);
		if (device_proxy == NULL) {
			BT_DBG("Device don't have this service");
			return BLUETOOTH_ERROR_INTERNAL;
		}
		dbus_g_proxy_call(device_proxy, "IsConnectedProfile", &error,
				G_TYPE_STRING, profile_uuid,
				G_TYPE_INVALID,
				G_TYPE_BOOLEAN, &val,
				G_TYPE_INVALID);
		if (error != NULL) {
			BT_ERR("Failed to get properties: %s\n", error->message);
			g_error_free(error);
		}

		*is_connected = val;
	}

	if (device_proxy)
		g_object_unref(device_proxy);

	return BLUETOOTH_ERROR_NONE;
}

static int __bt_mdm_get_connected_profile_address(char *address, char *UUID)
{
	int err;
	int ret = FALSE;
	int i;
	gboolean is_connected = FALSE;
	GArray *device_list = NULL;
	bluetooth_device_info_t info;
	guint size;

	device_list = g_array_new(FALSE, FALSE, sizeof(gchar));

	if (_bt_get_bonded_devices(&device_list)
					!= BLUETOOTH_ERROR_NONE) {
		g_array_free(device_list, TRUE);
		return ret;
	}

	size = (device_list->len) / sizeof(bluetooth_device_info_t);
	BT_DBG("g arrary size : [%d]", size);

	for (i = 0; i < size; i++) {

		info = g_array_index(device_list,
				bluetooth_device_info_t, i);

		if (info.connected == TRUE) {
			BT_DBG("Found Connected device[%s]", info.device_name.name);
			err = __bt_mdm_is_profile_connected(&info.device_address,
				UUID, &is_connected);

			if (err == BLUETOOTH_ERROR_NONE) {
				if (is_connected) {
					BT_DBG("connected device name : %s", info.device_name.name);
					_bt_convert_addr_type_to_string(address, (unsigned char *)info.device_address.addr);
					ret = TRUE;
					break;
				}
			}

		}
	}
	g_array_free(device_list, TRUE);

	return ret;
}

static void __bt_mdm_mode_changed(int mode)
{
	int visible = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;

	BT_DBG("allow mode: %d", mode);

	switch (mode) {
	case MDM_BT_ALLOWED:
		BT_DBG("MDM_BT_ALLOWED");
		/* Nothing to do */
		break;
	case MDM_BT_HANDSFREE_ONLY:
		BT_DBG("MDM_BT_HANDSFREE_ONLY");

		_bt_get_discoverable_mode(&visible);
		ret_if(visible == BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE);

		_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);

		_bt_opp_client_cancel_all_transfers();

		_bt_obex_server_cancel_all_transfers();

		_bt_rfcomm_client_disconnect_all();

		_bt_rfcomm_server_disconnect_all_connection();

		_bt_launch_mdm_popup("MDM_POLICY_DISABLE_BT_HANDSFREE");

		break;
	case MDM_BT_RESTRICTED:
		BT_DBG("MDM_BT_RESTRICTED");

		_bt_launch_mdm_popup("MDM_POLICY_DISABLE_BT");

		/* deactivate BT */
		_bt_disable_adapter();
		break;
	default:
		BT_DBG("Unknown mode");
		break;
	}

	BT_DBG("-");
}

static void __bt_mdm_discoverable_state_changed(int state)
{
	int visible = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;

	BT_DBG("state: %d", state);

	switch (state) {
	case MDM_ALLOWED:
		BT_DBG("MDM_ALLOWED");
		/* Nothing to do */
		break;
	case MDM_RESTRICTED:
		BT_DBG("MDM_RESTRICTED");

		_bt_get_discoverable_mode(&visible);
		ret_if(visible == BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE);

		_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
		break;
	default:
		BT_DBG("Unknown mode");
		break;
	}
}

static void __bt_mdm_limited_discoverable_state_changed(int state)
{
	int visible = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
	int timeout = 0;

	BT_DBG("state: %d", state);

	switch (state) {
	case MDM_ALLOWED:
		BT_DBG("MDM_ALLOWED");
		if (vconf_get_int(BT_FILE_VISIBLE_TIME, &timeout) != 0)
	                BT_ERR("Fail to get the timeout value");
		else {
			if (timeout != -1) {
				BT_DBG("_bt_set_discoverable_mode");
			        if (_bt_set_discoverable_mode(
					BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE,
					timeout) != BLUETOOTH_ERROR_NONE) {
			                if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			                        BT_ERR("Set vconf failed");
			        }
			}
		}

		break;
	case MDM_RESTRICTED:
		BT_DBG("MDM_RESTRICTED");

		_bt_get_discoverable_mode(&visible);
		ret_if(visible == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE);

		_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE,
				0);
		break;
	default:
		BT_DBG("Unknown mode");
		break;
	}
}

static int __bt_mdm_idle_cb(void *data)
{
	int *status = data;
	int mode;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	retv_if(status == NULL, FALSE);

	BT_DBG("policy: %d", *status);

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	switch (*status) {
	case MDM_BT_MODE_CHANGED:
		mode = mdm_get_allow_bluetooth_mode();
		__bt_mdm_mode_changed(mode);
		break;
	case MDM_BT_OUTGOING_CALL_CHANGED:
		BT_DBG("MDM_BT_OUTGOING_CALL_CHANGED");
		break;
	case MDM_BT_A2DP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_A2DP_PROFILE_CHANGED");
#ifdef MDM_PHASE_2
		if (mdm_get_bluetooth_profile_state(BLUETOOTH_A2DP_PROFILE)
			== MDM_RESTRICTED) {
			if (__bt_mdm_get_connected_profile_address(address,
							A2DP_SINK_UUID))
				_bt_disconnect_profile(address, A2DP_SINK_UUID,
								NULL, NULL);
		}
#endif
		break;
	case MDM_BT_AVRCP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_AVRCP_PROFILE_CHANGED");
#ifdef MDM_PHASE_2
		if (mdm_get_bluetooth_profile_state(BLUETOOTH_AVRCP_PROFILE)
			== MDM_RESTRICTED) {
			if (__bt_mdm_get_connected_profile_address(address,
							AVRCP_REMOTE_UUID))
				_bt_disconnect_profile(address, AVRCP_REMOTE_UUID,
								NULL, NULL);
		}
#endif
		break;
	case MDM_BT_BPP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_BPP_PROFILE_CHANGED");
		break;
	case MDM_BT_DUN_PROFILE_CHANGED:
		BT_DBG("MDM_BT_DUN_PROFILE_CHANGED");
		break;
	case MDM_BT_FTP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_FTP_PROFILE_CHANGED");
		break;
	case MDM_BT_HFP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_HFP_PROFILE_CHANGED");
#ifdef MDM_PHASE_2
		if (mdm_get_bluetooth_profile_state(BLUETOOTH_HFP_PROFILE)
			== MDM_RESTRICTED) {
			if (__bt_mdm_get_connected_profile_address(address,
							HFP_HS_UUID))
				_bt_disconnect_profile(address, HFP_HS_UUID,
								NULL, NULL);
		}
#endif
		break;
	case MDM_BT_HSP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_HSP_PROFILE_CHANGED");
#ifdef MDM_PHASE_2
		if (mdm_get_bluetooth_profile_state(BLUETOOTH_HSP_PROFILE)
			== MDM_RESTRICTED) {
			if (__bt_mdm_get_connected_profile_address(address,
							HSP_HS_UUID))
				_bt_disconnect_profile(address, HSP_HS_UUID,
								NULL, NULL);
		}
#endif
		break;
	case MDM_BT_PBAP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_PBAP_PROFILE_CHANGED");
#ifdef MDM_PHASE_2
		if (mdm_get_bluetooth_profile_state(BLUETOOTH_PBAP_PROFILE)
			== MDM_RESTRICTED) {
			if (__bt_mdm_get_connected_profile_address(address,
						OBEX_PSE_UUID)) {
				bluetooth_device_address_t addr;
				_bt_convert_addr_string_to_type(addr.addr,
						address);
				_bt_pbap_disconnect(&addr);
			}
		}
#endif
		break;
	case MDM_BT_SAP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_SAP_PROFILE_CHANGED");
		break;
	case MDM_BT_SPP_PROFILE_CHANGED:
		BT_DBG("MDM_BT_SPP_PROFILE_CHANGED");
		break;
	case MDM_BT_DESKTOP_CONNECTIVITY_STATE_CHANGED:
		BT_DBG("MDM_BT_DESKTOP_CONNECTIVITY_STATE_CHANGED");
		break;
	case MDM_BT_DISCOVERABLE_STATE_CHANGED:
		BT_DBG("MDM_BT_DISCOVERABLE_STATE_CHANGED");
#ifdef MDM_PHASE_2
		mode = mdm_get_bluetooth_discoverable_state();
		__bt_mdm_discoverable_state_changed(mode);
#endif
		break;
	case MDM_BT_PARINIG_STATE_CHANGED:
		BT_DBG("MDM_BT_PARINIG_STATE_CHANGED");
		break;
	case MDM_BT_LIMITED_DISCOVERABLE_STATE_CHANGED:
		BT_DBG("MDM_BT_LIMITED_DISCOVERABLE_STATE_CHANGED");
#ifdef MDM_PHASE_2
		mode = mdm_get_bluetooth_limited_discoverable_state();
		__bt_mdm_limited_discoverable_state_changed(mode);
#endif
		break;
	case MDM_BT_DATA_TRANSFER_CHANGED:
		BT_DBG("MDM_BT_DATA_TRANSFER_CHANGED");
#ifdef MDM_PHASE_2
		mode = mdm_get_bluetooth_data_transfer_state();
		if (mode == MDM_RESTRICTED) {
			_bt_opp_client_cancel_all_transfers();
			_bt_obex_server_cancel_all_transfers();
		}
#endif
		break;
	default:
		BT_DBG("Unknown mode");
		break;
	}

	g_free(status);

	mdm_release_service();

	BT_DBG("-");
	return FALSE;
}

static void __bt_mdm_policy_changed_cb(int status, void *data)
{
	int *mdm_status;

	BT_DBG("policy: %d", status);

	mdm_status = g_malloc0(sizeof(int));

	*mdm_status = status;

	g_idle_add((GSourceFunc)__bt_mdm_idle_cb, mdm_status);
}

void _bt_init_mdm_handle(void)
{
	mdm_handle = mdm_register_policy_receiver(MDM_POLICY_ON_BT,
						NULL,
						__bt_mdm_policy_changed_cb);
	if (mdm_handle == (policy_receiver_handle)NULL)
		BT_ERR("MDM register failed\n");
}

void _bt_deinit_mdm_handle(void)
{
	if(mdm_handle != (policy_receiver_handle)NULL) {
		mdm_deregister_policy_receiver(mdm_handle);
		mdm_handle = (policy_receiver_handle)NULL;
	}

	mdm_release_service();
}

int _bt_launch_mdm_popup(char *mode)
{
	int ret = 0;
	bundle *b;

	b = bundle_create();
	retv_if(b == NULL, BLUETOOTH_ERROR_INTERNAL);

	bundle_add(b, "mode", mode);

	ret = syspopup_launch(BT_MDM_SYSPOPUP, b);

	if (ret < 0)
		BT_DBG("Popup launch failed: %d\n", ret);

	bundle_free(b);

	return ret;
}

bt_mdm_status_e _bt_check_mdm_allow_restriction(void)
{
	mdm_bt_allow_t mode;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	mode = mdm_get_allow_bluetooth_mode();
	mdm_release_service();

	return (mode == MDM_BT_RESTRICTED) ? BT_MDM_RESTRICTED : BT_MDM_ALLOWED;
}

#ifdef MDM_PHASE_2
bt_mdm_status_e _bt_check_mdm_desktop_connectivity_restriction(void)
{
       bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

       if (mdm_get_service() != MDM_RESULT_SUCCESS)
               return BT_MDM_NO_SERVICE;

       if (mdm_get_bluetooth_desktop_connectivity_state() == MDM_RESTRICTED) {
               /* Not allow to visible on */
               BT_ERR("Desktop connection is restricted");
               mdm_status = BT_MDM_RESTRICTED;
       }
       mdm_release_service();

       return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_visible_restriction(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_discoverable_state() == MDM_RESTRICTED ||
	     mdm_get_allow_bluetooth_mode() == MDM_BT_HANDSFREE_ONLY) {
		/* Not allow to visible on */
		BT_ERR("Restricted to set visible mode");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_limited_discoverable_mode(void)
{
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	if (mdm_get_bluetooth_limited_discoverable_state() == MDM_RESTRICTED) {
		BT_ERR("limited discoverable mode");
		mdm_status = BT_MDM_RESTRICTED;
	}
	mdm_release_service();

	return mdm_status;
}

bt_mdm_status_e _bt_check_mdm_blacklist_devices(bluetooth_device_address_t *address)
{
	mdm_data_t *lp_data;
	GList *blacklist;
	char *device_name;
	bluetooth_device_info_t dev_info;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	memset(&dev_info, 0x00, sizeof(bluetooth_device_info_t));

	if (_bt_get_bonded_device_info(address,
				&dev_info) != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Not paired device");
		goto release;
	}

	lp_data = mdm_get_bluetooth_devices_from_blacklist();
	if (lp_data == NULL) {
		BT_ERR("No blacklist");
		goto release;
	}

	for (blacklist = (GList *)lp_data->data; blacklist; blacklist = blacklist->next) {
		device_name = blacklist->data;

		DBG_SECURE("blacklist name: %s", device_name);

		if (g_strcmp0(dev_info.device_name.name,
					device_name) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	mdm_free_data(lp_data);
release :
	mdm_release_service();
	return mdm_status;
}

mdm_bt_profile_t convert_uuid_string_to_type(const char* uuid)
{
	retv_if (uuid == NULL, MDM_BT_PROFILE_NONE);

	if (!strcasecmp(uuid, BT_A2DP_UUID))
		return BLUETOOTH_A2DP_PROFILE;
	else if (!strcasecmp(uuid, BT_AVRCP_TARGET_UUID))
		return BLUETOOTH_AVRCP_PROFILE;
	else if (!strcasecmp(uuid, BT_FTP_UUID))
		return BLUETOOTH_FTP_PROFILE;
	else if (!strcasecmp(uuid, BT_HFP_AUDIO_GATEWAY_UUID))
		return BLUETOOTH_HFP_PROFILE;
	else if (!strcasecmp(uuid, HSP_AG_UUID))
		return BLUETOOTH_HSP_PROFILE;
	else if (!strcasecmp(uuid, OBEX_PSE_UUID))
		return BLUETOOTH_PBAP_PROFILE;
	else if (!strcasecmp(uuid, BT_SPP_UUID))
		return BLUETOOTH_SPP_PROFILE;

	return MDM_BT_PROFILE_NONE;
}

bt_mdm_status_e _bt_check_mdm_blacklist_uuid(char *uuid)
{
	mdm_data_t *lp_data;
	GList *blacklist;
	char *blacklist_uuid;
	bt_mdm_status_e mdm_status = BT_MDM_ALLOWED;

	retv_if (uuid == NULL, mdm_status);

	if (mdm_get_service() != MDM_RESULT_SUCCESS) return BT_MDM_NO_SERVICE;

	lp_data = mdm_get_bluetooth_uuids_from_blacklist();
	if (lp_data == NULL) {
		BT_ERR("No blacklist");
		goto release;
	}

	for (blacklist = (GList *)lp_data->data; blacklist; blacklist = blacklist->next) {
		blacklist_uuid = blacklist->data;

		BT_DBG("blacklist_uuid: %s", blacklist_uuid);

		if (g_strcmp0(blacklist_uuid, uuid) == 0) {
			mdm_status = BT_MDM_RESTRICTED;
			break;
		}
	}

	if (mdm_status == BT_MDM_ALLOWED) {
		mdm_bt_profile_t profile;
		profile = convert_uuid_string_to_type(uuid);
		if (mdm_get_bluetooth_profile_state(profile) == MDM_RESTRICTED) {
			BT_ERR("Restricted UUID");
			mdm_status = BT_MDM_RESTRICTED;
		}
	}

	mdm_free_data(lp_data);

release :
	mdm_release_service();
	return mdm_status;
}
#endif
#endif


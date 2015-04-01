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

#include <stdio.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#if !defined(LIBNOTIFY_SUPPORT) && !defined(LIBNOTIFICATION_SUPPORT)
#include <syspopup_caller.h>
#endif
#include <aul.h>
#include <notification.h>
#ifdef ENABLE_TIZEN_2_4
#include <journal/device.h>
#endif

#include "bt-internal-types.h"
#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-adapter.h"
#include "bt-service-adapter-le.h"


#define BT_ADV_INTERVAL_MIN 20 /* msec */
#define BT_ADV_INTERVAL_MAX 10240
#define BT_ADV_INTERVAL_SPLIT 0.625
#define BT_DEFAULT_ADV_MIN_INTERVAL 500
#define BT_DEFAULT_ADV_MAX_INTERVAL 500
#define BT_ADV_FILTER_POLICY_DEFAULT	0x00
#define BT_ADV_TYPE_DEFAULT	0x00
#define BT_ADV_FILTER_POLICY_ALLOW_SCAN_CONN_WL_ONLY	0x03

typedef struct {
	int adv_inst_max;
	int rpa_offloading;
	int max_filter;
} bt_adapter_le_feature_info_t;

typedef struct {
	char *sender;
	gboolean is_advertising;
} bt_adapter_le_adv_slot_t;

static bluetooth_advertising_params_t adv_params = {
	BT_DEFAULT_ADV_MIN_INTERVAL,
	BT_DEFAULT_ADV_MAX_INTERVAL,
	BT_ADV_FILTER_POLICY_DEFAULT,
	BT_ADV_TYPE_DEFAULT};
static bluetooth_advertising_data_t adv_data = { {0} };
static int adv_data_len;
static bluetooth_scan_resp_data_t resp_data = { {0} };
static int resp_data_len;

static bt_adapter_le_feature_info_t le_feature_info = { 1, 0, 0 };
static bt_adapter_le_adv_slot_t *le_adv_slot = NULL;

void __bt_free_le_adv_slot(void)
{
	int i;

	if (le_adv_slot == NULL)
		return;

	for (i = 0; i < le_feature_info.adv_inst_max; i++) {
		if (le_adv_slot[i].sender)
			g_free(le_adv_slot[i].sender);
	}
	g_free(le_adv_slot);
	le_adv_slot = NULL;
}

int _bt_service_adapter_le_init(void)
{
	le_adv_slot = g_malloc0(sizeof(bt_adapter_le_adv_slot_t) * le_feature_info.adv_inst_max);

	return BLUETOOTH_ERROR_NONE;
}

void _bt_service_adapter_le_deinit(void)
{
	__bt_free_le_adv_slot();
}

gboolean _bt_update_le_feature_support(const char *item, const char *value)
{
	if (item== NULL || value == NULL)
		return FALSE;

	if (g_strcmp0(item, "adv_inst_max") == 0) {
		if (atoi(value) != le_feature_info.adv_inst_max) {
			__bt_free_le_adv_slot();
			le_feature_info.adv_inst_max = atoi(value);
			le_adv_slot = g_malloc0(sizeof(bt_adapter_le_adv_slot_t) * le_feature_info.adv_inst_max);
		}
	} else if (g_strcmp0(item, "rpa_offloading") == 0) {
		le_feature_info.rpa_offloading = atoi(value);
	} else if (g_strcmp0(item, "max_filter") == 0) {
		le_feature_info.max_filter = atoi(value);
	} else {
		BT_DBG("No registered item");
		return FALSE;
	}

	return TRUE;
}

static gboolean __bt_is_factory_test_mode(void)
{
	int mode = 0;
#ifdef ENABLE_TIZEN_2_4
	if (vconf_get_bool(VCONFKEY_BT_DUT_MODE, &mode)) {
		BT_ERR("Get the DUT Mode fail");
		return TRUE;
	}
#endif
	if (mode != FALSE) {
		BT_INFO("DUT Test Mode !!");
		return TRUE;
	}

	return FALSE;
}

int __bt_get_available_adv_slot_id(const char *sender, gboolean use_reserved_slot)
{
	int i;

	if (le_adv_slot == NULL)
		return -1;

	if (use_reserved_slot == TRUE) {
		if (le_feature_info.adv_inst_max > 1)
			return 0;
		else if (le_adv_slot[0].sender == NULL ||
			g_strcmp0(le_adv_slot[0].sender, sender) == 0)
			return 0;
		else
			return -1;
	}

	for (i = 0; i < le_feature_info.adv_inst_max; i++) {
		if (le_adv_slot[i].sender == NULL)
			continue;
		if (g_strcmp0(le_adv_slot[i].sender, sender) == 0)
			return i;
	}

	for (i = 0; i < le_feature_info.adv_inst_max; i++) {
		if (le_adv_slot[i].sender == NULL)
			return i;
	}

	return -1;
}

void __bt_register_adv_slot_owner(const char *sender, int slot_id)
{
	if (le_adv_slot[slot_id].sender == NULL)
		le_adv_slot[slot_id].sender = strdup(sender);
}

void __bt_unregister_adv_slot_owner(int slot_id)
{
	g_free(le_adv_slot[slot_id].sender);
	le_adv_slot[slot_id].sender = NULL;
	le_adv_slot[slot_id].is_advertising = FALSE;
}

const char* _bt_get_adv_slot_owner(int slot_id)
{
	if (le_adv_slot == NULL)
		return NULL;

	return le_adv_slot[slot_id].sender;
}

void _bt_set_advertising_status(int slot_id, gboolean mode)
{
	le_adv_slot[slot_id].is_advertising = mode;
}

gboolean _bt_is_advertising(void)
{
	gboolean status = FALSE;
	int i;

	for (i = 0; i < le_feature_info.adv_inst_max; i++) {
		if (le_adv_slot[i].is_advertising == TRUE)
			status = TRUE;
	}

	return status;
}

void _bt_stop_advertising_by_terminated_process(const char* terminated_name)
{
	int i;

	if (le_adv_slot == NULL)
		return;

	for (i = 0; i < le_feature_info.adv_inst_max; i++) {
		if (le_adv_slot[i].sender != NULL) {
			if (strcasecmp(terminated_name, le_adv_slot[i].sender) == 0) {
				BT_ERR("Stop advertising by terminated process(%s).", terminated_name);
				_bt_set_advertising(FALSE, terminated_name, FALSE);
			}
		}
	}
}

gboolean _bt_get_advertising_params(bluetooth_advertising_params_t *params)
{
	if (params == NULL)
		return FALSE;

	memcpy(params, &adv_params, sizeof(bluetooth_advertising_params_t));

	return TRUE;
}

int _bt_set_advertising(gboolean enable, const char *sender, gboolean use_reserved_slot)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	int slot_id;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to start advertising in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	if (_bt_adapter_get_status() != BT_ACTIVATED &&
		_bt_adapter_get_le_status() != BT_LE_ACTIVATED) {
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	slot_id = __bt_get_available_adv_slot_id(sender, use_reserved_slot);
	if (slot_id == -1) {
		BT_ERR("There is NO available slot!!");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	if (le_adv_slot[slot_id].is_advertising == TRUE && enable == TRUE)
		return BLUETOOTH_ERROR_IN_PROGRESS;

	if (le_adv_slot[slot_id].is_advertising == FALSE && enable == FALSE)
		return BLUETOOTH_ERROR_NOT_IN_OPERATION;

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(proxy, "SetAdvertising", &error,
			G_TYPE_BOOLEAN, enable,
			G_TYPE_INT, slot_id,
			G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("SetAdvertising Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	le_adv_slot[slot_id].is_advertising = enable;

	if (enable == TRUE)
		__bt_register_adv_slot_owner(sender, slot_id);
	else
		__bt_unregister_adv_slot_owner(slot_id);

	BT_INFO("Set advertising [%d]", enable);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_custom_advertising(gboolean enable, bluetooth_advertising_params_t *params,
				const char *sender, gboolean use_reserved_slot)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	guint32 min = 0;
	guint32 max = 0;
	int slot_id;

	BT_CHECK_PARAMETER(params, return);

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to start advertising in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	if (_bt_adapter_get_status() != BT_ACTIVATED &&
		_bt_adapter_get_le_status() != BT_LE_ACTIVATED) {
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (le_adv_slot[slot_id].is_advertising == TRUE && enable == TRUE)
		return BLUETOOTH_ERROR_IN_PROGRESS;

	if (le_adv_slot[slot_id].is_advertising == FALSE && enable == FALSE)
		return BLUETOOTH_ERROR_NOT_IN_OPERATION;

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (params->interval_min > params->interval_max ||
			params->interval_min < BT_ADV_INTERVAL_MIN ||
			params->interval_max > BT_ADV_INTERVAL_MAX)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (params->filter_policy > BLUETOOTH_ALLOW_SCAN_CONN_WHITE_LIST)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (params->type  == BLUETOOTH_ADV_CONNECTABLE_DIRECT_HIGH ||
			params->type == BLUETOOTH_ADV_CONNECTABLE_DIRECT_LOW ||
			params->type == BLUETOOTH_ADV_NON_CONNECTABLE)
		return BLUETOOTH_ERROR_NOT_SUPPORT;

	min = params->interval_min / BT_ADV_INTERVAL_SPLIT;
	max = params->interval_max / BT_ADV_INTERVAL_SPLIT;

	slot_id = __bt_get_available_adv_slot_id(sender, use_reserved_slot);
	if (slot_id == -1) {
		BT_ERR("There is NO available slot!!");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	dbus_g_proxy_call(proxy, "SetAdvertisingParameters", &error,
			G_TYPE_UINT, min,
			G_TYPE_UINT, max,
			G_TYPE_UINT, params->filter_policy,
			G_TYPE_UINT, params->type,
			G_TYPE_INT, slot_id,
			G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("SetAdvertisingParameters Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	adv_params.interval_min = params->interval_min;
	adv_params.interval_max = params->interval_max;
	adv_params.filter_policy = params->filter_policy;
	adv_params.type= params->type;

	dbus_g_proxy_call(proxy, "SetAdvertising", &error,
			G_TYPE_BOOLEAN, enable,
			G_TYPE_INT, slot_id,
			G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("SetAdvertising Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	le_adv_slot[slot_id].is_advertising = enable;

	if (enable == TRUE)
		__bt_register_adv_slot_owner(sender, slot_id);
	else
		__bt_unregister_adv_slot_owner(slot_id);

	BT_INFO_C("Set advertising [%d]", enable);
	return BLUETOOTH_ERROR_NONE;
}

static int __bt_get_ad_data_by_type(char *in_data, int in_len,
		char in_type, char **data, int *data_len)
{
	if (in_data == NULL || data == NULL || data_len == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	if (in_len < 0)
		return BLUETOOTH_ERROR_INTERNAL;

	int i;
	int len = 0;
	int type = 0;

	for (i = 0; i < in_len; i++) {
		len = in_data[i];
		if (len <= 0 || i + 1 >= in_len) {
			BT_ERR("Invalid advertising data");
			return BLUETOOTH_ERROR_INTERNAL;
		}

		type = in_data[i + 1];
		if (type == in_type) {
			i = i + 2;
			len--;
			break;
		}

		i += len;
		len = 0;
	}

	if (i + len > in_len) {
		BT_ERR("Invalid advertising data");
		return BLUETOOTH_ERROR_INTERNAL;
	} else if (len == 0) {
		BT_DBG("AD Type 0x%02x data is not set", in_type);
		*data = NULL;
		*data_len = 0;
		return BLUETOOTH_ERROR_NONE;
	}

	*data = g_memdup(&in_data[i], len);
	if (*data == NULL)
		return BLUETOOTH_ERROR_OUT_OF_MEMORY;
	*data_len = len;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_advertising_data(bluetooth_advertising_data_t *adv, int *length)
{
	BT_CHECK_PARAMETER(adv, return);
	BT_CHECK_PARAMETER(length, return);

	memcpy(adv, &adv_data, sizeof(adv_data));
	*length = adv_data_len;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_advertising_data(bluetooth_advertising_data_t *adv, int length,
				const char *sender, gboolean use_reserved_slot)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	GArray *arr;
	int i;
	char *old_mdata = NULL;
	char *new_mdata = NULL;
	int old_len = 0;
	int new_len = 0;
	int slot_id;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to set advertising data in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	BT_CHECK_PARAMETER(adv, return);

	if (_bt_adapter_get_status() != BT_ACTIVATED &&
		_bt_adapter_get_le_status() != BT_LE_ACTIVATED) {
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	arr = g_array_new(TRUE, TRUE, sizeof(guint8));

	for (i = 0; i < length; i++)
		g_array_append_vals(arr, &(adv->data[i]), sizeof(guint8));

	slot_id = __bt_get_available_adv_slot_id(sender, use_reserved_slot);
	if (slot_id == -1) {
		BT_ERR("There is NO available slot!!");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	dbus_g_proxy_call(proxy, "SetAdvertisingData", &error,
			DBUS_TYPE_G_UCHAR_ARRAY, arr,
			G_TYPE_INT, slot_id,
			G_TYPE_INVALID, G_TYPE_INVALID);

	g_array_free(arr, TRUE);

	if (error) {
		BT_ERR("SetAdvertisingData Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__bt_register_adv_slot_owner(sender, slot_id);

	__bt_get_ad_data_by_type((char *)adv_data.data, adv_data_len, 0xff,
			&old_mdata, &old_len);
	__bt_get_ad_data_by_type((char *)adv->data, length, 0xff,
			&new_mdata, &new_len);
	if (old_len != new_len ||
			(old_mdata && new_mdata &&
			 memcmp(old_mdata, new_mdata, new_len))) {
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_ADVERTISING_MANUFACTURER_DATA_CHANGED,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&new_mdata, new_len,
				DBUS_TYPE_INVALID);
	}
	g_free(new_mdata);
	g_free(old_mdata);

	memset(&adv_data, 0x00, sizeof(bluetooth_advertising_data_t));
	memcpy(&adv_data, adv, length);
	adv_data_len = length;

	BT_INFO("Set advertising data");

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_scan_response_data(bluetooth_scan_resp_data_t *response, int *length)
{
	BT_CHECK_PARAMETER(response, return);
	BT_CHECK_PARAMETER(length, return);

	memcpy(response, &resp_data, sizeof(resp_data));
	*length = resp_data_len;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_scan_response_data(bluetooth_scan_resp_data_t *response, int length,
				const char *sender, gboolean use_reserved_slot)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	GArray *arr;
	int i;
	char *old_mdata = NULL;
	char *new_mdata = NULL;
	int old_len = 0;
	int new_len = 0;
	int slot_id;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to set scan response list in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	BT_CHECK_PARAMETER(response, return);

	if (_bt_adapter_get_status() != BT_ACTIVATED &&
		_bt_adapter_get_le_status() != BT_LE_ACTIVATED) {
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	arr = g_array_new(TRUE, TRUE, sizeof(guint8));

	for (i = 0; i < length; i++)
		g_array_append_vals(arr, &(response->data[i]), sizeof(guint8));

	slot_id = __bt_get_available_adv_slot_id(sender, use_reserved_slot);
	if (slot_id == -1) {
		BT_ERR("There is NO available slot!!");
		return BLUETOOTH_ERROR_NO_RESOURCES;
	}

	dbus_g_proxy_call(proxy, "SetScanRespData", &error,
			DBUS_TYPE_G_UCHAR_ARRAY, arr,
			G_TYPE_INT, slot_id,
			G_TYPE_INVALID, G_TYPE_INVALID);

	g_array_free(arr, TRUE);

	if (error) {
		BT_ERR("SetScanRespData Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__bt_register_adv_slot_owner(sender, slot_id);

	/* Compare with previous scan resp data */
	__bt_get_ad_data_by_type((char *)resp_data.data, resp_data_len, 0xff,
			&old_mdata, &old_len);
	__bt_get_ad_data_by_type((char *)response->data, length, 0xff,
			&new_mdata, &new_len);
	if (old_len != new_len ||
			(old_mdata && new_mdata &&
			 memcmp(old_mdata, new_mdata, new_len))) {
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_SCAN_RESPONSE_MANUFACTURER_DATA_CHANGED,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&new_mdata, new_len,
				DBUS_TYPE_INVALID);
	}
	g_free(new_mdata);
	g_free(old_mdata);

	memset(&resp_data, 0x00, sizeof(bluetooth_scan_resp_data_t));
	memcpy(&resp_data, response, length);
	resp_data_len = length;

	BT_INFO("Set scan response data");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_scan_parameters(bluetooth_le_scan_params_t *params)
{
	DBusGProxy *proxy;
	GError *error = NULL;
	guint32 itv = 0;
	guint32 win = 0;

	BT_CHECK_PARAMETER(params, return);

	if (_bt_adapter_get_status() != BT_ACTIVATED &&
		_bt_adapter_get_le_status() != BT_LE_ACTIVATED) {
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (params->interval < BT_LE_SCAN_INTERVAL_MIN || params->interval > BT_LE_SCAN_INTERVAL_MAX)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (params->window < BT_LE_SCAN_WINDOW_MIN || params->window > BT_LE_SCAN_WINDOW_MAX)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	if (params->window > params->interval)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	itv = params->interval / BT_ADV_INTERVAL_SPLIT;
	win = params->window / BT_ADV_INTERVAL_SPLIT;

	dbus_g_proxy_call(proxy, "SetScanParameters", &error,
			G_TYPE_UINT, params->type,
			G_TYPE_UINT, itv,
			G_TYPE_UINT, win,
			G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("SetScanParameters Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	_bt_set_le_discovery_type(params->type);

	BT_INFO("Set scan parameters");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_add_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type)
{
	DBusGProxy *proxy;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	GError *error = NULL;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to add white list in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	BT_CHECK_PARAMETER(device_address, return);

	if (address_type != BLUETOOTH_DEVICE_PUBLIC_ADDRESS &&
		address_type != BLUETOOTH_DEVICE_RANDOM_ADDRESS)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bt_convert_addr_type_to_string(address, device_address->addr);

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(proxy, "AddDeviceWhiteList", &error,
		  G_TYPE_STRING, address,
		  G_TYPE_UINT, address_type,
		  G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("AddDeviceWhiteList Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	BT_INFO("Add white list");

	return BLUETOOTH_ERROR_NONE;
}

int _bt_remove_white_list(bluetooth_device_address_t *device_address, bluetooth_device_address_type_t address_type)
{
	DBusGProxy *proxy;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	GError *error = NULL;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to remove white list in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	BT_CHECK_PARAMETER(device_address, return);

	if (address_type != BLUETOOTH_DEVICE_PUBLIC_ADDRESS &&
		address_type != BLUETOOTH_DEVICE_RANDOM_ADDRESS)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bt_convert_addr_type_to_string(address, device_address->addr);

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(proxy, "RemoveDeviceWhiteList", &error,
		  G_TYPE_STRING, address,
		   G_TYPE_UINT, address_type,
		  G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("RemoveDeviceWhiteList Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	BT_INFO("Remove white list");

	return BLUETOOTH_ERROR_NONE;
}

int _bt_clear_white_list(void)
{
	DBusGProxy *proxy;
	GError *error = NULL;

	if (__bt_is_factory_test_mode()) {
		BT_ERR("Unable to clear white list in factory binary !!");
		return BLUETOOTH_ERROR_NOT_SUPPORT;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(proxy, "ClearDeviceWhiteList", &error,
		  G_TYPE_INVALID, G_TYPE_INVALID);

	if (error) {
		BT_ERR("ClearDeviceWhiteList Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	BT_INFO("Clear white list");

	return BLUETOOTH_ERROR_NONE;
}


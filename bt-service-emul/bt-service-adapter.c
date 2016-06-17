/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <alarm.h>
#include <vconf.h>
#include <bundle.h>
#include <eventsystem.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-adapter.h"
#include "bt-service-util.h"
#include "bt-service-main.h"

typedef struct {
	guint event_id;
	int timeout;
	time_t start_time;
	gboolean alarm_init;
	int alarm_id;
} bt_adapter_timer_t;

bt_adapter_timer_t visible_timer = {0, };

static gboolean is_discovering;
static gboolean cancel_by_user;
static bt_status_t adapter_status = BT_DEACTIVATED;
static bt_le_status_t adapter_le_status = BT_LE_DEACTIVATED;
static guint timer_id = 0;
static guint le_timer_id = 0;

static uint status_reg_id;

static char *g_local_name;
static gboolean g_is_discoverable;

#define BT_DISABLE_TIME 500 /* 500 ms */
#define BT_DEFAULT_NAME "Tizen Emulator"


static gboolean __bt_timeout_handler(gpointer user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	time_t current_time;
	int time_diff;

	/* Take current time */
	time(&current_time);
	time_diff = difftime(current_time, visible_timer.start_time);

	/* Send event to application */
	_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_CHANGED,
			g_variant_new("(in)", result, time_diff));

	if (visible_timer.timeout <= time_diff) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
		visible_timer.timeout = 0;

#ifndef TIZEN_WEARABLE
		if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			BT_ERR("Set vconf failed\n");
#endif
		return FALSE;
	}

	return TRUE;
}

static int __bt_visibility_alarm_cb(alarm_id_t alarm_id, void* user_param)
{
	BT_DBG("__bt_visibility_alarm_cb - alram id = [%d] \n", alarm_id);

	int result = BLUETOOTH_ERROR_NONE;
	int timeout = 0;

	if (alarm_id != visible_timer.alarm_id)
		return 0;

	if (visible_timer.event_id) {
		_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_CHANGED,
				g_variant_new("(in)", result, timeout));
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
		visible_timer.timeout = 0;

#ifndef TIZEN_WEARABLE
		if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			BT_ERR("Set vconf failed\n");
#endif
	}
	/* Switch Off visibility in Bluez */
	_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
	visible_timer.alarm_id = 0;
	return 0;
}

static void __bt_visibility_alarm_create()
{
	alarm_id_t alarm_id;
	int result;

	result = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, visible_timer.timeout,
						0, NULL, &alarm_id);
	if (result < 0) {
		BT_ERR("Failed to create alarm error = %d\n", result);
	} else {
		BT_DBG("Alarm created = %d\n", alarm_id);
		visible_timer.alarm_id = alarm_id;
	}
}

static void __bt_visibility_alarm_remove()
{
	if (visible_timer.event_id > 0) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
	}

	if (visible_timer.alarm_id > 0) {
		alarmmgr_remove_alarm(visible_timer.alarm_id);
		visible_timer.alarm_id = 0;
	}
}

int __bt_set_visible_time(int timeout)
{
	int result;

	__bt_visibility_alarm_remove();

	visible_timer.timeout = timeout;

#ifndef TIZEN_WEARABLE
	if (vconf_set_int(BT_FILE_VISIBLE_TIME, timeout) != 0)
		BT_ERR("Set vconf failed");
#endif

	if (timeout <= 0)
		return BLUETOOTH_ERROR_NONE;

	if (!visible_timer.alarm_init) {
		/* Set Alarm timer to switch off BT */
		result = alarmmgr_init("bt-service");
		if (result != 0)
			return BLUETOOTH_ERROR_INTERNAL;

		visible_timer.alarm_init = TRUE;
	}

	result = alarmmgr_set_cb(__bt_visibility_alarm_cb, NULL);
	if (result != 0)
		return BLUETOOTH_ERROR_INTERNAL;

	/* Take start time */
	time(&(visible_timer.start_time));
	visible_timer.event_id = g_timeout_add_seconds(1,
				__bt_timeout_handler, NULL);

	__bt_visibility_alarm_create();

	return BLUETOOTH_ERROR_NONE;
}

void _bt_set_discovery_status(gboolean mode)
{
	is_discovering = mode;
}

void _bt_set_cancel_by_user(gboolean value)
{
	cancel_by_user = value;
}

gboolean _bt_get_cancel_by_user(void)
{
	return cancel_by_user;
}

void _bt_adapter_set_status(bt_status_t status)
{
	BT_INFO("adapter_status changed [%d] -> [%d]", adapter_status, status);
	adapter_status = status;
}

bt_status_t _bt_adapter_get_status(void)
{
	return adapter_status;
}

void _bt_adapter_set_le_status(bt_le_status_t status)
{
	BT_INFO("adapter_le_status changed [%d] -> [%d]", adapter_le_status, status);
	adapter_le_status = status;
}

bt_le_status_t _bt_adapter_get_le_status(void)
{
	return adapter_le_status;
}

static void __bt_phone_name_changed_cb(keynode_t *node, void *data)
{
	char *phone_name = NULL;
	char *ptr = NULL;

	if (node == NULL)
		return;

	if (vconf_keynode_get_type(node) == VCONF_TYPE_STRING) {
		phone_name = vconf_keynode_get_str(node);

		if (phone_name && strlen(phone_name) != 0) {
                        if (!g_utf8_validate(phone_name, -1,
							(const char **)&ptr))
                                *ptr = '\0';

			_bt_set_local_name(phone_name);
		}
	}
}

#ifdef TIZEN_MOBILE
static void __bt_set_visible_mode(void)
{
	int timeout = 0;

	if (vconf_get_int(BT_FILE_VISIBLE_TIME, &timeout) != 0)
                BT_ERR("Fail to get the timeout value");

	if (timeout == -1) {
		if (_bt_set_discoverable_mode(
			BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE,
			timeout) != BLUETOOTH_ERROR_NONE) {
			if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
				BT_ERR("Set vconf failed");
		}
	} else {
		if (_bt_set_discoverable_mode(
			BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE,
			timeout) != BLUETOOTH_ERROR_NONE) {
				BT_ERR("Set connectable mode failed");
		}
	}
}
#endif

static void __bt_set_local_name(void)
{
	char *phone_name = NULL;
	char *ptr = NULL;

	phone_name = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);

	if (!phone_name)
		return;

	if (strlen(phone_name) != 0) {
		if (!g_utf8_validate(phone_name, -1, (const char **)&ptr))
			*ptr = '\0';

		_bt_set_local_name(phone_name);
	}
	free(phone_name);
}

static int __bt_set_enabled(void)
{
	BT_DBG("+");
	int result = BLUETOOTH_ERROR_NONE;

#ifdef TIZEN_MOBILE
	__bt_set_visible_mode();
#else
#ifdef TIZEN_TV
	if (_bt_set_discoverable_mode(
		BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE, 0) != BLUETOOTH_ERROR_NONE)
			BT_ERR("Fail to set discoverable mode");
#endif
#endif
	__bt_set_local_name();

	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_ON) != 0)
		BT_ERR("Set vconf failed\n");

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		BT_ERR("Set vconf failed\n");
#if 0
	if (_bt_eventsystem_set_value(SYS_EVENT_BT_STATE, EVT_KEY_BT_STATE,
						EVT_VAL_BT_ON) != ES_R_OK)
		BT_ERR("Fail to set value");
#endif

	/* Send enabled event to API */
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_ENABLED,
				g_variant_new("(i)", result));
	BT_DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

void _bt_set_disabled(int result)
{
	int power_off_status = 0;
	int ret;
	int ret_pm_ignore;
	int pm_ignore_mode = 0;

	ret = vconf_get_int(VCONFKEY_SYSMAN_POWER_OFF_STATUS, &power_off_status);
	BT_DBG("ret : %d, power_off_status : %d", ret, power_off_status);

	ret_pm_ignore = vconf_get_int(VCONFKEY_PM_KEY_IGNORE, &pm_ignore_mode);

	/* Update the vconf BT status in normal Deactivation case only */
	if (ret == 0 && power_off_status == VCONFKEY_SYSMAN_POWER_OFF_NONE &&
		ret_pm_ignore == 0 && pm_ignore_mode != VCONFKEY_PM_KEY_LOCK) {

		BT_DBG("Update vconf for BT normal Deactivation");

		if (result == BLUETOOTH_ERROR_TIMEOUT)
			if (vconf_set_int(BT_OFF_DUE_TO_TIMEOUT, 1) != 0)
				BT_ERR("Set vconf failed");

		/* Update Bluetooth Status to notify other modules */
		if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_OFF) != 0)
			BT_ERR("Set vconf failed");

		if (_bt_eventsystem_set_value(SYS_EVENT_BT_STATE, EVT_KEY_BT_STATE,
							EVT_VAL_BT_OFF) != ES_R_OK)
			BT_ERR("Fail to set value");
	}

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		BT_ERR("Set vconf failed\n");

	_bt_adapter_set_status(BT_DEACTIVATED);

	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_DISABLED,
			g_variant_new("(i)", result));

	BT_INFO("Adapter disabled");
}

static int __bt_set_le_enabled(void)
{
	BT_DBG("+");
	int result = BLUETOOTH_ERROR_NONE;
	bt_status_t status;

	__bt_set_local_name();

	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_LE_STATUS, VCONFKEY_BT_LE_STATUS_ON) != 0)
		BT_ERR("Set vconf failed\n");

	if (_bt_eventsystem_set_value(SYS_EVENT_BT_STATE, EVT_KEY_BT_LE_STATE,
						EVT_VAL_BT_LE_ON) != ES_R_OK)
		BT_ERR("Fail to set value");

	/* Send enabled event to API */
	/*
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_ENABLED,
				DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);
	*/
	status = _bt_adapter_get_status();
	if (status == BT_DEACTIVATED) {
		BT_INFO("BREDR is off, turn off PSCAN");
		_bt_set_connectable(FALSE);
	}
	if (le_timer_id > 0) {
		g_source_remove(le_timer_id);
		le_timer_id = 0;
	}

	/* Send enabled event to API */
	_bt_send_event(BT_LE_ADAPTER_EVENT, BLUETOOTH_EVENT_LE_ENABLED,
				g_variant_new("(i)", result));

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

void _bt_set_le_disabled(int result)
{
	int power_off_status;
	int ret;

	ret = vconf_get_int(VCONFKEY_SYSMAN_POWER_OFF_STATUS, &power_off_status);
	BT_DBG("ret : %d", ret);
	BT_DBG("power_off_status : %d", power_off_status);

	/* Update Bluetooth Status to notify other modules */
	BT_DBG("Update vconf for BT LE normal Deactivation");
	if (vconf_set_int(VCONFKEY_BT_LE_STATUS, VCONFKEY_BT_LE_STATUS_OFF) != 0)
		BT_ERR("Set vconf failed\n");
	_bt_adapter_set_le_status(BT_LE_DEACTIVATED);

	if (_bt_eventsystem_set_value(SYS_EVENT_BT_STATE, EVT_KEY_BT_LE_STATE,
						EVT_VAL_BT_LE_OFF) != ES_R_OK)
		BT_ERR("Fail to set value");

	/* Send disabled event */
	_bt_send_event(BT_LE_ADAPTER_EVENT, BLUETOOTH_EVENT_LE_DISABLED,
			g_variant_new_int32(result));
}

#if defined(TIZEN_BT_FLIGHTMODE_ENABLED) || (!defined(TIZEN_WEARABLE) && defined(ENABLE_TIZEN_2_4))
static void __bt_service_flight_ps_mode_cb(keynode_t *node, void *data)
{
	gboolean flight_mode = FALSE;
	int power_saving_mode = 0;
	int type;

	DBG_SECURE("key=%s", vconf_keynode_get_name(node));
	type = vconf_keynode_get_type(node);
	if (type == VCONF_TYPE_BOOL) {
		flight_mode = vconf_keynode_get_bool(node);
		if (flight_mode != TRUE) {
			BT_ERR("Ignore the event");
			return;
		}
	} else if (type == VCONF_TYPE_INT) {
		power_saving_mode = vconf_keynode_get_int(node);
		if (power_saving_mode != 2) {
			BT_ERR("Ignore the event");
			return;
		}
	} else {
		BT_ERR("Invaild vconf key type : %d", type);
		return;
	}
}
#endif

void _bt_service_register_vconf_handler(void)
{
	BT_DBG("+");

#ifdef TIZEN_BT_FLIGHTMODE_ENABLED
	if (vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			(vconf_callback_fn)__bt_service_flight_ps_mode_cb, NULL) < 0)
		BT_ERR("Unable to register key handler");
#else
	BT_DBG("Telephony is disabled");
#endif

#ifndef TIZEN_WEARABLE
#ifdef ENABLE_TIZEN_2_4
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_PSMODE,
			(vconf_callback_fn)__bt_service_flight_ps_mode_cb, NULL) < 0)
		BT_ERR("Unable to register key handler");
#endif
#endif
}

void _bt_service_unregister_vconf_handler(void)
{
	BT_DBG("+");

#ifdef TIZEN_BT_FLIGHTMODE_ENABLED
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			(vconf_callback_fn)__bt_service_flight_ps_mode_cb);
#endif

#ifndef TIZEN_WEARABLE
#ifdef ENABLE_TIZEN_2_4
	vconf_ignore_key_changed(VCONFKEY_SETAPPL_PSMODE,
			(vconf_callback_fn)__bt_service_flight_ps_mode_cb);
#endif
#endif
}

static void __bt_state_event_handler(const char *event_name, bundle *data, void *user_data)
{
#ifdef ENABLE_TIZEN_2_4
	const char *bt_status = NULL;
	const char *bt_le_status = NULL;
	BT_DBG("bt state set event(%s) received", event_name);
	bt_status = bundle_get_val(data, EVT_KEY_BT_STATE);
	BT_DBG("bt_state: (%s)", bt_status);

	bt_le_status = bundle_get_val(data, EVT_KEY_BT_LE_STATE);
	BT_DBG("bt_state: (%s)", bt_le_status);
#endif
}

void _bt_handle_adapter_added(void)
{
	BT_DBG("+");
	bt_status_t status;
	bt_le_status_t le_status;
	int ret;

	if (timer_id > 0) {
		BT_DBG("g_source is removed");
		g_source_remove(timer_id);
		timer_id = 0;
	}

	status = _bt_adapter_get_status();
	le_status = _bt_adapter_get_le_status();
	BT_DBG("status : %d", status);
	BT_DBG("le_status : %d", le_status);

	/* add the vconf noti handler */
	ret = vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
					__bt_phone_name_changed_cb, NULL);
	if (ret < 0)
		BT_ERR("Unable to register key handler");

	if (le_status == BT_LE_ACTIVATING ||
		 status == BT_ACTIVATING) {
		__bt_set_le_enabled();
		_bt_adapter_set_le_status(BT_LE_ACTIVATED);
	}

	if (status == BT_ACTIVATING) {
		__bt_set_enabled();
		_bt_adapter_set_status(BT_ACTIVATED);
	}
#ifdef ENABLE_TIZEN_2_4
	journal_bt_on();
#endif

	_bt_service_register_vconf_handler();

	/* eventsystem */
	if (eventsystem_register_event(SYS_EVENT_BT_STATE, &status_reg_id,
			(eventsystem_handler)__bt_state_event_handler, NULL) != ES_R_OK) {
		BT_ERR("Fail to register system event");
	}
}

void _bt_handle_adapter_removed(void)
{
	int ret;

	_bt_adapter_set_status(BT_DEACTIVATED);
#ifdef ENABLE_TIZEN_2_4
	journal_bt_off();
#endif

	__bt_visibility_alarm_remove();

	if (visible_timer.alarm_init) {
		alarmmgr_fini();
		visible_timer.alarm_init = FALSE;
	}

	ret = vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
				(vconf_callback_fn)__bt_phone_name_changed_cb);
	if (0 != ret) {
		BT_ERR("vconf_ignore_key_changed failed\n");
	}

	_bt_reliable_terminate_service(NULL);

	if (eventsystem_unregister_event(status_reg_id) != ES_R_OK) {
		BT_ERR("Fail to unregister system event");
	}

}

static gboolean __bt_enable_timeout_cb(gpointer user_data)
{
	timer_id = 0;

	retv_if(_bt_adapter_get_status() == BT_ACTIVATED, FALSE);

	BT_ERR("EnableAdapter is failed");

	_bt_set_disabled(BLUETOOTH_ERROR_TIMEOUT);

	_bt_terminate_service(NULL);

	return FALSE;
}

static gboolean __bt_enable_le_timeout_cb(gpointer user_data)
{
	le_timer_id = 0;

	retv_if(_bt_adapter_get_le_status() == BT_LE_ACTIVATED, FALSE);

	BT_ERR("EnableAdapterLE is failed");

	_bt_adapter_set_le_status(BT_LE_DEACTIVATED);

	_bt_set_le_disabled(BLUETOOTH_ERROR_TIMEOUT);

	if (_bt_adapter_get_status() == BT_DEACTIVATED)
		_bt_terminate_service(NULL);

	return FALSE;
}

void _bt_adapter_start_le_enable_timer(void)
{
	if (le_timer_id > 0) {
		g_source_remove(le_timer_id);
		le_timer_id = 0;
	}

	le_timer_id = g_timeout_add(BT_ENABLE_TIMEOUT,
			__bt_enable_le_timeout_cb, NULL);

	return;
}

void _bt_adapter_start_enable_timer(void)
{
	if (timer_id > 0) {
		g_source_remove(timer_id);
		timer_id = 0;
	}

	timer_id = g_timeout_add(BT_ENABLE_TIMEOUT,
			__bt_enable_timeout_cb, NULL);

	return;
}

int _bt_enable_adapter(void)
{
	bt_status_t status = _bt_adapter_get_status();
	bt_le_status_t le_status = _bt_adapter_get_le_status();

	BT_DBG("");

	if (status == BT_ACTIVATING) {
		BT_ERR("Enabling in progress");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (status == BT_ACTIVATED) {
		BT_ERR("Already enabled");
		return BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
	}

	if (status == BT_DEACTIVATING || le_status == BT_LE_DEACTIVATING) {
		BT_ERR("Disabling in progress");
		return BLUETOOTH_ERROR_DEVICE_BUSY;
	}

	_bt_adapter_set_status(BT_ADAPTER_ENABLED);

	__bt_set_enabled();

	return BLUETOOTH_ERROR_NONE;
}

int _bt_disable_adapter(void)
{
	BT_DBG("+");

	if (_bt_adapter_get_status() == BT_DEACTIVATING) {
		BT_DBG("Disabling in progress");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (_bt_adapter_get_status() == BT_DEACTIVATED) {
		BT_DBG("Already disabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (timer_id > 0) {
		g_source_remove(timer_id);
		timer_id = 0;
	}

	_bt_handle_adapter_removed();

	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_recover_adapter(void)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_reset_adapter(void)
{
	if (timer_id > 0) {
		g_source_remove(timer_id);
		timer_id = 0;
	}

	_bt_set_disabled(BLUETOOTH_ERROR_NONE);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_check_adapter(int *status)
{

	BT_CHECK_PARAMETER(status, return);

	*status = adapter_status;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_enable_adapter_le(void)
{
	BT_DBG("+");
	bt_status_t status = _bt_adapter_get_status();
	bt_le_status_t le_status = _bt_adapter_get_le_status();

	if (le_status == BT_LE_ACTIVATING) {
		BT_ERR("Enabling in progress");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (le_status == BT_LE_ACTIVATED) {
		BT_ERR("Already enabled");
		return BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
	}

	if (status == BT_DEACTIVATING || le_status == BT_LE_DEACTIVATING) {
		BT_ERR("Disabling in progress");
		return BLUETOOTH_ERROR_DEVICE_BUSY;
	}

	__bt_set_le_enabled();

	BT_DBG("le status : %d", _bt_adapter_get_le_status());
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_disable_adapter_le(void)
{
	BT_DBG("+");
	bt_le_status_t bt_le_state;

	bt_le_state = _bt_adapter_get_le_status();
	if (bt_le_state == BT_LE_DEACTIVATING) {
		BT_DBG("Disabling in progress");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (bt_le_state == BT_LE_DEACTIVATED) {
		BT_DBG("Already disabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	_bt_set_le_disabled(BLUETOOTH_ERROR_NONE);

	BT_DBG("le status : %d", _bt_adapter_get_le_status());
	BT_DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_local_address(bluetooth_device_address_t *local_address)
{
	const char *address = "11:22:33:44:55:66";

	BT_CHECK_PARAMETER(local_address, return);

	BT_DBG("Address:%s", address);

	_bt_convert_addr_string_to_type(local_address->addr, address);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_local_version(bluetooth_version_t *local_version)
{
	const char *ver = "Tizen BT emul v0.1";

	BT_CHECK_PARAMETER(local_version, return);

	g_strlcpy(local_version->version, ver, BLUETOOTH_VERSION_LENGTH_MAX + 1);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_local_name(bluetooth_device_name_t *local_name)
{
	BT_CHECK_PARAMETER(local_name, return);

	if (g_local_name != NULL)
		g_local_name = g_strdup(BT_DEFAULT_NAME);

	g_strlcpy(local_name->name, g_local_name, BLUETOOTH_DEVICE_NAME_LENGTH_MAX + 1);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_local_name(char *local_name)
{
	BT_CHECK_PARAMETER(local_name, return);

	g_free(g_local_name);
	g_local_name = g_strdup(local_name);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_is_service_used(char *service_uuid, gboolean *used)
{
	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_PARAMETER(used, return);

	*used = FALSE;

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_discoverable_mode(int *mode)
{
	BT_CHECK_PARAMETER(mode, return);

	if (g_is_discoverable == TRUE) {
		if (visible_timer.timeout == 0)
			*mode = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
		else
			*mode = BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
	} else {
		*mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
	}
	return BLUETOOTH_ERROR_NONE;
}


int _bt_set_discoverable_mode(int discoverable_mode, int timeout)
{
	int ret = BLUETOOTH_ERROR_NONE;

	switch (discoverable_mode) {
	case BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE:
		g_is_discoverable = FALSE;
		timeout = 0;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE:
		timeout = 0;
		g_is_discoverable = TRUE;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE:
		g_is_discoverable = TRUE;
		break;
	default:
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	BT_INFO("Req. discoverable_mode : %d, timeout : %d",
			discoverable_mode, timeout);

	if (discoverable_mode == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE)
		timeout = -1;

	ret = __bt_set_visible_time(timeout);

	return ret;
}

int _bt_start_discovery(void)
{
	return _bt_start_custom_discovery(DISCOVERY_ROLE_LE_BREDR);
}

int _bt_start_custom_discovery(bt_discovery_role_type_t role)
{
	is_discovering = TRUE;
	cancel_by_user = FALSE;

	/* Need to implement the timer and event for this API */

	return BLUETOOTH_ERROR_NONE;

}

int _bt_cancel_discovery(void)
{
	is_discovering = FALSE;
	cancel_by_user = TRUE;

	/* Need to implement the event for this API */

	return BLUETOOTH_ERROR_NONE;
}

gboolean _bt_is_discovering(void)
{
	return is_discovering;
}

gboolean _bt_is_connectable(void)
{
	return FALSE;
}

int _bt_set_connectable(gboolean is_connectable)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_get_bonded_devices(GArray **dev_list)
{
	/* Should implement this */

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_bonded_device_info(bluetooth_device_address_t *device_address,
				bluetooth_device_info_t *dev_info)
{
	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_PARAMETER(dev_info, return);
	
	/* Should implement this */

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_timeout_value(int *timeout)
{
	time_t current_time;
	int time_diff;

	/* Take current time */
	time(&current_time);
	time_diff = difftime(current_time, visible_timer.start_time);

	BT_DBG("Time diff = %d\n", time_diff);

	*timeout = visible_timer.timeout - time_diff;

	return BLUETOOTH_ERROR_NONE;
}

int _bt_set_le_privacy(gboolean set_privacy)
{
	return BLUETOOTH_ERROR_NOT_SUPPORT;
}

int _bt_set_manufacturer_data(bluetooth_manufacturer_data_t *m_data)
{
	BT_CHECK_PARAMETER(m_data, return);

	return BLUETOOTH_ERROR_NOT_SUPPORT;
}


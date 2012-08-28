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

#include <vconf.h>
#include <vconf-keys.h>
#include <syspopup_caller.h>

#include "bluetooth-gap-api.h"

static bluetooth_discovery_option_t discovery_option = { 0 };

static int __bluetooth_internal_bonding_req(void);
static void __bluetooth_internal_get_service_list(GValue *value, bluetooth_device_info_t *dev);

static int __bt_launch_terminate_popup(void)
{
	int ret = 0;
	bundle *b = NULL;

	b = bundle_create();

	if (b == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	bundle_add(b, "event-type", "terminate");

	ret = syspopup_launch("bt-syspopup", b);

	if (ret < 0)
		DBG("Popup launch failed: %d\n", ret);

	bundle_free(b);

	return ret;
}

BT_EXPORT_API int bluetooth_check_adapter(void)
{
	int adapter_state = BLUETOOTH_ADAPTER_DISABLED;

	DBG("+\n");

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == TRUE) {
		adapter_state = BLUETOOTH_ADAPTER_ENABLED;
	}

	DBG("-\n");

	return adapter_state;
}

void _bluetooth_internal_enabled_cb(void)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();
	if (bt_internal_info->bt_change_state_timer != 0) {
		g_source_remove(bt_internal_info->bt_change_state_timer);
		bt_internal_info->bt_change_state_timer = 0;
	}

	DBG("%s", bt_internal_info->bt_local_name.name);

	/* Vconf value is not exist */
	if (strlen(bt_internal_info->bt_local_name.name) == 0)
		_bluetooth_get_default_adapter_name(&bt_internal_info->bt_local_name,
						BLUETOOTH_DEVICE_NAME_LENGTH_MAX);

	DBG("%s", bt_internal_info->bt_local_name.name);

	/* default name setting*/
	if (bluetooth_set_local_name(&bt_internal_info->bt_local_name) < 0)
		ERR("init name setting failed");

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_ENABLED,
					  BLUETOOTH_ERROR_NONE, NULL);

	return;
}

void _bluetooth_internal_disabled_cb(void)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();
	if (bt_internal_info->bt_change_state_timer != 0) {
		g_source_remove(bt_internal_info->bt_change_state_timer);
		bt_internal_info->bt_change_state_timer = 0;
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_DISABLED,
					  BLUETOOTH_ERROR_NONE, NULL);
	return;
}

static int __bluetooth_internal_change_status_timeout_cb(void *data)
{
	bt_info_t *bt_internal_info = NULL;
	int event = BLUETOOTH_EVENT_NONE;

	bt_internal_info = _bluetooth_internal_get_information();
	bt_internal_info->bt_change_state_timer = 0;

	if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_ENABLE) {
		event = BLUETOOTH_EVENT_ENABLED;
		bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_DISABLED;
	} else if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_DISABLE) {
		event = BLUETOOTH_EVENT_DISABLED;
		bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_ENABLED;
	} else {
		ERR("Wrong adapter state [%d]", bt_internal_info->bt_adapter_state);
		return 0;
	}

	_bluetooth_internal_event_cb(event, BLUETOOTH_ERROR_TIMEOUT, NULL);

	return 0;
}

static void __bluetooth_internal_change_state_req_finish_cb(DBusGProxy *proxy, DBusGProxyCall *call,
							  gpointer user_data)
{
	GError *err = NULL;
	bt_info_t *bt_internal_info = NULL;
	int event = BLUETOOTH_EVENT_NONE;

	DBG("+");

	bt_internal_info = _bluetooth_internal_get_information();

	dbus_g_proxy_end_call(proxy, call, &err, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in change state [%s]", err->message);
		g_error_free(err);

		if (bt_internal_info->bt_change_state_timer != 0) {
			g_source_remove(bt_internal_info->bt_change_state_timer);
			bt_internal_info->bt_change_state_timer = 0;
		}

		if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_ENABLE) {
			event = BLUETOOTH_EVENT_ENABLED;
			bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_DISABLED;
		} else if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_DISABLE) {
			event = BLUETOOTH_EVENT_DISABLED;
			bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_ENABLED;
		} else {
			ERR("Wrong adapter state [%d]", bt_internal_info->bt_adapter_state);
			return;
		}

		_bluetooth_internal_event_cb(event, BLUETOOTH_ERROR_CANCEL_BY_USER, NULL);

		return;
	}

	DBG("-");
}

static int __bluetooth_internal_enable_adapter(void *data)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	/*BT intiate call to agent*/
	if (dbus_g_proxy_begin_call(bt_internal_info->agent_proxy, "ConfirmMode",
		(DBusGProxyCallNotify) __bluetooth_internal_change_state_req_finish_cb, NULL, NULL,
		G_TYPE_STRING, "enable", G_TYPE_INVALID) == NULL) {
		DBG("Agent call failed");
		return BLUETOOTH_ERROR_INTERNAL;
	} else {
		bt_internal_info->bt_change_state_timer =
		    g_timeout_add_seconds(BLUETOOTH_CHANGE_STATUS_TIMEOUT,
					  __bluetooth_internal_change_status_timeout_cb, NULL);
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_enable_adapter(void)
{
	bt_info_t *bt_internal_info = NULL;

	DBG("+\n");

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == TRUE) {
		DBG("Currently Enabled");
		return BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
	}

	/* This information is the local state, other process can't know this information */
	/* Nevertheless we add this code to avoid the unexpected result in one process */
	if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_ENABLE ||
	    bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_DISABLE) {
		DBG("Currently changing adapter state [%d]", bt_internal_info->bt_adapter_state);
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_CHANGING_ENABLE;

	DBG("-\n");
	return __bluetooth_internal_enable_adapter(NULL);
}

static int __bluetooth_internal_disable_adapter(void *data)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	/* BT terminate call to agent*/
	if (dbus_g_proxy_begin_call(bt_internal_info->agent_proxy, "ConfirmMode",
		(DBusGProxyCallNotify) __bluetooth_internal_change_state_req_finish_cb, NULL, NULL,
		G_TYPE_STRING, "disable", G_TYPE_INVALID) == NULL) {
		DBG("Agent call failed");
		return BLUETOOTH_ERROR_INTERNAL;
	} else {
		bt_internal_info->bt_change_state_timer =
		    g_timeout_add_seconds(BLUETOOTH_CHANGE_STATUS_TIMEOUT,
					  __bluetooth_internal_change_status_timeout_cb, NULL);
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_disable_adapter(void)
{
	bt_info_t *bt_internal_info = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently Disabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	/* This information is the local state, other process can't know this information */
	/* Nevertheless we add this code to avoid the unexpected result in one process */
	if (bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_ENABLE ||
	    bt_internal_info->bt_adapter_state == BLUETOOTH_ADAPTER_CHANGING_DISABLE) {
		DBG("Currently changing adapter state [%d]", bt_internal_info->bt_adapter_state);
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	bt_internal_info->bt_adapter_state = BLUETOOTH_ADAPTER_CHANGING_DISABLE;

	return __bluetooth_internal_disable_adapter(NULL);
}

BT_EXPORT_API int bluetooth_get_local_address(bluetooth_device_address_t *local_address)
{
	DBG("+\n");
	bt_info_t *bt_internal_info = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	char *address = NULL;

	if (local_address == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently Disabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "GetProperties", NULL,
			  	G_TYPE_INVALID,
			  	dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Address");
		address = (char *)(value ? g_value_get_string(value) : NULL);
	}

	if (address)
		_bluetooth_internal_convert_addr_string_to_addr_type(local_address, address);
	else
		return BLUETOOTH_ERROR_INTERNAL;

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_get_local_name(bluetooth_device_name_t *local_name)
{
	bt_info_t *bt_internal_info = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	char *name = NULL;
	char *ptr = NULL;

	if (local_name == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			  &hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		name = (char *)(value ? g_value_get_string(value) : NULL);
	}

	if (name && (strlen(name) > 0)) {
		/* Check the utf8 valitation & Fill the NULL in the invalid location*/
                if (!g_utf8_validate(name, -1, (const char **)&ptr))
                        *ptr = '\0';

		memcpy(local_name->name, name, BLUETOOTH_DEVICE_NAME_LENGTH_MAX);
	} else {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	local_name->name[BLUETOOTH_DEVICE_NAME_LENGTH_MAX] = '\0';

	return BLUETOOTH_ERROR_NONE;
}

void _bluetooth_internal_adapter_name_changed_cb(void)
{
	bt_info_t *bt_internal_info = NULL;
	bluetooth_device_name_t changed_name = { {0} };

	bt_internal_info = _bluetooth_internal_get_information();

	memcpy(&changed_name, &bt_internal_info->bt_local_name, sizeof(bluetooth_device_name_t));
	changed_name.name[BLUETOOTH_DEVICE_NAME_LENGTH_MAX] = '\0';

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_LOCAL_NAME_CHANGED,
				BLUETOOTH_ERROR_NONE, &changed_name);

	return;
}

BT_EXPORT_API int bluetooth_set_local_name(const bluetooth_device_name_t *local_name)
{
	bt_info_t *bt_internal_info = NULL;
	int ret = BLUETOOTH_ERROR_NONE;
	GError *error = NULL;
	char *ptr = NULL;

	if (local_name == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (strlen(local_name->name) > BLUETOOTH_DEVICE_NAME_LENGTH_MAX) {
		ERR("size overflow");
		return BLUETOOTH_ERROR_INVALID_DATA;
	}

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (!g_utf8_validate(local_name->name, -1, (const char **)&ptr))
		*ptr = '\0';

	/* Set the bluez name (BT enabled case) */
	GValue name = { 0 };
	g_value_init(&name, G_TYPE_STRING);
	g_value_set_string(&name, local_name->name);

	if (bt_internal_info->adapter_proxy != NULL) {
		dbus_g_proxy_call(bt_internal_info->adapter_proxy, "SetProperty",
				&error, G_TYPE_STRING, "Name",
				G_TYPE_VALUE, &name, G_TYPE_INVALID, G_TYPE_INVALID);

		if (error) {
			DBG("SetProperty Fail: %s", error->message);
			g_error_free(error);
			ret = BLUETOOTH_ERROR_INTERNAL;
		} else {
			ret = BLUETOOTH_ERROR_NONE;
		}
	}
	g_value_unset(&name);

	return ret;
}

BT_EXPORT_API int bluetooth_is_service_used(const char *service_uuid,
						gboolean *used)
{
	bt_info_t *bt_internal_info = NULL;
	char **uuids = NULL;
	int i = 0;
	GHashTable *hash = NULL;
	GValue *value = NULL;

	if (service_uuid == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (used == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bt_internal_info->adapter_proxy == NULL) {
		DBG("adapter_proxy is NULL");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			  &hash, G_TYPE_INVALID);

	if (hash == NULL) {
		DBG("hash is NULL");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	value = g_hash_table_lookup(hash, "UUIDs");
	uuids = g_value_get_boxed(value);

	if (uuids == NULL) {
		*used = FALSE;
		return BLUETOOTH_ERROR_NONE;
	}

	for (i = 0; uuids[i] != NULL; i++) {
		DBG("UUIDs %s ", uuids[i]);
		if (strcasecmp(uuids[i], service_uuid) == 0) {
			*used = TRUE;
			return BLUETOOTH_ERROR_NONE;
		}
	}

	*used = FALSE;

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_get_discoverable_mode(bluetooth_discoverable_mode_t *
						  discoverable_mode_ptr)
{
	DBG("+");
	bt_info_t *bt_internal_info = NULL;
	int timeout = 0;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	GValue *timeout_value = NULL;

	if (NULL == discoverable_mode_ptr) {
		DBG("discoverable pointer is NULL\n", discoverable_mode_ptr);
		return BLUETOOTH_ERROR_INVALID_DATA;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		if (vconf_get_int(BT_FILE_VISIBLE_TIME, &timeout) != 0) {
			DBG("Fail to get the timeout value");
			return BLUETOOTH_ERROR_INTERNAL;
		}

		if (timeout == -1) {
			*discoverable_mode_ptr = BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
		} else {
			*discoverable_mode_ptr = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		}

		return BLUETOOTH_ERROR_NONE;
	}

	if (bt_internal_info->adapter_proxy != NULL) {
		dbus_g_proxy_call(bt_internal_info->adapter_proxy, "GetProperties", NULL,
				  G_TYPE_INVALID,
				  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				  &hash, G_TYPE_INVALID);

		if (hash != NULL) {
			value = g_hash_table_lookup(hash, "Discoverable");
			timeout_value = g_hash_table_lookup(hash, "DiscoverableTimeout");

			if (g_value_get_boolean(value)) {
				if (g_value_get_uint(timeout_value) == 0)
					*discoverable_mode_ptr =
					    BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE;
				else
					*discoverable_mode_ptr =
					    BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
			} else {
				*discoverable_mode_ptr = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
			}

			DBG("-");
			return BLUETOOTH_ERROR_NONE;
		}
	}
	DBG("Error: Proxy is NULL-");
	return BLUETOOTH_ERROR_INTERNAL;
}

BT_EXPORT_API int bluetooth_set_discoverable_mode(bluetooth_discoverable_mode_t discoverable_mode,
						  int timeout)
{
	DBG("+");
	int ret = BLUETOOTH_ERROR_NONE;
	bt_info_t *bt_internal_info = NULL;
	gboolean inq_scan = 0;
	gboolean pg_scan = 0;
	GError *error = NULL;
	GValue connectable = { 0 };
	GValue discoverable = { 0 };
	GValue val_timeout = { 0 };

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	g_value_init(&connectable, G_TYPE_BOOLEAN);
	g_value_init(&discoverable, G_TYPE_BOOLEAN);
	g_value_init(&val_timeout, G_TYPE_UINT);

	DBG("Discoverable_mode = %d", discoverable_mode);
	switch (discoverable_mode) {
	case BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE:
		pg_scan = TRUE;
		inq_scan = FALSE;
		timeout = 0;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE:
		pg_scan = TRUE;
		inq_scan = TRUE;
		timeout = 0;
		break;
	case BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE:
		inq_scan = TRUE;
		pg_scan = TRUE;
		break;
	default:
		return BLUETOOTH_ERROR_INVALID_PARAM;
		break;

	}

	g_value_set_boolean(&connectable, pg_scan);
	g_value_set_boolean(&discoverable, inq_scan);
	g_value_set_uint(&val_timeout, timeout);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "SetProperty", &error,
				   G_TYPE_STRING, "Powered", G_TYPE_VALUE, &connectable,
				   G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Powered set err:[%s]", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "SetProperty", &error,
				   G_TYPE_STRING, "Discoverable", G_TYPE_VALUE, &discoverable,
				   G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Discoverable set err:[%s]", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "SetProperty", &error,
				   G_TYPE_STRING, "DiscoverableTimeout", G_TYPE_VALUE, &val_timeout,
				   G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		DBG("Timeout set err:[%s]", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* Set discoverable Timer in agent */
	if (discoverable_mode == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE)
		timeout = -1;

	dbus_g_proxy_call_no_reply(bt_internal_info->agent_proxy, "SetDiscoverableTimer",
			G_TYPE_INT, timeout,
			G_TYPE_INVALID,
			G_TYPE_INVALID);

	g_value_unset(&val_timeout);
	g_value_unset(&connectable);
	g_value_unset(&discoverable);

	DBG("-");
	return ret;
}

void _bluetooth_internal_discovery_started_cb(void)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_discovery_req_timer != 0) {
		g_source_remove(bt_internal_info->bt_discovery_req_timer);
		bt_internal_info->bt_discovery_req_timer = 0;
		bt_internal_info->is_discovery_req = 1;
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_DISCOVERY_STARTED,
					BLUETOOTH_ERROR_NONE, NULL);
	return;
}

void _bluetooth_internal_remote_device_found_cb(const char *address,
					       int rssi, unsigned int remote_class, gboolean paired)
{
	bt_info_t *bt_internal_info = NULL;
	bluetooth_device_info_t dev_info = { { { 0 } } };

	bt_internal_info = _bluetooth_internal_get_information();

	_bluetooth_internal_convert_addr_string_to_addr_type(&dev_info.device_address, address);
	_bluetooth_internal_divide_device_class(&dev_info.device_class, remote_class);
	dev_info.rssi = rssi;
	dev_info.paired = paired;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND,
					BLUETOOTH_ERROR_NONE, &dev_info);
	return;
}


static bool __bluetooth_match_discovery_option(bluetooth_device_class_t device_class, unsigned int mask)
{
	DBG("+");

	bluetooth_device_major_mask_t major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_MISC;

	if (mask == 0x000000)
		return TRUE;

	DBG("mask: %x", mask);

	DBG("service_class: %x", device_class.service_class);

	/* Check the service_class */
	if (device_class.service_class & mask)
		return TRUE;

	/* Check the major class */
	switch (device_class.major_class) {
	case BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_COMPUTER;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_PHONE;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_LAN_ACCESS_POINT;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_AUDIO;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_PERIPHERAL;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_IMAGING;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_WEARABLE;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_TOY:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_TOY;
		break;
	case BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_HEALTH;
		break;
	default:
		major_mask = BLUETOOTH_DEVICE_MAJOR_MASK_MISC;
		break;
	}

	DBG("major_mask: %x", major_mask);

	if (mask & major_mask)
		return TRUE;

	return FALSE;
	DBG("-");
}

void _bluetooth_internal_remote_device_name_updated_cb(const char *address,
						      const char *name, int rssi,
						      unsigned int remote_class, gboolean paired)
{
	bt_info_t *bt_internal_info = NULL;
	bluetooth_device_info_t dev_info = { { { 0 } } };

	bt_internal_info = _bluetooth_internal_get_information();

	_bluetooth_internal_divide_device_class(&dev_info.device_class, remote_class);

	if (__bluetooth_match_discovery_option(dev_info.device_class,
				discovery_option.classOfDeviceMask) == FALSE)
		return;

	if (name == NULL || address == NULL)
		return;

	_bluetooth_internal_convert_addr_string_to_addr_type(&dev_info.device_address, address);
	if (strlen(name) <= BLUETOOTH_DEVICE_NAME_LENGTH_MAX) {
		memcpy(&dev_info.device_name, name, strlen(name));
	}

	dev_info.rssi = rssi;
	dev_info.paired = paired;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED,
					BLUETOOTH_ERROR_NONE, &dev_info);
	return;
}

void _bluetooth_internal_discovery_completed_cb(void)
{
	bt_info_t *bt_internal_info = NULL;
	int result = BLUETOOTH_ERROR_NONE;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->is_discovery_cancel) {
		result = BLUETOOTH_ERROR_CANCEL_BY_USER;
		bt_internal_info->is_discovery_cancel = FALSE;
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_DISCOVERY_FINISHED,
					result, NULL);

	bt_internal_info->is_discovery_req = 0;

	return;
}

static int __bluetooth_internal_discovery_req_timeout_cb(void *data)
{
	bt_info_t *bt_internal_info = NULL;

	bt_internal_info = _bluetooth_internal_get_information();
	bt_internal_info->bt_discovery_req_timer = 0;

	DBG("");

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, NULL,
				"StopDiscovery",
				G_TYPE_INVALID, G_TYPE_INVALID);

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_DISCOVERY_STARTED,
					BLUETOOTH_ERROR_TIMEOUT, NULL);

	return 0;
}

BT_EXPORT_API int bluetooth_start_discovery(unsigned short max_response,
					    unsigned short discovery_duration,
					    unsigned int classOfDeviceMask)
{
	DBG("+");

	bt_info_t *bt_internal_info = NULL;
	DBusGProxy *adapter_proxy;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bluetooth_is_discovering() == TRUE) {
		DBG("BT is already in discovering");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (classOfDeviceMask > 0x800000) {
		DBG("Not supported class");
		return BLUETOOTH_ERROR_SERVICE_NOT_FOUND;
	}

	if (discovery_option.max_response == 0)
		discovery_option.max_response = 0;	/*unlimited*/

	if (discovery_option.discovery_duration == 0)
		discovery_option.discovery_duration = 180;	/* 3 minutes*/

	discovery_option.classOfDeviceMask = classOfDeviceMask;	/*searching Type*/

	bt_internal_info = _bluetooth_internal_get_information();

	adapter_proxy = _bluetooth_internal_get_adapter_proxy(bt_internal_info->conn);

	if (adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	if (!dbus_g_proxy_call(adapter_proxy, "StartDiscovery", NULL,
			       G_TYPE_INVALID, G_TYPE_INVALID)) {
		DBG("Discover start failed");
		g_object_unref(adapter_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_object_unref(adapter_proxy);

	if (bt_internal_info->bt_discovery_req_timer != 0) {
		g_source_remove(bt_internal_info->bt_discovery_req_timer);
		bt_internal_info->bt_discovery_req_timer = 0;
	}

	bt_internal_info->bt_discovery_req_timer =
	    g_timeout_add_seconds(2, __bluetooth_internal_discovery_req_timeout_cb, NULL);

	DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_cancel_discovery(void)
{
	bt_info_t *bt_internal_info = NULL;
	GError *error = NULL;
	int ret = BLUETOOTH_ERROR_NONE;
	DBusGProxy *adapter_proxy;

	DBG("+");

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	adapter_proxy = _bluetooth_internal_get_adapter_proxy(bt_internal_info->conn);

	if (adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(adapter_proxy, "StopDiscovery", &error,
			  G_TYPE_INVALID, G_TYPE_INVALID);

	g_object_unref(adapter_proxy);

	if (error) {
		DBG("error in StopDiscovery [%s]\n", error->message);

		if (!strcmp(error->message, "Invalid discovery session"))
			ret = BLUETOOTH_ERROR_NOT_IN_OPERATION;
		else
			ret = BLUETOOTH_ERROR_INTERNAL;

		g_error_free(error);
		DBG("Discover stop failed");
		return ret;
	}

	bt_internal_info->is_discovery_cancel = TRUE;

	DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_is_discovering(void)
{
	bt_info_t *bt_internal_info = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	int is_discovering = 0;
	DBusGProxy *adapter_proxy;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	adapter_proxy = _bluetooth_internal_get_adapter_proxy(bt_internal_info->conn);

	if (adapter_proxy == NULL)
		return is_discovering;

	dbus_g_proxy_call(adapter_proxy, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			  &hash, G_TYPE_INVALID);

	g_object_unref(adapter_proxy);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Discovering");

		if (value)
			is_discovering = (g_value_get_boolean(value) == FALSE) ? 0 : 1;
	}

	return is_discovering;
}

static int __bluetooth_is_headset_class(int dev_class)
{
	DBG("bluetooth_is_headset, %d +", dev_class);

	int is_headset = 0;

	switch ((dev_class & 0x1f00) >> 8) {
	case 0x04:
		switch ((dev_class & 0xfc) >> 2) {
		case 0x01:
		case 0x02:
			/* Headset */
			is_headset = 1;
			break;
		case 0x06:
			/* Headphone */
			is_headset = 1;
			break;
		case 0x0b:	/* VCR */
		case 0x0c:	/* Video Camera */
		case 0x0d:	/* Camcorder */
			break;
		default:
			/* Other audio device */
			is_headset = 1;
			break;
		}
		break;
	}

	return is_headset;
}


int _bluetooth_is_headset_device(DBusGProxy *proxy)
{
	int is_headset = 0;
	int remote_class = 0;
	GHashTable *hash = NULL;
	GValue *value = NULL;

	if (proxy == NULL)
		return 0;

	dbus_g_proxy_call(proxy, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
					      G_TYPE_VALUE), &hash,
			  G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Class");
		remote_class = value ? g_value_get_uint(value) : 0;
	}

	DBG("remote_class: %d", remote_class);

	is_headset = __bluetooth_is_headset_class(remote_class);

	return is_headset;
}


static void __bluetooth_internal_bonding_req_reply_cb(int error_type,
						    const bluetooth_device_info_t *device_info,
						    int is_headset)
{
	bt_info_t *bt_internal_info = NULL;
	bluetooth_device_address_t device_address = { {0} };

	DBG("+");

	bt_internal_info = _bluetooth_internal_get_information();
	/* We need to cancel the timer */
	if (bt_internal_info->bt_bonding_req_timer)
		g_source_remove(bt_internal_info->bt_bonding_req_timer);

	bt_internal_info->bt_bonding_req_timer = 0;

	if (error_type != BLUETOOTH_ERROR_NONE) {
		dbus_g_proxy_call_no_reply(bt_internal_info->adapter_proxy, "CancelDeviceCreation",
					   G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr,
					   G_TYPE_INVALID, G_TYPE_INVALID);

		DBG("error_type: %d", error_type);

		/* Add the codes about auto-headset pairing */
		if (error_type == BLUETOOTH_ERROR_AUTHENTICATION_FAILED &&
			bt_internal_info->is_headset_pin_req == FALSE) {
			if (is_headset) {
				dbus_g_proxy_call_no_reply(bt_internal_info->agent_proxy,
							   "IgnoreAutoPairing", G_TYPE_STRING,
							   bt_internal_info->bt_bonding_req_addrstr,
							   G_TYPE_INVALID, G_TYPE_INVALID);

				/* Auto-pairing fail case */
				_bluetooth_internal_convert_addr_string_to_addr_type(&device_address,
							bt_internal_info->bt_bonding_req_addrstr);

				bt_internal_info->is_headset_pin_req = TRUE;
				bt_internal_info->is_bonding_req = FALSE;
				bt_internal_info->is_headset_bonding = FALSE;
				memset(bt_internal_info->bt_bonding_req_addrstr,
						0x00, BT_ADDRESS_STRING_SIZE);

				bluetooth_bond_device(&device_address);
				return;
			}
		}
	}

	bt_internal_info->is_headset_pin_req = FALSE;
	bt_internal_info->is_bonding_req = FALSE;
	bt_internal_info->is_headset_bonding = FALSE;
	memset(bt_internal_info->bt_bonding_req_addrstr, 0x00, BT_ADDRESS_STRING_SIZE);

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_BONDING_FINISHED,
					error_type, (void *)device_info);
	DBG("-");
}

void _bluetooth_internal_bonding_created_cb(const char *bond_address, gpointer user_data)
{
	int remote_class = 0;
	gboolean trust = FALSE;

	DBusGProxy *device_proxy = (DBusGProxy *)user_data;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	GValue *uuid_value = NULL;
	const gchar *name = NULL;	/*Sparrow fix */
	gint rssi = 0;

	DBG("+\n");

	dbus_g_proxy_call(device_proxy, "GetProperties", NULL,
			  	G_TYPE_INVALID,
			  	dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Class");
		remote_class = value ? g_value_get_uint(value) : 0;

		value = g_hash_table_lookup(hash, "Trusted");
		trust = value ? g_value_get_boolean(value) : FALSE;

		value = g_hash_table_lookup(hash, "RSSI");
		rssi = value ? g_value_get_int(value) : 0;

		value = g_hash_table_lookup(hash, "UUIDs");
		uuid_value = value;
	}

	DBG("Bonding Created with [%s][%s] Remote Class:[%#x]\n", name, bond_address, remote_class);

	{
		int is_headset = 0;
		bluetooth_device_info_t device_info = { { { 0 } } };
		bt_info_t *bt_internal_info = _bluetooth_internal_get_information();

		_bluetooth_internal_convert_addr_string_to_addr_type(&device_info.device_address,
								    bond_address);

		if (name && strlen(name) > 0)
			g_strlcpy(device_info.device_name.name, name,
				  sizeof(device_info.device_name.name));
		else
			g_strlcpy(device_info.device_name.name, bond_address,
				  sizeof(device_info.device_name.name));

		device_info.rssi = rssi;
		device_info.trust = trust;
		device_info.paired = TRUE;

		__bluetooth_internal_get_service_list(uuid_value, &device_info);
		_bluetooth_internal_divide_device_class(&device_info.device_class, remote_class);

		is_headset = __bluetooth_is_headset_class(remote_class);

		bt_internal_info->is_headset_pin_req = FALSE;
		__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_NONE, &device_info,
							is_headset);
	}

	DBG("-\n");

	return;
}

static void __bluetooth_internal_bonding_req_finish_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						     gpointer user_data)
{
	int remote_class = 0;
	int is_headset = 0;
	char *device_path = NULL;
	bt_info_t *bt_internal_info = NULL;
	GError *err = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	DBusGProxy *device_proxy = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	DBG("+");

	bt_internal_info = _bluetooth_internal_get_information();

	dbus_g_proxy_end_call(proxy, call, &err,
			      DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in CreateBonding [%s]", err->message);
		if (!strcmp(err->message, "Already Exists")) {
			DBG("Existing Bond, remove and retry");
			g_error_free(err);
			err = NULL;
			dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
					  G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr,
					  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &device_path,
					  G_TYPE_INVALID);

			if (device_path != NULL) {

				dbus_g_proxy_call(bt_internal_info->adapter_proxy, "RemoveDevice",
						  &err, DBUS_TYPE_G_OBJECT_PATH, device_path,
						  G_TYPE_INVALID, G_TYPE_INVALID);

				if (err != NULL) {
					DBG("RemoveDevice Fail", err->message);
					g_error_free(err);
					__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_PARING_FAILED,
											NULL, 0);
				} else {
					__bluetooth_internal_bonding_req();
				}
			} else {
				ERR("No device in adapter");
				__bluetooth_internal_bonding_req_reply_cb
				    (BLUETOOTH_ERROR_PARING_FAILED, NULL, 0);
			}
			return;
		} else if (!strcmp(err->message, "Authentication Rejected")) {
			__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_ACCESS_DENIED,
									NULL, 0);
		} else if (!strcmp(err->message, "CanceledbyUser") ||
					!strcmp(err->message, "Authentication Canceled")) {
			__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_CANCEL_BY_USER,
								NULL, 0);
		} else if (!strcmp(err->message, "In Progress")) {
			__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_IN_PROGRESS,
								NULL, 0);
		} else if (!strcmp(err->message, "Authentication Failed")) {
			dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
					  G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr,
					  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &device_path,
					  G_TYPE_INVALID);
			if (!device_path) {
				DBG("device_path is NULL");
			}

			/* Pairing fail case by wrong pin code */
			device_proxy = _bluetooth_internal_find_device_by_path(device_path);

			if (device_proxy) {
				dbus_g_proxy_call(device_proxy, "GetProperties", NULL,
						  G_TYPE_INVALID,
						  dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
								      G_TYPE_VALUE), &hash,
						  G_TYPE_INVALID);
			} else {
				DBG("device proxy is NULL");
			}

			if (hash != NULL) {
				value = g_hash_table_lookup(hash, "Class");
				remote_class = value ? g_value_get_uint(value) : 0;
			}

			DBG("remote_class: %d", remote_class);

			is_headset = __bluetooth_is_headset_class(remote_class);

			__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_AUTHENTICATION_FAILED,
									NULL, is_headset);
		} else if (!strcmp(err->message, "Page Timeout")) {
			/* This is the special case
			     As soon as call bluetooth_bond_device, try to cancel bonding.
			     In this case, before completing to call 'CreatePairedDevice' method
			     the procedure is stopped. So 'Cancle' error is not return.
			*/

			if (bt_internal_info->is_bonding_req == FALSE) {
				__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_CANCEL_BY_USER,
										NULL, 0);
			} else {
				if (bt_internal_info->is_headset_bonding)
					/* Headset auto-pairing fail case */
					__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_AUTHENTICATION_FAILED,
										NULL, 1);
				else
					__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_HOST_DOWN,
											NULL, 0);
			}
		} else {
			__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_PARING_FAILED,
									NULL, 0);
		}

		if (err != NULL)
			g_error_free(err);
	} else {
		dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
				  G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr,
				  G_TYPE_INVALID, DBUS_TYPE_G_OBJECT_PATH, &device_path,
				  G_TYPE_INVALID);
		if (!device_path) {
			DBG("device_path is NULL");
		}

		_bluetooth_internal_device_path_to_address(device_path, address);

		device_proxy = _bluetooth_internal_find_device_by_path(device_path);

		_bluetooth_internal_bonding_created_cb(address,
						(gpointer)device_proxy);
	}

	/* Terminate the BT system popup (In the keyboard case) */
	__bt_launch_terminate_popup();

	DBG("-");
}

static int __bluetooth_internal_bonding_req_timeout_cb(void *data)
{
	DBG("+");
	__bluetooth_internal_bonding_req_reply_cb(BLUETOOTH_ERROR_TIMEOUT, NULL, 0);
	DBG("-");

	return 0;
}

BT_EXPORT_API int bluetooth_oob_read_local_data(bt_oob_data_t *local_oob_data)
{
	DBG("+\n");
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	unsigned char *local_hash = NULL;
	unsigned char *local_randomizer = NULL;
	bt_info_t *bt_internal_info = NULL;

	if (NULL == local_oob_data)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	bt_internal_info = _bluetooth_internal_get_information();

	if (!bt_internal_info->sys_conn) {
		bt_internal_info->sys_conn =
				dbus_g_connection_get_connection(
					bt_internal_info->conn);
	}

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
					bt_internal_info->adapter_path,
					"org.bluez.OutOfBand",
					"ReadLocalData");

	if (msg == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(bt_internal_info->sys_conn,
					msg, -1, &err);

	dbus_message_unref(msg);
	if (!reply) {
		DBG("Error in ReadLocalData \n");
		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!dbus_message_get_args(reply, NULL,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&local_hash, &local_oob_data->hash_len,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&local_randomizer, &local_oob_data->randomizer_len,
			DBUS_TYPE_INVALID)) {
		DBG("Error in reading arguments\n");
		dbus_message_unref(reply);
		return BLUETOOTH_ERROR_INVALID_DATA;
	}

	if (NULL != local_hash)
		memcpy(local_oob_data->hash, local_hash, local_oob_data->hash_len);

	if (NULL != local_randomizer)
		memcpy(local_oob_data->randomizer, local_randomizer,
					local_oob_data->randomizer_len);

	dbus_message_unref(reply);
	DBG("-\n");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_oob_add_remote_data(
			const bluetooth_device_address_t *remote_device_address,
			bt_oob_data_t *remote_oob_data)
{
	DBG("+\n");
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError err;
	const char *dev_addr = NULL;

	bt_info_t *bt_internal_info = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	unsigned char *remote_hash = NULL;
	unsigned char *remote_randomizer = NULL;

	if (NULL == remote_oob_data) {
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (!bt_internal_info->sys_conn) {
		bt_internal_info->sys_conn =
				dbus_g_connection_get_connection(
					bt_internal_info->conn);
	}

	_bluetooth_internal_addr_type_to_addr_string(address,
		remote_device_address);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
			bt_internal_info->adapter_path,
			"org.bluez.OutOfBand",
			"AddRemoteData");

	if (NULL == msg) {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("remote hash len = [%d] and remote random len = [%d]\n",
		remote_oob_data->hash_len, remote_oob_data->randomizer_len);

	remote_hash = remote_oob_data->hash;
	remote_randomizer = remote_oob_data->randomizer;

	dev_addr = g_strdup(address);
	DBG("dev_addr = [%s]\n", dev_addr);

	dbus_message_append_args(msg,
		DBUS_TYPE_STRING, &dev_addr,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
		&remote_hash, remote_oob_data->hash_len,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
		&remote_randomizer, remote_oob_data->randomizer_len,
		DBUS_TYPE_INVALID);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(bt_internal_info->sys_conn,
					msg, -1, &err);

	dbus_message_unref(msg);
	if (!reply) {
		DBG("Error in AddRemoteData \n");
		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
			g_free((void *)dev_addr);
			return BLUETOOTH_ERROR_INTERNAL;
		}
	}

	g_free((void *)dev_addr);
	dbus_message_unref(reply);
	DBG("+\n");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_oob_remove_remote_data(
			const bluetooth_device_address_t *remote_device_address)
{
	DBG("+\n");
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError err;

	bt_info_t *bt_internal_info = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	bt_internal_info = _bluetooth_internal_get_information();

	if (!bt_internal_info->sys_conn) {
		bt_internal_info->sys_conn =
				dbus_g_connection_get_connection(
					bt_internal_info->conn);
	}

	_bluetooth_internal_addr_type_to_addr_string(address, remote_device_address);

	const char *dev_addr = g_strdup(address);
	DBG("dev_addr = [%s]\n", dev_addr);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE_NAME,
			bt_internal_info->adapter_path,
			"org.bluez.OutOfBand",
			"RemoveRemoteData");

	if (NULL == msg ) {
		g_free((void *)dev_addr);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING,
		&dev_addr, DBUS_TYPE_INVALID);

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(bt_internal_info->sys_conn,
					msg, -1, &err);

	dbus_message_unref(msg);
	if (!reply) {
		DBG("Error in AddRemoteData \n");
		if (dbus_error_is_set(&err)) {
			DBG("%s", err.message);
			dbus_error_free(&err);
			g_free((void *)dev_addr);
			return BLUETOOTH_ERROR_INTERNAL;
		}
	}

	g_free((void *)dev_addr);
	dbus_message_unref(reply);
	DBG("+\n");

	return BLUETOOTH_ERROR_NONE;
}

static int __bluetooth_internal_bonding_req(void)
{
	DBG("+");
	bt_info_t *bt_internal_info = NULL;
	char default_path[128] = { 0 };

	bt_internal_info = _bluetooth_internal_get_information();

	snprintf(default_path, 128, "/org/bluez/agent_slp");

	if (!dbus_g_proxy_begin_call_with_timeout(bt_internal_info->adapter_proxy,
		"CreatePairedDevice",
	     	(DBusGProxyCallNotify) __bluetooth_internal_bonding_req_finish_cb, NULL, NULL, 50000,
	     	G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr, DBUS_TYPE_G_OBJECT_PATH,
	     	default_path, G_TYPE_STRING, "DisplayYesNo", G_TYPE_INVALID)) {
		DBG("CreatePairedDevice call fail");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_bond_device(const bluetooth_device_address_t *device_address)
{
	DBG("+");
	bt_info_t *bt_internal_info = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (device_address == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bluetooth_is_discovering() == TRUE) {
		DBG("Currently in discovery");
		return BLUETOOTH_ERROR_DEVICE_BUSY;
	}

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	g_strlcpy(bt_internal_info->bt_bonding_req_addrstr, address,
			sizeof(bt_internal_info->bt_bonding_req_addrstr));

	if (__bluetooth_internal_bonding_req() != BLUETOOTH_ERROR_NONE) {
		DBG("bonding request fail");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	bt_internal_info->is_bonding_req = TRUE;

	bt_internal_info->bt_bonding_req_timer =
	    g_timeout_add_seconds(BLUETOOTH_BONDING_TIMEOUT,
				  __bluetooth_internal_bonding_req_timeout_cb, NULL);

	DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_cancel_bonding(void)
{
	DBG("+");

	bt_info_t *bt_internal_info = NULL;
	GError *error = NULL;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bt_internal_info->bt_bonding_req_timer)
		g_source_remove(bt_internal_info->bt_bonding_req_timer);

	bt_internal_info->bt_bonding_req_timer = 0;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "CancelDeviceCreation", &error,
				   G_TYPE_STRING, bt_internal_info->bt_bonding_req_addrstr,
				   G_TYPE_INVALID, G_TYPE_INVALID);

	bt_internal_info->is_bonding_req = 0;
	memset(bt_internal_info->bt_bonding_req_addrstr, 0x00, 18);

	if (error) {
		DBG("CancelDeviceCreation error: [%s]", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_NOT_IN_OPERATION;
	}

	DBG("-");
	return BLUETOOTH_ERROR_NONE;
}

void _bluetooth_internal_bonding_removed_cb(const char *bond_address, gpointer user_data)
{
	bluetooth_device_address_t device_address = { {0} };

	DBG("+ Bonding Removed from [%s]\n", bond_address);

	_bluetooth_internal_convert_addr_string_to_addr_type(&device_address, bond_address);


	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
					BLUETOOTH_ERROR_NONE, &device_address);

	DBG("-\n");

	return;
}

static void __bluetooth_internal_unbond_request_complete_cb(DBusGProxy *proxy, DBusGProxyCall *call,
							  gpointer user_data)
{
	GError *err = NULL;
	bluetooth_device_address_t *device_address;

	DBG("+\n");

	dbus_g_proxy_end_call(proxy, call, &err, G_TYPE_INVALID);

	device_address = (bluetooth_device_address_t *)user_data;

	if (err != NULL) {
		DBG("Error occured in RemoveBonding [%s]\n", err->message);
		g_error_free(err);

		/* If control reaches here, it is always a debond request failure*/
		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
						BLUETOOTH_ERROR_NOT_PAIRED, device_address);
	}

	/*release user_data which was allocated in caller*/
	if (device_address != NULL)
		free(device_address);

	DBG("-\n");
}

BT_EXPORT_API int bluetooth_unbond_device(const bluetooth_device_address_t *device_address)
{
	bt_info_t *bt_internal_info = NULL;
	char address[18] = { 0 };
	char *device_path = NULL;
	bluetooth_device_address_t *bluetooth_address;

	_bluetooth_internal_session_init();

	bt_internal_info = _bluetooth_internal_get_information();

	if (device_address == NULL) {
		ERR("wrong parameter");
		return BLUETOOTH_ERROR_INVALID_PARAM;
	}

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	if (bluetooth_is_discovering() == TRUE) {
		DBG("Currently in discovery");
		return BLUETOOTH_ERROR_DEVICE_BUSY;
	}

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);

	/* allocate user data so that it can be retrieved in callback */
	bluetooth_address =
	    (bluetooth_device_address_t *)malloc(sizeof(bluetooth_device_address_t));
	if (bluetooth_address == NULL) {
		DBG("Out of memory");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	memcpy(bluetooth_address, device_address, BLUETOOTH_ADDRESS_LENGTH);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, address, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);

	if (device_path != NULL) {
		if (!dbus_g_proxy_begin_call(bt_internal_info->adapter_proxy, "RemoveDevice",
			(DBusGProxyCallNotify) __bluetooth_internal_unbond_request_complete_cb,
			(gpointer)bluetooth_address, NULL, DBUS_TYPE_G_OBJECT_PATH, device_path,
			G_TYPE_INVALID)) {
			DBG("RemoveBonding begin failed\n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
	} else {
		DBG("No paired device");
		free(bluetooth_address);
		return BLUETOOTH_ERROR_NOT_PAIRED;
	}

	return BLUETOOTH_ERROR_NONE;
}

static void __bluetooth_internal_get_service_list(GValue *value, bluetooth_device_info_t *dev)
{
	DBG("+\n");

	int i = 0;
	char **uuids = NULL;
	char **parts = NULL;

	if (value == NULL || dev == NULL) {
		ERR("wrong parameter");
		return;
	}

	uuids = g_value_get_boxed(value);

	if (uuids == NULL)
		return;

	dev->service_index = 0;

	for (i = 0; uuids[i] != NULL && i < BLUETOOTH_MAX_SERVICES_FOR_DEVICE; i++) {
		g_strlcpy(dev->uuids[i], uuids[i], BLUETOOTH_UUID_STRING_MAX);

		parts = g_strsplit(uuids[i], "-", -1);

		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			break;
		}

		dev->service_list_array[i] = g_ascii_strtoull(parts[0], NULL, 16);
		g_strfreev(parts);

		DBG("dev->service_index is %d\n", dev->service_index);

		dev->service_index++;
	}

	DBG("-\n");
}

static int __bluetooth_internal_get_bonded_device_list_details(gchar *device_path,
							     bluetooth_device_info_t *dev)
{
	DBG("+\n");
	GValue *value = { 0 };
	GError *err = NULL;

	const gchar *address, *name;
	unsigned int cod;
	gint rssi;
	gboolean trust;
	gboolean paired;
	gboolean connected;
	GHashTable *hash;
	int ret_val = BLUETOOTH_ERROR_INTERNAL;

	if ((dev == NULL) || (device_path == NULL))
		return BLUETOOTH_ERROR_INVALID_PARAM;

	DBusGProxy *device_proxy = _bluetooth_internal_find_device_by_path(device_path);
	if (device_proxy == NULL) {
		DBG("Not Found device with path %s\n", device_path);

		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(device_proxy, "GetProperties", &err,
			  	G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n", err->message);
		g_error_free(err);

		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Paired");
		paired = g_value_get_boolean(value);

		if (paired == FALSE)
			return BLUETOOTH_ERROR_NOT_PAIRED;

		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Alias");
		name = value ? g_value_get_string(value) : NULL;
		if (name != NULL)
			DBG("Alias Name [%s]", name);
		else {
			value = g_hash_table_lookup(hash, "Name");
			name = value ? g_value_get_string(value) : NULL;
		}

		value = g_hash_table_lookup(hash, "Class");
		cod = value ? g_value_get_uint(value) : 0;
		DBG("Address [%s], Name [%s], COD [0x%X]\n", address, name, cod);

		value = g_hash_table_lookup(hash, "Connected");
		connected = value ? g_value_get_boolean(value) : FALSE;

		value = g_hash_table_lookup(hash, "Trusted");
		trust = value ? g_value_get_boolean(value) : FALSE;

		value = g_hash_table_lookup(hash, "RSSI");
		rssi = value ? g_value_get_int(value) : 0;

		value = g_hash_table_lookup(hash, "UUIDs");
		__bluetooth_internal_get_service_list(value, dev);

		_bluetooth_internal_convert_addr_string_to_addr_type(&dev->device_address,
								    address);
		g_strlcpy(dev->device_name.name, name,
				BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);

		dev->rssi = rssi;
		dev->trust = trust;
		dev->paired = paired;
		dev->connected = connected;
		_bluetooth_internal_divide_device_class(&dev->device_class, cod);

		ret_val = BLUETOOTH_ERROR_NONE;
	} else {
		DBG("Hash is NULL\n");
		ret_val = BLUETOOTH_ERROR_INTERNAL;
	}

	DBG("-\n");
	return ret_val;

}

static int bluetooth_internal_get_bonded_device_list(GPtrArray **dev_list)
{
	DBG("+\n");
	int ret_val = BLUETOOTH_ERROR_NONE;
	int i;
	bt_info_t *bt_internal_info = NULL;
	GPtrArray *gp_array = NULL;
	GPtrArray *result = NULL;
	GError *error = NULL;
	bluetooth_device_info_t *devinfo;

	if (dev_list == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;
	result = *dev_list;

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "ListDevices", &error,
			  	G_TYPE_INVALID,
				dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
			 	&gp_array, G_TYPE_INVALID);
	if (error != NULL)
		goto err_listdev;

	if (gp_array == NULL) {
		DBG("DBus error: \n");
		goto err_done;
	}


	if (gp_array->len == 0) {
		result->len = 0;
		goto success;
	}

	DBG("Num of ListDevices = [%d]", gp_array->len);
	for (i = 0; i < gp_array->len; i++) {
		gchar *gp_path = g_ptr_array_index(gp_array, i);

		if (gp_path == NULL)
			continue;

		DBG("Newly list device [%s]\n", gp_path);
		devinfo = (bluetooth_device_info_t *)malloc(sizeof(*devinfo));
		memset(devinfo, 0, sizeof(*devinfo));
		if (__bluetooth_internal_get_bonded_device_list_details(gp_path,
					devinfo) == BLUETOOTH_ERROR_NONE) {
			g_ptr_array_add(result, (gpointer)devinfo);
		} else {
			DBG("Can't get the paired device path \n");
			free(devinfo);
			break;
		}
	}

success:
	g_ptr_array_free(gp_array, TRUE);
	DBG("-\n");
	return ret_val;

err_listdev:
	DBG("ListDevices error: [%s]\n", error->message);
	g_error_free(error);

err_done:
	DBG("-\n");
	return BLUETOOTH_ERROR_INTERNAL;
}

BT_EXPORT_API int bluetooth_get_bonded_device_list(GPtrArray **dev_list)
{
	int ret_val = BLUETOOTH_ERROR_NONE;

	if (dev_list == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	ret_val = bluetooth_internal_get_bonded_device_list(dev_list);
	return ret_val;
}

BT_EXPORT_API int bluetooth_get_bonded_device(const bluetooth_device_address_t *device_address,
					      bluetooth_device_info_t *dev_info)
{
	bt_info_t *bt_internal_info = NULL;
	GPtrArray *gp_array = NULL;
	GError *error = NULL;

	if (device_address == NULL || dev_info == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "ListDevices", &error,
			  	G_TYPE_INVALID,
				dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
			  	&gp_array, G_TYPE_INVALID);

	if (error == NULL) {
		if (gp_array != NULL) {
			if (gp_array->len != 0) {
				int i;
				bluetooth_device_info_t devinfo;

				DBG("Num of ListDevices = [%d]", gp_array->len);
				for (i = 0; i < gp_array->len; i++) {
					gchar *gp_path = g_ptr_array_index(gp_array, i);
					if (gp_path != NULL) {
						memset(&devinfo, 0x00,
								sizeof(bluetooth_device_info_t));

						if (__bluetooth_internal_get_bonded_device_list_details(gp_path,
												&devinfo) == 													BLUETOOTH_ERROR_NONE) {
							if (memcmp(devinfo.device_address.addr,
										device_address->addr,
									BLUETOOTH_ADDRESS_LENGTH) == 0) {
								memcpy(dev_info, &devinfo,
								       sizeof(bluetooth_device_info_t));
								g_ptr_array_free(gp_array, TRUE);
								return BLUETOOTH_ERROR_NONE;
							}
						} else {
							DBG("Can't get the paired device path \n");
							break;
						}
					}
				}
			} else {
				DBG("Num of ListDevices is 0");
			}
			g_ptr_array_free(gp_array, TRUE);
		} else {
			DBG("DBus error: \n");
			return BLUETOOTH_ERROR_INTERNAL;
		}
	} else {
		DBG("ListDevices error: [%s]\n", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	DBG("-\n");

	return BLUETOOTH_ERROR_NOT_FOUND;
}

BT_EXPORT_API int bluetooth_get_remote_device(const bluetooth_device_address_t *device_address)
{
	if (device_address == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_set_alias(const bluetooth_device_address_t *device_address,
				      const char *alias)
{
	bt_info_t *bt_internal_info = NULL;
	char addr[18] = { 0 };
	int result = BLUETOOTH_ERROR_NONE;

	const char *path = NULL;
	DBusGProxy *device_proxy = NULL;
	GValue name = { 0 };

	if (!device_address)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	_bluetooth_internal_addr_type_to_addr_string(addr, device_address);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, addr, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);

	device_proxy = _bluetooth_internal_find_device_by_path(path);

	if (device_proxy == NULL) {
		DBG("No device [%s]\n", addr);
		result = BLUETOOTH_ERROR_NOT_PAIRED;
		goto done;
	}

	g_value_init(&name, G_TYPE_STRING);
	g_value_set_string(&name, alias);

	dbus_g_proxy_call_no_reply(device_proxy, "SetProperty",
				   G_TYPE_STRING, "Alias", G_TYPE_VALUE, &name, G_TYPE_INVALID);

	g_value_unset(&name);

 done:
	return result;
}

BT_EXPORT_API int bluetooth_authorize_device(const bluetooth_device_address_t *device_address,
					     gboolean authorized)
{
	bt_info_t *bt_internal_info = NULL;
	char addr[18] = { 0 };
	int result = BLUETOOTH_ERROR_NONE;

	const char *path = NULL;
	DBusGProxy *device_proxy = NULL;
	GValue trusted = { 0 };

	if (!device_address)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	_bluetooth_internal_addr_type_to_addr_string(addr, device_address);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", NULL,
			  G_TYPE_STRING, addr, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);

	device_proxy = _bluetooth_internal_find_device_by_path(path);

	if (device_proxy == NULL) {
		DBG("No device [%s]\n", addr);
		result = BLUETOOTH_ERROR_NOT_PAIRED;
		goto done;
	}

	g_value_init(&trusted, G_TYPE_BOOLEAN);
	g_value_set_boolean(&trusted, authorized);

	dbus_g_proxy_call_no_reply(device_proxy, "SetProperty",
				   G_TYPE_STRING, "Trusted", G_TYPE_VALUE, &trusted,
				   G_TYPE_INVALID);

	g_value_unset(&trusted);

 done:
	return result;
}

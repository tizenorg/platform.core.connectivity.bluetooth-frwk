/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *              http://www.apache.org/licenses/LICENSE-2.0
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
#include <status.h>
#if !defined(LIBNOTIFY_SUPPORT) && !defined(LIBNOTIFICATION_SUPPORT)
#include <syspopup_caller.h>
#endif
#include <aul.h>

#include "alarm.h"

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-adapter.h"
#include "bt-service-util.h"
#include "bt-service-network.h"
#include "bt-service-obex-server.h"
#include "bt-service-agent.h"
#include "bt-service-main.h"
#include "bt-service-avrcp.h"

typedef struct {
	guint event_id;
	int timeout;
	time_t start_time;
	int alarm_id;
} bt_adapter_timer_t;

bt_adapter_timer_t visible_timer;
static gboolean is_discovering;
static gboolean cancel_by_user;
static bt_status_t adapter_status = BT_DEACTIVATED;
static void *adapter_agent = NULL;
static DBusGProxy *core_proxy = NULL;

#define BT_CORE_NAME "org.projectx.bt_core"
#define BT_CORE_PATH "/org/projectx/bt_core"
#define BT_CORE_INTERFACE "org.projectx.btcore"

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
			DBUS_TYPE_INT32, &result,
			DBUS_TYPE_INT16, &time_diff,
			DBUS_TYPE_INVALID);

	if (visible_timer.timeout <= time_diff) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
		visible_timer.timeout = 0;

		if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
			BT_DBG("Set vconf failed\n");
		return FALSE;
	}

	return TRUE;
}

static int __bt_visibility_alarm_cb(alarm_id_t alarm_id, void* user_param)
{
	BT_DBG("__bt_visibility_alarm_cb \n");

	/* Switch Off visibility in Bluez */
	_bt_set_discoverable_mode(BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE, 0);
	visible_timer.alarm_id = 0;
	alarmmgr_fini();
	return 0;
}

static void __bt_visibility_alarm_create()
{
	alarm_id_t alarm_id;
	int result;

	result = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, visible_timer.timeout,
						0, NULL, &alarm_id);
	if(result < 0) {
		BT_DBG("Failed to create alarm error = %d\n", result);
		alarmmgr_fini();
	} else {
		BT_DBG("Alarm created = %d\n", alarm_id);
		visible_timer.alarm_id = alarm_id;
	}
}

int __bt_set_visible_time(int timeout)
{
	int result;

	if (visible_timer.event_id > 0) {
		g_source_remove(visible_timer.event_id);
		visible_timer.event_id = 0;
	}

	if (visible_timer.alarm_id > 0) {
		alarmmgr_remove_alarm(visible_timer.alarm_id);
		visible_timer.alarm_id = 0;
	}

	visible_timer.timeout = timeout;

	if (vconf_set_int(BT_FILE_VISIBLE_TIME, timeout) != 0)
		BT_ERR("Set vconf failed\n");

	if (timeout <= 0)
		return BLUETOOTH_ERROR_NONE;

	/* Take start time */
	time(&(visible_timer.start_time));
	visible_timer.event_id = g_timeout_add_seconds(1,
				__bt_timeout_handler, NULL);

	/* Set Alarm timer to switch off BT */
	result = alarmmgr_init("bt-service");
	if (result != 0)
		return BLUETOOTH_ERROR_INTERNAL;

	result = alarmmgr_set_cb(__bt_visibility_alarm_cb, NULL);
	if (result != 0)
		return BLUETOOTH_ERROR_INTERNAL;

	__bt_visibility_alarm_create();

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_get_service_list(GValue *value, bluetooth_device_info_t *dev)
{
	int i;
	char **uuids;
	char **parts;

	ret_if(value == NULL);
	ret_if(dev == NULL);

	uuids = g_value_get_boxed(value);
	ret_if(uuids == NULL);

	dev->service_index = 0;

	for (i = 0; uuids[i] != NULL; i++) {
		g_strlcpy(dev->uuids[i], uuids[i], BLUETOOTH_UUID_STRING_MAX);

		parts = g_strsplit(uuids[i], "-", -1);

		if (parts == NULL || parts[0] == NULL)
			break;

		dev->service_list_array[i] = g_ascii_strtoull(parts[0], NULL, 16);
		g_strfreev(parts);

		dev->service_index++;
	}
}

static bt_remote_dev_info_t *__bt_parse_remote_device_info(
					DBusMessageIter *item_iter)
{
	DBusMessageIter value_iter;
	bt_remote_dev_info_t *dev_info;

	dbus_message_iter_recurse(item_iter, &value_iter);

	if (dbus_message_iter_get_arg_type(&value_iter) !=
					DBUS_TYPE_DICT_ENTRY) {
		BT_DBG("No entry");
		return NULL;
	}

	dev_info = g_malloc0(sizeof(bt_remote_dev_info_t));

	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		char *value = NULL;
		char *key;
		DBusMessageIter dict_entry;
		DBusMessageIter iter_dict_val;

		dbus_message_iter_recurse(&value_iter, &dict_entry);

		dbus_message_iter_get_basic(&dict_entry, &key);

		if (key == NULL) {
			dbus_message_iter_next(&value_iter);
			continue;
		}

		if (!dbus_message_iter_next(&dict_entry)) {
			dbus_message_iter_next(&value_iter);
			continue;
		}
		dbus_message_iter_recurse(&dict_entry, &iter_dict_val);

		if (strcasecmp(key, "Address") == 0) {
			const char *address = NULL;
			dbus_message_iter_get_basic(&iter_dict_val,
							&address);
			dev_info->address = g_strdup(address);
		} else if (strcasecmp(key, "Class") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->class);
		} else if (strcasecmp(key, "Name") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
							&value);
			if (dev_info->name == NULL)
				dev_info->name = g_strdup(value);
		} else if (strcasecmp(key, "Connected") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->connected);
		} else if (strcasecmp(key, "paired") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->paired);
		} else if (strcasecmp(key, "Trusted") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->trust);
		} else if (strcasecmp(key, "RSSI") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->rssi);
		} else if (strcasecmp(key, "UUIDs") == 0) {
			DBusMessageIter uuid_iter;
			DBusMessageIter tmp_iter;
			int i = 0;

			dbus_message_iter_recurse(&iter_dict_val,
							&uuid_iter);
			tmp_iter = uuid_iter;

			/* Store the uuid count */
			while (dbus_message_iter_get_arg_type(&tmp_iter) !=
							DBUS_TYPE_INVALID) {

				dbus_message_iter_get_basic(&tmp_iter,
								&value);

				dev_info->uuid_count++;
				if (!dbus_message_iter_next(&tmp_iter))
					break;
			}

			/* Store the uuids */
			if (dev_info->uuid_count > 0) {
				dev_info->uuids = g_new0(char *,
						dev_info->uuid_count + 1);
			} else {
				dbus_message_iter_next(&value_iter);
				continue;
			}

			while (dbus_message_iter_get_arg_type(&uuid_iter) !=
							DBUS_TYPE_INVALID) {
				dbus_message_iter_get_basic(&uuid_iter,
								&value);
				dev_info->uuids[i] = g_strdup(value);
				i++;
				if (!dbus_message_iter_next(&uuid_iter)) {
					break;
				}
			}
		}

		dbus_message_iter_next(&value_iter);
	}

	return dev_info;
}

static void __bt_extract_remote_devinfo(DBusMessageIter *msg_iter,
						GArray **dev_list)
{
	bt_remote_dev_info_t *dev_info = NULL;
	char *object_path = NULL;
	DBusMessageIter value_iter;

	/* Parse the signature:  oa{sa{sv}}} */
	ret_if(dbus_message_iter_get_arg_type(msg_iter) !=
					DBUS_TYPE_OBJECT_PATH);

	dbus_message_iter_get_basic(msg_iter, &object_path);
	ret_if(object_path == NULL);

	/* object array (oa) */
	ret_if(dbus_message_iter_next(msg_iter) == FALSE);
	ret_if(dbus_message_iter_get_arg_type(msg_iter) != DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(msg_iter, &value_iter);

	/* string array (sa) */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
					DBUS_TYPE_DICT_ENTRY) {
		char *interface_name = NULL;
		DBusMessageIter interface_iter;

		dbus_message_iter_recurse(&value_iter, &interface_iter);

		ret_if(dbus_message_iter_get_arg_type(&interface_iter) !=
							DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&interface_iter, &interface_name);

		ret_if(dbus_message_iter_next(&interface_iter) == FALSE);

		ret_if(dbus_message_iter_get_arg_type(&interface_iter) !=
							DBUS_TYPE_ARRAY);

		if (g_strcmp0(interface_name, "org.bluez.Device1") == 0) {
			BT_DBG("Found a device: %s", object_path);
			dev_info = __bt_parse_remote_device_info(
							&interface_iter);

			if (dev_info) {
				g_array_append_vals(*dev_list, dev_info,
					sizeof(bt_remote_dev_info_t));
			}
		}

		dbus_message_iter_next(&value_iter);
	}
}

int _bt_get_remote_found_devices(GArray **dev_list)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
						BT_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
		BT_ERR("Fail to iterate the reply");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		__bt_extract_remote_devinfo(&msg_iter, dev_list);

		dbus_message_iter_next(&value_iter);
	}

	return BLUETOOTH_ERROR_NONE;
}

static int __bt_get_bonded_device_info(gchar *device_path,
		bluetooth_device_info_t *dev_info)
{
	GValue *value = { 0 };
	GError *err = NULL;
	DBusGProxy *device_proxy;
	const gchar *address;
	const gchar *name;
	unsigned int cod;
	gint rssi;
	gboolean trust;
	gboolean paired;
	gboolean connected;
	GHashTable *hash = NULL;
	int ret;
	DBusGConnection *conn;

	BT_CHECK_PARAMETER(device_path, return);
	BT_CHECK_PARAMETER(dev_info, return);

	conn = _bt_get_system_gconn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	device_proxy = dbus_g_proxy_new_for_name(conn, BT_BLUEZ_NAME,
				device_path, BT_PROPERTIES_INTERFACE);

	retv_if(device_proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(device_proxy, "GetAll", &err,
				G_TYPE_STRING, BT_DEVICE_INTERFACE,
			  	G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
				G_TYPE_VALUE), &hash, G_TYPE_INVALID);

	g_object_unref(device_proxy);

	if (err != NULL) {
		BT_ERR("Error occured in Proxy call [%s]\n", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Paired");
		paired = g_value_get_boolean(value);

		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Alias");
		name = value ? g_value_get_string(value) : NULL;

		if (name != NULL)
			BT_DBG("Alias Name [%s]", name);
		else {
			value = g_hash_table_lookup(hash, "Name");
			name = value ? g_value_get_string(value) : NULL;
		}

		value = g_hash_table_lookup(hash, "Class");
		cod = value ? g_value_get_uint(value) : 0;

		value = g_hash_table_lookup(hash, "Connected");
		connected = value ? g_value_get_boolean(value) : FALSE;

		value = g_hash_table_lookup(hash, "Trusted");
		trust = value ? g_value_get_boolean(value) : FALSE;

		if ((paired == FALSE) && (trust == FALSE)) {
			return BLUETOOTH_ERROR_NOT_PAIRED;
		}

		value = g_hash_table_lookup(hash, "RSSI");
		rssi = value ? g_value_get_int(value) : 0;

		value = g_hash_table_lookup(hash, "UUIDs");
		__bt_get_service_list(value, dev_info);

		_bt_convert_addr_string_to_type(dev_info->device_address.addr,
						address);

		_bt_divide_device_class(&dev_info->device_class, cod);

		g_strlcpy(dev_info->device_name.name, name,
				BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);

		dev_info->rssi = rssi;
		dev_info->trust = trust;
		dev_info->paired = paired;
		dev_info->connected = connected;
		g_hash_table_destroy(hash);
		ret = BLUETOOTH_ERROR_NONE;
	} else {
		BT_ERR("Hash is NULL\n");
		ret = BLUETOOTH_ERROR_INTERNAL;
	}

	return ret;
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

static void __bt_flight_mode_cb(keynode_t *node, void *data)
{
	gboolean flight_mode = FALSE;
	int bt_status;

	BT_DBG("key=%s\n", vconf_keynode_get_name(node));

	bt_status = _bt_adapter_get_status();

	if (vconf_keynode_get_type(node) == VCONF_TYPE_BOOL) {
		flight_mode = vconf_keynode_get_bool(node);

		BT_DBG("value=%d\n", flight_mode);

		if (flight_mode == TRUE) {
			BT_DBG("Deactivate Bluetooth Service\n");
			if (vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 1) != 0)
				BT_DBG("Set vconf failed+\n");

			if (bt_status == BT_ACTIVATED)
				_bt_disable_adapter();
		} else {

			int value = 0;

			if (vconf_get_int(BT_OFF_DUE_TO_FLIGHT_MODE, &value))
				BT_ERR("Fail get flight mode value");

			if (value == 0)
				return;

			BT_DBG("Activate Bluetooth Service\n");
			if (vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 0))
				BT_DBG("Set vconf failed\n");

			if (bt_status == BT_DEACTIVATED)
				_bt_enable_adapter();
		}
	}
}

static void __launch_bt_service(int status, int run_type)
{
	bundle *kb;
	char status_val[5] = { 0, };
	char run_type_val[5] = { 0, };

	snprintf(status_val, sizeof(status_val), "%d", status);
	snprintf(run_type_val, sizeof(run_type_val), "%d", run_type);

	BT_DBG("status: %s, run_type: %s", status_val, run_type_val);

	kb = bundle_create();

	bundle_add(kb, "launch-type", "setstate");
	bundle_add(kb, "status", status_val);
	bundle_add(kb, "run-type", run_type_val);

	aul_launch_app("com.samsung.bluetooth", kb);

	bundle_free(kb);
}

static void __bt_adapter_set_status(bt_status_t status)
{
	adapter_status = status;
}

bt_status_t _bt_adapter_get_status(void)
{
	return adapter_status;
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

static void __bt_set_visible_mode(void)
{
	int timeout;

	if (vconf_get_int(BT_FILE_VISIBLE_TIME, &timeout) != 0)
                BT_ERR("Fail to get the timeout value");

	/* -1: Always on */
	if (timeout == -1) {
	        if (_bt_set_discoverable_mode(
			BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE,
			timeout) != BLUETOOTH_ERROR_NONE) {
	                if (vconf_set_int(BT_FILE_VISIBLE_TIME, 0) != 0)
	                        BT_ERR("Set vconf failed");
	        }
	}
}

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
	int enabled = FALSE;
	int result = BLUETOOTH_ERROR_NONE;

	_bt_check_adapter(&enabled);

	if (enabled == FALSE) {
		BT_ERR("Bluetoothd is not running");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__bt_set_visible_mode();

	__bt_set_local_name();

	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_ON) != 0)
		BT_ERR("Set vconf failed\n");

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		BT_ERR("Set vconf failed\n");

	/* Send enabled event to API */
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_ENABLED,
				DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_set_disabled(int result)
{
	/* Update Bluetooth Status to notify other modules */
	if (vconf_set_int(VCONFKEY_BT_STATUS, VCONFKEY_BT_STATUS_OFF) != 0)
		BT_ERR("Set vconf failed\n");

	if (vconf_set_int(VCONFKEY_BT_DEVICE, VCONFKEY_BT_DEVICE_NONE) != 0)
		BT_ERR("Set vconf failed\n");

	/* Send disabled event */
	_bt_send_event(BT_ADAPTER_EVENT, BLUETOOTH_EVENT_DISABLED,
				DBUS_TYPE_INT32, &result, DBUS_TYPE_INVALID);
}

void *_bt_get_adapter_agent(void)
{
	return adapter_agent;
}

void _bt_handle_flight_mode_noti(void)
{
	BT_DBG("+");
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__bt_flight_mode_cb, NULL);
	BT_DBG("-");
}

void _bt_handle_adapter_added(void)
{
	 adapter_agent = _bt_create_agent(BT_ADAPTER_AGENT_PATH, TRUE);
	 if (!adapter_agent) {
		BT_ERR("Fail to register agent");
		return;
	 }

#ifdef __TIZEN_MOBILE__
	if (_bt_register_media_player() != BLUETOOTH_ERROR_NONE)
		BT_ERR("Fail to register media player");
#endif

	if (_bt_register_obex_server() != BLUETOOTH_ERROR_NONE)
		BT_ERR("Fail to init obex server");
/*
	if (_bt_network_activate() != BLUETOOTH_ERROR_NONE)
		BT_ERR("Fail to activate network");
*/

	/* add the vconf noti handler */
	vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
					__bt_phone_name_changed_cb, NULL);

	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__bt_flight_mode_cb, NULL);

	__bt_set_enabled();

	__bt_adapter_set_status(BT_ACTIVATED);
}

void _bt_handle_adapter_removed(void)
{
	__bt_adapter_set_status(BT_DEACTIVATED);

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
				(vconf_callback_fn)__bt_phone_name_changed_cb);

	_bt_destroy_agent(adapter_agent);
	adapter_agent = NULL;

	__bt_set_disabled(BLUETOOTH_ERROR_NONE);

	_bt_terminate_service(NULL);
}

DBusGProxy *_bt_init_core_proxy(void)
{
       DBusGProxy *proxy;
	DBusGConnection *conn;

	conn = _bt_get_system_gconn();
	if (!conn)
		return NULL;

       proxy = dbus_g_proxy_new_for_name(conn, BT_CORE_NAME,
                       BT_CORE_PATH, BT_CORE_INTERFACE);
	if (!proxy)
		return NULL;

       core_proxy = proxy;

       return proxy;
}

static DBusGProxy *__bt_get_core_proxy(void)
{
       return (core_proxy) ? core_proxy : _bt_init_core_proxy();
}

gboolean __bt_enable_timeout_cb(gpointer user_data)
{
	DBusGProxy *proxy;

	retv_if(_bt_adapter_get_status() == BT_ACTIVATED, FALSE);

	proxy = __bt_get_core_proxy();
	if (!proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	/* Clean up the process */
	if (dbus_g_proxy_call(proxy, "DisableAdapter", NULL,
			G_TYPE_INVALID, G_TYPE_INVALID) == FALSE) {
			BT_ERR("Bt core call failed");
	}

	__bt_adapter_set_status(BT_DEACTIVATED);

	__bt_set_disabled(BLUETOOTH_ERROR_TIMEOUT);

	/* Display notification */
	status_message_post(BT_STR_NOT_SUPPORT);

	_bt_terminate_service(NULL);

	return FALSE;
}

int _bt_enable_adapter(void)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	BT_DBG("");

	if (_bt_adapter_get_status() == BT_ACTIVATING) {
			BT_DBG("Enabling in progress");
			return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (_bt_adapter_get_status() == BT_ACTIVATED) {
			BT_DBG("Already enabled");
			return BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED;
	}

	__bt_adapter_set_status(BT_ACTIVATING);

	proxy = __bt_get_core_proxy();
	if (!proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	 if (dbus_g_proxy_call_with_timeout(proxy, "EnableAdapter",
					BT_ENABLE_TIMEOUT, &err,
					G_TYPE_INVALID,
					G_TYPE_INVALID) == FALSE) {

		__bt_adapter_set_status(BT_DEACTIVATED);

		if (err != NULL) {
			BT_ERR("Bt core call failed: [%s]", err->message);
			g_error_free(err);
		}

		/* Clean up the process */
		if (dbus_g_proxy_call(proxy, "DisableAdapter", NULL,
				G_TYPE_INVALID, G_TYPE_INVALID) == FALSE) {
				BT_ERR("Bt core call failed");
		}

		/* Display notification */
		status_message_post(BT_STR_NOT_SUPPORT);

		/* Terminate myself */
		g_idle_add((GSourceFunc)_bt_terminate_service, NULL);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_timeout_add(BT_ENABLE_TIMEOUT,
			(GSourceFunc)__bt_enable_timeout_cb,
			NULL);

	return BLUETOOTH_ERROR_NONE;
}

int _bt_disable_adapter(void)
{
	DBusGProxy *proxy;

	BT_DBG("");

	if (_bt_adapter_get_status() == BT_DEACTIVATING) {
			BT_DBG("Disabling in progress");
			return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	if (_bt_adapter_get_status() == BT_DEACTIVATED) {
			BT_DBG("Already disabled");
			return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	__bt_adapter_set_status(BT_DEACTIVATING);

	proxy = __bt_get_core_proxy();
	if (!proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	if (dbus_g_proxy_call(proxy, "DisableAdapter", NULL,
	                               G_TYPE_INVALID, G_TYPE_INVALID) == FALSE) {
		BT_ERR("Bt core call failed");
		__bt_adapter_set_status(BT_ACTIVATED);
		return BLUETOOTH_ERROR_INTERNAL;
       }

	return BLUETOOTH_ERROR_NONE;
}

int _bt_reset_adapter(void)
{
	DBusGProxy *proxy;

	BT_DBG("");

	proxy = __bt_get_core_proxy();
	if (!proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	if (dbus_g_proxy_call(proxy, "ResetAdapter", NULL,
	                               G_TYPE_INVALID, G_TYPE_INVALID) == FALSE) {
		BT_ERR("Bt core call failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	/* Terminate myself */
	if (_bt_adapter_get_status() == BT_DEACTIVATED) {
		g_idle_add((GSourceFunc)_bt_terminate_service, NULL);
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_check_adapter(int *status)
{
	char *adapter_path = NULL;

	BT_CHECK_PARAMETER(status, return);

	*status = 0; /* 0: disabled */

	adapter_path = _bt_get_adapter_path();

	if (adapter_path != NULL)
		*status = 1; /* 1: enabled */

	g_free(adapter_path);
	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_local_address(bluetooth_device_address_t *local_address)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	char *address;
	GValue address_v = { 0 };

	BT_CHECK_PARAMETER(local_address, return);

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Address",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &address_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	address = (char *)g_value_get_string(&address_v);

	if (address) {
		_bt_convert_addr_string_to_type(local_address->addr, address);
	} else {
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_local_name(bluetooth_device_name_t *local_name)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	GValue name_v = { 0 };
	char *name = NULL;
	char *ptr = NULL;
	int ret = BLUETOOTH_ERROR_NONE;

	BT_CHECK_PARAMETER(local_name, return);

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Alias",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &name_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	name = (char *)g_value_get_string(&name_v);

	if (name && (strlen(name) > 0)) {
		/* Check the utf8 valitation & Fill the NULL in the invalid location*/
		if (!g_utf8_validate(name, -1, (const char **)&ptr))
			*ptr = '\0';

		g_strlcpy(local_name->name, name,
				BLUETOOTH_DEVICE_NAME_LENGTH_MAX + 1);
	} else {
		ret = BLUETOOTH_ERROR_INTERNAL;
	}

	return ret;
}

int _bt_set_local_name(char *local_name)
{
	GValue name = { 0 };
	DBusGProxy *proxy;
	GError *error = NULL;
	char *ptr = NULL;

	BT_CHECK_PARAMETER(local_name, return);

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!g_utf8_validate(local_name, -1, (const char **)&ptr))
		*ptr = '\0';

	g_value_init(&name, G_TYPE_STRING);
	g_value_set_string(&name, local_name);

	dbus_g_proxy_call(proxy, "Set", &error,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Alias",
			G_TYPE_VALUE, &name,
			G_TYPE_INVALID, G_TYPE_INVALID);

	g_value_unset(&name);

	if (error) {
		BT_ERR("SetProperty Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_is_service_used(char *service_uuid, gboolean *used)
{
	char **uuids;
	int i;
	DBusGProxy *proxy;
	GHashTable *hash = NULL;
	GValue *value;
	int ret = BLUETOOTH_ERROR_NONE;

	BT_CHECK_PARAMETER(service_uuid, return);
	BT_CHECK_PARAMETER(used, return);

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	dbus_g_proxy_call(proxy, "GetProperties", NULL,
			  G_TYPE_INVALID,
			  dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
			  G_TYPE_VALUE), &hash, G_TYPE_INVALID);

	retv_if(hash == NULL, BLUETOOTH_ERROR_INTERNAL);

	value = g_hash_table_lookup(hash, "UUIDs");
	uuids = g_value_get_boxed(value);

	if (uuids == NULL) {
		/* Normal case */
		*used = FALSE;
		goto done;
	}

	for (i = 0; uuids[i] != NULL; i++) {
		if (strcasecmp(uuids[i], service_uuid) == 0) {
			*used = TRUE;
			goto done;
		}
	}

	*used = FALSE;
done:
	g_hash_table_destroy(hash);
	return ret;
}

static gboolean __bt_get_discoverable_property(void)
{
	DBusGProxy *proxy;
	GValue discoverable_v = { 0 };
	GError *err = NULL;

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Discoverable",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &discoverable_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return g_value_get_boolean(&discoverable_v);
}

int _bt_get_discoverable_mode(int *mode)
{
	gboolean discoverable;
	unsigned int timeout;

	BT_CHECK_PARAMETER(mode, return);

	discoverable = __bt_get_discoverable_property();
	timeout = _bt_get_discoverable_timeout_property();

	if (discoverable == TRUE) {
		if (timeout == 0)
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
	gboolean inq_scan;
	gboolean pg_scan;
	GError *error = NULL;
	GValue connectable = { 0 };
	GValue discoverable = { 0 };
	GValue val_timeout = { 0 };
	DBusGProxy *proxy;

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	g_value_init(&connectable, G_TYPE_BOOLEAN);
	g_value_init(&discoverable, G_TYPE_BOOLEAN);
	g_value_init(&val_timeout, G_TYPE_UINT);

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
	}

	g_value_set_boolean(&connectable, pg_scan);
	g_value_set_boolean(&discoverable, inq_scan);
	g_value_set_uint(&val_timeout, timeout);

	dbus_g_proxy_call(proxy, "Set", &error,
				G_TYPE_STRING, BT_ADAPTER_INTERFACE,
				G_TYPE_STRING, "Powered",
				G_TYPE_VALUE, &connectable,
				G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		BT_ERR("Powered set err:[%s]", error->message);
		g_error_free(error);
		ret = BLUETOOTH_ERROR_INTERNAL;
		goto done;
	}

	dbus_g_proxy_call(proxy, "Set", &error,
				G_TYPE_STRING, BT_ADAPTER_INTERFACE,
				G_TYPE_STRING, "Discoverable",
				G_TYPE_VALUE, &discoverable,
				G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		BT_ERR("Discoverable set err:[%s]", error->message);
		g_error_free(error);
		ret = BLUETOOTH_ERROR_INTERNAL;
		goto done;
	}

	dbus_g_proxy_call(proxy, "Set", &error,
				G_TYPE_STRING, BT_ADAPTER_INTERFACE,
				G_TYPE_STRING, "DiscoverableTimeout",
				G_TYPE_VALUE, &val_timeout,
				G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		BT_ERR("Timeout set err:[%s]", error->message);
		g_error_free(error);
		ret = BLUETOOTH_ERROR_INTERNAL;
		goto done;
	}

	if (discoverable_mode == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE)
		timeout = -1;

	__bt_set_visible_time(timeout);

done:
	g_value_unset(&val_timeout);
	g_value_unset(&connectable);
	g_value_unset(&discoverable);

	return ret;
}

int _bt_start_discovery(void)
{
	DBusGProxy *proxy;

	if (_bt_is_discovering() == TRUE) {
		BT_ERR("BT is already in discovering");
		return BLUETOOTH_ERROR_IN_PROGRESS;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "StartDiscovery", NULL,
			       G_TYPE_INVALID, G_TYPE_INVALID)) {
		BT_ERR("Discover start failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	_bt_stop_discovery_timeout();

	is_discovering = TRUE;
	cancel_by_user = FALSE;
	/* discovery status will be change in event */

	return BLUETOOTH_ERROR_NONE;
}

int _bt_cancel_discovery(void)
{
	DBusGProxy *proxy;

	if (_bt_is_discovering() == FALSE) {
		BT_ERR("BT is not in discovering");
		return BLUETOOTH_ERROR_NOT_IN_OPERATION;
	}

	proxy = _bt_get_adapter_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "StopDiscovery", NULL,
			       G_TYPE_INVALID, G_TYPE_INVALID)) {
		BT_ERR("Discover stop failed");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	cancel_by_user = TRUE;
	/* discovery status will be change in event */

	return BLUETOOTH_ERROR_NONE;
}

gboolean _bt_is_discovering(void)
{
	return is_discovering;
}

gboolean _bt_get_discovering_property(void)
{
	DBusGProxy *proxy;
	GValue discovering_v = { 0 };
	GError *err = NULL;

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "Discovering",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &discovering_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return g_value_get_boolean(&discovering_v);
}

unsigned int _bt_get_discoverable_timeout_property(void)
{
	DBusGProxy *proxy;
	GValue timeout_v = { 0 };
	GError *err = NULL;

	proxy = _bt_get_adapter_properties_proxy();
	retv_if(proxy == NULL, 0);

	if (!dbus_g_proxy_call(proxy, "Get", &err,
			G_TYPE_STRING, BT_ADAPTER_INTERFACE,
			G_TYPE_STRING, "DiscoverableTimeout",
			G_TYPE_INVALID,
			G_TYPE_VALUE, &timeout_v,
			G_TYPE_INVALID)) {
		if (err != NULL) {
			BT_ERR("Getting property failed: [%s]\n", err->message);
			g_error_free(err);
		}
		return 0;
	}

	return g_value_get_uint(&timeout_v);
}

static bluetooth_device_info_t *__bt_parse_device_info(DBusMessageIter *item_iter)
{
	DBusMessageIter value_iter;
	bluetooth_device_info_t *dev_info;

	dbus_message_iter_recurse(item_iter, &value_iter);

	if (dbus_message_iter_get_arg_type(&value_iter) != DBUS_TYPE_DICT_ENTRY) {
		BT_DBG("No entry");
		return NULL;
	}

	dev_info = g_malloc0(sizeof(bluetooth_device_info_t));

	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		char *value = NULL;
		char *key;
		DBusMessageIter dict_entry;
		DBusMessageIter iter_dict_val;

		dbus_message_iter_recurse(&value_iter, &dict_entry);

		dbus_message_iter_get_basic(&dict_entry, &key);

		if (key == NULL) {
			dbus_message_iter_next(&value_iter);
			continue;
		}

		if (!dbus_message_iter_next(&dict_entry)) {
			dbus_message_iter_next(&value_iter);
			continue;
		}
		dbus_message_iter_recurse(&dict_entry, &iter_dict_val);

		if (strcasecmp(key, "Address") == 0) {
			const char *address = NULL;
			dbus_message_iter_get_basic(&iter_dict_val, &address);
			_bt_convert_addr_string_to_type(dev_info->device_address.addr,
							address);

		} else if (strcasecmp(key, "Class") == 0) {
			unsigned int cod;
			dbus_message_iter_get_basic(&iter_dict_val, &cod);
			_bt_divide_device_class(&dev_info->device_class, cod);
		} else if (strcasecmp(key, "Name") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val, &value);

			/* If there is no Alias */
			if (strlen(dev_info->device_name.name) == 0) {
				g_strlcpy(dev_info->device_name.name, value,
						BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);
			}
		} else if (strcasecmp(key, "Alias") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val, &value);

			/* Overwrite the name */
			if (value) {
				memset(dev_info->device_name.name, 0x00,
						BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);
				g_strlcpy(dev_info->device_name.name, value,
						BLUETOOTH_DEVICE_NAME_LENGTH_MAX+1);
			}
		} else if (strcasecmp(key, "Connected") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->connected);
		} else if (strcasecmp(key, "paired") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->paired);
		} else if (strcasecmp(key, "Trusted") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->trust);
		} else if (strcasecmp(key, "RSSI") == 0) {
			dbus_message_iter_get_basic(&iter_dict_val,
						&dev_info->rssi);
		} else if (strcasecmp(key, "UUIDs") == 0) {
			DBusMessageIter uuid_iter;
			char **parts;
			int i = 0;

			dbus_message_iter_recurse(&iter_dict_val, &uuid_iter);

			while (dbus_message_iter_get_arg_type(&uuid_iter) != DBUS_TYPE_INVALID) {
				dbus_message_iter_get_basic(&uuid_iter,
							&value);

				g_strlcpy(dev_info->uuids[i], value,
						BLUETOOTH_UUID_STRING_MAX);

				parts = g_strsplit(value, "-", -1);

				if (parts == NULL || parts[0] == NULL)
					break;

				dev_info->service_list_array[i] = g_ascii_strtoull(parts[0], NULL, 16);
				g_strfreev(parts);

				i++;
				if (!dbus_message_iter_next(&uuid_iter)) {
					break;
				}
			}

			dev_info->service_index = i;
		}

		dbus_message_iter_next(&value_iter);
	}

	return dev_info;
}

static void __bt_extract_device_info(DBusMessageIter *msg_iter,
							GArray **dev_list)
{
	bluetooth_device_info_t *dev_info = NULL;
	char *object_path = NULL;
	DBusMessageIter value_iter;

	/* Parse the signature:  oa{sa{sv}}} */
	ret_if(dbus_message_iter_get_arg_type(msg_iter) !=
				DBUS_TYPE_OBJECT_PATH);

	dbus_message_iter_get_basic(msg_iter, &object_path);
	ret_if(object_path == NULL);

	/* object array (oa) */
	ret_if(dbus_message_iter_next(msg_iter) == FALSE);
	ret_if(dbus_message_iter_get_arg_type(msg_iter) != DBUS_TYPE_ARRAY);

	dbus_message_iter_recurse(msg_iter, &value_iter);

	/* string array (sa) */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
					DBUS_TYPE_DICT_ENTRY) {
		char *interface_name = NULL;
		DBusMessageIter interface_iter;

		dbus_message_iter_recurse(&value_iter, &interface_iter);

		ret_if(dbus_message_iter_get_arg_type(&interface_iter) !=
							DBUS_TYPE_STRING);

		dbus_message_iter_get_basic(&interface_iter, &interface_name);

		ret_if(dbus_message_iter_next(&interface_iter) == FALSE);

		ret_if(dbus_message_iter_get_arg_type(&interface_iter) !=
							DBUS_TYPE_ARRAY);

		if (g_strcmp0(interface_name, "org.bluez.Device1") == 0) {
			BT_DBG("Found a device: %s", object_path);
			dev_info = __bt_parse_device_info(&interface_iter);

			if (dev_info) {
				if (dev_info->paired == TRUE) {
					g_array_append_vals(*dev_list, dev_info,
							sizeof(bluetooth_device_info_t));
				} else {
					g_free(dev_info);
				}
			}

			return;
		}

		dbus_message_iter_next(&value_iter);
	}

	BT_DBG("There is no device interface");
}

int _bt_get_bonded_devices(GArray **dev_list)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter value_iter;
	DBusError err;
	DBusConnection *conn;

	conn = _bt_get_system_conn();
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	msg = dbus_message_new_method_call(BT_BLUEZ_NAME, BT_MANAGER_PATH,
						BT_MANAGER_INTERFACE,
						"GetManagedObjects");

	retv_if(msg == NULL, BLUETOOTH_ERROR_INTERNAL);

	/* Synchronous call */
	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(
					conn, msg,
					-1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		BT_ERR("Can't get managed objects");

		if (dbus_error_is_set(&err)) {
			BT_ERR("%s", err.message);
			dbus_error_free(&err);
		}
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (dbus_message_iter_init(reply, &reply_iter) == FALSE) {
	    BT_ERR("Fail to iterate the reply");
	    return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_message_iter_recurse(&reply_iter, &value_iter);

	/* signature of GetManagedObjects:  a{oa{sa{sv}}} */
	while (dbus_message_iter_get_arg_type(&value_iter) ==
						DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter msg_iter;

		dbus_message_iter_recurse(&value_iter, &msg_iter);

		__bt_extract_device_info(&msg_iter, dev_list);

		dbus_message_iter_next(&value_iter);
	}

	return BLUETOOTH_ERROR_NONE;
}

int _bt_get_bonded_device_info(bluetooth_device_address_t *device_address,
				bluetooth_device_info_t *dev_info)
{
	char *object_path = NULL;
	DBusGProxy *adapter_proxy;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	BT_CHECK_PARAMETER(device_address, return);
	BT_CHECK_PARAMETER(dev_info, return);

	adapter_proxy = _bt_get_adapter_proxy();
	retv_if(adapter_proxy == NULL, BLUETOOTH_ERROR_INTERNAL);

	_bt_convert_addr_type_to_string(address, device_address->addr);

	object_path = _bt_get_device_object_path(address);

	retv_if(object_path == NULL, BLUETOOTH_ERROR_NOT_FOUND);

	if (__bt_get_bonded_device_info(object_path,
				dev_info) != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Can't get the paired device path \n");
		g_free(object_path);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	g_free(object_path);
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


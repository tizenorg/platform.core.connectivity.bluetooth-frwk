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

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <stacktrim.h>
#include <syspopup_caller.h>

#include "bluetooth-agent.h"
#include "sc_core_agent.h"

extern struct bt_agent_appdata *app_data;

#define BT_APP_AUTHENTICATION_TIMEOUT		35
#define BT_APP_AUTHORIZATION_TIMEOUT		15

#define HFP_AUDIO_GATEWAY_UUID "0000111f-0000-1000-8000-00805f9b34fb"
#define A2DP_UUID "0000110D-0000-1000-8000-00805F9B34FB"

#define BT_PIN_MAX_LENGTH 16
#define BT_PASSKEY_MAX_LENGTH 6

#define BT_AGENT_SYSPOPUP_TIMEOUT_FOR_MULTIPLE_POPUPS 200

static int __bt_agent_is_auto_response(uint32_t dev_class, const gchar *address);
static const int __bt_agent_is_hid_keyboard(uint32_t dev_class);

static void __bt_agent_release_memory(void)
{
	/* Release Malloc Memory*/
	malloc_trim(0);

	/* Release Stack Memory*/
	stack_trim();
}

static void __bt_agent_show_confirm_mode_request(const char *mode, const char *sender,
					       gboolean need_popup, void *data)
{
	bt_agent_changed_mode_type_t changed_mode = 0;

	if (strcasecmp(mode, "enable") == 0) {
		changed_mode = BT_AGENT_CHANGED_MODE_ENABLE;
	} else if (strcasecmp(mode, "disable") == 0) {
		changed_mode = BT_AGENT_CHANGED_MODE_DISABLE;
	} else {
		sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(), changed_mode,
						   SC_CORE_AGENT_REJECT, NULL);
		return;
	}

	sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(), changed_mode,
					   SC_CORE_AGENT_ACCEPT, NULL);
}

static gboolean __bt_agent_system_popup_timer_cb(gpointer user_data)
{
	int ret = 0;
	bundle *b = (bundle *) user_data;

	if (NULL == b) {
		DBG("There is some problem with the user data..popup can not be created\n");
		return FALSE;
	}
	ret = syspopup_launch("bt-syspopup", b);

	if (0 > ret) {
		DBG("Sorry Can not launch popup\n");
		return TRUE;
	} else {
		DBG("Hurray Popup launched \n");
		bundle_free(b);
		return FALSE;
	}
}

int _bt_agent_launch_system_popup(bt_agent_event_type_t event_type, const char *device_name,
				 char *passkey, const char *filename)
{
	int ret = 0;
	bundle *b = NULL;
	char event_str[BT_MAX_EVENT_STR_LENGTH + 1] = { 0 };

	DBG("_bt_agent_launch_system_popup +");

	b = bundle_create();

	bundle_add(b, "device-name", device_name);
	bundle_add(b, "passkey", passkey);
	bundle_add(b, "file", filename);

	switch (event_type) {
	case BT_AGENT_EVENT_PIN_REQUEST:
		strncpy(event_str, "pin-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST:
		strncpy(event_str, "passkey-confirm-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_PASSKEY_REQUEST:
		strncpy(event_str, "passkey-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_PASSKEY_DISPLAY_REQUEST:
		strncpy(event_str, "passkey-display-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_AUTHORIZE_REQUEST:
		strncpy(event_str, "authorize-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_CONFIRM_MODE_REQUEST:
		strncpy(event_str, "confirm-mode-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_FILE_RECIEVED:
		strncpy(event_str, "file-recieved", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST:
		strncpy(event_str, "keyboard-passkey-request", BT_MAX_EVENT_STR_LENGTH);
		break;

	case BT_AGENT_EVENT_TERMINATE:
		strncpy(event_str, "terminate", BT_MAX_EVENT_STR_LENGTH);
		break;

	default:

		break;

	}

	bundle_add(b, "event-type", event_str);

	ret = syspopup_launch("bt-syspopup", b);
	if (0 > ret) {
		DBG("Popup launch failed...retry %d\n", ret);
		g_timeout_add(BT_AGENT_SYSPOPUP_TIMEOUT_FOR_MULTIPLE_POPUPS,
			      (GSourceFunc) __bt_agent_system_popup_timer_cb, b);
	} else {
		bundle_free(b);
	}

	DBG("_bt_agent_launch_system_popup -%d", ret);
	return 0;
}

static gboolean __pincode_request(DBusGProxy *device)
{
	uint32_t device_class;
	GHashTable *hash = NULL;
	GValue *value;
	const gchar *address, *name;
	GError *error = NULL;

	DBG("+\n");

	dbus_g_proxy_call(device, "GetProperties", &error,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Class");
		device_class = value ? g_value_get_uint(value) : 0;

		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;

		if (__bt_agent_is_auto_response(device_class, address)) {
			/* Use Fixed PIN "0000" for basic pairing*/
			sc_core_agent_reply_pin_code(_sc_core_agent_get_proxy(),
						     SC_CORE_AGENT_ACCEPT, "0000", NULL);
		} else if (__bt_agent_is_hid_keyboard(device_class)) {
			char str_passkey[7] = { 0 };

			bt_agent_generate_passkey(str_passkey, sizeof(str_passkey));

			if (name)
				_bt_agent_launch_system_popup(BT_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST,
							(const char *)name, str_passkey, NULL);
			else
				_bt_agent_launch_system_popup(BT_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST,
							(const char *)address, str_passkey, NULL);
		} else {
			value = g_hash_table_lookup(hash, "Name");
			name = value ? g_value_get_string(value) : NULL;

			if (!name && !address)
				sc_core_agent_reply_pin_code(_sc_core_agent_get_proxy(),
							     SC_CORE_AGENT_REJECT, "", NULL);

			if (name)
				_bt_agent_launch_system_popup(BT_AGENT_EVENT_PIN_REQUEST,
							     (const char *)name, NULL, NULL);
			else
				_bt_agent_launch_system_popup(BT_AGENT_EVENT_PIN_REQUEST,
							     (const char *)address, NULL, NULL);

		}
	} else {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
		sc_core_agent_reply_pin_code(_sc_core_agent_get_proxy(), SC_CORE_AGENT_REJECT, "",
					     NULL);
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __passkey_request(DBusGProxy *device)
{
	GHashTable *hash = NULL;
	GValue *value;
	const gchar *address, *name;
	GError *error = NULL;

	DBG("+\n");

	dbus_g_proxy_call(device, "GetProperties", &error,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;

		if (!name && !address)
			sc_core_agent_reply_passkey(_sc_core_agent_get_proxy(),
						    SC_CORE_AGENT_REJECT, "", NULL);

		if (name)
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_PASSKEY_REQUEST,
						     (const char *)name, NULL, NULL);
		else
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_PASSKEY_REQUEST,
						     (const char *)address, NULL, NULL);

	} else {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
		sc_core_agent_reply_passkey(_sc_core_agent_get_proxy(), SC_CORE_AGENT_REJECT, "",
					    NULL);
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __display_request(DBusGProxy *device, guint passkey, guint entered)
{
	GHashTable *hash = NULL;
	GValue *value;
	const gchar *address, *name;
	GError *error = NULL;

	DBG("+\n");

	dbus_g_proxy_call(device, "GetProperties", &error,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;
	} else {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __confirm_request(DBusGProxy *device, guint passkey)
{
	GHashTable *hash = NULL;
	GValue *value;
	const gchar *address, *name;
	GError *error = NULL;
	char str_passkey[7] = { 0 };

	DBG("+ passkey[%.6d]\n", passkey);

	snprintf(str_passkey, sizeof(str_passkey), "%.6d", passkey);

	dbus_g_proxy_call(device, "GetProperties", &error,
				G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;

		if (name != NULL)
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST,
						     (const char *)name, str_passkey, NULL);
		else if (address != NULL)
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST,
						     (const char *)address, str_passkey, NULL);
		else
			sc_core_agent_reply_confirmation(_sc_core_agent_get_proxy(),
							 SC_CORE_AGENT_REJECT, NULL);
	} else {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
		sc_core_agent_reply_confirmation(_sc_core_agent_get_proxy(), SC_CORE_AGENT_REJECT,
						 NULL);
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __pairing_cancel_request(const char *address)
{
	DBG("On Going Pairing is cancelled by remote\n");

	sc_core_agent_reply_pin_code(_sc_core_agent_get_proxy(), SC_CORE_AGENT_CANCEL, "", NULL);

	_bt_agent_launch_system_popup(BT_AGENT_EVENT_TERMINATE, NULL, NULL, NULL);

	__bt_agent_release_memory();

	return TRUE;
}

static gboolean __authorize_request(DBusGProxy *device, const char *uuid)
{
	GHashTable *hash = NULL;
	GValue *value;
	const gchar *address, *name;
	gboolean trust = FALSE;
	GError *error = NULL;

	DBG("+\n");

	if (!strcasecmp(uuid, HFP_AUDIO_GATEWAY_UUID) || !strcasecmp(uuid, A2DP_UUID)) {
		DBG("In case of audio device(HFP,A2DP), we authorize the request [%s]\n", uuid);
		sc_core_agent_reply_authorize(_sc_core_agent_get_proxy(), SC_CORE_AGENT_ACCEPT,
					      NULL);

		return TRUE;
	}

	dbus_g_proxy_call(device, "GetProperties", &error, G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Name");
		name = value ? g_value_get_string(value) : NULL;

		value = g_hash_table_lookup(hash, "Trusted");
		trust = value ? g_value_get_boolean(value) : 0;

		DBG("Authorization request for device [%s] Service:[%s]\n", address, uuid);

		if (trust) {
			DBG("Trusted device, so authorize\n");
			sc_core_agent_reply_authorize(_sc_core_agent_get_proxy(),
						      SC_CORE_AGENT_ACCEPT, NULL);
		} else if (name != NULL)
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_AUTHORIZE_REQUEST,
						     (const char *)name, NULL, NULL);
		else if (address != NULL)
			_bt_agent_launch_system_popup(BT_AGENT_EVENT_AUTHORIZE_REQUEST,
						     (const char *)address, NULL, NULL);
		else
			sc_core_agent_reply_authorize(_sc_core_agent_get_proxy(),
						      SC_CORE_AGENT_REJECT, NULL);
	} else {
		DBG("error in GetBasicProperties [%s]\n", error->message);
		g_error_free(error);
		error = NULL;
		sc_core_agent_reply_authorize(_sc_core_agent_get_proxy(), SC_CORE_AGENT_REJECT,
					      NULL);
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __authorization_cancel_request(const char *address)
{
	DBG("On Going Authorization is cancelled by remote\n");

	sc_core_agent_reply_authorize(_sc_core_agent_get_proxy(), SC_CORE_AGENT_CANCEL, NULL);

	_bt_agent_launch_system_popup(BT_AGENT_EVENT_TERMINATE, NULL, NULL, NULL);

	__bt_agent_release_memory();

	return TRUE;
}

static gboolean __confirm_mode_request(const char *mode, const char *sender, gboolean need_popup,
				     void *data)
{
	DBG("+\n");

	if (mode != NULL) {
		__bt_agent_show_confirm_mode_request(mode, sender, need_popup, data);
	} else {
		DBG("Wrong mode requested [%s]\n", mode);
		sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(),
						   BT_AGENT_CHANGED_MODE_ENABLE,
						   SC_CORE_AGENT_REJECT, NULL);
	}

	__bt_agent_release_memory();

	DBG("-\n");

	return TRUE;
}

static gboolean __ignore_auto_pairing_request(const char *address)
{
	DBG("+\n");

	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)app_data;

	if (address == NULL)
		return FALSE;

	/* To input the pin code, if headset does not have '0000' pin code */
	ad->ignore_auto_pairing = 1;
	memset(ad->bonding_addr, 0x00, BT_AGENT_ADDR_SIZE + 1);
	strncpy(ad->bonding_addr, address, BT_AGENT_ADDR_SIZE);

	DBG("-\n");

	return TRUE;
}

void _bt_agent_register(DBusGProxy *adapter_proxy)
{
	SC_CORE_AGENT_FUNC_CB func_cb = { 0 };

	func_cb.pincode_func = __pincode_request;
	func_cb.display_func = __display_request;
	func_cb.passkey_func = __passkey_request;
	func_cb.confirm_func = __confirm_request;
	func_cb.authorize_func = __authorize_request;
	func_cb.pairing_cancel_func = __pairing_cancel_request;
	func_cb.authorization_cancel_func = __authorization_cancel_request;
	func_cb.confirm_mode_func = __confirm_mode_request;
	func_cb.ignore_auto_pairing_func = __ignore_auto_pairing_request;

	if (_sc_core_agent_add(adapter_proxy, &func_cb) < 0) {
		if (adapter_proxy == NULL) {
			return;
		}
		ERR("Agent register failed, Agent finish.\n");
	}

	DBG("Agent registered.\n");
}

static const int __bt_agent_is_hid_keyboard(uint32_t dev_class)
{
	int is_keyboard = 0;

	switch ((dev_class & 0x1f00) >> 8) {
	case 0x05:
		switch ((dev_class & 0xc0) >> 6) {
		case 0x01:
			/* input-keyboard";*/
			is_keyboard = 1;
			break;
		}
		break;
	}

	DBG("is_keyboard: %d\n", is_keyboard);

	return is_keyboard;
}

static int __bt_agent_is_auto_response(uint32_t dev_class, const gchar *address)
{
	DBG("bt_agent_is_headset_class, %d +", dev_class);

	int is_headset = 0, ret = 0;
	struct bt_agent_appdata *ad = (struct bt_agent_appdata *)app_data;

	if (address == NULL)
		return 0;

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

	if (is_headset) {
		if (ad->ignore_auto_pairing == 0 || (strcmp(address, ad->bonding_addr) != 0))
			ret = 1;
	}

	ad->ignore_auto_pairing = 0;
	memset(ad->bonding_addr, 0x00, BT_AGENT_ADDR_SIZE + 1);

	return ret;
}

int bt_agent_generate_passkey(char *passkey, int size)
{
	int i = 0;
	int random_fd = 0;
	unsigned int value = 0;

	if (passkey == NULL)
		return -1;

	if (size <= 0)
		return -1;

	random_fd = open("/dev/urandom", O_RDONLY);

	if (random_fd < 0)
		return -1;

	for (i = 0; i < size - 1; i++) {
		read(random_fd, &value, sizeof(value));
		passkey[i] = '0' + (value % 10);
	}

	close(random_fd);

	passkey[size - 1] = '\0';

	DBG("passkey: %s", passkey);

	return 0;
}

/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
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

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <syspopup_caller.h>
#include <vconf.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <eventsystem.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>
#include <vconf.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

/* BT HAL Headers */
#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-internal.h"
#include "bt-hal-utils.h"
#include "bt-hal-event-receiver.h"
#include "bt-hal-dbus-common-utils.h"

#include "bt-hal-adapter-dbus-handler.h"
#include "bt-hal-event-receiver.h"

#include <bt-hal-agent.h>
#include <bt-hal-gap-agent.h>
#include <bt-hal-dbus-common-utils.h>

#define BT_HAL_AGENT_AUTO_PAIR_BLACKLIST_FILE (APP_SYSCONFDIR"/auto-pair-blacklist")
#define BT_HAL_AGENT_NEW_LINE "\r\n"
#define BUF_SIZE                256
#define PAGE_SIZE               (1 << 12)
#define _ALIGN_UP(addr, size)    (((addr)+((size)-1))&(~((size)-1)))
#define _ALIGN_DOWN(addr, size) ((addr)&(~((size)-1)))
#define PAGE_ALIGN(addr)        _ALIGN_DOWN(addr, PAGE_SIZE)
#define BT_HAL_PIN_MAX_LENGTH 16
#define BT_HAL_PASSKEY_MAX_LENGTH 4
#define BT_HAL_LOWER_ADDRESS_LENGTH 9
#define BT_HAL_AGENT_SYSPOPUP_TIMEOUT_FOR_MULTIPLE_POPUPS 200
#define BT_HAL_AGENT_SYSPOPUP_MAX_ATTEMPT 3

#define G_VARIANT_UNREF(variant) \
        g_variant_unref(variant); \
        variant = NULL
#define BT_HAL_MAX_EVENT_STR_LENGTH 50

static void *adapter_agent = NULL;

/* Forward delcaration */
static void __bt_hal_send_pin_request_event(const gchar *address, const gchar *name,
		uint32_t cod);
static gboolean __bt_hal_pincode_request(GapAgentPrivate *agent, GDBusProxy *device);
static gboolean __bt_hal_display_request(GapAgentPrivate *agent, GDBusProxy *device,
		guint passkey);
static gboolean __bt_hal_passkey_request(GapAgentPrivate *agent, GDBusProxy *device);
static gboolean __bt_hal_confirm_request(GapAgentPrivate *agent, GDBusProxy *device,
		guint passkey);
static gboolean __bt_hal_authorize_request(GapAgentPrivate *agent, GDBusProxy *device,
                                                        const char *uuid);
static GVariant *__bt_hal_service_getall(GDBusProxy *device, const char *interface);
static void __bt_hal_agent_release_memory(void);
static inline void stack_trim(void);
static void __bt_hal_send_authorize_request_event(const gchar *address, const char *uuid);

#ifdef TIZEN_SYSPOPUP_SUPPORTED
static gboolean __bt_hal_device_is_hid_keyboard(unsigned int dev_class);
static int __bt_hal_device_generate_passkey(char *passkey, int size);
static gboolean __bt_hal_device_is_auto_response(uint32_t dev_class,
                const gchar *address, const gchar *name);
static gboolean __bt_hal_device_is_device_blacklisted(const char *address, const char *name);
static gboolean __bt_hal_find_device_by_address_exactname(char *buffer,
                const char *address);
static gboolean __bt_hal_find_device_by_partial_name(char *buffer,
                const char *partial_name);
static gboolean __bt_hal_agent_system_popup_timer_cb(gpointer user_data);
#else
static void __bt_hal_send_ssp_request_events(const gchar *address, const gchar *name,
		guint passkey, uint32_t cod, unsigned char variant);
#endif

void* _bt_hal_create_agent(const char *path, gboolean adapter)
{
	GAP_AGENT_FUNC_CB func_cb;
	GDBusProxy *adapter_proxy;
	GapAgentPrivate *agent;

	DBG("+");
	adapter_proxy = _bt_get_adapter_proxy();
	if (!adapter_proxy)
		return NULL;

	func_cb.pincode_func = __bt_hal_pincode_request;
	func_cb.display_func = __bt_hal_display_request;
	func_cb.passkey_func = __bt_hal_passkey_request;
	func_cb.confirm_func = __bt_hal_confirm_request;
	func_cb.authorize_func = __bt_hal_authorize_request;
	func_cb.pairing_cancel_func = NULL;
	func_cb.authorization_cancel_func = NULL;

	/* Allocate memory*/
	agent = g_new0(GapAgentPrivate, 1);

	_gap_agent_setup_dbus(agent, &func_cb, path, adapter_proxy);

	if (adapter) {
		if (!_gap_agent_register(agent)) {
			ERR("gap agent registration failed!");
			_bt_hal_destroy_agent(agent);
			agent = NULL;
		}
	}
	DBG("-");
	return agent;
}

void _bt_hal_destroy_agent(void *agent)
{
	DBG("+");
	if (!agent)
		return;

	_gap_agent_reset_dbus((GapAgentPrivate *)agent);

	g_free(agent);
	DBG("-");
}

gboolean _bt_hal_agent_is_canceled(void)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return FALSE;

	return _gap_agent_is_canceled(agent);
}

int _bt_hal_agent_reply_cancellation(void)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return BT_STATUS_FAIL;

	if (gap_agent_reply_confirmation(agent, GAP_AGENT_CANCEL, NULL) != TRUE) {
		ERR("Fail to reply agent");
		return BT_STATUS_FAIL;
	}
	DBG("gap agent cancellation done successfully!");
	return BT_STATUS_SUCCESS;

}

void _bt_hal_agent_set_canceled(gboolean value)
{
	void *agent = _bt_hal_get_adapter_agent();
	if (!agent)
		return;

	return _gap_agent_set_canceled(agent, value);
}

void _bt_hal_initialize_adapter_agent(void)
{
	adapter_agent = _bt_hal_create_agent(BT_HAL_ADAPTER_AGENT_PATH, TRUE);
	if (!adapter_agent) {
		ERR("Fail to register agent");
		return;
	}
}

void _bt_hal_destroy_adapter_agent(void)
{
	if (adapter_agent)
		_bt_hal_destroy_agent(adapter_agent);
	adapter_agent = NULL;
}

void* _bt_hal_get_adapter_agent(void)
{
	return adapter_agent;
}

static void __bt_hal_send_authorize_request_event(const gchar *address, const char *uuid)
{
	struct hal_ev_authorize_request ev;
	memset(&ev, 0, sizeof(ev));

	DBG("Remote Device address [%s]", address);

	_bt_convert_addr_string_to_type(ev.bdaddr, address);
	ev.service_id = _bt_convert_uuid_string_to_service_id(uuid);

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending AUTHORIZE REQUEST");
		event_cb(HAL_EV_AUTHORIZE_REQUEST, (void*)&ev, sizeof(ev));
	}

	DBG("-");
}

/* Legacy Pairing */
static void __bt_hal_send_pin_request_event(const gchar *address, const gchar *name,
		uint32_t cod)
{
	struct hal_ev_pin_request ev;
	memset(&ev, 0, sizeof(ev));

	DBG("Remote Device address [%s]", address);
	DBG("Remote Device Name [%s]", name);
	DBG("Remote Device COD [%u]", cod);

	_bt_convert_addr_string_to_type(ev.bdaddr, address);

	memcpy(ev.name, name, strlen(name));
	ev.class_of_dev = cod;

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending PIN REQUEST");
		event_cb(HAL_EV_PIN_REQUEST, (void*)&ev, sizeof(ev));
	}

	DBG("-");
}

static gboolean __bt_hal_pincode_request(GapAgentPrivate *agent, GDBusProxy *device)
{
	uint32_t device_class;
	const gchar *address;
	const gchar *name;
	GVariant *reply = NULL;
	GVariant *reply_temp = NULL;
	GVariant *tmp_value;
	DBG("+");

	reply_temp = __bt_hal_service_getall(device, BT_HAL_DEVICE_INTERFACE);

	if (reply_temp == NULL) {
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "",
				NULL);
		goto done;
	}

	g_variant_get(reply_temp,"(@a{sv})", &reply); /* Format of reply a{sv}*/

	tmp_value = g_variant_lookup_value(reply, "Class", G_VARIANT_TYPE_UINT32);
	g_variant_get(tmp_value, "u", &device_class);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Address", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &address);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Name", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &name);
	G_VARIANT_UNREF(tmp_value);

	if (!name)
		name = address;
#ifdef TIZEN_SYSPOPUP_SUPPORTED
	if (__bt_hal_device_is_hid_keyboard(device_class)) {
		DBG("Device is HID Keyboard");
		char str_passkey[BT_HAL_PASSKEY_MAX_LENGTH + 1] = { 0 };
		if (__bt_hal_device_generate_passkey(str_passkey,
					BT_HAL_PASSKEY_MAX_LENGTH) != 0) {
			gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT,
					"", NULL);
			goto done;
		}
		gap_agent_reply_pin_code(agent, GAP_AGENT_ACCEPT,
				str_passkey, NULL);

		DBG("Launch BT Syspopup");
		_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST,
				name, str_passkey, NULL,
				_gap_agent_get_path(agent));
	} else if (!__bt_hal_device_is_auto_response(device_class, address, name)) {
		DBG("Device is not of AUto response class, Show PIN Entry");
		_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_PIN_REQUEST, name, NULL,
				NULL, _gap_agent_get_path(agent));
	} else {
		DBG("Device is of Type Auto response, send event to HAL");
		__bt_hal_send_pin_request_event(address, name, device_class);
	}
#else
	DBG("PIN CODE request, device class [%u]", device_class);
	__bt_hal_send_pin_request_event(address, name, device_class);
#endif

done:
	g_variant_unref(reply);
	g_variant_unref(reply_temp);
	__bt_hal_agent_release_memory();
	DBG("-");

	return TRUE;
}


/* BT_SSP_VARIANT_PASSKEY_CONFIRMATION */
/* BT_SSP_VARIANT_PASSKEY_NOTIFICATION */
/* BT_SSP_VARIANT_PASSKEY_ENTRY */
/* BT_SSP_VARIANT_CONSENT */

#ifndef TIZEN_SYSPOPUP_SUPPORTED
static void __bt_hal_send_ssp_request_events(const gchar *address,
		const gchar *name,
		guint passkey,
		uint32_t cod,
		unsigned char variant)
{
	struct hal_ev_ssp_request ev;
	memset(&ev, 0, sizeof(ev));
	DBG("sizeof ev [%d]", sizeof(ev));

	DBG("Remote Device address [%s]", address);
	DBG("Remote Device Name [%s]", name);
	DBG("Remote Device passkey [%d]", passkey);
	DBG("Remote Device pairing variant [0x%x]", variant);
	DBG("Remote Device cod [%d]", cod);

	_bt_convert_addr_string_to_type(ev.bdaddr, address);

	memcpy(ev.name, name, strlen(name));
	ev.class_of_dev = cod;
	ev.pairing_variant = variant;
	ev.passkey = passkey;

	handle_stack_msg event_cb = _bt_hal_get_stack_message_handler();
	if (event_cb) {
		DBG("Sending SSP type [%d]", variant);
		event_cb(HAL_EV_SSP_REQUEST, (void*)&ev, sizeof(ev));
	}

	DBG("-");
}
#endif

/* SSP */
static gboolean __bt_hal_display_request(GapAgentPrivate *agent, GDBusProxy *device,
		guint passkey)
{
	const gchar *address;
	const gchar *name;
	char *str_passkey;
	uint32_t device_class;
	GVariant *reply = NULL;
	GVariant *reply_temp = NULL;
	GVariant *tmp_value = NULL;
	DBG("+");

	reply_temp = __bt_hal_service_getall(device, BT_HAL_DEVICE_INTERFACE);
	if (reply_temp == NULL) {
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "",
				NULL);
		goto done;
	}

	g_variant_get(reply_temp,"(@a{sv})", &reply); /* Format of reply a{sv}*/

	tmp_value = g_variant_lookup_value (reply, "Address", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &address);
	G_VARIANT_UNREF(tmp_value);
	if (!address) {
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "", NULL);
		goto done;
	}

	tmp_value = g_variant_lookup_value(reply, "Name", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &name);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Class", G_VARIANT_TYPE_UINT32);
	g_variant_get(tmp_value, "u", &device_class);
	G_VARIANT_UNREF(tmp_value);

	if (!name)
		name = address;

	str_passkey = g_strdup_printf("%d", passkey);

#ifdef TIZEN_SYSPOPUP_SUPPORTED
	DBG("Launch BT Syspopup: KEYBOARD_PASSKEY_REQUEST");
	_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST, name,
			str_passkey, NULL,
			_gap_agent_get_path(agent));
#else

	__bt_hal_send_ssp_request_events(address, name, passkey, device_class,
			BT_SSP_VARIANT_PASSKEY_NOTIFICATION);
#endif

	g_free(str_passkey);
done:
	g_variant_unref(reply);
	g_variant_unref(reply_temp);
	__bt_hal_agent_release_memory();

	DBG("-");
	return TRUE;
}

/* SSP */
static gboolean __bt_hal_passkey_request(GapAgentPrivate *agent, GDBusProxy *device)
{
	const gchar *address;
	const gchar *name;
	uint32_t device_class;
	GVariant *reply = NULL;
	GVariant *reply_temp = NULL;
	GVariant *tmp_value;
	DBG("+");

	reply_temp = __bt_hal_service_getall(device, BT_HAL_DEVICE_INTERFACE);

	if (reply_temp == NULL) {
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "",
				NULL);
		goto done;
	}

	g_variant_get(reply_temp,"(@a{sv})", &reply); /* Format of reply a{sv}*/

	tmp_value = g_variant_lookup_value (reply, "Address", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &address);
	G_VARIANT_UNREF(tmp_value);
	if (!address) {
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "", NULL);
		goto done;
	}

	tmp_value = g_variant_lookup_value(reply, "Name", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &name);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Class", G_VARIANT_TYPE_UINT32);
	g_variant_get(tmp_value, "u", &device_class);
	G_VARIANT_UNREF(tmp_value);

	if (!name)
		name = address;
#ifdef TIZEN_SYSPOPUP_SUPPORTED
	DBG("Launch BT Syspopup: PASSKEY_REQUEST");
	_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_PASSKEY_REQUEST, name, NULL, NULL,
			_gap_agent_get_path(agent));
#else
	__bt_hal_send_ssp_request_events(address, name, 0, device_class,
			BT_SSP_VARIANT_PASSKEY_ENTRY);
#endif

done:
	g_variant_unref(reply);
	g_variant_unref(reply_temp);
	__bt_hal_agent_release_memory();

	DBG("-");
	return TRUE;
}

/*ssp*/
static gboolean __bt_hal_confirm_request(GapAgentPrivate *agent, GDBusProxy *device,
		guint passkey)
{
	const gchar *address;
	const gchar *name;
	char str_passkey[7];
	uint32_t device_class;
	GVariant *reply_temp = NULL;
	GVariant *reply = NULL;
	GVariant *tmp_value;
	DBG("+ passkey[%.6d]", passkey);
	DBG("Agent Path [%s]", agent->path);

	snprintf(str_passkey, sizeof(str_passkey), "%.6d", passkey);

	reply_temp = __bt_hal_service_getall(device, BT_HAL_DEVICE_INTERFACE);

	if (reply_temp == NULL) {
		ERR("####Device doesn't exist####");
		gap_agent_reply_pin_code(agent, GAP_AGENT_REJECT, "",
				NULL);
		goto done;
	}
	g_variant_get(reply_temp,"(@a{sv})", &reply); /* Format of reply a{sv}*/

	tmp_value = g_variant_lookup_value (reply, "Address", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &address);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value (reply, "Name", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &name);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Class", G_VARIANT_TYPE_UINT32);
	g_variant_get(tmp_value, "u", &device_class);
	G_VARIANT_UNREF(tmp_value);

	if (!name)
		name = address;
#ifdef TIZEN_WEARABLE
	uint32_t major_class;


	major_class = (device_class & 0x1f00) >> 8;

	if (major_class == BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO) {
		DBG("Audio device. Launch passkey pop-up");
		_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST, name,
				str_passkey, NULL, _gap_agent_get_path(agent));
		goto done;
	}

	if (__is_reset_required(address)) {
		DBG("Launch system reset pop-up");
		_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_SYSTEM_RESET_REQUEST, name,
				NULL, NULL, _gap_agent_get_path(agent));
	} else {
		DBG("Launch passkey pop-up");
		_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_PASSKEY_AUTO_ACCEPTED, name,
				str_passkey, NULL, _gap_agent_get_path(agent));

		gap_agent_reply_confirmation(agent, GAP_AGENT_ACCEPT, NULL);
	}
#else

#ifdef TIZEN_SYSPOPUP_SUPPORTED
	DBG("Launch BT Syspopup");
	DBG("Name [%s]", name);
	DBG("Passkey [%s]", str_passkey);
	_bt_hal_launch_system_popup(BT_HAL_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST, name,
			str_passkey, NULL,
			_gap_agent_get_path(agent));
#else
	__bt_hal_send_ssp_request_events(address, name, passkey,
			device_class, BT_SSP_VARIANT_PASSKEY_CONFIRMATION);
#endif //TIZEN_SYSPOPUP_SUPPORTED
#endif //TIZEN_WEARABLE

done:
	g_variant_unref(reply);
	g_variant_unref(reply_temp);
	__bt_hal_agent_release_memory();
	DBG("-");
	return TRUE;
}

static gboolean __bt_hal_authorize_request(GapAgentPrivate *agent, GDBusProxy *device,
                                                        const char *uuid)
{
	const gchar *address;
	const gchar *name;
	gboolean trust;
	gboolean paired;
	GVariant *reply = NULL;
	GVariant *reply_temp = NULL;
	GVariant *tmp_value;

	DBG("Authorize Request from Bluez Stack: UUID [%s]", uuid);

	reply_temp = __bt_hal_service_getall(device, BT_HAL_DEVICE_INTERFACE);
	if (reply_temp == NULL) {
		gap_agent_reply_authorize(agent, GAP_AGENT_REJECT, NULL);
		goto done;
	}

	g_variant_get(reply_temp,"(@a{sv})", &reply); /* Format of reply a{sv}*/

	tmp_value = g_variant_lookup_value (reply, "Address", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &address);
	G_VARIANT_UNREF(tmp_value);
	if (!address) {
		gap_agent_reply_authorize(agent, GAP_AGENT_REJECT, NULL);
		goto done;
	}

	tmp_value = g_variant_lookup_value(reply, "Alias", G_VARIANT_TYPE_STRING);
	g_variant_get(tmp_value, "s", &name);
	G_VARIANT_UNREF(tmp_value);
	if (!name)
		name = address;

	tmp_value = g_variant_lookup_value(reply, "Trusted", G_VARIANT_TYPE_BOOLEAN);
	g_variant_get(tmp_value, "b", &trust);
	G_VARIANT_UNREF(tmp_value);

	tmp_value = g_variant_lookup_value(reply, "Paired", G_VARIANT_TYPE_BOOLEAN);
	g_variant_get(tmp_value, "b", &paired);
	G_VARIANT_UNREF(tmp_value);
	if ((paired == FALSE) && (trust == FALSE)) {
		ERR("No paired & No trusted device");
		gap_agent_reply_authorize(agent, GAP_AGENT_REJECT, NULL);
		goto done;
	}

	INFO("Authorization request for device [%s] Service:[%s]\n", address, uuid);

	if (trust) {
		INFO("Trusted device, so authorize\n");
		gap_agent_reply_authorize(agent, GAP_AGENT_ACCEPT, NULL);
		goto done;
	} else {
		INFO("Device is not Trusted, so prompt user to accept or reject authorization \n");
	}

	/*
	 * TODO: Handling for authorization request for different profiles will be
	 * implemented while profiles support is added. For now send all the request
	 * to bt-service or, launch bt-syspopup.
	 */
#ifdef TIZEN_SYSPOPUP_SUPPORTED
	DBG("Launch Syspopup: AUTHORIZE_REQUEST");
	_bt_hal_launch_system_popup(BT_AGENT_EVENT_AUTHORIZE_REQUEST,
			name, NULL, NULL, _gap_agent_get_path(agent));
#else
	__bt_hal_send_authorize_request_event(address, uuid);
#endif

done:
	g_variant_unref(reply);
	g_variant_unref(reply_temp);
	__bt_hal_agent_release_memory();

	DBG("-");
	return TRUE;
}

#ifdef TIZEN_SYSPOPUP_SUPPORTED
int _bt_hal_launch_system_popup(bt_hal_agent_event_type_t event_type,
		const char *device_name,
		char *passkey,
		const char *filename,
		const char *agent_path)
{
	int ret;
	bundle *b;
	char event_str[BT_HAL_MAX_EVENT_STR_LENGTH + 1];
	DBG("+");

	b = bundle_create();
	if (!b) {
		DBG("Launching system popup failed");
		return -1;
	}

	bundle_add(b, "device-name", device_name);
	bundle_add(b, "passkey", passkey);
	bundle_add(b, "file", filename);
	bundle_add(b, "agent-path", agent_path);

	switch (event_type) {
		case BT_HAL_AGENT_EVENT_PIN_REQUEST:
			g_strlcpy(event_str, "pin-request", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST:
			g_strlcpy(event_str, "passkey-confirm-request",
					sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_PASSKEY_AUTO_ACCEPTED:
			g_strlcpy(event_str, "passkey-auto-accepted",
					sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_PASSKEY_REQUEST:
			g_strlcpy(event_str, "passkey-request", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_PASSKEY_DISPLAY_REQUEST:
			g_strlcpy(event_str, "passkey-display-request",
					sizeof(event_str));
		case BT_HAL_AGENT_EVENT_AUTHORIZE_REQUEST:
			g_strlcpy(event_str, "authorize-request",
					sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_CONFIRM_MODE_REQUEST:
			g_strlcpy(event_str, "confirm-mode-request",
					sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_FILE_RECEIVED:
			g_strlcpy(event_str, "file-received", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST:
			g_strlcpy(event_str, "keyboard-passkey-request",
					sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_TERMINATE:
			g_strlcpy(event_str, "terminate", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_EXCHANGE_REQUEST:
			g_strlcpy(event_str, "exchange-request", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_PBAP_REQUEST:
			g_strlcpy(event_str, "phonebook-request", sizeof(event_str));
			break;

		case BT_HAL_AGENT_EVENT_MAP_REQUEST:
			g_strlcpy(event_str, "message-request", sizeof(event_str));
			break;
#ifdef TIZEN_WEARABLE
		case BT_HAL_AGENT_EVENT_SYSTEM_RESET_REQUEST:
			__bt_register_popup_event_signal();
			g_strlcpy(event_str, "system-reset-request", sizeof(event_str));
			break;
#endif

		case BT_HAL_AGENT_EVENT_LEGACY_PAIR_FAILED_FROM_REMOTE:
			g_strlcpy(event_str, "remote-legacy-pair-failed", sizeof(event_str));
			break;

		default:
			DBG("Invalid event type");
			bundle_free(b);
			return -1;

	}

	bundle_add(b, "event-type", event_str);

	ret = syspopup_launch("bt-syspopup", b);
	if (0 > ret) {
		DBG("Popup launch failed...retry %d", ret);

		g_timeout_add(BT_HAL_AGENT_SYSPOPUP_TIMEOUT_FOR_MULTIPLE_POPUPS,
				(GSourceFunc)__bt_hal_agent_system_popup_timer_cb, b);
	} else {
		bundle_free(b);
	}

	DBG("_bt_agent_launch_system_popup");
	return 0;
}

static gboolean __bt_hal_agent_system_popup_timer_cb(gpointer user_data)
{
	int ret;
	static int retry_count;
	bundle *b = (bundle *)user_data;
	if (user_data == NULL)
		return  FALSE;

	++retry_count;

	ret = syspopup_launch("bt-syspopup", b);
	if (ret < 0) {
		DBG("Sorry! Can't launch popup, ret=%d, Re-try[%d] time..",
				ret, retry_count);
		if (retry_count >= BT_HAL_AGENT_SYSPOPUP_MAX_ATTEMPT) {
			DBG("Sorry!! Max retry %d reached", retry_count);
			bundle_free(b);
			retry_count = 0;
			return FALSE;
		}
	} else {
		DBG("Hurray!! Finally Popup launched");
		retry_count = 0;
		bundle_free(b);
	}

	return (ret < 0) ? TRUE : FALSE;
}

static gboolean __bt_hal_device_is_hid_keyboard(unsigned int dev_class)
{
	switch ((dev_class & 0x1f00) >> 8) {
		case 0x05:
			switch ((dev_class & 0xc0) >> 6) {
				case 0x01:
					/* input-keyboard" */
					return TRUE;
			}
			break;
	}

	return FALSE;
}

static int __bt_hal_device_generate_passkey(char *passkey, int size)
{
	int i;
	ssize_t len;
	int random_fd;
	unsigned int value = 0;

	if (passkey == NULL)
		return -1;

	if (size <= 0)
		return -1;

	random_fd = open("/dev/urandom", O_RDONLY);

	if (random_fd < 0)
		return -1;

	for (i = 0; i < size; i++) {
		len = read(random_fd, &value, sizeof(value));
		if (len > 0)
			passkey[i] = '0' + (value % 10);
	}

	close(random_fd);

	DBG("passkey: %s", passkey);

	return 0;
}

static gboolean __bt_hal_find_device_by_address_exactname(char *buffer,
		const char *address)
{
	char *pch;
	char *last;

	pch = strtok_r(buffer, "= ,", &last);

	if (pch == NULL)
		return FALSE;

	while ((pch = strtok_r(NULL, ",", &last))) {
		if (0 == g_strcmp0(pch, address)) {
			DBG("Match found\n");
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean __bt_hal_find_device_by_partial_name(char *buffer,
		const char *partial_name)
{
	char *pch;
	char *last;

	pch = strtok_r(buffer, "= ,", &last);

	if (pch == NULL)
		return FALSE;

	while ((pch = strtok_r(NULL, ",", &last))) {
		if (g_str_has_prefix(partial_name, pch)) {
			DBG("Match found\n");
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean __bt_hal_device_is_device_blacklisted(const char *address,
		const char *name)
{
	char *buffer;
	char **lines;
	int i;
	FILE *fp;
	long size;
	size_t result;

	DBG("+");

	fp = fopen(BT_HAL_AGENT_AUTO_PAIR_BLACKLIST_FILE, "r");

	if (fp == NULL) {
		ERR("Unable to open blacklist file");
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	if (size <= 0) {
		DBG("size is not a positive number");
		fclose(fp);
		return FALSE;
	}

	rewind(fp);

	buffer = g_malloc0(sizeof(char) * size);
	/* Fix : NULL_RETURNS */
	if (buffer == NULL) {
		ERR("Fail to allocate memory");
		fclose(fp);
		return FALSE;
	}
	result = fread((char *)buffer, 1, size, fp);
	fclose(fp);
	if (result != size) {
		ERR("Read Error");
		g_free(buffer);
		return FALSE;
	}

	DBG("Buffer = %s", buffer);

	lines = g_strsplit_set(buffer, BT_HAL_AGENT_NEW_LINE, 0);
	g_free(buffer);

	if (lines == NULL) {
		ERR("No lines in the file");
		return FALSE;
	}

	for (i = 0; lines[i] != NULL; i++) {
		if (g_str_has_prefix(lines[i], "AddressBlacklist"))
			if (__bt_hal_find_device_by_address_exactname(
						lines[i], address))
				goto done;
		if (g_str_has_prefix(lines[i], "ExactNameBlacklist"))
			if (__bt_hal_find_device_by_address_exactname(
						lines[i], name))
				goto done;
		if (g_str_has_prefix(lines[i], "PartialNameBlacklist"))
			if (__bt_hal_find_device_by_partial_name(lines[i],
						name))
				goto done;
		if (g_str_has_prefix(lines[i], "KeyboardAutoPair"))
			if (__bt_hal_find_device_by_address_exactname(
						lines[i], address))
				goto done;
	}
	g_strfreev(lines);
	DBG("-");
	return FALSE;
done:
	DBG("Found the device");
	g_strfreev(lines);
	return TRUE;
}

static gboolean __bt_hal_device_is_auto_response(uint32_t dev_class,
		const gchar *address, const gchar *name)
{
	gboolean is_headset = FALSE;
	gboolean is_mouse = FALSE;
	char lap_address[BT_HAL_LOWER_ADDRESS_LENGTH];

	DBG("bt_agent_is_headset_class, %d +", dev_class);

	if (address == NULL)
		return FALSE;

	switch ((dev_class & 0x1f00) >> 8) {
		case 0x04:
			switch ((dev_class & 0xfc) >> 2) {
				case 0x01:
				case 0x02:
					/* Headset */
					is_headset = TRUE;
					break;
				case 0x06:
					/* Headphone */
					is_headset = TRUE;
					break;
				case 0x0b:      /* VCR */
				case 0x0c:      /* Video Camera */
				case 0x0d:      /* Camcorder */
					break;
				default:
					/* Other audio device */
					is_headset = TRUE;
					break;
			}
			break;
		case 0x05:
			switch (dev_class & 0xff) {
				case 0x80:  /* 0x80: Pointing device(Mouse) */
					is_mouse = TRUE;
					break;

				case 0x40: /* 0x40: input device (BT keyboard) */

					/* Get the LAP(Lower Address part) */
					g_strlcpy(lap_address, address, sizeof(lap_address));

					/* Need to Auto pair the blacklisted Keyboard */
					if (__bt_hal_device_is_device_blacklisted(lap_address, name) != TRUE) {
						DBG("Device is not black listed\n");
						return FALSE;
					} else {
						ERR("Device is black listed\n");
						return TRUE;
					}
			}
	}

	if ((!is_headset) && (!is_mouse))
		return FALSE;

	/* Get the LAP(Lower Address part) */
	g_strlcpy(lap_address, address, sizeof(lap_address));

	DBG("Device address = %s\n", address);
	DBG("Address 3 byte = %s\n", lap_address);

	if (__bt_hal_device_is_device_blacklisted(lap_address, name)) {
		ERR("Device is black listed\n");
		return FALSE;
	}

	return TRUE;
}
#endif

static GVariant *__bt_hal_service_getall(GDBusProxy *device, const char *interface)
{
	GError *error = NULL;
	GVariant *reply;
	DBG("+");
	reply = g_dbus_proxy_call_sync(device,
			"GetAll", g_variant_new("(s)", interface),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	if (reply == NULL) {
		ERR("GetAll dBUS-RPC failed");
		if (error) {
			ERR("D-Bus API failure: errCode[%x], message[%s]",
					error->code, error->message);
			g_clear_error(&error);
		}
		return NULL;
	}

	DBG("-");
	return reply;
}

static void __bt_hal_agent_release_memory(void)
{
	/* Release Malloc Memory*/
	malloc_trim(0);

	/* Release Stack Memory*/
	stack_trim();
}

static inline void stack_trim(void)
{
#ifdef STACK_FLUSH
        unsigned int sp;
        char buf[BUF_SIZE];
        FILE *file;
        unsigned int stacktop;
        int found = 0;

        asm volatile ("mov %0,sp " : "=r"(sp));

        sprintf(buf, "/proc/%d/maps", getpid());
        file = fopen(buf, "r");
        while (fgets(buf, BUF_SIZE, file) != NULL) {
                if (strstr(buf, "[stack]")) {
                        found = 1;
                        break;
                }
        }
        fclose(file);

        if (found) {
                sscanf(buf, "%x-", &stacktop);
                if (madvise((void *)PAGE_ALIGN(stacktop), PAGE_ALIGN(sp) - stacktop,
                                                                                MADV_DONTNEED) < 0)
                        perror("stack madvise fail");
        }
#endif
}

/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
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

#include <notification.h>
#include <vconf.h>

#include "plugin.h"
#include "common.h"
#include "vertical.h"
#include "version.h"

#define BT_AGENT_APP_NAME "bt-agent"

#define NOTIFICATION_MAX_LEN 	50

#define BLUETOOTH_ICON_PATH	"/usr/share/icons/default/bt-icon.png"
#define BT_OFF_DUE_TO_FLIGHT_MODE "file/private/bt-service/flight_mode_deactivated"

// distinguish different popups types using below strings.
// use NOTIFICATION_TEXT_TYPE_INFO_1 arg type to transport such information.
#define POPUP_TYPE_INFO  "user_info_popup"
#define POPUP_TYPE_USERCONFIRM "user_confirm_popup"
#define POPUP_TYPE_USERPROMPT "user_agreement_popup"

#define REGISTER_PAIRING_AGENT_TITLE "register_pairing_agent"
#define REGISTER_OPP_AGENT_TITLE "register_opp_agent"

#define PASSKEY_SIZE 6

static int noti_id;
static notification_h noti = NULL;

struct pairing_context {
	gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
	gpointer user_data;
};

struct opp_context {
	gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
	gpointer user_data;
};

static bluetooth_flight_cb flight_mode_callback;
static void *flight_mode_data;

static bluetooth_name_cb bt_set_name_callback;
static void *bt_set_name_data;

const char* error_to_string(notification_error_e error)
{
    if (error == NOTIFICATION_ERROR_INVALID_DATA)
        return "NOTIFICATION_ERROR_INVALID_DATA";
    if (error == NOTIFICATION_ERROR_NO_MEMORY)
        return "NOTIFICATION_ERROR_NO_MEMORY";
    if (error == NOTIFICATION_ERROR_FROM_DB)
        return "NOTIFICATION_ERROR_FROM_DB";
    if (error == NOTIFICATION_ERROR_ALREADY_EXIST_ID)
        return "NOTIFICATION_ERROR_ALREADY_EXIST_ID";
    if (error == NOTIFICATION_ERROR_FROM_DBUS)
        return "NOTIFICATION_ERROR_FROM_DBUS";
    if (error == NOTIFICATION_ERROR_NOT_EXIST_ID)
        return "NOTIFICATION_ERROR_NOT_EXIST_ID";
    if (error == NOTIFICATION_ERROR_IO)
        return "NOTIFICATION_ERROR_IO";
    if (error == NOTIFICATION_ERROR_SERVICE_NOT_READY)
        return "NOTIFICATION_ERROR_SERVICE_NOT_READY";
    if (error == NOTIFICATION_ERROR_NONE)
        return "NOTIFICATION_ERROR_NONE";

    return "UNHANDLED ERROR";
}

static notification_h create_notification(notification_type_e type)
{
	notification_h noti = NULL;
	noti = notification_create(type);
	if (!noti) {
		DBG("Fail to notification_new\n");
		return NULL;
	}

	return noti;
}

static int set_notification_property(notification_h noti, int flag)
{
	if (!noti)
		return -1;

	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	ret = notification_set_property(noti, flag);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_set_property [%d]\n", ret);
	}

	ret = notification_set_display_applist(noti,
				 NOTIFICATION_DISPLAY_APP_ALL ^
				 NOTIFICATION_DISPLAY_APP_TICKER);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_set_display_applist [%d]\n", ret);
	}

	return ret;
}

static int insert_notification(notification_h noti, char *title,
				char *content, char *icon_path)
{
	int noti_id = 0;

	if (!noti)
		return -1;

	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	if (icon_path) {
		ret = notification_set_image(noti,
				NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_image [%d]\n", ret);
		}
	}

	if (title) {
		ret = notification_set_text(noti, NOTIFICATION_TEXT_TYPE_TITLE,
				title, NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_text [%d]\n", ret);
		}
	}

	if (content) {
		ret = notification_set_text(noti, NOTIFICATION_TEXT_TYPE_CONTENT,
				content, NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_text [%d]\n", ret);
		}
	}

	ret = notification_insert(noti, &noti_id);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_insert [%d]\n", ret);
	}

	return noti_id;
}

static int update_notification(notification_h noti, char *title,
				char *content, char *icon_path)
{
	char str[NOTIFICATION_MAX_LEN] = {0,};

	if (!noti)
		return -1;

	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	if (icon_path) {
		ret = notification_set_image(noti, NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_image [%d]\n", ret);
		}
	}

	if (title) {
		snprintf(str, sizeof(str), "%s: %s", "Hello Share", title);

		ret = notification_set_text(noti,
					NOTIFICATION_TEXT_TYPE_TITLE,
					str, NULL,
					NOTIFICATION_VARIABLE_TYPE_NONE);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_text [%d]\n", ret);
		}
	}

	if (content) {
		ret = notification_set_text(noti,
					NOTIFICATION_TEXT_TYPE_CONTENT,
					content, NULL,
					NOTIFICATION_VARIABLE_TYPE_NONE);
		if (ret != NOTIFICATION_ERROR_NONE) {
			DBG("Fail to notification_set_text [%d]\n", ret);
		}
	}

	ret = notification_update(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_update [%d]\n", ret);
	}

	return ret;
}

static int update_notification_progress(void *handle,
				int id,
				int val)
{
	notification_error_e ret = NOTIFICATION_ERROR_NONE;
	ret = notification_update_progress(handle, id, (double) val / 100);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_update_progress [%d]\n", ret);
	}

	return ret;
}

static int delete_notification(notification_h noti)
{
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	if (!noti)
		return -1;

	ret = notification_delete(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		DBG("Fail to notification_delete [%d]\n", ret);
	}

	return ret;
}

static int set_notification_app_launch(notification_h noti)
{
	DBG("+\n");
	if (!noti)
		return -1;

	return 0;
}

static void start_notification_on_plane(void)
{
	noti = create_notification(NOTIFICATION_TYPE_ONGOING);

	set_notification_property(noti,
			NOTIFICATION_PROP_DISABLE_TICKERNOTI);

	noti_id = insert_notification(noti, "Bluetooth",
					NULL, BLUETOOTH_ICON_PATH);

	update_notification(noti, NULL, NULL, NULL);
}

static void update_notification_on_plane(int progress)
{
	update_notification_progress(NULL, noti_id, progress);
}

static void complete_notification_on_plane(void)
{
	notification_h noti_completed;

	if (noti == NULL)
		return;

	update_notification_progress(NULL, noti_id, 100);

	delete_notification(noti);

	noti_completed = create_notification(NOTIFICATION_TYPE_NOTI);

	set_notification_app_launch(noti);

	set_notification_property(noti_completed,
				NOTIFICATION_PROP_DISABLE_AUTO_DELETE |
				NOTIFICATION_PROP_VOLATILE_DISPLAY);

	insert_notification(noti_completed, "Bluetooth Received",
				"1 successful, 0 failed",
				BLUETOOTH_ICON_PATH);

	noti = NULL;
}

static int bt_set_storage_value(enum storage_key key, void *value)
{
	if (key == STORAGE_KEY_BT_STATE)
		vconf_set_int(VCONFKEY_BT_STATUS, *(int *)value);
	else if (key == STORAGE_KEY_BT_HEADSET_NAME)
		vconf_set_str(VCONFKEY_BT_HEADSET_NAME, (char *)value);
	else if (key == STORAGE_KEY_BT_PROFILE_STATE)
		vconf_set_int(VCONFKEY_BT_DEVICE, *(int *)value);
	else if (key == STORAGE_KEY_BT_FLIGHT_MODE)
		vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, *(int *)value);
	else
		return -1;

	return 0;
}

static int bt_get_storage_value(enum storage_key key, void **value)
{
	int *temp;

	if (!value)
		return -1;

	if (key == STORAGE_KEY_BT_STATE) {
		temp = g_try_new0(int, 1);
		vconf_get_int(VCONFKEY_BT_STATUS, temp);
		*value = temp;
	} else if (key == STORAGE_KEY_BT_PROFILE_STATE) {
		temp = g_try_new0(int, 1);
		vconf_get_int(VCONFKEY_BT_DEVICE, temp);
		*value = temp;
	} else if (key == STORAGE_KEY_BT_HEADSET_NAME) {
		*value = vconf_get_str(VCONFKEY_BT_HEADSET_NAME);
	} else if (key == STORAGE_KEY_BT_FLIGHT_MODE) {
		temp = g_try_new0(int, 1);
		vconf_get_int(BT_OFF_DUE_TO_FLIGHT_MODE, temp);
		*value = temp;
	} else if (key == STORAGE_KEY_TELEPHONE_FLIGHT_MODE) {
		temp = g_try_new0(int, 1);
		vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE,
						(gboolean *)temp);
		*value = temp;
	} else
		return -1;

	return 0;
}

void bt_set_flight_mode_cb(bluetooth_flight_cb cb, void *user_data)
{
	flight_mode_callback = cb;
	flight_mode_data = user_data;
}

void bt_set_name_cb(bluetooth_name_cb cb, void *user_data)
{
	bt_set_name_callback = cb;
	bt_set_name_data = user_data;
}

static int bt_probe(void)
{
	DBG("");

	return 0;
}

static int bt_enabled(void)
{
	int bt_status, profile_status;
	gboolean flight_mode;

	DBG("");

	vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &flight_mode);

	DBG("flight_mode = %d", flight_mode);
	if (flight_mode) {
		vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 1);
		/*Not sure that the value can be used in Tizen common*/
		/*Todo not return -1, if it is used, return -1*/
		/*
		bt_status = VCONFKEY_BT_STATUS_OFF;
		bt_set_storage_value(STORAGE_KEY_BT_STATE, &bt_status);
		return -1
		*/
	} else
		vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 0);

	bt_status = VCONFKEY_BT_STATUS_ON;
	bt_set_storage_value(STORAGE_KEY_BT_STATE, &bt_status);

	profile_status = VCONFKEY_BT_DEVICE_NONE;
	bt_set_storage_value(STORAGE_KEY_BT_HEADSET_NAME, &profile_status);

	return 0;
}

static int bt_disabled(void)
{
	int bt_status, profile_status;

	DBG("");

	bt_status = VCONFKEY_BT_STATUS_OFF;
	bt_set_storage_value(STORAGE_KEY_BT_STATE, &bt_status);

	profile_status = VCONFKEY_BT_DEVICE_NONE;
	bt_set_storage_value(STORAGE_KEY_BT_HEADSET_NAME, &profile_status);

	return 0;
}

static int bt_transfer(double progress)
{
	DBG("progress: %f", progress);

	if (progress == 0)
		start_notification_on_plane();
	else if (progress > 0 && progress < 100)
		update_notification_on_plane(progress);
	else if (progress == 100)
		complete_notification_on_plane();
	else
		ERROR("Error progress");

	return 0;
}

static gchar* get_device_name_from_device_path(gchar* device_path)
{
	char *string;
	GError *error = NULL;
	GDBusConnection *connection;
	GVariant *string_vv, *string_v;

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (connection == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);
	}

	string_vv = g_dbus_connection_call_sync(connection,
			"org.bluez",
			device_path,
			"org.freedesktop.DBus.Properties",
			"Get",
			g_variant_new("(ss)", "org.bluez.Device1", "Alias"),
			G_VARIANT_TYPE("(v)"),
			G_DBUS_CALL_FLAGS_NONE,
			-1, NULL, &error);

	if (string_vv == NULL) {
		ERROR("%s", error->message);
		g_error_free(error);
	}

	g_variant_get(string_vv, "(v)", &string_v);
	string = g_variant_dup_string(string_v, NULL);
	g_variant_unref(string_v);
	return string;
}

static int bt_pairing_agent_on(void *data)
{
	struct pairing_context *pairing_data = (struct pairing_context *) data;

	notification_h noti;
	gchar *event_type = NULL;
	gchar *device_name = NULL;
	gchar *title = NULL;
	gchar *body = NULL;

	event_type = pairing_data->method_name;
	LOGD("create notification for [%s] event", event_type);

	noti = notification_create(NOTIFICATION_TYPE_NOTI);
	notification_set_pkgname(noti, BT_AGENT_APP_NAME);

	if (!g_strcmp0(event_type, "RegisterPairingAgent")) {
		LOGD("Send a notification in order to register a pairing agent");
		title = g_strdup_printf(REGISTER_PAIRING_AGENT_TITLE);
		insert_notification(noti, title, NULL, NULL);
		g_free(title);
		return 0;
	}

	if (!g_strcmp0(event_type, "RequestPinCode")) {
		gchar *device_path = NULL;
		g_variant_get(pairing_data->parameters, "(o)", &device_path);
		device_name = get_device_name_from_device_path(device_path);

		title = g_strdup_printf("Bluetooth pairing request");
		body = g_strdup_printf("Enter PIN to pair with %s (Try 0000 or 1234)", device_name);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_USERPROMPT,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);

	} else if (!g_strcmp0(event_type, "DisplayPinCode")) {
		gchar *device_path = NULL;
		gchar *pincode =  NULL;
		g_variant_get(pairing_data->parameters, "(os)", &device_path, &pincode);
		device_name = get_device_name_from_device_path(device_path);

		title = g_strdup_printf("Bluetooth PIN code display");
		body = g_strdup_printf("Display %s PIN code to pair with %s", pincode, device_name);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_INFO,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);
		g_free(pincode);

	} else if (!g_strcmp0(event_type, "RequestPasskey")) {
		gchar *device_path = NULL;
		g_variant_get(pairing_data->parameters, "(o)", &device_path);
		device_name = get_device_name_from_device_path(device_path);
		title = g_strdup_printf("Bluetooth pairing passkey request");
		body = g_strdup_printf("Enter passkey to pair with %s ", device_name);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_USERPROMPT,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);

	} else if (!g_strcmp0(event_type, "RequestConfirmation")) {
		gchar *device_path = NULL;
		guint32 passkey = 0;
		g_variant_get(pairing_data->parameters, "(ou)", &device_path, &passkey);
		device_name = get_device_name_from_device_path(device_path);

		gchar *passkey_str = g_strdup_printf("%u", passkey);
		// Set '0' padding if the passkey has less than 6 digits
		char passkey_tab[PASSKEY_SIZE] = "000000";
		int size = strlen((char *)passkey_str);
		if (size <= PASSKEY_SIZE) {
			memcpy(&passkey_tab[PASSKEY_SIZE - size], passkey_str, size);
		}

		title = g_strdup_printf("Bluetooth passkey confirm request");
		body = g_strdup_printf("Confirm passkey is %s to pair with %s", passkey_tab, device_name);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_USERCONFIRM,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);
		g_free(passkey_str);

	} else if (!g_strcmp0(event_type, "AuthorizeService")) {
		gchar *device_path = NULL;
		gchar *uuid = NULL;
		guint32 fd = 0;
		g_variant_get(pairing_data->parameters, "(osh)", &device_path, &uuid, &fd);
		device_name = get_device_name_from_device_path(device_path);

		title = g_strdup_printf("Bluetooth authorize service");
		body = g_strdup_printf("Allow connection on %s service", uuid);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_USERCONFIRM,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);
		g_free(uuid);

	} else if (!g_strcmp0(event_type, "RequestAuthorization")) {
		gchar *device_path = NULL;
		g_variant_get(pairing_data->parameters, "(o)", &device_path);
		device_name = get_device_name_from_device_path(device_path);

		title = g_strdup_printf("Bluetooth authorize request");
		body = g_strdup_printf("Allow %s to connect?", device_name);
		notification_set_text( noti, NOTIFICATION_TEXT_TYPE_INFO_1, POPUP_TYPE_USERCONFIRM,
				NULL, NOTIFICATION_VARIABLE_TYPE_NONE);

		g_free(device_path);

	} else {
		ERROR("event_type not recognized: [%s] !!!", event_type);
		g_free(title);
		g_free(body);
		return -1;
	}

	insert_notification(noti, title, body, BLUETOOTH_ICON_PATH);
	g_free(title);
	g_free(body);

	return 0;
}

static int bt_opp_agent_on(void *data)
{
	struct opp_context *opp_data = (struct opp_context *) data;

	notification_h noti;
	gchar *event_type = NULL;
	gchar *title = NULL;

	event_type = opp_data->method_name;
	LOGD("create notification for [%s] event", event_type);

	noti = notification_create(NOTIFICATION_TYPE_NOTI);
	notification_set_pkgname(noti, BT_AGENT_APP_NAME);

	if (!g_strcmp0(event_type, "RegisterOppAgent")) {
		LOGD("Send a notification in order to register an opp agent");
		title = g_strdup_printf(REGISTER_OPP_AGENT_TITLE);
		insert_notification(noti, title, NULL, NULL);
		g_free(title);
	}
	return 0;
}

static void bt_name_cb(keynode_t *node, void *data)
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
			if (bt_set_name_callback)
				bt_set_name_callback(phone_name,
						bt_set_name_data);
		}
	}
}

static void bt_flight_mode_cb(keynode_t *node, void *data)
{
	gboolean flight_mode = FALSE;
	int bt_status;

	DBG("key=%s", vconf_keynode_get_name(node));

	if (vconf_keynode_get_type(node) == VCONF_TYPE_BOOL) {
		flight_mode = vconf_keynode_get_bool(node);
		vconf_get_int(VCONFKEY_BT_STATUS, &bt_status);

		DBG("value=%d, status = %d", flight_mode, bt_status);

		if (flight_mode == TRUE) {
			DBG("Deactivate Bluetooth Service");
			if (vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 1))
				DBG("Set vconf failed");
		} else {
			DBG("Activate Bluetooth Service");
			if (vconf_set_int(BT_OFF_DUE_TO_FLIGHT_MODE, 0))
				DBG("Set vconf failed");
		}

		if (bt_status == VCONFKEY_BT_STATUS_ON && !flight_mode)
			flight_mode = FALSE;
		else
			flight_mode = TRUE;

		if (flight_mode_callback)
			flight_mode_callback(flight_mode, flight_mode_data);
	}
}

static struct bluetooth_vertical_driver bt_driver = {
	.name = "Common",
	.probe = bt_probe,
	.enabled = bt_enabled,
	.disabled = bt_disabled,
	.set_value = bt_set_storage_value,
	.get_value = bt_get_storage_value,
	.set_flight_mode_cb = bt_set_flight_mode_cb,
	.set_name_cb = bt_set_name_cb,
	.transfer = bt_transfer,
	.pairing_agent_on = bt_pairing_agent_on,
	.opp_agent_on = bt_opp_agent_on,
};

static int bt_init(void)
{
	DBG("");
	comms_service_register_bt_vertical_driver(&bt_driver);

	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
					bt_flight_mode_cb, NULL);

	vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
					bt_name_cb, NULL);
	return 0;
}

static void bt_exit(void)
{
	DBG("");
	comms_service_unregister_bt_vertical_driver(&bt_driver);
}

COMMS_SERVICE_PLUGIN_DEFINE(bluetooth, "Bleutooth service plugin for Tizen",
					COMMS_SERVICE_VERSION, bt_init, bt_exit);

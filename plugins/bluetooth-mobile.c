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

#include <syspopup_caller.h>
#include <notification.h>

#include "plugin.h"
#include "common.h"
#include "vertical.h"
#include "version.h"

#define BT_AGENT_APP_NAME "bt-agent"
#define PAIRING_AGENT "bt_pairing_agent"
#define OPP_AGENT "bt_obex_agent"

#define NOTIFICATION_MAX_LEN 	50
#define BLUETOOTH_ICON_RECEIVE_PIC "/usr/ug/res/images/ug-setting-bluetooth-efl/Q02_icon_BT_receive.png"

static int noti_id;
static notification_h noti = NULL;

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
					NULL, BLUETOOTH_ICON_RECEIVE_PIC);

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
				BLUETOOTH_ICON_RECEIVE_PIC);

	noti = NULL;
}

static int bt_probe(void)
{
	DBG("");

	return 0;
}

static int bt_enabled(void)
{
	DBG("");

	return 0;
}

static int bt_disabled(void)
{
	DBG("");

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

static int bt_pairing_agent_on(void *data)
{
	bundle *b;
	int ret;

	DBG("");

	b = bundle_create();
	if (!b)
		return -1;

	bundle_add(b, "agent_type", PAIRING_AGENT);

	ret = syspopup_launch(BT_AGENT_APP_NAME, b);
	if (ret < 0) {
		ERROR("Launch pairing agent failed");
		return -1;
	}

	bundle_free(b);

	return 0;
}

static int bt_opp_agent_on(void *data)
{
	bundle *b;
	int ret;

	DBG("");

	b = bundle_create();
	if (!b)
		return -1;

	bundle_add(b, "agent_type", OPP_AGENT);

	ret = syspopup_launch(BT_AGENT_APP_NAME, b);
	if (ret < 0) {
		ERROR("Launch opp agent failed");
		return -1;
	}

	bundle_free(b);

	return 0;
}

static struct bluetooth_vertical_driver bt_driver = {
	.name = "Mobile",
	.probe = bt_probe,
	.enabled = bt_enabled,
	.disabled = bt_disabled,
	.transfer = bt_transfer,
	.pairing_agent_on = bt_pairing_agent_on,
	.opp_agent_on = bt_opp_agent_on,
};

static int bt_init(void)
{
	DBG("");

	comms_service_register_bt_vertical_driver(&bt_driver);
	return 0;
}

static void bt_exit(void)
{
	DBG("");
	comms_service_unregister_bt_vertical_driver(&bt_driver);
}

COMMS_SERVICE_PLUGIN_DEFINE(bluetooth, "Bleutooth service plugin for Tizen",
					COMMS_SERVICE_VERSION, bt_init, bt_exit);

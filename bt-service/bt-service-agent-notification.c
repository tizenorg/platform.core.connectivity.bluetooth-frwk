/*
 * bluetooth-frwk
 *
 * Copyright (c) 2013 Intel Corporation.
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

#include "bt-service-agent-notification.h"

const char*
error_to_string(notification_error_e error)
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

static int
__notification_set_text(notification_h noti, char *title, char *body)
{
    notification_error_e err = NOTIFICATION_ERROR_NONE;

    err = notification_set_text(    noti, NOTIFICATION_TEXT_TYPE_TITLE,
                                    title,
                                    NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to set notification title: %s", error_to_string(err));
        return BT_FAILED;
    }

    err = notification_set_text(    noti, NOTIFICATION_TEXT_TYPE_CONTENT,
                                    body,
                                    NULL, NOTIFICATION_VARIABLE_TYPE_NONE);
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to set notification content: %s", error_to_string(err));
        return BT_FAILED;
    }
    return BT_SUCCESS;
}

int
notification_launch(bundle * user_data)
{
    int ret = BT_SUCCESS;
    const char *device_name = NULL;
    const char *passkey = NULL;
    const char *file = NULL;
    const char *event_type = NULL;
    char *title = NULL;
    char *body = NULL;
    notification_h notif;
    notification_error_e err = NOTIFICATION_ERROR_NONE;

    event_type = bundle_get_val(user_data, "event-type");
    BT_DBG("create notification for '%s' event", event_type);

    notif = notification_new(NOTIFICATION_TYPE_NOTI,
                             NOTIFICATION_GROUP_ID_NONE,
                             NOTIFICATION_PRIV_ID_NONE);
    if (notif == NULL) {
        BT_ERR("Failed to create notification: %s", error_to_string(err));
        return BT_FAILED;
    }

    err = notification_set_pkgname(notif, "bluetooth-frwk-bt-service");
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to set pkgname: %s", error_to_string(err));
        return BT_FAILED;
    }

    err = notification_set_image(notif, NOTIFICATION_IMAGE_TYPE_ICON, BT_ICON);
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to set notification icon path: %s", error_to_string(err));
        return BT_FAILED;
    }

    /* 
     * Pass the full bundle to the notification
     */
    err  = notification_set_execute_option(notif, NOTIFICATION_EXECUTE_TYPE_SINGLE_LAUNCH, NULL, NULL, user_data);
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to set notification icon path: %s", error_to_string(err));
        return BT_FAILED;
    }

    if(!strcasecmp(event_type, "pin-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth pairing request");
        body = g_strdup_printf("Enter PIN to pair with %s (Try 0000 or 1234)", device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "passkey-confirm-request")){
        device_name = (gchar*) bundle_get_val(user_data, "device-name");
        passkey = (gchar*) bundle_get_val(user_data, "passkey");

        title = g_strdup_printf("Bluetooth passkey confirm request");
        body = g_strdup_printf("Confirm passkey is %s to pair with %s", passkey, device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    }  else if (!strcasecmp(event_type, "passkey-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth pairing request");
        body = g_strdup_printf("Enter PIN to pair with %s (Try 0000 or 1234)", device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "passkey-display-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");
        passkey = (gchar*) bundle_get_val(user_data, "passkey");

        title = g_strdup_printf("Bluetooth passkey display request");
        body = g_strdup_printf("Enter %s on %s to pair", passkey, device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "authorize-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth authorize request");
        body = g_strdup_printf("Allow %s to connect?", device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "app-confirm-request")) {
        /* FIXME Seems to be an osp mechanism so not implemented to be confirmed */
        BT_DBG("app-confirm-request even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed");
        ret = BT_FAILED;
    } else if (!strcasecmp(event_type, "push-authorize-request")) {
        file = (gchar*) bundle_get_val(user_data, "file");
        device_name = (gchar*) bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth push authorize request");
        body = g_strdup_printf("Receive %s from %s?", file, device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "confirm-overwrite-request")) {
        /* FIXME Seems to be an osp mechanism so not implemented to be confirmed*/
        BT_DBG("confirm-overwrite-request even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed");
        ret = BT_FAILED;
    } else if (!strcasecmp(event_type, "keyboard-passkey-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");
        passkey = (gchar*) bundle_get_val(user_data, "passkey");

        title = g_strdup_printf("Bluetooth keyboard passkey request");
        body = g_strdup_printf("Enter %s on %s to pair", passkey, device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "bt-information")) {
        /* FIXME Seems to be an osp mechanism so not implemented to be confirmed */
        BT_DBG("bt-information even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed");
        ret = BT_FAILED;
    } else if (!strcasecmp(event_type, "exchange-request")) {
        device_name = (gchar*) bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth exchange request");
        body = g_strdup_printf("exchange-request from %s", device_name);

        ret = __notification_set_text(notif, title, body);
        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "phonebook-request")) {
        device_name = bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth phonebook request");
        body = g_strdup_printf("Allow %s phonebook access", device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else if (!strcasecmp(event_type, "message-request")) {
        device_name = bundle_get_val(user_data, "device-name");

        title = g_strdup_printf("Bluetooth keyboard passkey request");
        body = g_strdup_printf("Allow %s to access messages?", device_name);

        ret = __notification_set_text(notif, title, body);

        g_free(title);
        g_free(body);
    } else {
        ret = BT_FAILED;
    }

    err = notification_insert(notif, NULL);
    if (err != NOTIFICATION_ERROR_NONE) {
        BT_ERR("Unable to insert notification: %s\n", error_to_string(err));
        return BT_FAILED;
    }

    return ret;
}


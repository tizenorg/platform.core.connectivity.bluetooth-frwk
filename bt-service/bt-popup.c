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

#include "bt-popup.h"

static void
__free_user_data(struct bt_popup_appdata *ad)
{
	if (ad->agent_proxy) {
		g_object_unref(ad->agent_proxy);
		ad->agent_proxy = NULL;
	}
	if (ad->obex_proxy) {
		g_object_unref(ad->obex_proxy);
		ad->obex_proxy = NULL;
	}
	g_free(ad);
}

static DBusGProxy*
__bluetooth_create_agent_proxy(DBusGConnection *sys_conn, const char *path)
{
	return dbus_g_proxy_new_for_name (	sys_conn,
						"org.projectx.bt",
						path,
						"org.bluez.Agent");
}

static DBusGProxy*
__bluetooth_create_obex_proxy(DBusGConnection *sys_conn)
{
	return dbus_g_proxy_new_for_name(	sys_conn,
						"org.bluez.frwk_agent",
						"/org/obex/ops_agent",
						"org.openobex.Agent");
}

static void
__gtk_pin_ok_cb(GtkWidget *widget, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(ad->agent_proxy,
				   "ReplyPinCode",
				   G_TYPE_UINT, BT_AGENT_ACCEPT,
				   G_TYPE_STRING, gtk_entry_get_text(GTK_ENTRY(ad->entry)),
				   G_TYPE_INVALID, G_TYPE_INVALID);

	gtk_widget_destroy(GTK_WIDGET(ad->window));
	__free_user_data(ad);
}

static void
__gtk_pin_cancel_cb(GtkWidget *widget, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(ad->agent_proxy,
				   "ReplyPinCode",
				   G_TYPE_UINT, BT_AGENT_CANCEL,
				   G_TYPE_STRING, "",
				   G_TYPE_INVALID, G_TYPE_INVALID);

	gtk_widget_destroy(GTK_WIDGET(ad->window));
	__free_user_data(ad);
}

static void
__gtk_passkey_ok_cb(GtkWidget *widget, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(ad->agent_proxy,
				   "ReplyPasskey",
				   G_TYPE_UINT, BT_AGENT_ACCEPT,
				   G_TYPE_STRING, gtk_entry_get_text(GTK_ENTRY(ad->entry)),
				   G_TYPE_INVALID, G_TYPE_INVALID);

	gtk_widget_destroy(GTK_WIDGET(ad->window));
	__free_user_data(ad);
}

static void
__gtk_passkey_cancel_cb(GtkWidget *widget, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(ad->agent_proxy,
				   "ReplyPasskey",
				   G_TYPE_UINT, BT_AGENT_CANCEL,
				   G_TYPE_STRING, "",
				   G_TYPE_INVALID, G_TYPE_INVALID);

	gtk_widget_destroy(GTK_WIDGET(ad->window));
	__free_user_data(ad);
}

static void
__notify_passkey_confirm_request_accept_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->agent_proxy, "ReplyConfirmation",
	   	   	   		G_TYPE_UINT, BT_AGENT_ACCEPT,
	   	   	   		G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}



static void
__notify_passkey_confirm_request_cancel_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->agent_proxy, "ReplyConfirmation",
		   	   	   	G_TYPE_UINT, BT_AGENT_CANCEL,
		   	   	   	G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}

static void
__notify_passkey_display_request_ok_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	/* Close the popup */
	notify_notification_close(n, NULL);
}

static void
__notify_passkey_display_request_cancel_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	bluetooth_cancel_bonding();

	notify_notification_close(n, NULL);
}

static void
__notify_push_authorize_request_accept_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->obex_proxy, "ReplyAuthorize",
				   	G_TYPE_UINT, BT_AGENT_ACCEPT,
				   	G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}

static void
__notify_push_authorize_request_cancel_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->obex_proxy, "ReplyAuthorize",
					G_TYPE_UINT, BT_AGENT_CANCEL,
					G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}

static void
__notify_authorize_request_accept_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->agent_proxy, "ReplyAuthorize",
					G_TYPE_UINT, BT_AGENT_ACCEPT,
					G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}

static void
__notify_authorize_request_cancel_cb(NotifyNotification *n, const char *action, struct bt_popup_appdata *ad)
{
	g_assert(ad != NULL);

	dbus_g_proxy_call_no_reply(	ad->agent_proxy, "ReplyAuthorize",
					G_TYPE_UINT, BT_AGENT_CANCEL,
					G_TYPE_INVALID, G_TYPE_INVALID);

	notify_notification_close(n, NULL);
}

static GdkPixbuf*
__create_pixbuf(const gchar * filename)
{
	GdkPixbuf *pixbuf;
	GError *error = NULL;
	pixbuf = gdk_pixbuf_new_from_file(filename, &error);
	if(!pixbuf) {
		BT_ERR("%s\n", error->message);
		g_error_free(error);
	}

	return pixbuf;
}

static void
__close_window(GtkWidget *widget, struct bt_popup_appdata *ad)
{
	gtk_widget_destroy(GTK_WIDGET(ad->window));
}

static int
__draw_input_view(	const char *event_type,
			struct bt_popup_appdata *ad,
			char *title,
			char* body,
			void *ok_cb,
			void *cancel_cb)
{

	if ((!event_type) && strcasecmp(event_type, "pin-request") && strcasecmp(event_type, "passkey-request"))
		return BT_FAILED;
	GtkWidget *layout;
	GtkWidget *text_wdgt;
	GtkWidget *image;
	GtkWidget *ok_bt;
	GtkWidget *cancel_bt;

	gtk_init(NULL, NULL);
	ad->window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(ad->window), 300, 100);
	gtk_window_set_position(GTK_WINDOW(ad->window), GTK_WIN_POS_CENTER);
	gtk_window_set_icon(GTK_WINDOW(ad->window), __create_pixbuf(NOTIFY_ICON));
	gtk_window_set_title(GTK_WINDOW (ad->window), title);

	layout = gtk_layout_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER (ad->window), layout);
	gtk_widget_show(layout);

	image = gtk_image_new_from_file(NOTIFY_ICON);
	gtk_layout_put(GTK_LAYOUT(layout), image, 0, 25);

	text_wdgt = gtk_label_new(body);
	gtk_layout_put(GTK_LAYOUT(layout), text_wdgt, 90, 0);

	ad->entry = gtk_entry_new();

	if(!strcasecmp(event_type, "pin-request"))
		gtk_entry_set_max_length(GTK_ENTRY(ad->entry), BT_PIN_MLEN);
	else if (!strcasecmp(event_type, "passkey-request"))
		gtk_entry_set_max_length(GTK_ENTRY(ad->entry), BT_PK_MLEN);

	gtk_layout_put(GTK_LAYOUT(layout), ad->entry, 90, 20);

	ok_bt = gtk_button_new_with_label("Ok");
	gtk_layout_put(GTK_LAYOUT(layout), ok_bt, 100, 50);
	gtk_widget_set_size_request(ok_bt, 60, 35);

	cancel_bt = gtk_button_new_with_label("Cancel");
	gtk_layout_put(GTK_LAYOUT(layout), cancel_bt, 160, 50);
	gtk_widget_set_size_request(cancel_bt, 60, 35);

	g_signal_connect (ad->window, "destroy",  G_CALLBACK(__close_window), ad);
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(ok_cb), ad);
	g_signal_connect(cancel_bt, "clicked", G_CALLBACK(cancel_cb), ad);

	gtk_widget_show_all(ad->window);

	return BT_SUCCESS;
}

static int
__notify_send_popup(	struct bt_popup_appdata *ad,
			char *body,
			char *action1_name,
			NotifyActionCallback action1_cb,
			char *action2_name,
			NotifyActionCallback action2_cb)
{
	NotifyNotification *n = NULL;
	GError *error = NULL;

	n = notify_notification_new(	"Tizen Bluetooth",
					body,
					NOTIFY_ICON);
	if (!n){
		__free_user_data(ad);
		BT_ERR("failed to create new notification\n");
		return BT_FAILED;
	}

	notify_notification_set_timeout(n, NOTIFY_EXPIRES_DEFAULT);

	if (action1_name && action1_cb)
		notify_notification_add_action(	n, "action1", action1_name,
						(NotifyActionCallback)action1_cb,
						ad,
						(GFreeFunc) __free_user_data);
	if (action2_name && action2_cb)
		notify_notification_add_action(	n, "action2", action2_name,
						(NotifyActionCallback)action2_cb,
						ad,
						(GFreeFunc) __free_user_data);
	if (!notify_notification_show(n, &error)){
		__free_user_data(ad);
		BT_ERR("failed to send notification : %s\n", error->message);
		return BT_FAILED;
	}
	return BT_SUCCESS;
}

int
notify_launch(bundle * user_data)
{
	int ret = 0;
	struct bt_popup_appdata *ad;
	ad = (struct bt_popup_appdata*) malloc ( sizeof(struct bt_popup_appdata));
	memset(ad, 0x0, sizeof(struct bt_popup_appdata));
	DBusGConnection *sys_conn;
	const char *device_name = NULL;
	const char *passkey = NULL;
	const char *file = NULL;
	const char *agent_path;
	const char *event_type = NULL;
	char *title = NULL;
	char *body = NULL;

	if (!notify_is_initted())
		if (!notify_init("Tizen Bluetooth-frwk")){
			BT_ERR("notification init failed\n");
			return BT_FAILED;
		}

	event_type = bundle_get_val(user_data, "event-type");

	if(!strcasecmp(event_type, "pin-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		title = g_strdup_printf("Bluetooth pairing request");
		body = g_strdup_printf("Enter PIN to pair with %s (Try 0000 or 1234)", device_name);

		ret = __draw_input_view(event_type, ad, title, body, &__gtk_pin_ok_cb, &__gtk_pin_cancel_cb);
		g_free(body);
		g_free(title);
	} else if (!strcasecmp(event_type, "passkey-confirm-request")){
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		passkey = (gchar*) bundle_get_val(user_data, "passkey");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("Confirm passkey is %s to pair with %s", passkey, device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_passkey_confirm_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_passkey_confirm_request_cancel_cb);
		g_free(body);
	}  else if (!strcasecmp(event_type, "passkey-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		title = g_strdup_printf("Bluetooth pairing request");
		body = g_strdup_printf("Enter PIN to pair with %s (Try 0000 or 1234)", device_name);

		ret = __draw_input_view(event_type, ad, title, body, &__gtk_passkey_ok_cb, &__gtk_passkey_cancel_cb);
		g_free(body);
		g_free(title);
	} else if (!strcasecmp(event_type, "passkey-display-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		passkey = (gchar*) bundle_get_val(user_data, "passkey");

		body = g_strdup_printf("Enter %s on %s to pair", passkey, device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Ok",
						(NotifyActionCallback) __notify_passkey_display_request_ok_cb,
						"Cancel",
						(NotifyActionCallback) __notify_passkey_display_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "authorize-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("Allow %s to connect?", device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_authorize_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_authorize_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "app-confirm-request")) {
		/* FIXME Seems to be an osp mechanism so not implemented to be confirmed */
		BT_DBG("app-confirm-request even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed\n");
		ret = BT_FAILED;
	} else if (!strcasecmp(event_type, "push-authorize-request")) {
		file = (gchar*) bundle_get_val(user_data, "file");
		device_name = (gchar*) bundle_get_val(user_data, "device-name");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->obex_proxy = __bluetooth_create_obex_proxy(sys_conn);
		if (!ad->obex_proxy){
			BT_ERR("create new obex_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("Receive %s from %s?", file, device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_push_authorize_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_push_authorize_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "confirm-overwrite-request")) {
		/* FIXME Seems to be an osp mechanism so not implemented to be confirmed*/
		BT_DBG("confirm-overwrite-request even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed\n");
		ret = BT_FAILED;
	} else if (!strcasecmp(event_type, "keyboard-passkey-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		passkey = (gchar*) bundle_get_val(user_data, "passkey");

		body = g_strdup_printf("Enter %s on %s to pair", passkey, device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Ok",
						(NotifyActionCallback) __notify_passkey_display_request_ok_cb,
						"Cancel",
						(NotifyActionCallback) __notify_passkey_display_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "bt-information")) {
		/* FIXME Seems to be an osp mechanism so not implemented to be confirmed */
		BT_DBG("bt-information even_type seems to be an osp mechanism so not implemented in gnome environment; to be confirmed\n");
		ret = BT_FAILED;
	} else if (!strcasecmp(event_type, "exchange-request")) {
		device_name = (gchar*) bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("exchange-request from %s", device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_authorize_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_authorize_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "phonebook-request")) {
		device_name = bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("Allow %s phonebook access", device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_authorize_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_authorize_request_cancel_cb);
		g_free(body);
	} else if (!strcasecmp(event_type, "message-request")) {
		device_name = bundle_get_val(user_data, "device-name");
		agent_path = bundle_get_val(user_data, "agent-path");

		sys_conn = _bt_get_system_gconn();
		if (sys_conn == NULL) {
			BT_ERR("ERROR: Can't get on system bus");
			return BT_FAILED;
		}

		ad->agent_proxy = __bluetooth_create_agent_proxy(sys_conn, agent_path);
		if (!ad->agent_proxy){
			BT_ERR("create new agent_proxy failed\n");
			return BT_FAILED;
		}

		body = g_strdup_printf("Allow %s to access messages?", device_name);

		ret = __notify_send_popup(	ad,
						body,
						"Accept",
						(NotifyActionCallback) __notify_authorize_request_accept_cb,
						"Cancel",
						(NotifyActionCallback) __notify_authorize_request_cancel_cb);
		g_free(body);
	} else {
		ret = BT_FAILED;
	}

	return ret;
}

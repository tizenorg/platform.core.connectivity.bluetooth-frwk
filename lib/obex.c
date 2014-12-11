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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gio/gio.h>
#include "common.h"
#include "obex.h"

#define OBEX_NAME "org.bluez.obex"

#define OBJECT_MANAGE_PATH "/"

#define OBJECT_OBEX_PATH "/org/bluez/obex"

#define OBEX_AGENT_INTERFACE "org.bluez.obex.AgentManager1"

#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

#define OBEX_SESSION_INTERFACE "org.bluez.obex.Session1"

#define OBEX_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"

static GDBusConnection *g_connection;
static int g_opp_startup;
static GDBusProxy *manager_proxy;
static GDBusObjectManager *object_manager;

static obex_agent_added_cb_t obex_agent_added_cb;
static void *obex_agent_added_cb_data;
static GList *transfer_watched_list;

static GDBusConnection *_obex_get_session_dbus(void)
{
	GError *error = NULL;

	if (g_connection)
		return g_connection;

	g_connection =
		g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (g_connection == NULL) {
		DBG("%s", error->message);
		g_error_free(error);
	}

	return g_connection;
}

void obex_agent_set_agent_added(obex_agent_added_cb_t cb, void *user_data)
{
	obex_agent_added_cb = cb;
	obex_agent_added_cb_data = user_data;
}

void obex_agent_unset_agent_added(void)
{
	obex_agent_added_cb = NULL;
	obex_agent_added_cb_data = NULL;
}

struct agent_data {
	agent_cb_t cb;
	void *user_data;
	GDBusConnection *conn;
};

static void agent_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	enum bluez_error_type error_type = ERROR_NONE;
	struct agent_data *agent_data = user_data;

	DBG("+");

	ret = g_dbus_connection_call_finish(agent_data->conn,
						res, &error);
	if (ret == NULL) {
		error_type = get_error_type(error);
		ERROR("error = %d", error_type);
		g_free(error);
	}

	if (agent_data && agent_data->cb) {
		agent_data->cb(error_type, agent_data->user_data);
		g_free(agent_data);
	}

	DBG("-");
}

void obex_agent_register_agent(const char *agent_path,
				agent_cb_t cb,
				void *user_data)
{
	struct agent_data *register_data;
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("");

	register_data = g_new0(struct agent_data, 1);
	if (register_data == NULL) {
		ERROR("no memory");
		return;
	}

	register_data->cb = cb;
	register_data->user_data = user_data;
	register_data->conn = connection;

	if (g_opp_startup)
		g_dbus_connection_call(connection, "org.bluez.obex",
					"/org/bluez/obex",
					"org.bluez.obex.AgentManager1",
					"RegisterAgent",
					g_variant_new("(o)", agent_path),
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
					agent_callback, register_data);
	else
		ERROR("agent not registered");
}

void obex_agent_unregister_agent(const char *agent_path,
					agent_cb_t cb,
					void *user_data)
{
	struct agent_data *unregister_data;
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("");

	unregister_data = g_new0(struct agent_data, 1);
	if (unregister_data == NULL) {
		ERROR("no memory");
		return;
	}

	unregister_data->cb = cb;
	unregister_data->user_data = user_data;
	unregister_data->conn = connection;

	if (g_opp_startup)
		g_dbus_connection_call(connection, "org.bluez.obex",
					"/org/bluez/obex",
					"org.bluez.obex.AgentManager1",
					"UnregisterAgent",
					g_variant_new("(o)", agent_path),
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
					agent_callback, unregister_data);
	else
		ERROR("agent not registered");
}

static enum transfer_state get_transfer_state_from_string(const char *string)
{
	if (string == NULL)
		return OBEX_TRANSFER_UNKNOWN;

	if (!g_strcmp0(string, "queued"))
		return OBEX_TRANSFER_QUEUED;

	if (!g_strcmp0(string, "active"))
		return OBEX_TRANSFER_ACTIVE;

	if (!g_strcmp0(string, "complete"))
		return OBEX_TRANSFER_COMPLETE;

	if (!g_strcmp0(string, "error"))
		return OBEX_TRANSFER_ERROR;

	return OBEX_TRANSFER_UNKNOWN;
}

enum transfer_state obex_transfer_get_property_state(const char *path)
{
	GDBusProxy *p_proxy;
	char *status = NULL;

	DBG("");

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		status = property_get_string(p_proxy,
				OBEX_TRANSFER_INTERFACE, "Status");

	g_object_unref(p_proxy);

	return get_transfer_state_from_string(status);
}

int obex_transfer_get_property_transferred(const char *path,
				guint64 *u64)
{
	GDBusProxy *p_proxy;
	int ret = -1;

	DBG("");

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		ret = property_get_uint64(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Transferred", u64);

	g_object_unref(p_proxy);

	return ret;
}

int obex_transfer_get_property_size(const char *path,
				guint64 *u64)
{
	GDBusProxy *p_proxy;
	int ret = -1;

	DBG("path = %s", path);
	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		ret = property_get_uint64(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Size", u64);

	g_object_unref(p_proxy);

	return ret;
}

static void parse_object(gpointer data, gpointer user_data)
{
	GDBusObject *obj = data;
	const char *path = g_dbus_object_get_object_path(obj);


	DBG("object path name %s", path);

	if (!g_strcmp0(path, OBJECT_OBEX_PATH)) {
		if (g_opp_startup == 1)
			return;
		g_opp_startup = 1;
		if (obex_agent_added_cb)
			obex_agent_added_cb(obex_agent_added_cb_data);
	}

	return;
}


static void interfaces_removed(GVariant *parameters)
{
	gchar *object_path;
	GVariantIter *iter;

	gchar *parameters_s = g_variant_print(parameters, TRUE);

	g_variant_get(parameters, "(oas)", &object_path, &iter);

	DBG("%s", parameters_s);

	g_free(parameters_s);

	DBG("%s", object_path);

	if (!g_strcmp0(object_path, OBJECT_OBEX_PATH))
		g_opp_startup = 0;
}

static void interfaces_added(GVariant *parameters)
{
	gchar *object_path;
	GDBusObject *obj;

	g_variant_get(parameters, "(oa{sa{sv}})", &object_path, NULL);

	DBG("object %s", object_path);

	obj = g_dbus_object_manager_get_object(object_manager, object_path);

	if (obj)
		parse_object(obj, NULL);
}

static gboolean handle_interfaces_added(gpointer user_data)
{
	GVariant *parameters = user_data;

	interfaces_added(parameters);

	g_variant_unref(parameters);

	return FALSE;
}

static void interfaces_changed(GDBusProxy *proxy,
				gchar *sender_name,
				gchar *signal_name,
				GVariant *parameters,
				gpointer user_data)
{
	if (!g_strcmp0(signal_name, "InterfacesAdded"))
		g_idle_add(handle_interfaces_added,
				g_variant_ref_sink(parameters));
	if (!g_strcmp0(signal_name, "InterfacesRemoved"))
		interfaces_removed(parameters);
}

int obex_agent_get_agent(void)
{
	return g_opp_startup;
}

int obex_lib_init(void)
{
	GList *obj_list;

	DBG("");

	if (object_manager != NULL)
		return 0;

	manager_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SESSION, 0,
						NULL,
						OBEX_NAME,
						"/",
						MANAGER_INTERFACE,
						NULL, NULL);

	if (manager_proxy == NULL)
		ERROR("create manager_proxy error");
	else {
		DBG("manager proxy 0x%p created", manager_proxy);

		g_signal_connect(manager_proxy,
				"g-signal",
				G_CALLBACK(interfaces_changed),
				NULL);
	}

	object_manager = g_dbus_object_manager_client_new_for_bus_sync(
							G_BUS_TYPE_SESSION,
							0,
							OBEX_NAME,
							OBJECT_MANAGE_PATH,
							NULL, NULL, NULL,
							NULL, NULL);

	if (object_manager == NULL) {
		ERROR("create object manager error");
		/* TODO: define error type */
		return -1;
	}

	DBG("object manager %p is created", object_manager);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);

	return 0;
}

static void destruct_obex_object_manager(void)
{
	DBG("");

	g_object_unref(object_manager);

	object_manager = NULL;
}

void obex_lib_deinit(void)
{
	DBG("");

	if (manager_proxy)
		g_object_unref(manager_proxy);

	destruct_obex_object_manager();
}

struct obex_session_result {
	obex_session_state_cb cb;
	void *user_data;
	GDBusConnection *conn;
};

static const char *get_obex_target_string(enum obex_target target)
{
	switch (target) {
	case OBEX_TARGET_UNKNOWN:
		return NULL;
	case OBEX_FTP:
		return "ftp";
	case OBEX_MAP:
		return "map";
	case OBEX_OPP:
		return "opp";
	case OBEX_PBAP:
		return "pbap";
	case OBEX_SYNC:
		return "sync";
	default:
		return NULL;
	}

	return NULL;
}

static void create_session_cb(GObject *object,
				GAsyncResult *res,
				gpointer user_data)
{
	GError *error;
	char *session;
	GVariant *result;
	struct obex_session_result *async_node;

	error = NULL;
	async_node = user_data;

	DBG("+");

	result = g_dbus_connection_call_finish(async_node->conn,
						res, &error);

	if (error) {
		ERROR("create session error %s", error->message);

		async_node->cb(NULL, NULL, OBEX_SESSION_FAILED,
					async_node->user_data,
					g_strdup(error->message));

		g_error_free(error);
	} else {

		g_variant_get(result, "(o)", &session);

		DBG("Sesseion created %s", session);

		async_node->cb(NULL, session, OBEX_SESSION_CREATED,
					async_node->user_data, NULL);

		g_free(session);

		g_variant_unref(result);
	}

	g_free(async_node);

	DBG("-");
}

static void remove_session_cb(GObject *object,
				GAsyncResult *res,
				gpointer user_data)
{
	GError *error;
	GVariant *result;
	GDBusConnection *conn = user_data;

	DBG("");

	error = NULL;
	result = g_dbus_connection_call_finish(conn, res, &error);

	if (error) {
		ERROR("create session error %s", error->message);

		g_error_free(error);
	} else
		g_variant_unref(result);
}

int obex_create_session(const char *destination,
				enum obex_target target,
				obex_session_state_cb cb,
				void *data)
{
	GVariantBuilder *builder;
	const char *target_s;
	GVariant *target_v;
	struct obex_session_result *async_node;
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("+");

	if (!connection)
		return -1;

	async_node = g_new0(struct obex_session_result, 1);
	if (async_node == NULL) {
		ERROR("no memory");
		return -1;
	}

	async_node->cb = cb;
	async_node->user_data = data;
	async_node->conn = connection;

	target_s = get_obex_target_string(target);
	target_v = g_variant_new("s", target_s);
	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(builder, "{sv}", "Target", target_v);

	DBG("destination = %s, target_s = %s", destination, target_s);

	g_dbus_connection_call(connection, "org.bluez.obex",
					"/org/bluez/obex",
					"org.bluez.obex.Client1",
					"CreateSession",
					g_variant_new("(sa{sv})",
					destination, builder),
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
					create_session_cb, async_node);

	g_variant_builder_unref(builder);

	DBG("-");

	return 0;
}

void obex_session_remove_session(const char *object_path)
{
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("");

	if (!connection)
		return;

	g_dbus_connection_call(connection, "org.bluez.obex",
				"/org/bluez/obex",
				"org.bluez.obex.Client1",
				"RemoveSession",
				g_variant_new("(o)", object_path),
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				remove_session_cb, connection);
}

struct obex_transfer_result {
	obex_transfer_state_cb cb;
	void *user_data;
	GDBusConnection *conn;
};

static void create_transfer_cb(GObject *object,
				GAsyncResult *res,
				gpointer user_data)
{
	GError *error = NULL;
	char *transfer;
	GVariant *result;
	struct obex_transfer_result *async_node = user_data;

	DBG("+");

	result = g_dbus_connection_call_finish(async_node->conn,
						res, &error);

	async_node = user_data;

	if (error) {
		ERROR("transfer error %s", error->message);

		async_node->cb(NULL, OBEX_TRANSFER_ERROR, NULL, 0, 0,
				NULL, g_strdup(error->message));

		g_error_free(error);
	} else {
		g_variant_get(result, "(oa{sv})", &transfer, NULL);

		DBG("transfer created %s", transfer);

		async_node->cb(g_strdup(transfer), OBEX_TRANSFER_QUEUED,
				NULL, 0, 0, async_node->user_data, NULL);

		g_free(transfer);

		g_variant_unref(result);
	}

	g_free(async_node);

	DBG("-");
}

void obex_session_opp_send_file(const char *session,
				const char *file,
				obex_transfer_state_cb cb,
				void *data)
{
	struct obex_transfer_result *async_node;
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("");

	if (!connection)
		return;

	async_node = g_new0(struct obex_transfer_result, 1);
	if (async_node == NULL) {
		ERROR("no memory");
		return;
	}

	async_node->cb = cb;
	async_node->user_data = data;
	async_node->conn = connection;

	g_dbus_connection_call(connection, "org.bluez.obex",
					session,
					"org.bluez.obex.ObjectPush1",
					"SendFile",
					g_variant_new("(s)", file),
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
					create_transfer_cb, async_node);
}

struct obex_watch_result {
	obex_transfer_state_cb cb;
	void *user_data;
	char *path;
	unsigned int proxy_id;
	GDBusProxy *proxy;
};

int obex_get_transfer_id(const char *transfer_path, enum obex_role role)
{
	int id;
	char *p = g_strrstr(transfer_path, "transfer");

	if (p == NULL) {
		ERROR("Can't get transfer id");
		return -1;
	}

	id = atoi(8 + p);

	if (role == OBEX_SERVER)
		id = id + 10000;

	DBG("transfer id %d", id);

	return id;
}

static struct obex_watch_result *find_watch_node(const char *path)
{
	struct obex_watch_result *node;
	GList *list, *next;

	DBG("path = %s", path);

	if (!transfer_watched_list ||
			!g_list_length(transfer_watched_list))
		return NULL;

	for (list = g_list_first(transfer_watched_list);
					list; list = next) {
		next = g_list_next(list);
		node = list->data;

		if (node && !g_strcmp0(node->path, path))
			return node;
	}

	return NULL;
}

static void transfer_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	struct obex_watch_result *async_node = user_data;
	gchar *status;
	enum transfer_state state;
	gchar *name = NULL;
	guint64 size = 0;
	gboolean variant_found;
	guint64 transferred = 0;
	GDBusProxy *p_proxy;

	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);
	g_free(properties);

	if (!async_node || !async_node->path)
		return;

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					async_node->path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (!p_proxy)
		return;

	variant_found = g_variant_lookup(changed_properties,
					"Status", "s", &status);

	if (variant_found) {
		DBG("status = %s", status);
		state = get_transfer_state_from_string(status);
		if (state == OBEX_TRANSFER_ERROR ||
			state == OBEX_TRANSFER_COMPLETE)
			goto done;
	} else {
		status = property_get_string(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Status");
		state = get_transfer_state_from_string(status);
	}

	variant_found = g_variant_lookup(changed_properties,
				"Transferred", "t", &transferred);

	if (!variant_found)
		property_get_uint64(p_proxy,
			OBEX_TRANSFER_INTERFACE,
			"Transferred", &transferred);
	name = property_get_string(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Filename");

	property_get_uint64(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Size", &size);

	DBG("state: %d, %ju, %s, %s, %ju", state, transferred,
						name, status, size);

	async_node->cb(async_node->path, state, name, size,
			transferred, async_node->user_data, NULL);

	g_object_unref(p_proxy);
	return;
done:
	DBG("state: %d, %ju, %s, %s, %ju", state, transferred,
						name, status, size);

	async_node->cb(async_node->path, state, name, size, transferred,
				async_node->user_data, NULL);

	g_signal_handler_disconnect(async_node->proxy,
						async_node->proxy_id);

	transfer_watched_list = g_list_remove(transfer_watched_list,
							async_node);
	g_object_unref(p_proxy);
	g_object_unref(async_node->proxy);
	if (async_node->path)
		g_free(async_node->path);
	async_node->path = NULL;
	g_free(async_node);
	async_node = NULL;
}

/* notify specific transfer */
int obex_transfer_set_notify(char *transfer_path,
				obex_transfer_state_cb cb, void *data)
{
	struct obex_watch_result *async_node;
	GDBusProxy *proxy;

	DBG("");

	async_node = g_new0(struct obex_watch_result, 1);
	if (async_node == NULL) {
		ERROR("no memory");
		return -1;
	}

	DBG("transfer_path = %s", transfer_path);
	proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					transfer_path,
					"org.bluez.obex.Transfer1",
					NULL, NULL);

	if (proxy == NULL) {
		g_free(async_node);
		WARN("properties proxy error");
		return -1;
	}

	async_node->cb = cb;
	async_node->user_data = data;
	async_node->proxy = g_object_ref(proxy);
	async_node->path = g_strdup(transfer_path);

	async_node->proxy_id = g_signal_connect(async_node->proxy,
			"g-properties-changed",
			G_CALLBACK(transfer_properties_changed),
			async_node);

	transfer_watched_list = g_list_append(transfer_watched_list,
							async_node);

	return 0;
}

void obex_transfer_clear_notify(char *transfer_path)
{
	struct obex_watch_result *async_node;

	DBG("transfer_path = %s", transfer_path);

	if (!transfer_path)
		return;

	async_node = find_watch_node(transfer_path);
	if (!async_node)
		return;

	g_signal_handler_disconnect(async_node->proxy,
					async_node->proxy_id);

	transfer_watched_list = g_list_remove(transfer_watched_list,
							async_node);

	g_object_unref(async_node->proxy);
	if (async_node->path)
		g_free(async_node->path);
	g_free(async_node);
}

static void simple_cancle_cb(GObject *object,
			GAsyncResult *res, gpointer user_data)
{
	GError *error;
	GVariant *result;
	GDBusConnection *conn = user_data;

	DBG("");

	error = NULL;
	result = g_dbus_connection_call_finish(conn, res, &error);

	if (error) {
		ERROR("create session error %s", error->message);
		g_error_free(error);
	} else
		g_variant_unref(result);
}

void obex_transfer_cancel(const char *path)
{
	GDBusConnection *connection = _obex_get_session_dbus();

	DBG("");

	if (!connection)
		return;

	if (path == NULL)
		return;

	DBG("path = %s", path);

	g_dbus_connection_call(connection, "org.bluez.obex",
				path,
				"org.bluez.obex.Transfer1",
				"Cancel",
				NULL,
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				simple_cancle_cb, connection);
}

static char *_obex_transfer_get_property_session(const char *path)
{
	char *session = NULL;
	GDBusProxy *p_proxy;

	DBG("");

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		session = property_get_string(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Session");

	g_object_unref(p_proxy);

	return session;
}

char *obex_transfer_get_property_source(const char *path)
{
	char *source = NULL, *session;
	GDBusProxy *p_proxy;

	DBG("");

	session = _obex_transfer_get_property_session(path);

	DBG("session = %s", session);

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					session,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		source = property_get_string(p_proxy,
			OBEX_SESSION_INTERFACE, "Source");

	g_object_unref(p_proxy);

	return source;
}

char *obex_transfer_get_property_destination(const char *path)
{
	char *dest = NULL, *session;
	GDBusProxy *p_proxy;

	session = _obex_transfer_get_property_session(path);

	DBG("session = %s, path = %s", session, path);

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					session,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		dest = property_get_string(p_proxy,
			OBEX_SESSION_INTERFACE, "Destination");

	g_object_unref(p_proxy);

	return dest;
}

char *obex_transfer_get_property_file_name(const char *path)
{
	char *name = NULL;
	GDBusProxy *p_proxy;

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		name = property_get_string(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Filename");

	g_object_unref(p_proxy);

	return name;
}

char *obex_transfer_get_property_name(const char *path)
{
	char *name = NULL;
	GDBusProxy *p_proxy;

	DBG("path = %s", path);

	p_proxy = g_dbus_proxy_new_for_bus_sync(
					G_BUS_TYPE_SESSION, 0,
					NULL,
					"org.bluez.obex",
					path,
					PROPERTIES_INTERFACE,
					NULL, NULL);

	if (p_proxy)
		name = property_get_string(p_proxy,
			OBEX_TRANSFER_INTERFACE, "Name");

	g_object_unref(p_proxy);

	return name;
}

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

#define FTP_TARGET_UUID "F9EC7BC4-953C-11D2-984E-525400DC9E09"
#define MAP_TARGET_UUID "BB582B40-420C-11DB-B0DE-0800200C9A66"
#define PBAP_TARGET_UUID "796135F0-F0C5-11D8-0966-0800200C9A66"
#define SYNC_TARGET_UUID "BB582B40-420C-11DB-B0DE-0800200C9A66"

#define OBEX_NAME "org.bluez.obex"

#define OBJECT_MANAGE_PATH "/"

#define OBJECT_OBEX_PATH "/org/bluez/obex"

#define OBEX_AGENT_INTERFACE "org.bluez.obex.AgentManager1"

#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

#define MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"

#define OBEX_CLIENT_INTERFACE "org.bluez.obex.Client1"

#define OBEX_SESSION_INTERFACE "org.bluez.obex.Session1"
#define OBEX_SESSION_FTP_INTERFACE "org.bluez.obex.FileTransfer"
#define OBEX_SESSION_MAP_INTERFACE "org.bluez.obex.MessageAccess1"
#define OBEX_SESSION_OPP_INTERFACE "org.bluez.obex.ObjectPush1"
#define OBEX_SESSION_PBAP_INTERFACE "org.bluez.obex.PhonebookAccess1"
#define OBEX_SESSION_SYNC_INTERFACE "org.bluez.obex.Synchronization1"

#define OBEX_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"

static GDBusObjectManager *object_manager;

struct _obex_object {
	char *service_name;
	char *path_name;
	GDBusObject *obj;
	GList *interfaces;
	GDBusProxy *properties_proxy;
};

struct _obex_client {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _obex_object *parent;
};

struct _obex_agent {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusProxy *proxy;
	struct _obex_object *parent;
};

struct _proxy {
	char *interface_name;
	GDBusInterface *interface;
	GDBusProxy *proxy;
};

/*
 * We combine the session interface and obex interface into session
 * to make things easy to handle, we use session interface to indentify
 * the obex_session
 */
struct _obex_session {
	char *interface_name;
	char *identity;
	int ref_count;
	enum obex_target target;
	enum obex_role role;
	char *object_path;
	struct _obex_object *parent;
	struct _proxy session_proxy;
	struct _proxy obex_proxy;
};

struct _obex_transfer {
	char *interface_name;
	int ref_count;
	char *object_path;
	int id;
	struct _obex_object *parent;
	struct _proxy proxy;
	struct _obex_session *session;
	char *source;
	char *destination;
	enum obex_target target;
	char *create_time;
};

static GHashTable *obex_object_hash;

static struct _obex_object *get_object_from_path(const char *path)
{
	return g_hash_table_lookup(obex_object_hash, (gpointer) path);
}

static struct _obex_object *create_object(GDBusObject *obj)
{
	GDBusProxy *properties_proxy;
	struct _obex_object *object;
	const char *path = g_dbus_object_get_object_path(obj);

	DBG("object 0x%p, object path %s", obj, path);

	object = g_try_new0(struct _obex_object, 1);
	if (object == NULL) {
		ERROR("no memeory");
		return NULL;
	}

	object->service_name = g_strdup(OBEX_NAME);

	object->obj = g_object_ref(obj);

	properties_proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SESSION, 0,
						NULL,
						OBEX_NAME,
						path,
						PROPERTIES_INTERFACE,
						NULL, NULL);
	if (properties_proxy == NULL)
		WARN("create properties proxy error");

	object->properties_proxy = properties_proxy;
	object->path_name = g_strdup(path);

	return object;
}

static GList *obex_object_list;

static void register_obex_object(struct _obex_object *object)
{
	DBG("%p", object);

	obex_object_list = g_list_prepend(obex_object_list,
						(gpointer) object);
	g_hash_table_insert(obex_object_hash,
				(gpointer) object->path_name,
				(gpointer) object);
}

static void free_obex_client(struct _obex_client *client)
{
	g_free(client->interface_name);
	g_free(client->object_path);
	g_object_unref(client->interface);
	g_object_unref(client->proxy);
	g_free(client);
}

static struct _obex_client *create_client(struct _obex_object *object)
{
	struct _obex_client *client;
	GDBusInterface *interface;
	GDBusInterfaceInfo *interface_info;

	interface = g_dbus_object_get_interface(object->obj,
						OBEX_CLIENT_INTERFACE);
	if (interface == NULL)
		return NULL;

	DBG("");

	client = g_try_new0(struct _obex_client, 1);
	if (client == NULL) {
		g_object_unref(interface);
		ERROR("no memory");
		return NULL;
	}

	client->interface = interface;

	interface_info = g_dbus_interface_get_info(interface);

	client->proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SESSION, 0,
						interface_info,
						OBEX_NAME,
						object->path_name,
						OBEX_CLIENT_INTERFACE,
						NULL, NULL);
	if (client->proxy == NULL) {
		ERROR("client create proxy error");
		g_object_unref(client->interface);
		g_free(client);
		return NULL;
	}

	client->interface_name = g_strdup(OBEX_CLIENT_INTERFACE);

	client->object_path = g_strdup(object->path_name);

	client->parent = object;

	return client;
}

static struct _obex_client *this_client;

static void register_obex_client(struct _obex_client *client)
{
	GList **interface_list = &client->parent->interfaces;

	*interface_list = g_list_prepend(*interface_list, (gpointer) client);

	DBG("client %p", client);

	if (this_client)
		WARN("client %p not unregister", this_client);

	this_client = client;
}

static void unregister_obex_client(struct _obex_client *client)
{

	DBG("%p", client);

	if (this_client == NULL)
		return;

	this_client = NULL;
}

static void free_obex_agent(struct _obex_agent *agent)
{
	g_free(agent->interface_name);
	g_free(agent->object_path);
	g_object_unref(agent->interface);
	g_object_unref(agent->proxy);
	g_free(agent);
}

static struct _obex_agent *create_agent(struct _obex_object *object)
{
	struct _obex_agent *agent;
	GDBusInterface *interface;
	GDBusInterfaceInfo *interface_info;

	DBG("");

	interface = g_dbus_object_get_interface(object->obj,
						OBEX_AGENT_INTERFACE);
	if (interface == NULL)
		return NULL;

	agent = g_try_new0(struct _obex_agent, 1);
	if (agent == NULL) {
		ERROR("no memory");
		g_object_unref(interface);
		return NULL;
	}

	agent->interface = interface;

	interface_info = g_dbus_interface_get_info(interface);

	agent->proxy = g_dbus_proxy_new_for_bus_sync(
						G_BUS_TYPE_SESSION, 0,
						interface_info,
						OBEX_NAME,
						object->path_name,
						OBEX_AGENT_INTERFACE,
						NULL, NULL);
	if (agent->proxy == NULL) {
		ERROR("agent create proxy error");
		g_object_unref(agent->interface);
		g_free(agent);
		return NULL;
	}

	agent->interface_name = g_strdup(OBEX_AGENT_INTERFACE);

	agent->object_path = g_strdup(object->path_name);

	agent->parent = object;

	return agent;
}

static struct _obex_agent *this_agent;
static obex_agent_added_cb_t obex_agent_added_cb;
static void *obex_agent_added_cb_data;

obex_agent_t *obex_agent_get_agent(void)
{
	return this_agent;
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

static void register_obex_agent(struct _obex_agent *agent)
{
	GList **interface_list = &agent->parent->interfaces;

	*interface_list = g_list_prepend(*interface_list, (gpointer) agent);

	DBG("");

	if (this_agent)
		WARN("agent %p not unregister", this_agent);

	this_agent = agent;

	if (obex_agent_added_cb)
		obex_agent_added_cb(this_agent, obex_agent_added_cb_data);
}

static void unregister_obex_agent(struct _obex_agent *agent)
{
	DBG("");

	if (this_agent == NULL)
		return;

	this_agent = NULL;
}

struct agent_data {
	agent_cb_t cb;
	void *user_data;
};

static void agent_callback(GObject *source_object,
					GAsyncResult *res,
					gpointer user_data)
{
	GVariant *ret;
	GError *error = NULL;
	enum bluez_error_type error_type = ERROR_NONE;
	struct agent_data *agent_data = user_data;

	ret = g_dbus_proxy_call_finish(this_agent->proxy,
						res, &error);
	if (ret == NULL) {
		error_type = get_error_type(error);

		g_free(error);
	}

	agent_data->cb(error_type, agent_data->user_data);

	g_free(agent_data);
}

void obex_agent_register_agent(const char *agent_path,
				agent_cb_t cb,
				void *user_data)
{
	struct agent_data *register_data;

	register_data = g_new0(struct agent_data, 1);
	if (register_data == NULL) {
		ERROR("no memory");
		return;
	}

	register_data->cb = cb;
	register_data->user_data = user_data;

	if (this_agent)
		g_dbus_proxy_call(this_agent->proxy, "RegisterAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				agent_callback, register_data);
	else
		ERROR("agent not registered");
}

void obex_agent_unregister_agent(const char *agent_path,
					agent_cb_t cb,
					void *user_data)
{
	struct agent_data *unregister_data;

	unregister_data = g_new0(struct agent_data, 1);
	if (unregister_data == NULL) {
		ERROR("no memory");
		return;
	}

	unregister_data->cb = cb;
	unregister_data->user_data = user_data;

	if (this_agent)
		g_dbus_proxy_call(this_agent->proxy, "UnregisterAgent",
				g_variant_new("(o)", agent_path),
				0, -1, NULL,
				agent_callback, unregister_data);
	else
		ERROR("agent not registered");
}

static inline int get_proxy(struct _proxy *proxy,
				struct _obex_object *object,
				gboolean is_system,
				const char *interface_name)
{
	GDBusInterfaceInfo *interface_info;

	if (interface_name == NULL) {
		proxy->proxy = NULL;
		return -1;
	}

	proxy->interface = g_dbus_object_get_interface(object->obj,
							interface_name);
	interface_info = g_dbus_interface_get_info(proxy->interface);

	proxy->interface_name = g_strdup(interface_name);

	proxy->proxy = g_dbus_proxy_new_for_bus_sync((is_system ?
							G_BUS_TYPE_SYSTEM :
							G_BUS_TYPE_SESSION),
							0,
							interface_info,
							object->service_name,
							object->path_name,
							interface_name,
							NULL, NULL);
	if (proxy->proxy == NULL) {
		g_object_unref(proxy->interface);
		proxy->interface = NULL;
		g_free(proxy->interface_name);
		proxy->interface_name = NULL;
		return -1;
	}

	DBG("proxy %p", proxy->proxy);

	return 0;
}

/* Use the typical interface name to check the object type */
static inline gboolean check_object_type(struct _obex_object *object,
						const char *interface_name)
{
	GDBusInterface *interface =
			g_dbus_object_get_interface(object->obj,
							interface_name);
	if (interface != NULL) {
		g_object_unref(interface);
		return TRUE;
	}

	return FALSE;
}

static enum obex_role get_session_role(struct _obex_object *object)
{
	if (check_object_type(object, OBEX_SESSION_FTP_INTERFACE))
		return OBEX_CLIENT;

	if (check_object_type(object, OBEX_SESSION_MAP_INTERFACE))
		return OBEX_CLIENT;

	if (check_object_type(object, OBEX_SESSION_OPP_INTERFACE))
		return OBEX_CLIENT;

	if (check_object_type(object, OBEX_SESSION_PBAP_INTERFACE))
		return OBEX_CLIENT;

	if (check_object_type(object, OBEX_SESSION_SYNC_INTERFACE))
		return OBEX_CLIENT;


	return OBEX_SERVER;
}

static inline const char *get_session_interface_name(enum obex_target target)
{
	switch (target) {
	case OBEX_TARGET_UNKNOWN:
		return NULL;
	case OBEX_FTP:
		return OBEX_SESSION_FTP_INTERFACE;
	case OBEX_MAP:
		return OBEX_SESSION_MAP_INTERFACE;
	case OBEX_OPP:
		return OBEX_SESSION_OPP_INTERFACE;
	case OBEX_PBAP:
		return OBEX_SESSION_PBAP_INTERFACE;
	case OBEX_SYNC:
		return OBEX_SESSION_SYNC_INTERFACE;
	}

	return NULL;
}

static inline void property_set_uint64(GDBusProxy *proxy,
						const char *property,
						guint64 u64)
{
	g_dbus_proxy_set_cached_property(proxy, property,
				g_variant_new("t", u64));
}

static inline void property_set_string(GDBusProxy *proxy,
						const char *property,
						const char *str)
{
	g_dbus_proxy_set_cached_property(proxy, property,
				g_variant_new("s", str));
}

gchar *obex_session_property_get_destination(struct _obex_session *session)
{
	GVariant *dest_vv, *dest_v;
	GError *error = NULL;
	char *dest;

	DBG("session: %p", session);

	if (session == NULL)
		return NULL;

	dest_vv = g_dbus_proxy_call_sync(
			session->parent->properties_proxy, "Get",
			g_variant_new("(ss)", session->interface_name, "Destination"),
			0, -1, NULL, &error);
	if (dest_vv == NULL) {
		ERROR("Get property Name error %s", error->message);

		g_error_free(error);

		return NULL;
	}

	g_variant_get(dest_vv, "(v)", &dest_v);
	dest = g_strdup(g_variant_get_string(dest_v, 0));

	g_variant_unref(dest_vv);

	return dest;
}

gchar *obex_session_property_get_source(struct _obex_session *session)
{
	if (session == NULL)
		return NULL;

	return property_get_string(session->session_proxy.proxy,
					"Source");
}

gchar *obex_session_property_get_target_uuid(struct _obex_session *session)
{
	if (session == NULL)
		return NULL;

	return property_get_string(session->session_proxy.proxy,
					"Target");
}

static inline enum obex_target target_uuid_to_target(const char *target_uuid)
{
	/*
	 * OPP target header should not be used see
	 * SIG OBJECT PUSH PROFILE v.12 Section 5.4
	 */
	if (target_uuid == NULL || !g_strcmp0(target_uuid, "00001105-0000-1000-8000-00805f9b34fb"))
		return OBEX_OPP;

	if (!g_strcmp0(target_uuid, FTP_TARGET_UUID))
		return OBEX_FTP;
	if (!g_strcmp0(target_uuid, MAP_TARGET_UUID))
		return OBEX_MAP;
	if (!g_strcmp0(target_uuid, PBAP_TARGET_UUID))
		return OBEX_PBAP;
	if (!g_strcmp0(target_uuid, SYNC_TARGET_UUID))
		return OBEX_SYNC;

	ERROR("Unknown uuid %s", target_uuid);

	return OBEX_TARGET_UNKNOWN;
}

static inline enum obex_target get_session_target(struct _obex_session *session)
{
	char *target_uuid = obex_session_property_get_target_uuid(session);

	return target_uuid_to_target(target_uuid);
}

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
	}

	return NULL;
}

static char *get_session_id(struct _obex_session *session)
{
	char *identity, *source, *destination;

	if (session->target == OBEX_TARGET_UNKNOWN)
		return NULL;

	source = obex_session_property_get_source(session);
	destination = obex_session_property_get_destination(session);

	if (source == NULL && destination == NULL)
		goto fail;

	if (source == NULL)
		source = g_strdup("local");

	if (destination == NULL)
		destination = g_strdup("local");

	identity = g_strconcat((const char *) source,
				(const char *) destination,
				get_obex_target_string(session->target), NULL);

	DBG("session identity %s", identity);
	return identity;

fail:
	g_free(source);
	g_free(destination);

	return NULL;
}

static void free_proxy(struct _proxy *proxy)
{
	g_free(proxy->interface_name);
	if (proxy->interface)
		g_object_unref(proxy->interface);
	if (proxy->proxy)
		g_object_unref(proxy->proxy);
}

static GList *session_notify_list;

struct _session_state_notify {
	char *id;
	gboolean is_watch;
	struct _obex_session *session;
	obex_session_state_cb cb;
	enum session_state state;
	char *error_msg;
	void *data;
};

static struct _session_state_notify *session_watch;

static void free_session_state_notify(struct _session_state_notify *notify)
{
	if (notify->id)
		g_free(notify->id);

	if (notify->error_msg)
		g_free(notify->error_msg);

	if (notify->is_watch)
		session_watch = NULL;
}

static struct _session_state_notify *create_session_state_notify(
						obex_session_state_cb cb,
						gboolean is_watch, void *data)
{
	struct _session_state_notify *notify;

	notify = g_try_new0(struct _session_state_notify, 1);
	if (notify == NULL)
		return NULL;

	notify->is_watch = TRUE;
	notify->session = NULL;
	notify->cb = cb;
	notify->data = data;
	notify->state = OBEX_SESSION_NO_SERVICE;

	return notify;
}

static void free_session(struct _obex_session *session)
{
	DBG("");
	g_free(session->identity);
	g_free(session->object_path);
	free_proxy(&session->session_proxy);
	free_proxy(&session->obex_proxy);
	g_free(session);
}

static GHashTable *id_session_hash;
static GHashTable *path_session_hash;
static GList *adopted_transfer_list;

static void unregister_obex_session(struct _obex_session *session)
{
	g_hash_table_remove(id_session_hash,
				(gconstpointer) session->identity);

	g_hash_table_remove(path_session_hash,
				(gconstpointer) session->object_path);
}

static int obex_session_unref(struct _obex_session *session)
{
	int ref = __sync_sub_and_fetch(&session->ref_count, 1);

	DBG("%p: ref=%d", session, ref);

	if (ref > 0)
		return ref;

	unregister_obex_session(session);
	free_session(session);

	return ref;
}

static void session_remove_notify(struct _session_state_notify *notify)
{
	session_notify_list = g_list_remove(session_notify_list, notify);

	free_session_state_notify(notify);
}

gboolean _notify_session(gpointer user_data)
{
	struct _session_state_notify *notify = user_data;

	notify->cb((const char *)notify->id,
			notify->session,
			notify->state,
			notify->data,
			notify->error_msg);

	if (notify->session)
		obex_session_unref(notify->session);

	/* Session notify only once */
	session_remove_notify(notify);
	
	return FALSE;
}

static void _session_notify_state(struct _session_state_notify *notify,
						enum session_state state)
{
	notify->state = state;

	g_idle_add(_notify_session, notify);
}

static struct _obex_session *obex_session_ref(struct _obex_session *session)
{
	int ref = __sync_add_and_fetch(&session->ref_count, 1);

	DBG("%p: ref=%d", session, ref);

	return session;
}

static void session_notify_state(struct _obex_session *session,
					enum session_state state)
{
	GList *list, *next;

	for (list = g_list_first(session_notify_list); list; list = next) {
		struct _session_state_notify *notify = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(notify->id, session->identity)) {

			notify->session = obex_session_ref(session);
			_session_notify_state(notify, state);

		}
	}
}

static void session_add_notify(struct _session_state_notify *notify)
{
	session_notify_list = g_list_prepend(session_notify_list, notify);
}

struct _obex_session *obex_session_get_session_from_path(const char *path)
{
	return g_hash_table_lookup(path_session_hash, (gconstpointer) path);
}

gchar *obex_transfer_property_get_session_path(struct _obex_transfer *transfer)
{
	return property_get_string(transfer->proxy.proxy, "Session");
}

static GList *transfer_notify_list;

struct _transfer_notify {
	int ref_count;
	gboolean is_watch;
	char *transfer_path;
	obex_transfer_state_cb cb;
	struct _obex_transfer *transfer;
	enum transfer_state state;
	guint64 transferred;
	void *data;
	char *error_msg;
};

static struct _transfer_notify *obex_transfer_notify_ref(
					struct _transfer_notify *n)
{
	int ref = __sync_add_and_fetch(&n->ref_count, 1);

	DBG("%p: ref=%d", n, ref);

	return n;
}

static struct _transfer_notify *transfer_watch;

static int obex_transfer_notify_unref(struct _transfer_notify *n)
{
	int ref = __sync_sub_and_fetch(&n->ref_count, 1);

	DBG("%p: ref=%d", n, ref);

	if (ref > 0)
		return ref;

	if (n->is_watch)
		transfer_watch = NULL;
	else
		g_free(n->transfer_path);
	g_free(n);

	if (n->error_msg)
		g_free(n->error_msg);

	return ref;
}

static gboolean remove_transfer_notify(gpointer user_data)
{
	struct _transfer_notify *n = user_data;
	transfer_notify_list = g_list_remove(transfer_notify_list, n);

	obex_transfer_notify_unref(n);

	return FALSE;
}

static inline void free_transfer(struct _obex_transfer *transfer)
{
	obex_session_unref(transfer->session);

	g_free(transfer->interface_name);
	g_free(transfer->object_path);
	free_proxy(&transfer->proxy);
	g_free(transfer->source);
	g_free(transfer->destination);
	g_free(transfer->create_time);
	g_free(transfer);
}

static GHashTable *path_transfer_hash;
static GHashTable *id_transfer_hash;

static void unregister_obex_transfer(struct _obex_transfer *transfer)
{
	g_hash_table_remove(path_transfer_hash,
				(gconstpointer) transfer->object_path);

	g_hash_table_remove(id_transfer_hash, &transfer->id);
}

static int obex_transfer_unref(struct _obex_transfer *transfer)
{
	int ref = __sync_sub_and_fetch(&transfer->ref_count, 1);

	DBG("%p: ref=%d", transfer, ref);

	if (ref > 0)
		return ref;

	unregister_obex_transfer(transfer);
	free_transfer(transfer);

	return ref;
}

gboolean _notify_transfer(gpointer user_data)
{
	struct _transfer_notify *notify = user_data;

	if (notify->cb)
		notify->cb((const char *)notify->transfer_path,
				notify->transfer,
				notify->state,
				notify->transferred,
				notify->data,
				notify->error_msg);

	obex_transfer_notify_unref(notify);

	if (notify->transfer)
		obex_transfer_unref(notify->transfer);

	return FALSE;
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

enum transfer_state obex_transfer_property_get_state(
				struct _obex_transfer *transfer)
{
	char *status = property_get_string(transfer->proxy.proxy, "Status");

	return get_transfer_state_from_string(status);
}

int obex_transfer_property_get_transferred(
				struct _obex_transfer *transfer,
				guint64 *u64)
{
	return property_get_uint64(transfer->proxy.proxy, "Transferred", u64);
}

int obex_transfer_property_get_size(
				struct _obex_transfer *transfer,
				guint64 *u64)
{
	return property_get_uint64(transfer->proxy.proxy, "Size", u64);
}

void obex_transfer_set_property_name(struct _obex_transfer *transfer,
							const char *name)
{
	property_set_string(transfer->proxy.proxy, "Name", name);
}

void obex_transfer_set_property_size(struct _obex_transfer *transfer,
							guint64 size)
{
	property_set_uint64(transfer->proxy.proxy, "Size", size);
}

static struct _transfer_notify *create_transfer_notify(
					obex_transfer_state_cb cb,
					gboolean is_watch, void *data)
{
	struct _transfer_notify *notify;

	notify = g_try_new0(struct _transfer_notify, 1);
	if (notify == NULL)
		return NULL;

	notify->ref_count = 1;
	notify->is_watch = is_watch;
	notify->transfer_path = NULL;
	notify->cb = cb;
	notify->transfer = NULL;
	notify->state = OBEX_TRANSFER_UNKNOWN;
	notify->transferred = 0;
	notify->data = data;
	return notify;
}

static void _transfer_notify_state(struct _transfer_notify *notify,
						enum transfer_state state)
{
	notify->state = state;

	if (state == OBEX_TRANSFER_UNKNOWN)
		notify->state = obex_transfer_property_get_state(
							notify->transfer);
	if (notify->state == OBEX_TRANSFER_ACTIVE)
		obex_transfer_property_get_transferred(
				notify->transfer, &notify->transferred);

	g_idle_add_full(G_PRIORITY_HIGH_IDLE + 30,
			_notify_transfer, notify, NULL);

	if ((notify->state == OBEX_TRANSFER_COMPLETE ||
		notify->state == OBEX_TRANSFER_ERROR ||
			notify->state == OBEX_TRANSFER_CANCELED) &&
				!notify->is_watch)
		g_idle_add_full(G_PRIORITY_HIGH_IDLE + 30,
				remove_transfer_notify, notify, NULL);
}

static struct _obex_transfer *obex_transfer_ref(
				struct _obex_transfer *transfer)
{
	int ref = __sync_add_and_fetch(&transfer->ref_count, 1);

	DBG("%p: ref=%d", transfer, ref);

	return transfer;
}

static void transfer_notify_state(struct _obex_transfer *transfer,
					enum transfer_state state)
{
	GList *list, *next;

	for (list = g_list_first(transfer_notify_list); list; list = next) {
		struct _transfer_notify *notify = list->data;

		next = g_list_next(list);

		if (!g_strcmp0(notify->transfer_path, transfer->object_path)) {
			notify->transfer = obex_transfer_ref(transfer);
			_transfer_notify_state(obex_transfer_notify_ref(notify),
									state);
		}
	}
}

static void transfer_add_notify(struct _transfer_notify *notify)
{
	transfer_notify_list = g_list_prepend(transfer_notify_list, notify);
}

static void _register_obex_transfer(struct _obex_transfer *transfer)
{
	GList **interface_list = &transfer->parent->interfaces;
	struct _transfer_notify *watched_notify;

	DBG("%p", transfer);

	*interface_list = g_list_prepend(*interface_list, (gpointer) transfer);

	g_hash_table_insert(path_transfer_hash,
				(gpointer) transfer->object_path,
				(gpointer) transfer);

	g_hash_table_insert(id_transfer_hash, &transfer->id,
					(gpointer) transfer);

	if (transfer_watch) {
		watched_notify = create_transfer_notify(transfer_watch->cb,
						FALSE, transfer_watch->data);
		watched_notify->transfer_path =
					g_strdup(transfer->object_path);
		transfer_add_notify(watched_notify);
	}

	transfer_notify_state(transfer, OBEX_TRANSFER_UNKNOWN);
}

static void register_obex_transfer(struct _obex_transfer *transfer)
{
	if (transfer->session)
		_register_obex_transfer(transfer);
	else
		adopted_transfer_list = g_list_append(
						adopted_transfer_list,
						transfer);
}

static void transfer_properties_changed(GDBusProxy *proxy,
					GVariant *changed_properties,
					GStrv *invalidated_properties,
					gpointer user_data)
{
	struct _obex_transfer *transfer = user_data;
	gchar *properties = g_variant_print(changed_properties, TRUE);

	DBG("properties %s", properties);
	g_free(properties);

	transfer_notify_state(transfer, OBEX_TRANSFER_UNKNOWN);
}

	
static int get_transfer_id(struct _obex_transfer *transfer)
{
	int id;
	char *p = g_strrstr(transfer->object_path, "transfer");
	if (p == NULL) {
		ERROR("Can't get transfer id");
		return -1;
	}

	id = atoi(8 + p);

	if (transfer->session->role == OBEX_SERVER)
		id = id + 10000;

	DBG("transfer id %d", id);

	return id;
}

static struct _obex_transfer *create_transfer(struct _obex_object *object)
{
	int err;
	char *session_path;
	struct _obex_transfer *transfer;
	struct _obex_session *session;

	DBG("");

	transfer = g_try_new0(struct _obex_transfer, 1);
	if (transfer == NULL) {
		ERROR("no memory");
		return NULL;
	}
	transfer->interface_name = g_strdup(OBEX_TRANSFER_INTERFACE);

	transfer->object_path = g_strdup(object->path_name);

	transfer->parent = object;

	err = get_proxy(&transfer->proxy, object, FALSE,
					OBEX_TRANSFER_INTERFACE);
	if (err) {
		ERROR("create transfer proxy error");
		free_transfer(transfer);
		return NULL;
	}

	session_path = obex_transfer_property_get_session_path(transfer);

	session = obex_session_get_session_from_path(session_path);
	transfer->session = obex_session_ref(session);

	g_free(session_path);

	transfer->source = obex_session_property_get_source(
							transfer->session);
	transfer->destination = obex_session_property_get_destination(
							transfer->session);
	if (transfer->session) {
		transfer->target = transfer->session->target;

		transfer->id = get_transfer_id(transfer);
	}

	transfer->ref_count = 1;

	g_signal_connect(transfer->proxy.proxy,
			"g-properties-changed",
			G_CALLBACK(transfer_properties_changed),
			transfer);

	return transfer;
}

static void match_transfer(struct _obex_session *session)
{
	struct _obex_transfer *transfer;
	GList *list, *next;
	gchar *session_path;

	for (list = g_list_first(adopted_transfer_list); list; list = next) {
		next = g_list_next(list);

		transfer = list->data;

		session_path =
			obex_transfer_property_get_session_path(transfer);
		if (g_strcmp0(session_path, session->object_path)) {
			g_free(session_path);
			continue;
		}

		transfer->session = session;
		transfer->target = transfer->session->target;
		transfer->id = get_transfer_id(transfer);
		if (!transfer->destination)
			transfer->destination =
				obex_session_property_get_destination(transfer->session);

		_register_obex_transfer(transfer);

		adopted_transfer_list = g_list_remove(adopted_transfer_list,
								transfer);

		g_free(session_path);
	}
}

static void register_obex_session(struct _obex_session *session)
{
	GList **interface_list = &session->parent->interfaces;
	struct _session_state_notify *watched_notify;

	DBG("%p", session);

	*interface_list = g_list_prepend(*interface_list, (gpointer) session);

	g_hash_table_insert(id_session_hash,
				(gpointer) session->identity,
				(gpointer) session);

	g_hash_table_insert(path_session_hash,
				(gpointer) session->object_path,
				(gpointer) session);

	if (session_watch) {
		watched_notify = create_session_state_notify(session_watch->cb,
						FALSE, session_watch->data);
		watched_notify->id = session->identity;
		session_add_notify(watched_notify);
	}

	session_notify_state(session, OBEX_SESSION_CREATED);

	match_transfer(session);
}

static struct _obex_session *create_session(struct _obex_object *object)
{
	int err;
	struct _obex_session *session;

	DBG("");

	session = g_try_new0(struct _obex_session, 1);
	if (session == NULL) {
		ERROR("no memory");
		return NULL;
	}
	session->interface_name = g_strdup(OBEX_SESSION_INTERFACE);

	session->object_path = g_strdup(object->path_name);

	session->parent = object;

	err = get_proxy(&session->session_proxy, object, FALSE,
					OBEX_SESSION_INTERFACE);
	if (err) {
		ERROR("create session proxy error");
		free_session(session);
		return NULL;
	}

	session->target = get_session_target(session);

	session->identity = get_session_id(session);
	if (session->identity == NULL) {
		ERROR("get session identity error");
		free_session(session);
		return NULL;
	}

	DBG("session id %s", session->identity);

	session->ref_count = 1;

	session->role = get_session_role(object);
	if (session->role == OBEX_SERVER)
		return session;

	err = get_proxy(&session->obex_proxy, object, FALSE,
				get_session_interface_name(session->target));
	if (err) {
		ERROR("create session proxy error");
		free_session(session);
		return NULL;
	}

	return session;
}

static void parse_object(gpointer data, gpointer user_data)
{
	GDBusObject *obj = data;
	struct _obex_object *object;
	const char *path = g_dbus_object_get_object_path(obj);

	object = get_object_from_path(path);
	if (!object) {
		object = create_object(obj);
		register_obex_object(object);
	}

	DBG("object path name %s", object->path_name);

	if (!g_strcmp0(object->path_name, OBJECT_OBEX_PATH)) {
		struct _obex_client *client;
		struct _obex_agent *agent;

		if (!this_client) {
			client = create_client(object);
			if (client)
				register_obex_client(client);
		}

		if (!this_agent) {
			agent = create_agent(object);
			if (agent)
				register_obex_agent(agent);
		}

		return;
	}

	if (check_object_type(object, OBEX_SESSION_INTERFACE)) {
		struct _obex_session *session =
				create_session(object);
		if (session)
			register_obex_session(session);
		return;
	}

	if (check_object_type(object, OBEX_TRANSFER_INTERFACE)) {
		struct _obex_transfer *transfer =
				create_transfer(object);
		if (transfer)
			register_obex_transfer(transfer);
		return;
	}

	WARN("Unknow Object");

	return;
}

static void destruct_obex_interfaces(GList *interfaces)
{
	GList *list, *next;

	for (list = g_list_first(interfaces); list; list = next) {
		const char **interface_name = list->data;
		next = g_list_next(list);

		if (!g_strcmp0(*interface_name,
					OBEX_CLIENT_INTERFACE)) {
			struct _obex_client *client = list->data;
			unregister_obex_client(client);
			free_obex_client(client);
			list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name, OBEX_AGENT_INTERFACE)) {
			struct _obex_agent *agent = list->data;
			unregister_obex_agent(agent);
			free_obex_agent(agent);
			list->data = NULL;
			continue;
		}

		WARN("unknown interface name %s", *interface_name);
	}
}

static void destruct_obex_object_interfaces(struct _obex_object *object)
{
	GList *list, *next, *interfaces;

	interfaces = object->interfaces;

	DBG("interfaces %p", object->interfaces);
	if (!g_strcmp0(object->path_name, OBJECT_OBEX_PATH)) {
		destruct_obex_interfaces(interfaces);
		return;
	}

	for (list = g_list_first(interfaces); list; list = next) {
		const char **interface_name = list->data;
		next = g_list_next(list);

		if (!g_strcmp0(*interface_name,
					OBEX_SESSION_INTERFACE)) {
			struct _obex_session *session = list->data;
			DBG("free session %s", session->object_path);
			if (obex_session_unref(session) == 0)
				list->data = NULL;
			continue;
		}

		if (!g_strcmp0(*interface_name,
					OBEX_TRANSFER_INTERFACE)) {
			struct _obex_transfer *transfer = list->data;
			enum transfer_state state;

			state = obex_transfer_property_get_state(transfer);

			if (obex_transfer_unref(transfer) == 0)
				list->data = NULL;

			if (state == OBEX_TRANSFER_ERROR ||
					state == OBEX_TRANSFER_COMPLETE)
				continue;

			transfer_notify_state(transfer,
					OBEX_TRANSFER_CANCELED);
		}

		WARN("unknown interface name %s", *interface_name);
	}

	g_list_free(object->interfaces);

	object->interfaces = NULL;
}

static void destruct_obex_object(gpointer data)
{
	struct _obex_object *object = data;

	DBG("");

	obex_object_list = g_list_remove(obex_object_list, object);

	destruct_obex_object_interfaces(object);
	object->interfaces = NULL;

	g_free(object->service_name);

	g_free(object->path_name);

	g_object_unref(object->obj);

	if (object->properties_proxy)
		g_object_unref(object->properties_proxy);

	g_free(object);
}

GDBusProxy *manager_proxy;

static void interfaces_removed(GVariant *parameters)
{
	struct _obex_object *object;
	gchar *object_path;
	GVariantIter *iter;

	gchar *parameters_s = g_variant_print(parameters, TRUE);

	g_variant_get(parameters, "(oas)", &object_path, &iter);

	DBG("%s", parameters_s);

	g_free(parameters_s);

	DBG("%s", object_path);

	object = get_object_from_path(object_path);
	if (object == NULL)
		return;

	g_hash_table_remove(obex_object_hash,
				(gconstpointer) object->path_name);
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

	obex_object_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, destruct_obex_object);

	id_session_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, NULL);
	path_session_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, NULL);

	path_transfer_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, NULL);

	id_transfer_hash = g_hash_table_new_full(g_int_hash, g_int_equal,
						NULL, NULL);

	obj_list = g_dbus_object_manager_get_objects(object_manager);

	g_list_foreach(obj_list, parse_object, NULL);

	return 0;
}

static void destruct_obex_objects(void)
{
	DBG("");

	g_hash_table_destroy(obex_object_hash);

	obex_object_hash = NULL;
}

static void destruct_obex_object_manager(void)
{
	g_object_unref(object_manager);

	object_manager = NULL;
}

void obex_lib_deinit(void)
{
	if (manager_proxy)
		g_object_unref(manager_proxy);

	destruct_obex_objects();
	destruct_obex_object_manager();
}

static gboolean session_creating;

static void create_session_cb(GObject *object,
				GAsyncResult *res,
				gpointer user_data)
{
	GError *error;
	char *session;
	struct _session_state_notify *notify = user_data;
	GDBusProxy *proxy = G_DBUS_PROXY(object);

	session_creating = FALSE;

	error = NULL;
	GVariant *session_v = g_dbus_proxy_call_finish(proxy, res, &error);
	if (session_v == NULL) {
		ERROR("create session error %s", error->message);

		notify->error_msg = g_strdup(error->message);

		_session_notify_state(notify, OBEX_SESSION_FAILED);

		g_error_free(error);
	} else {

		session_add_notify(notify);

		g_variant_get(session_v, "(o)", &session);

		DBG("Sesseion created %s", session);

		g_free(session);

		g_variant_unref(session_v);
	}
}

static struct _obex_session *get_session(const char *id)
{
	struct _obex_session *session;

	session = obex_session_get_session(id);

	if (session == NULL)
		return NULL;

	return session;
}

int obex_create_session(const char *destination,
				enum obex_target target,
				obex_session_state_cb cb,
				void *data)
{
	struct _session_state_notify *notify;
	struct _obex_session *session;
	GVariantBuilder *builder;
	const char *target_s;
	GVariant *target_v;

	if (this_client == NULL) {
		WARN("no client to create session");
		return -1;
	}

	notify = create_session_state_notify(cb, FALSE, data);
	if (notify == NULL)
		return -ENOMEM;

	target_s = get_obex_target_string(target);

	notify->id = g_strconcat("local", destination, target_s, NULL);

	session = get_session(notify->id);
	if (session) {
		notify->session = obex_session_ref(session);
		_session_notify_state(notify, OBEX_SESSION_CREATED);
		return 0;
	}

	if (session_creating) {
		_session_notify_state(notify, OBEX_SESSION_RETRY);
		return 0;
	}

	target_v = g_variant_new("s", target_s);
	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(builder, "{sv}", "Target", target_v);

	session_creating = TRUE;

	g_dbus_proxy_call(this_client->proxy,
				"CreateSession",
				g_variant_new("(sa{sv})", destination, builder),
				0, -1, NULL, create_session_cb, notify);

	g_variant_builder_unref(builder);

	return 0;
}

void obex_session_remove_session(struct _obex_session *session)
{
	DBG("");
	if (session == NULL)
		return;

	g_dbus_proxy_call(this_client->proxy, "RemoveSession",
				g_variant_new("(o)", session->object_path),
				0, -1, NULL, simple_reply_callback, NULL);
}

int obex_session_set_watch(obex_session_state_cb cb, void *data)
{
	struct _session_state_notify *notify;

	if (session_watch) {
		ERROR("Session watch busy");
		return -EBUSY;
	}

	notify = create_session_state_notify(cb, TRUE, data);
	if (notify == NULL)
		return -ENOMEM;

	session_add_notify(notify);

	session_watch = notify;

	return 0;
}

struct _obex_session *obex_session_get_session(const char *id)
{
	return g_hash_table_lookup(id_session_hash,
				(gconstpointer) id);
}

static void create_transfer_cb(GObject *object,
				GAsyncResult *res,
				gpointer user_data)
{
	struct _transfer_notify *notify = user_data;
	GDBusProxy *proxy = G_DBUS_PROXY(object);
	GError *error = NULL;
	char *transfer;

	GVariant *transfer_v = g_dbus_proxy_call_finish(proxy, res, &error);
	if (transfer_v == NULL) {
		ERROR("transfer error %s", error->message);

		notify->error_msg = g_strdup(error->message);

		_transfer_notify_state(obex_transfer_notify_ref(notify),
							OBEX_TRANSFER_ERROR);

		g_error_free(error);
	} else {
		g_variant_get(transfer_v, "(oa{sv})", &transfer, NULL);

		notify->transfer_path = g_strdup(transfer);
		transfer_add_notify(notify);

		DBG("transfer created %s", transfer);

		g_free(transfer);

		g_variant_unref(transfer_v);
	}
}

void obex_session_opp_send_file(struct _obex_session *session,
				const char *file,
				obex_transfer_state_cb cb,
				void *data)
{
	struct _transfer_notify *notify;

	if (session == NULL)
		return;

	if (session->target != OBEX_OPP) {
		ERROR("transfer is not OPP");
		return;
	}

	notify = create_transfer_notify(cb, FALSE, data);

	g_dbus_proxy_call(session->obex_proxy.proxy,
				"SendFile", g_variant_new("(s)", file),
				0, -1, NULL, create_transfer_cb, notify);
}

/* notify specific transfer */
int obex_transfer_set_notify(struct _obex_transfer *transfer,
				obex_transfer_state_cb cb, void *data)
{
	struct _transfer_notify *notify;

	notify = create_transfer_notify(cb, FALSE, data);
	notify->transfer_path = g_strdup(transfer->object_path);

	transfer_add_notify(notify);

	return 0;
}

/* watch all the transfers */
int obex_transfer_set_watch(obex_transfer_state_cb cb, void *data)
{
	struct _transfer_notify *notify;

	if (transfer_watch) {
		ERROR("Transfer watch busy");
		return -EBUSY;
	}

	notify = create_transfer_notify(cb, TRUE, data);

	transfer_add_notify(notify);

	transfer_watch = notify;

	return 0;
}

void obex_transfer_clear_watch(void)
{
	obex_transfer_notify_unref(transfer_watch);
}

struct _obex_transfer *obex_transfer_get_transfer_from_path(const char *path)
{
	return g_hash_table_lookup(path_transfer_hash, (gpointer) path);
}

struct _obex_transfer *obex_transfer_get_transfer_from_id(int id)
{
	return g_hash_table_lookup(id_transfer_hash, &id);
}

const GList *obex_transfer_get_pathes(void)
{
	return g_hash_table_get_keys(path_transfer_hash);
}

const GList *obex_transfer_get_ids(void)
{
	return g_hash_table_get_keys(id_transfer_hash);
}

void obex_transfer_cancel(struct _obex_transfer *transfer)
{
	if (transfer == NULL)
		return;

	g_dbus_proxy_call(transfer->proxy.proxy,
				"Cancel", NULL, 0,
				-1, NULL,
				simple_reply_callback, NULL);
}

char *obex_transfer_get_property_source(struct _obex_transfer *transfer)
{
	return g_strdup(transfer->source);
}

char *obex_transfer_get_property_destination(struct _obex_transfer *transfer)
{
	return g_strdup(transfer->destination);
}

char *obex_transfer_get_property_file_name(struct _obex_transfer *transfer)
{
	return property_get_string(transfer->proxy.proxy, "Filename");
}

char *obex_transfer_get_property_name(struct _obex_transfer *transfer)
{

	return property_get_string(transfer->proxy.proxy, "Name");
}

char *obex_transfer_get_name(struct _obex_transfer *transfer)
{
	GVariant *name_vv, *name_v;
	GError *error = NULL;
	char *name;
	name_vv = g_dbus_proxy_call_sync(
			transfer->parent->properties_proxy, "Get",
			g_variant_new("(ss)", transfer->interface_name, "Name"),
			0, -1, NULL, &error);
	if (name_vv == NULL) {
		ERROR("Get property Name error %s", error->message);

		g_error_free(error);

		return NULL;
	}

	g_variant_get(name_vv, "(v)", &name_v);
	name = g_strdup(g_variant_get_string(name_v, 0));

	g_variant_unref(name_vv);

	return name;
}

int obex_transfer_get_size(struct _obex_transfer *transfer, guint64 *size)
{
	GVariant *size_v, *size_vv;
	GError *error = NULL;
	size_vv = g_dbus_proxy_call_sync(
			transfer->parent->properties_proxy, "Get",
			g_variant_new("(ss)", transfer->interface_name, "Size"),
			0, -1, NULL, &error);
	if (size_vv == NULL) {
		ERROR("Get property Name error %s", error->message);

		g_error_free(error);

		return -1;
	}

	g_variant_get(size_vv, "(v)", &size_v);

	*size = g_variant_get_uint64(size_v);

	g_variant_unref(size_vv);

	return 0;
}

int obex_transfer_get_id(struct _obex_transfer *transfer)
{
	return transfer->id;
}

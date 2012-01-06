/*
 *  Bluetooth-frwk
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "bluetooth-api-common.h"
#include <stdio.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "obex-agent.h"
#include <dlog.h>
#include "marshal.h"

#define BT_OBEX "BT_OBEX"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_OBEX, "%s():%d "fmt, __func__, __LINE__, ##args)

#define OBEX_SERVICE	"org.openobex.client"

#define OBEX_CLIENT_PATH	"/"
#define OBEX_CLIENT_INTERFACE	"org.openobex.Client"
#define OBEX_TRANSFER_INTERFACE	"org.openobex.Transfer"

static DBusGConnection *connection = NULL;

#define OBEX_AGENT_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), \
					OBEX_TYPE_AGENT, ObexAgentPrivate))

typedef struct _ObexAgentPrivate ObexAgentPrivate;

struct _ObexAgentPrivate {
	gchar *busname;
	gchar *path;

	ObexAgentAuthorizeFunc authorize_func;
	gpointer authorize_data;

	ObexAgentReleaseFunc release_func;
	gpointer release_data;

	ObexAgentRequestFunc request_func;
	gpointer request_data;

	ObexAgentProgressFunc progress_func;
	gpointer progress_data;

	ObexAgentCompleteFunc complete_func;
	gpointer complete_data;

	ObexAgentErrorFunc error_func;
	gpointer error_data;
};

G_DEFINE_TYPE(ObexAgent, obex_agent, G_TYPE_OBJECT)

static gboolean obex_agent_request(ObexAgent *agent, const char *path,
				   DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	DBG("agent %p sender %s", agent, sender);

	if (priv->busname == NULL) {
		/* When we get called the first time, if OBEX_SERVICE
		 * was not available, we get its name here */
		priv->busname = sender;
	} else {
		if (g_strcmp0(sender, priv->busname) != 0) {
			g_free(sender);
			return FALSE;
		}

		g_free(sender);
	}

	if (priv->request_func) {
		DBusGProxy *proxy;

		proxy = dbus_g_proxy_new_for_name(connection, OBEX_SERVICE,
						  path, OBEX_TRANSFER_INTERFACE);

		/*FIXME check result*/
		result = priv->request_func(context, proxy, priv->request_data);

		g_object_unref(proxy);
	} else
		dbus_g_method_return(context, "");

	return TRUE;
}

static gboolean obex_agent_authorize(ObexAgent *agent, const char *path, const char *bdaddress,
				     const char *name, const char *type, gint length, gint time,
				     DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	gboolean result = FALSE;

	DBG("agent %p sender %s", agent);

	if (priv->authorize_func) {
		result = priv->authorize_func(context, path, bdaddress, name, type, length, time,
					 	priv->authorize_data);
	} else
		dbus_g_method_return(context);

	return result;
}

static gboolean obex_agent_progress(ObexAgent *agent, const char *path,
				    guint64 transferred, DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	DBG("agent %p sender %s", agent, sender);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	g_free(sender);

	if (priv->progress_func) {
		DBusGProxy *proxy;

		proxy = dbus_g_proxy_new_for_name(connection, OBEX_SERVICE,
						  path, OBEX_TRANSFER_INTERFACE);

		result = priv->progress_func(context, proxy, transferred, priv->progress_data);

		g_object_unref(proxy);
	} else
		dbus_g_method_return(context);

	return result;
}

static gboolean obex_agent_complete(ObexAgent *agent, const char *path,
				    DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	DBG("agent %p sender %s", agent, sender);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	g_free(sender);

	if (priv->complete_func) {
		DBusGProxy *proxy;

		proxy = dbus_g_proxy_new_for_name(connection, OBEX_SERVICE,
						  path, OBEX_TRANSFER_INTERFACE);

		result = priv->complete_func(context, proxy, priv->complete_data);

		g_object_unref(proxy);
	} else
		dbus_g_method_return(context);

	return result;
}

static gboolean obex_agent_release(ObexAgent *agent, DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	DBG("agent %p sender %s bbus %s", agent, sender, priv->busname);
	if (priv->busname) {
		/*In H2 if user denies auth,release will come without request and hence
		priv->busname will be NULL */
		if (g_strcmp0(sender, priv->busname) != 0) {
			g_free(sender);
			return FALSE;
		}
	}
	g_free(sender);

	if (priv->release_func)
		result = priv->release_func(context, priv->release_data);
	else
		dbus_g_method_return(context);

	g_object_unref(agent);

	return result;
}

static gboolean obex_agent_error(ObexAgent *agent,
				 const char *path,
				 const char *message, DBusGMethodInvocation *context)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	DBG("agent %p sender %s", agent, sender);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	g_free(sender);

	if (priv->error_func) {
		DBusGProxy *proxy;

		proxy = dbus_g_proxy_new_for_name(connection, OBEX_SERVICE,
						  path, OBEX_TRANSFER_INTERFACE);

		result = priv->error_func(context, proxy, message, priv->progress_data);

		g_object_unref(proxy);
	} else
		dbus_g_method_return(context);

	return result;
}

#include "obex-agent-glue.h"

static void obex_agent_init(ObexAgent *agent)
{
	DBG("agent %p", agent);
}

static void obex_agent_finalize(GObject *agent)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	g_free(priv->path);
	g_free(priv->busname);

	G_OBJECT_CLASS(obex_agent_parent_class)->finalize(agent);
}

static void obex_agent_class_init(ObexAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;
	GError *error = NULL;

	DBG("class %p", klass);

	g_type_class_add_private(klass, sizeof(ObexAgentPrivate));

	object_class->finalize = obex_agent_finalize;

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);

	if (error != NULL) {
		DBG("error:%s", error->message);
		g_printerr("Connecting to session bus failed: %s\n", error->message);
		g_error_free(error);
	}

	dbus_g_object_type_install_info(OBEX_TYPE_AGENT, &dbus_glib_obex_agent_object_info);
}

BT_EXPORT_API ObexAgent *obex_agent_new(void)
{
	ObexAgent *agent;

	agent = OBEX_AGENT(g_object_new(OBEX_TYPE_AGENT, NULL));
	DBG("agent %p", agent);

	return agent;
}

BT_EXPORT_API gboolean obex_agent_setup(ObexAgent *agent, const char *path)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);
	DBusGProxy *proxy;
	GObject *object;

	DBG("agent %p path %s", agent, path);

	if (priv->path != NULL)
		return FALSE;

	priv->path = g_strdup(path);

	proxy = dbus_g_proxy_new_for_name_owner(connection, OBEX_SERVICE,
						OBEX_CLIENT_PATH, OBEX_CLIENT_INTERFACE, NULL);

	g_free(priv->busname);

	if (proxy != NULL) {
		priv->busname = g_strdup(dbus_g_proxy_get_bus_name(proxy));
		g_object_unref(proxy);
	} else
		priv->busname = NULL;

	object = dbus_g_connection_lookup_g_object(connection, priv->path);
	if (object != NULL)
		g_object_unref(object);

	dbus_g_connection_register_g_object(connection, priv->path, G_OBJECT(agent));

	dbus_g_object_register_marshaller(marshal_VOID__OBJECT_BOOLEAN,
					  G_TYPE_NONE, DBUS_TYPE_G_OBJECT_PATH, G_TYPE_BOOLEAN,
					  G_TYPE_INVALID);

	dbus_g_object_register_marshaller(marshal_VOID__INT_INT,
					  G_TYPE_NONE, G_TYPE_INT, G_TYPE_INT, G_TYPE_INVALID);
	return TRUE;
}

BT_EXPORT_API void obex_agent_set_authorize_func(ObexAgent *agent,
						 ObexAgentAuthorizeFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->authorize_func = func;
	priv->authorize_data = data;
}

BT_EXPORT_API void obex_agent_set_release_func(ObexAgent *agent,
					       ObexAgentReleaseFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->release_func = func;
	priv->release_data = data;
}

BT_EXPORT_API void obex_agent_set_request_func(ObexAgent *agent,
					       ObexAgentRequestFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->request_func = func;
	priv->request_data = data;
}

BT_EXPORT_API void obex_agent_set_progress_func(ObexAgent *agent,
						ObexAgentProgressFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->progress_func = func;
	priv->progress_data = data;
}

BT_EXPORT_API void obex_agent_set_complete_func(ObexAgent *agent,
						ObexAgentCompleteFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->complete_func = func;
	priv->complete_data = data;
}

BT_EXPORT_API void obex_agent_set_error_func(ObexAgent *agent,
					     ObexAgentErrorFunc func, gpointer data)
{
	ObexAgentPrivate *priv = OBEX_AGENT_GET_PRIVATE(agent);

	DBG("agent %p", agent);

	priv->error_func = func;
	priv->error_data = data;
}

/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vconf.h>
#include <vconf-keys.h>

#include  <bt-hal-gap-agent1.h>
#include  <bt-hal-agent.h>
#include  <bt-hal-internal.h>

#include "bt-hal.h"
#include "bt-hal-log.h"
#include "bt-hal-msg.h"
#include "bt-hal-utils.h"

#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <gio/gio.h>
#include <dlog.h>

#include "bt-hal-adapter-dbus-handler.h"
#include "bt-hal-dbus-common-utils.h"

static GDBusConnection *connection = NULL;

typedef enum {
	GAP_AGENT_ERROR_REJECT,
	GAP_AGENT_ERROR_CANCEL,
	GAP_AGENT_ERROR_TIMEOUT,
} GapAgentError;


/* Forward declaration */
static gboolean __gap_agent_unregister(GapAgentPrivate *agent);
static GDBusNodeInfo *__bt_service_create_method_node_info
(const gchar *introspection_data);
static void __bt_gap_agent_method(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data);
void _gap_agent_set_canceled(GapAgentPrivate *agent, gboolean value);



static gint gap_agent_id = -1;

gboolean _gap_agent_register(GapAgentPrivate *agent)
{
	GapAgentPrivate *priv = agent;
	GDBusProxy *agent_manager;
	GError *error = NULL;
	GVariant *reply;

	if (!priv)
		return FALSE;
	if (!connection)
		return FALSE;

	if (priv->agent_manager == NULL) {
		agent_manager = g_dbus_proxy_new_sync(connection,
				G_DBUS_PROXY_FLAGS_NONE, NULL,
				BT_HAL_BLUEZ_NAME, BT_HAL_BLUEZ_PATH,
				BT_HAL_AGENT_MANAGER_INTERFACE, NULL, &error);
		if (!agent_manager) {
			if (error) {
				ERR("Unable to create proxy: %s", error->message);
				g_clear_error(&error);
			}
			return FALSE;
		}
	} else {
		agent_manager = priv->agent_manager;
	}

	reply = g_dbus_proxy_call_sync(agent_manager, "RegisterAgent",
#ifdef TIZEN_BT_IO_CAPA_NO_INPUT_OUTPUT
			g_variant_new("(os)", priv->path, "NoInputNoOutput"),
#else
			g_variant_new("(os)", priv->path, "DisplayYesNo"),
#endif
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	if (reply == NULL) {
		ERR("Agent registration failed");
		if (error) {
			ERR("Agent registration failed: errCode[%x], message[%s]",
					error->code, error->message);
			g_clear_error(&error);
		}
		g_object_unref(agent_manager);
		priv->agent_manager = NULL;
		return FALSE;
	}
	g_variant_unref(reply);
	reply = NULL;

	/* Set the defalut agent */
	DBG("agent_manager[%p] priv->path[%s]", agent_manager, priv->path);
	reply = g_dbus_proxy_call_sync(agent_manager, "RequestDefaultAgent",
			g_variant_new("(o)", priv->path),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	if (reply == NULL) {
		ERR("Request Default Agent failed");
		if (error) {
			ERR("Request Default Agent failed: errCode[%x], message[%s]",
					error->code, error->message);
			g_clear_error(&error);
		}
		g_object_unref(agent_manager);
		priv->agent_manager = NULL;
		return FALSE;
	}
	g_variant_unref(reply);

	priv->agent_manager = agent_manager;

	return TRUE;
}


static const gchar gap_agent_bluez_introspection_xml[] =
"<node name='/'>"
"  <interface name='org.bluez.Agent1'>"
"    <method name='RequestPinCode'>"
"      <arg type='o' name='device' direction='in'/>"
"      <arg type='s' name='pincode' direction='out'/>"
"    </method>"
"    <method name='RequestPasskey'>"
"      <arg type='o' name='device' direction='in'/>"
"      <arg type='u' name='passkey' direction='out'/>"
"    </method>"
"    <method name='DisplayPasskey'>"
"      <arg type='o' name='device' direction='in'/>"
"      <arg type='u' name='passkey' direction='in'/>"
"      <arg type='q' name='entered' direction='in'/>"
"    </method>"
"    <method name='RequestConfirmation'>"
"      <arg type='o' name='device' direction='in'/>"
"      <arg type='u' name='passkey' direction='in'/>"
"    </method>"
"    <method name='RequestAuthorization'>"
"      <arg type='o' name='device' direction='in'/>"
"    </method>"
"    <method name='AuthorizeService'>"
"      <arg type='o' name='device' direction='in'/>"
"      <arg type='s' name='uuid' direction='in'/>"
"    </method>"
"    <method name='Cancel'>"
"    </method>"
"    <method name='Release'>"
"    </method>"
"    <method name='ReplyPinCode'>"
"      <arg type='u' name='accept' direction='in'/>"
"      <arg type='s' name='pincode' direction='in'/>"
"    </method>"
"    <method name='ReplyPasskey'>"
"      <arg type='u' name='accept' direction='in'/>"
"      <arg type='s' name='passkey' direction='in'/>"
"    </method>"
"    <method name='ReplyConfirmation'>"
"      <arg type='u' name='accept' direction='in'/>"
"    </method>"
"    <method name='ReplyAuthorize'>"
"      <arg type='u' name='accept' direction='in'/>"
"    </method>"
"    <method name='ConfirmModeChange'>"
"      <arg type='s' name='mode' direction='in'/>"
"    </method>"
"    <method name='GetDiscoverableTimeout'>"
"      <arg type='u' name='timeout' direction='out'/>"
"    </method>"
"  </interface>"
"</node>";


static const GDBusInterfaceVTable method_table = {
	__bt_gap_agent_method,
	NULL,
	NULL,
};

void _gap_agent_setup_dbus(GapAgentPrivate *agent, GAP_AGENT_FUNC_CB *func_cb,
		const char *path,
		GDBusProxy *adapter)
{
	GapAgentPrivate *priv = agent;
	GDBusProxy *proxy;
	GDBusNodeInfo *node_info;
	GError *error = NULL;
	DBG("+");

	priv->path = g_strdup(path);

	node_info = __bt_service_create_method_node_info(
			gap_agent_bluez_introspection_xml);
	if (node_info == NULL)
		return;

	DBG("path is [%s]", path);

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!connection) {
		if (error) {
			ERR("Unable to connect to gdbus: %s", error->message);
			g_clear_error(&error);
		}
		return;
	}

	if (gap_agent_id == -1) {
		gap_agent_id = g_dbus_connection_register_object(connection, path,
				node_info->interfaces[0],
				&method_table, priv,
				NULL, &error);
	}

	g_dbus_node_info_unref(node_info);

	if (gap_agent_id == 0) {
		ERR("Failed to register for Path: %s", path);
		if (error) {
			ERR("Failed to register: %s", error->message);
			g_clear_error(&error);
		}
		return;
	}

	memcpy(&priv->cb, func_cb, sizeof(GAP_AGENT_FUNC_CB));

	priv->exec_type = GAP_AGENT_EXEC_NO_OPERATION;
	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));
	memset(priv->authorize_addr, 0x00, sizeof(priv->authorize_addr));
	priv->reply_context = NULL;

	DBG("path: %s", path);

	proxy =  g_dbus_proxy_new_sync(connection,
			G_DBUS_PROXY_FLAGS_NONE, NULL,
			BT_HAL_BLUEZ_NAME, path,
			BT_HAL_AGENT_INTERFACE, NULL, &error);

	if (!proxy) {
		ERR("Unable to create proxy");
		if (error) {
			ERR("Error: %s", error->message);
			g_clear_error(&error);
		}
		priv->busname = NULL;
	} else {
		priv->busname = g_strdup(g_dbus_proxy_get_name(proxy));
		g_object_unref(proxy);
		DBG("Busname: %s", priv->busname);
	}
	DBG("-");
}


void _gap_agent_reset_dbus(GapAgentPrivate *agent)
{
	GapAgentPrivate *priv = agent;

	/* Fix : NULL_RETURNS */
	if (priv == NULL)
		return ;

	__gap_agent_unregister(agent);

	if (gap_agent_id > 0) {

		if (connection)
			g_dbus_connection_unregister_object(connection,
					gap_agent_id);
		gap_agent_id = -1;
	}
	/*TODO*/
#if 0
	if (priv->osp_servers) {
		__gap_agent_remove_osp_servers(priv->osp_servers);
		g_slist_free(priv->osp_servers);
		priv->osp_servers = NULL;
	}
#endif
	g_object_ref(priv->adapter);
	priv->adapter = NULL;

	g_free(priv->path);
	priv->path = NULL;

	g_free(priv->busname);
	priv->busname = NULL;
}

gchar* _gap_agent_get_path(GapAgentPrivate *agent)
{
	GapAgentPrivate *priv = agent;

	/* Fix : NULL_RETURNS */
	if (priv == NULL)
		return NULL;

	return priv->path;
}

gboolean _gap_agent_is_canceled(GapAgentPrivate *agent)
{
	GapAgentPrivate *priv = agent;

	/* Fix : NULL_RETURNS */
	if (priv == NULL)
		return  FALSE;

	return priv->canceled;
}

void _gap_agent_set_canceled(GapAgentPrivate *agent, gboolean value)
{
	GapAgentPrivate *priv = agent;

	/* Fix : NULL_RETURNS */
	if (priv == NULL)
		return;

	priv->canceled = value;
}

static gboolean __gap_agent_unregister(GapAgentPrivate *agent)
{
	GapAgentPrivate *priv = agent;
	GDBusProxy *agent_manager;
	GError *error = NULL;
	GVariant *reply;

	if (priv == NULL || priv->path == NULL|| connection == NULL )
		return  FALSE;

	if (priv->agent_manager == NULL) {
		agent_manager = g_dbus_proxy_new_sync(connection,
				G_DBUS_PROXY_FLAGS_NONE, NULL,
				BT_HAL_BLUEZ_NAME, BT_HAL_BLUEZ_PATH,
				BT_HAL_AGENT_MANAGER_INTERFACE, NULL, &error);
		if (!agent_manager) {
			if (error) {
				ERR("Unable to create proxy: %s", error->message);
				g_clear_error(&error);
			}
			return FALSE;
		}
	} else {
		agent_manager = priv->agent_manager;
	}

	reply = g_dbus_proxy_call_sync(agent_manager, "UnregisterAgent",
			g_variant_new("o", priv->path),
			G_DBUS_CALL_FLAGS_NONE, -1,
			NULL, &error);
	g_object_unref(agent_manager);
	priv->agent_manager = NULL;

	if (reply == NULL) {
		ERR("Agent unregistration failed");
		if (error) {
			ERR("Agent unregistration failed: errCode[%x], message[%s]",
					error->code, error->message);
			g_clear_error(&error);
		}
		return FALSE;
	}
	g_variant_unref(reply);

	return TRUE;
}

	static GDBusNodeInfo *__bt_service_create_method_node_info
(const gchar *introspection_data)
{
	GError *err = NULL;
	GDBusNodeInfo *node_info = NULL;

	if (introspection_data == NULL)
		return NULL;

	node_info = g_dbus_node_info_new_for_xml(introspection_data, &err);

	if (err) {
		ERR("Unable to create node: %s", err->message);
		g_clear_error(&err);
	}
	return node_info;
}

static void __bt_gap_agent_method(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	DBG("+");
	FN_START;

	DBG("Method[%s] Object Path[%s] Interface Name[%s]",
			method_name, object_path, interface_name);
	/* TODO Fill handlers */
	if (g_strcmp0(method_name, "RequestPinCode") == 0) {
	} else if (g_strcmp0(method_name, "RequestPasskey") == 0) {
	} else if (g_strcmp0(method_name, "DisplayPasskey") == 0) {
	} else if (g_strcmp0(method_name, "RequestConfirmation") == 0) {
	} else if (g_strcmp0(method_name, "AuthorizeService") == 0) {
	} else if (g_strcmp0(method_name, "RequestAuthorization") == 0) {
	} else if (g_strcmp0(method_name, "ConfirmModeChange") == 0) {
	} else if (g_strcmp0(method_name, "Cancel") == 0) {
	} else if (g_strcmp0(method_name, "Release") == 0) {
	} else if (g_strcmp0(method_name, "GetDiscoverableTimeout") == 0) {
	} else if (g_strcmp0(method_name, "ReplyPinCode") == 0) {
	} else if (g_strcmp0(method_name, "ReplyPasskey") == 0) {
	} else if (g_strcmp0(method_name, "ReplyConfirmation") == 0) {
	} else if (g_strcmp0(method_name, "ReplyAuthorize") == 0) {
	}
	DBG("-");
}

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bluetooth-agent.h"
#include "sc_core_agent.h"

static DBusGConnection *connection = NULL;
#ifdef _SESSION_BUS_
static DBusGConnection *session_connection = NULL;
#endif
static ScCoreAgent *gap_agent = NULL;

typedef enum {
	SC_CORE_AGENT_EXEC_NO_OPERATION,
	SC_CORE_AGENT_EXEC_PAIRING,
	SC_CORE_AGENT_EXEC_AUTHORZATION,
	SC_CORE_AGENT_EXEC_CONFIRM_MODE,
} ScCoreAgentExecType;

typedef struct _ScCoreAgentPrivate ScCoreAgentPrivate;

struct _ScCoreAgentPrivate {
	gchar *busname;
	gchar *path;
	DBusGProxy *adapter;
	DBusGProxy *dbus_proxy;

	ScCoreAgentExecType exec_type;
	DBusGMethodInvocation *reply_context;

	char pairing_addr[18];
	char authorize_addr[18];

	SC_CORE_AGENT_FUNC_CB cb;
};

G_DEFINE_TYPE(ScCoreAgent, sc_core_agent, G_TYPE_OBJECT);

static gboolean sc_core_agent_request_pin_code(ScCoreAgent *agent, const char *path,
						DBusGMethodInvocation *context);

static gboolean sc_core_agent_request_passkey(ScCoreAgent *agent, const char *path,
						DBusGMethodInvocation *context);

static gboolean sc_core_agent_display_passkey(ScCoreAgent *agent, const char *path, guint passkey,
						guint8 entered, DBusGMethodInvocation *context);

static gboolean sc_core_agent_request_confirmation(ScCoreAgent *agent, const char *path,
						guint passkey, DBusGMethodInvocation *context);

static gboolean sc_core_agent_authorize(ScCoreAgent *agent, const char *path, const char *uuid,
						DBusGMethodInvocation *context);

static gboolean sc_core_agent_confirm_mode(ScCoreAgent *agent, const char *mode,
						DBusGMethodInvocation *context);

static gboolean sc_core_agent_cancel(ScCoreAgent *agent, DBusGMethodInvocation *context);

static gboolean sc_core_agent_release(ScCoreAgent *agent, DBusGMethodInvocation *context);

static gboolean sc_core_agent_ignore_auto_pairing(ScCoreAgent *agent, const char *address,
						DBusGMethodInvocation *context);

static void __sc_core_agent_name_owner_changed(DBusGProxy *object, const char *name,
						const char *prev, const char *new,
						gpointer user_data);

static void __sc_core_agent_mode_change(int changed_mode);

static gboolean __sc_cre_core_agent_readd(gpointer data);

#include "sc_core_agent_glue.h"

typedef enum {
	SC_CORE_AGENT_ERROR_REJECT,
	SC_CORE_AGENT_ERROR_CANCEL,
	SC_CORE_AGENT_ERROR_TIMEOUT,
} ScCoreAgentError;

#define SC_CORE_AGENT_ERROR (sc_core_agent_error_quark())

static GQuark sc_core_agent_error_quark(void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string("agent");

	return quark;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GError *sc_core_agent_error(ScCoreAgentError error, const char *err_msg)
{
	return g_error_new(SC_CORE_AGENT_ERROR, error, err_msg);
}

static void sc_core_agent_init(ScCoreAgent *agent)
{
	DBG("agent %p\n", agent);
}

static void sc_core_agent_finalize(GObject *agent)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	SC_CORE_AGENT_FUNC_CB *cb_ptr = NULL;

	DBG("Free agent %p\n", agent);

	g_free(priv->path);
	g_free(priv->busname);

	cb_ptr = (SC_CORE_AGENT_FUNC_CB *) malloc(sizeof(SC_CORE_AGENT_FUNC_CB));
	if (cb_ptr) {
		memcpy(cb_ptr, &priv->cb, sizeof(SC_CORE_AGENT_FUNC_CB));
		g_idle_add(__sc_cre_core_agent_readd, (void *)cb_ptr);
	} else {
		DBG("Error copy callback pointer\n");
	}

	G_OBJECT_CLASS(sc_core_agent_parent_class)->finalize(agent);
}

static void sc_core_agent_class_init(ScCoreAgentClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;
	GError *error = NULL;

	DBG("class %p\n", klass);

	g_type_class_add_private(klass, sizeof(ScCoreAgentPrivate));

	object_class->finalize = sc_core_agent_finalize;

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);

	if (error != NULL) {
		g_printerr("Connecting to system bus failed: %s\n", error->message);
		g_error_free(error);
	}
#ifdef _SESSION_BUS_
	session_connection = dbus_g_bus_get(DBUS_BUS_SESSION, &error);

	if (error != NULL) {
		g_printerr("Connecting to system bus failed: %s\n", error->message);
		g_error_free(error);
	}
#endif

	dbus_g_object_type_install_info(SC_CORE_TYPE_AGENT, &dbus_glib_sc_core_agent_object_info);
}

ScCoreAgent *sc_core_agent_new(void)
{
	ScCoreAgent *agent;

	agent = SC_CORE_GET_AGENT(g_object_new(SC_CORE_TYPE_AGENT, NULL));

	DBG("agent %p\n", agent);

	return agent;
}

static gboolean sc_core_agent_request_pin_code(ScCoreAgent *agent,
					       const char *path, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	DBusGProxy *device = NULL;
	gboolean result = FALSE;

	char *addr;

	if (sender == NULL)
		return FALSE;

	DBG("Request PIN : agent %p sender %s priv->busname %s Device Path :%s\n", agent, sender,
	    priv->busname, path);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.passkey_func) {
		if (priv->adapter != NULL) {
			device = dbus_g_proxy_new_from_proxy(priv->adapter, BLUEZ_DEVICE_INTERFACE,
								path);
		}

		if (device == NULL) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"No proxy for device");
			DBG("Fail to make device proxy\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		priv->exec_type = SC_CORE_AGENT_EXEC_PAIRING;
		priv->reply_context = context;

		addr = strstr(path, "dev_");
		if (addr != NULL) {
			char *pos = NULL;
			addr += 4;
			strncpy(priv->pairing_addr, addr, sizeof(priv->pairing_addr) - 1);

			while ((pos = strchr(priv->pairing_addr, '_')) != NULL) {
				*pos = ':';
			}
		}

		result = priv->cb.pincode_func(device);

		if (device != NULL)
			g_object_unref(device);
	}

	g_free(sender);
	return result;
}

static gboolean sc_core_agent_request_passkey(ScCoreAgent *agent,
					      const char *path, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	DBusGProxy *device = NULL;
	gboolean result = FALSE;
	char *addr;

	if (sender == NULL)
		return FALSE;

	DBG("Request passkey : agent %p sender %s priv->busname %s Device Path :%s\n", agent,
	    sender, priv->busname, path);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.passkey_func) {
		if (priv->adapter != NULL) {
			device = dbus_g_proxy_new_from_proxy(priv->adapter, BLUEZ_DEVICE_INTERFACE,
								path);
		}

		if (device == NULL) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"No proxy for device");
			DBG("Fail to make device proxy\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		priv->exec_type = SC_CORE_AGENT_EXEC_PAIRING;
		priv->reply_context = context;

		addr = strstr(path, "dev_");
		if (addr != NULL) {
			char *pos = NULL;
			addr += 4;
			strncpy(priv->pairing_addr, addr, sizeof(priv->pairing_addr) - 1);

			while ((pos = strchr(priv->pairing_addr, '_')) != NULL) {
				*pos = ':';
			}
		}

		result = priv->cb.passkey_func(device);

		if (device != NULL)
			g_object_unref(device);
	}

	g_free(sender);
	return result;

}

static gboolean sc_core_agent_display_passkey(ScCoreAgent *agent, const char *path, guint passkey,
						guint8 entered, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	DBusGProxy *device = NULL;
	gboolean result = FALSE;

	if (sender == NULL)
		return FALSE;

	DBG("Request passkey display : agent %p sender %s priv->busname %s Device Path :%s\n",
	    agent, sender, priv->busname, path);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.display_func) {
		if (priv->adapter != NULL) {
			device = dbus_g_proxy_new_from_proxy(priv->adapter, BLUEZ_DEVICE_INTERFACE,
								path);
		}

		if (device == NULL) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"No proxy for device");
			DBG("Fail to make device proxy\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		dbus_g_method_return(context);

		result = priv->cb.display_func(device, passkey, entered);

		if (device != NULL)
			g_object_unref(device);
	}

	g_free(sender);
	return result;
}

static gboolean sc_core_agent_request_confirmation(ScCoreAgent *agent, const char *path,
						guint passkey, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	DBusGProxy *device = NULL;
	gboolean result = FALSE;
	char *addr;

	if (sender == NULL)
		return FALSE;

	DBG("Request passkey confirmation : agent %p sender %s priv->busname %s Device Path :%s\n",
	    agent, sender, priv->busname, path);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.confirm_func) {
		if (priv->adapter != NULL) {
			device = dbus_g_proxy_new_from_proxy(priv->adapter, BLUEZ_DEVICE_INTERFACE,
								path);
		}

		if (device == NULL) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"No proxy for device");
			DBG("Fail to make device proxy\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		priv->exec_type = SC_CORE_AGENT_EXEC_PAIRING;
		priv->reply_context = context;

		addr = strstr(path, "dev_");
		if (addr != NULL) {
			char *pos = NULL;
			addr += 4;
			strncpy(priv->pairing_addr, addr, sizeof(priv->pairing_addr) - 1);

			while ((pos = strchr(priv->pairing_addr, '_')) != NULL) {
				*pos = ':';
			}
		}

		result = priv->cb.confirm_func(device, passkey);

		if (device != NULL)
			g_object_unref(device);
	}

	g_free(sender);
	return result;
}

static gboolean sc_core_agent_authorize(ScCoreAgent *agent, const char *path, const char *uuid,
					DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	DBusGProxy *device = NULL;
	gboolean result = FALSE;
	char *addr;

	if (sender == NULL)
		return FALSE;

	DBG("Request authorization : agent %p sender %s priv->busname %s Device Path :%s\n", agent,
	    sender, priv->busname, path);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.authorize_func) {
		if (priv->adapter != NULL) {
			device = dbus_g_proxy_new_from_proxy(priv->adapter, BLUEZ_DEVICE_INTERFACE,
								path);
		}

		if (device == NULL) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"No proxy for device");
			DBG("Fail to make device proxy\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		priv->exec_type = SC_CORE_AGENT_EXEC_AUTHORZATION;
		priv->reply_context = context;

		addr = strstr(path, "dev_");
		if (addr != NULL) {
			char *pos = NULL;
			addr += 4;
			strncpy(priv->authorize_addr, addr, sizeof(priv->authorize_addr) - 1);

			while ((pos = strchr(priv->authorize_addr, '_')) != NULL) {
				*pos = ':';
			}
		}

		result = priv->cb.authorize_func(device, uuid);

		if (device != NULL)
			g_object_unref(device);
	}

	g_free(sender);
	return result;
}

static gboolean sc_core_agent_confirm_mode(ScCoreAgent *agent, const char *mode,
						DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;
	unsigned int inhouse_pid = 0, sender_pid = 0;
	gboolean need_asking = TRUE;

	if (sender == NULL)
		return FALSE;

	DBG("Request confirm mode : agent %p sender %s mode %s\n", agent, sender, mode);

	if (dbus_g_proxy_call(priv->dbus_proxy, "GetConnectionUnixProcessID", NULL,
			      G_TYPE_STRING, "org.projectx.bluetooth", G_TYPE_INVALID,
			      G_TYPE_UINT, &inhouse_pid, G_TYPE_INVALID)) {
		if (inhouse_pid > 0 &&
			dbus_g_proxy_call(priv->dbus_proxy, "GetConnectionUnixProcessID", NULL,
					 G_TYPE_STRING, sender, G_TYPE_INVALID, G_TYPE_UINT,
					 &sender_pid, G_TYPE_INVALID)) {
			DBG("inhouse [%d] sender [%d]\n", inhouse_pid, sender_pid);
			if (sender_pid == inhouse_pid) {
				need_asking = FALSE;
			}
			inhouse_pid = 0;
		}
		DBG("inhouse [%d] sender [%d]\n", inhouse_pid, sender_pid);
	}

	if (need_asking && dbus_g_proxy_call(priv->dbus_proxy, "GetConnectionUnixProcessID", NULL,
					     G_TYPE_STRING,
					     "org.tizen.SplusA.bluetooth.BluetoothService",
					     G_TYPE_INVALID, G_TYPE_UINT, &inhouse_pid,
					     G_TYPE_INVALID)) {
		if (inhouse_pid > 0 && (sender_pid > 0 ||
			dbus_g_proxy_call(priv->dbus_proxy, "GetConnectionUnixProcessID", NULL,
					     G_TYPE_STRING, sender, G_TYPE_INVALID, G_TYPE_UINT,
					     &sender_pid, G_TYPE_INVALID))) {
			DBG("SplusA [%d] sender [%d]\n", inhouse_pid, sender_pid);
			if (sender_pid == inhouse_pid) {
				need_asking = FALSE;
			}
		}
	}

	if (priv->cb.confirm_mode_func) {
		if (mode == NULL || strlen(mode) == 0) {
			GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"Wrong mode");
			DBG("mode is wrong\n");
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			g_free(sender);
			return FALSE;
		}

		priv->exec_type = SC_CORE_AGENT_EXEC_CONFIRM_MODE;
		priv->reply_context = context;

		result = priv->cb.confirm_mode_func(mode, sender, need_asking, (void *)context);
	} else {
		GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT, "No callback");
		DBG("No callback for confirm mode\n");
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		g_free(sender);
		return FALSE;
	}

	g_free(sender);
	return TRUE;
}

static gboolean sc_core_agent_cancel(ScCoreAgent *agent, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	if (sender == NULL)
		return FALSE;

	DBG("Cancelled : agent %p sender %s\n", agent, sender);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	if (priv->cb.authorization_cancel_func &&
					priv->exec_type == SC_CORE_AGENT_EXEC_AUTHORZATION) {
		result = priv->cb.authorization_cancel_func(priv->authorize_addr);
		memset(priv->authorize_addr, 0x00, sizeof(priv->authorize_addr));
	} else if (priv->cb.pairing_cancel_func && priv->exec_type == SC_CORE_AGENT_EXEC_PAIRING) {
		result = priv->cb.pairing_cancel_func(priv->pairing_addr);
		memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));
	}

	if (priv->exec_type != SC_CORE_AGENT_EXEC_CONFIRM_MODE &&
	    priv->exec_type != SC_CORE_AGENT_EXEC_NO_OPERATION && priv->reply_context != NULL) {
		GError *error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
							"Rejected by remote cancel");
		dbus_g_method_return_error(priv->reply_context, error);
		g_error_free(error);
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;

	g_free(sender);
	return result;
}

static gboolean sc_core_agent_release(ScCoreAgent *agent, DBusGMethodInvocation *context)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);

	if (sender == NULL)
		return FALSE;

	DBG("Released : agent %p sender %s\n", agent, sender);

	if (g_strcmp0(sender, priv->busname) != 0) {
		g_free(sender);
		return FALSE;
	}

	dbus_g_method_return(context);

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;

	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));
	memset(priv->authorize_addr, 0x00, sizeof(priv->authorize_addr));

	/* Check blocking this part */
	g_signal_handlers_disconnect_by_func(priv->dbus_proxy,
					     G_CALLBACK(__sc_core_agent_name_owner_changed), NULL);
	g_object_unref(agent);
	gap_agent = NULL;

	g_free(sender);
	return TRUE;
}

static gboolean sc_core_agent_ignore_auto_pairing(ScCoreAgent *agent, const char *address,
						  DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	char *sender = dbus_g_method_get_sender(context);
	gboolean result = FALSE;

	if (address == NULL || strlen(address) == 0) {
		DBG("address is NULL\n");
		g_free(sender);
		return FALSE;
	}

	DBG("Request ignore auto pairing : agent %p sender %s address %s\n", agent, sender,
	    address);

	if (priv->cb.ignore_auto_pairing_func) {
		result = priv->cb.ignore_auto_pairing_func(address);
	} else {
		DBG("No callback for ignore_auto_pairing_func\n");
		g_free(sender);
		return FALSE;
	}

	DBG("-\n");
	g_free(sender);
	return TRUE;
}

gboolean sc_core_agent_reply_pin_code(ScCoreAgent *agent, const guint accept, const char *pin_code,
				      DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	if (priv->exec_type != SC_CORE_AGENT_EXEC_NO_OPERATION && priv->reply_context != NULL) {
		if (accept == SC_CORE_AGENT_ACCEPT) {
			dbus_g_method_return(priv->reply_context, pin_code);
		} else {
			GError *error = NULL;
			switch (accept) {
			case SC_CORE_AGENT_CANCEL:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_CANCEL,
								"CanceledbyUser");
				break;
			case SC_CORE_AGENT_TIMEOUT:
			case SC_CORE_AGENT_REJECT:
			default:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"Pairing request rejected");
				break;
			}
			dbus_g_method_return_error(priv->reply_context, error);
			g_error_free(error);
		}
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;
	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));

	DBG("-\n");

	return TRUE;
}

gboolean sc_core_agent_reply_passkey(ScCoreAgent *agent, const guint accept, const char *passkey,
				     DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	if (priv->exec_type != SC_CORE_AGENT_EXEC_NO_OPERATION && priv->reply_context != NULL) {
		if (accept == SC_CORE_AGENT_ACCEPT) {
			guint pass_key = atoi(passkey);
			dbus_g_method_return(priv->reply_context, pass_key);
		} else {
			GError *error = NULL;
			switch (accept) {
			case SC_CORE_AGENT_CANCEL:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_CANCEL,
								"CanceledbyUser");
				break;
			case SC_CORE_AGENT_TIMEOUT:
			case SC_CORE_AGENT_REJECT:
			default:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"Passkey request rejected");
				break;
			}
			dbus_g_method_return_error(priv->reply_context, error);
			g_error_free(error);
		}
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;
	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));

	DBG("-\n");

	return TRUE;
}

gboolean sc_core_agent_reply_confirmation(ScCoreAgent *agent, const guint accept,
					  DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	if (priv->exec_type != SC_CORE_AGENT_EXEC_NO_OPERATION && priv->reply_context != NULL) {
		if (accept == SC_CORE_AGENT_ACCEPT) {
			dbus_g_method_return(priv->reply_context);
		} else {
			GError *error = NULL;
			switch (accept) {
			case SC_CORE_AGENT_CANCEL:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_CANCEL,
								"CanceledbyUser");
				break;
			case SC_CORE_AGENT_TIMEOUT:
			case SC_CORE_AGENT_REJECT:
			default:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"Confirmation request rejected");
				break;
			}
			dbus_g_method_return_error(priv->reply_context, error);
			g_error_free(error);
		}
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;
	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));

	DBG("-\n");

	return TRUE;
}

gboolean sc_core_agent_reply_authorize(ScCoreAgent *agent, const guint accept,
				       DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	if (priv->exec_type != SC_CORE_AGENT_EXEC_NO_OPERATION && priv->reply_context != NULL) {
		if (accept == SC_CORE_AGENT_ACCEPT) {
			dbus_g_method_return(priv->reply_context);
		} else {
			GError *error = NULL;
			switch (accept) {
			case SC_CORE_AGENT_CANCEL:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_CANCEL,
								"CanceledbyUser");
				break;
			case SC_CORE_AGENT_TIMEOUT:
			case SC_CORE_AGENT_REJECT:
			default:
				error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
								"Authorization request rejected");
				break;
			}
			dbus_g_method_return_error(priv->reply_context, error);
			g_error_free(error);
		}
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	priv->reply_context = NULL;
	memset(priv->authorize_addr, 0x00, sizeof(priv->authorize_addr));

	DBG("-\n");

	return TRUE;
}

gboolean sc_core_agent_reply_adapter_enable(ScCoreAgent *agent, const guint changed_mode,
					    const guint accept, DBusGMethodInvocation *context)
{
	DBG("+\n");

	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	if (accept == SC_CORE_AGENT_ACCEPT) {
		__sc_core_agent_mode_change(changed_mode);
		dbus_g_method_return(priv->reply_context);
	} else {
		GError *error = NULL;
		switch (accept) {
		case SC_CORE_AGENT_CANCEL:
			error = sc_core_agent_error(SC_CORE_AGENT_ERROR_CANCEL, "CanceledbyUser");
			break;
		case SC_CORE_AGENT_TIMEOUT:
		case SC_CORE_AGENT_REJECT:
		default:
			error = sc_core_agent_error(SC_CORE_AGENT_ERROR_REJECT,
							"Confirming mode request rejected");
			break;
		}
		dbus_g_method_return_error(priv->reply_context, error);
		g_error_free(error);
	}

	DBG("-\n");

	return TRUE;
}

static void __sc_core_agent_mode_change(int changed_mode)
{
	int ret = 0;

	switch (changed_mode) {
	case BT_AGENT_CHANGED_MODE_ENABLE:
		/* Run BT intiate script */
		if ((ret = system("/usr/etc/bluetooth/bt-stack-up.sh &")) < 0) {
			DBG("running script failed");
			ret = system("/usr/etc/bluetooth/bt-dev-end.sh &");

			sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(), changed_mode,
							   SC_CORE_AGENT_REJECT, NULL);
			return;
		}
		break;

	case BT_AGENT_CHANGED_MODE_DISABLE:
		/* Run BT terminate script */
		if ((ret = system("/usr/etc/bluetooth/bt-stack-down.sh &")) < 0) {
			DBG("running script failed");

			sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(), changed_mode,
							   SC_CORE_AGENT_REJECT, NULL);
			return;
		}
		break;

	default:
		ERR("Unknown mode [%#x]\n", changed_mode);
		sc_core_agent_reply_adapter_enable(_sc_core_agent_get_proxy(), changed_mode,
						   SC_CORE_AGENT_REJECT, NULL);
		return;
	}
}

static gboolean __sc_core_agent_register_on_adapter(ScCoreAgent *agent, DBusGProxy *adapter,
						  SC_CORE_AGENT_FUNC_CB *func_cb)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	DBusGProxy *proxy;
	GObject *object;
	GError *error = NULL;

	DBG("agent %p\n", agent);

	if (priv->adapter != NULL)
		return FALSE;

	/* DBUS method call install */
	if (priv->path == NULL) {
		priv->path = g_strdup_printf("/org/bluez/agent/frwk_agent");

		DBG("%s \n", priv->path);

		object = dbus_g_connection_lookup_g_object(connection, priv->path);
		if (object != NULL)
			g_object_unref(object);

		dbus_g_connection_register_g_object(connection, priv->path, G_OBJECT(agent));
	}

	if (func_cb) {
		priv->cb.pincode_func = func_cb->pincode_func;
		priv->cb.display_func = func_cb->display_func;
		priv->cb.passkey_func = func_cb->passkey_func;
		priv->cb.confirm_func = func_cb->confirm_func;
		priv->cb.authorize_func = func_cb->authorize_func;
		priv->cb.pairing_cancel_func = func_cb->pairing_cancel_func;
		priv->cb.authorization_cancel_func = func_cb->authorization_cancel_func;
		priv->cb.confirm_mode_func = func_cb->confirm_mode_func;
		priv->cb.ignore_auto_pairing_func = func_cb->ignore_auto_pairing_func;
	}

	priv->exec_type = SC_CORE_AGENT_EXEC_NO_OPERATION;
	memset(priv->pairing_addr, 0x00, sizeof(priv->pairing_addr));
	memset(priv->authorize_addr, 0x00, sizeof(priv->authorize_addr));
	priv->reply_context = NULL;

	/* Adapter agent register */
	if (adapter) {
		priv->adapter = g_object_ref(adapter);

		proxy = dbus_g_proxy_new_for_name_owner(connection,
							dbus_g_proxy_get_bus_name(priv->adapter),
							dbus_g_proxy_get_path(priv->adapter),
							dbus_g_proxy_get_interface(priv->adapter),
							NULL);

		if (priv->busname)
			g_free(priv->busname);

		if (proxy != NULL) {
			priv->busname = g_strdup(dbus_g_proxy_get_bus_name(proxy));
			g_object_unref(proxy);
		} else
			priv->busname = g_strdup(dbus_g_proxy_get_bus_name(adapter));

		dbus_g_proxy_call(priv->adapter, "RegisterAgent", &error,
				  DBUS_TYPE_G_OBJECT_PATH, priv->path,
				  G_TYPE_STRING, "DisplayYesNo", G_TYPE_INVALID, G_TYPE_INVALID);

		if (error != NULL) {
			DBG("Agent registration failed: %s\n", error->message);
			g_error_free(error);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean __sc_core_agent_unregister(ScCoreAgent *agent)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);
	GError *error = NULL;

	DBG("agent %p\n", agent);

	if (priv->adapter == NULL)
		return FALSE;

	dbus_g_proxy_call(priv->adapter, "UnregisterAgent", &error,
			  DBUS_TYPE_G_OBJECT_PATH, priv->path, G_TYPE_INVALID, G_TYPE_INVALID);

	if (error != NULL) {
		g_printerr("Agent unregistration failed: %s\n", error->message);
		g_error_free(error);
	}

	g_object_unref(priv->adapter);
	priv->adapter = NULL;

	g_free(priv->path);
	priv->path = NULL;

	return TRUE;
}

static void __sc_core_agent_name_owner_changed(DBusGProxy *object, const char *name,
					     const char *prev, const char *new, gpointer user_data)
{
	if (g_strcmp0(name, "org.bluez") == 0 && *new == '\0') {
		DBG("BlueZ is terminated\n");
	}
}

static void __sc_core_setup_dbus(ScCoreAgent *agent)
{
	guint result;
	GError *error = NULL;
	gchar *agent_name = NULL;
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	agent_name = g_strdup_printf("org.bluez.frwk_agent");

#ifdef _SESSION_BUS_
	priv->dbus_proxy = dbus_g_proxy_new_for_name(session_connection, DBUS_SERVICE_DBUS,
						     DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
#else
	priv->dbus_proxy = dbus_g_proxy_new_for_name(connection, DBUS_SERVICE_DBUS,
						     DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
#endif
	if (dbus_g_proxy_call(priv->dbus_proxy, "RequestName", &error,
			      G_TYPE_STRING, agent_name, G_TYPE_UINT, 0, G_TYPE_INVALID,
			      G_TYPE_UINT, &result, G_TYPE_INVALID) == FALSE) {
		if (error != NULL) {
			DBG("Can't get unique name on session bus [%s]\n", error->message);
			g_error_free(error);
		}
		g_free(agent_name);
		g_object_unref(priv->dbus_proxy);
		priv->dbus_proxy = NULL;
		return;
	} else {
		DBG("Reply of dbus name request [%d]\n", result);
	}

	g_free(agent_name);

	dbus_g_proxy_add_signal(priv->dbus_proxy, "NameOwnerChanged",
				G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);

	dbus_g_proxy_connect_signal(priv->dbus_proxy, "NameOwnerChanged",
				    G_CALLBACK(__sc_core_agent_name_owner_changed), NULL, NULL);
}

static void __sc_core_reset_dbus(ScCoreAgent *agent)
{
	ScCoreAgentPrivate *priv = SC_CORE_AGENT_GET_PRIVATE(agent);

	g_object_unref(priv->dbus_proxy);
	priv->dbus_proxy = NULL;
	priv->adapter = NULL;
}

int _sc_core_agent_add(DBusGProxy *adapter_proxy, SC_CORE_AGENT_FUNC_CB *func_cb)
{
	if (gap_agent == NULL) {
		gap_agent = sc_core_agent_new();
		__sc_core_setup_dbus(gap_agent);
	}

	if (__sc_core_agent_register_on_adapter(gap_agent, adapter_proxy, func_cb))
		return 0;

	return -1;
}

static gboolean __sc_cre_core_agent_readd(gpointer data)
{
	SC_CORE_AGENT_FUNC_CB *cb_ptr = (SC_CORE_AGENT_FUNC_CB *) data;

	_sc_core_agent_add(NULL, cb_ptr);

	if (cb_ptr) {
		free(cb_ptr);
	}
	return 0;
}

void _sc_core_agent_remove(void)
{
	__sc_core_agent_unregister(gap_agent);

	__sc_core_reset_dbus(gap_agent);
}

ScCoreAgent *_sc_core_agent_get_proxy(void)
{
	return gap_agent;
}

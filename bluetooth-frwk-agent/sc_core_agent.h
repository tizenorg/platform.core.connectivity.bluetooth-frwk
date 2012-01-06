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

#ifndef SC_CORE_AGENT_H
#define SC_CORE_AGENT_H

#include <stdint.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#define BLUEZ_DEVICE_INTERFACE	"org.bluez.Device"

#define SC_CORE_TYPE_AGENT (sc_core_agent_get_type())
#define SC_CORE_GET_AGENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), SC_CORE_TYPE_AGENT, ScCoreAgent))
#define SC_CORE_IS_AGENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), SC_CORE_TYPE_AGENT))

#define SC_CORE_AGENT_CLASS(class) (G_TYPE_CHECK_CLASS_CAST((class), SC_CORE_TYPE_AGENT, \
										ScCoreAgentClass))
#define SC_CORE_GET_AGENT_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), SC_CORE_TYPE_AGENT, \
										ScCoreAgentClass))
#define SC_CORE_IS_AGENT_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE((class), SC_CORE_TYPE_AGENT))

#define SC_CORE_AGENT_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), SC_CORE_TYPE_AGENT, \
									ScCoreAgentPrivate))

typedef struct _ScCoreAgent ScCoreAgent;
typedef struct _ScCoreAgentClass ScCoreAgentClass;

typedef gboolean(*ScCoreAgentPasskeyFunc) (DBusGProxy *device);
typedef gboolean(*ScCoreAgentDisplayFunc) (DBusGProxy *device, guint passkey, guint entered);
typedef gboolean(*ScCoreAgentConfirmFunc) (DBusGProxy *device, guint passkey);
typedef gboolean(*ScCoreAgentAuthorizeFunc) (DBusGProxy *device, const char *uuid);
typedef gboolean(*ScCoreAgentConfirmModeFunc) (const char *mode, const char *sender,
					       gboolean need_popup, void *data);
typedef gboolean(*ScCoreAgentCancelFunc) (const char *address);
typedef gboolean(*ScCoreAgentIgnoreAutoPairingFunc) (const char *address);
typedef uint8_t bool_t;

typedef struct {
	ScCoreAgentPasskeyFunc pincode_func;
	ScCoreAgentDisplayFunc display_func;
	ScCoreAgentPasskeyFunc passkey_func;
	ScCoreAgentConfirmFunc confirm_func;
	ScCoreAgentAuthorizeFunc authorize_func;
	ScCoreAgentCancelFunc pairing_cancel_func;
	ScCoreAgentCancelFunc authorization_cancel_func;
	ScCoreAgentConfirmModeFunc confirm_mode_func;
	ScCoreAgentIgnoreAutoPairingFunc ignore_auto_pairing_func;
} SC_CORE_AGENT_FUNC_CB;

typedef enum {
	SC_CORE_AGENT_ACCEPT,
	SC_CORE_AGENT_REJECT,
	SC_CORE_AGENT_CANCEL,
	SC_CORE_AGENT_TIMEOUT,
} SC_CORE_AGENT_ACCEPT_TYPE_T;

struct _ScCoreAgent {
	GObject parent;
};

struct _ScCoreAgentClass {
	GObjectClass parent_class;
};

int _sc_core_agent_add(DBusGProxy *adapter_proxy, SC_CORE_AGENT_FUNC_CB *func_cb);
void _sc_core_agent_remove(void);
ScCoreAgent *_sc_core_agent_get_proxy(void);

gboolean sc_core_agent_reply_pin_code(ScCoreAgent *agent, const guint accept, const char *pin_code,
				      DBusGMethodInvocation *context);
gboolean sc_core_agent_reply_passkey(ScCoreAgent *agent, const guint accept, const char *passkey,
				     DBusGMethodInvocation *context);
gboolean sc_core_agent_reply_confirmation(ScCoreAgent *agent, const guint accept,
					  DBusGMethodInvocation *context);
gboolean sc_core_agent_reply_authorize(ScCoreAgent *agent, const guint accept,
				       DBusGMethodInvocation *context);
gboolean sc_core_agent_reply_adapter_enable(ScCoreAgent *agent, const guint mode,
					    const guint accept, DBusGMethodInvocation *context);

#endif

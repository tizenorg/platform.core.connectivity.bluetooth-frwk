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

#ifndef __OBEX_AGENT_H
#define __OBEX_AGENT_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS
#define OBEX_TYPE_AGENT (obex_agent_get_type())
#define OBEX_AGENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
						OBEX_TYPE_AGENT, ObexAgent))
#define OBEX_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
					OBEX_TYPE_AGENT, ObexAgentClass))
#define OBEX_IS_AGENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
							OBEX_TYPE_AGENT))
#define OBEX_IS_AGENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), \
							OBEX_TYPE_AGENT))
#define OBEX_GET_AGENT_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), \
					OBEX_TYPE_AGENT, ObexAgentClass))
typedef struct _ObexAgent ObexAgent;
typedef struct _ObexAgentClass ObexAgentClass;

struct _ObexAgent {
	GObject parent;
};

struct _ObexAgentClass {
	GObjectClass parent_class;
};

GType obex_agent_get_type(void);

ObexAgent *obex_agent_new(void);

gboolean obex_agent_setup(ObexAgent *agent, const char *path);

typedef gboolean(*ObexAgentAuthorizeFunc) (DBusGMethodInvocation *context,
					   const char *path,
					   const char *bdaddress,
					   const char *name,
					   const char *type, gint length, gint time, gpointer data);
typedef gboolean(*ObexAgentReleaseFunc) (DBusGMethodInvocation *context, gpointer data);
typedef gboolean(*ObexAgentRequestFunc) (DBusGMethodInvocation *context,
					 DBusGProxy *transfer, gpointer data);
typedef gboolean(*ObexAgentProgressFunc) (DBusGMethodInvocation *context,
					  DBusGProxy *transfer,
					  guint64 transferred, gpointer data);
typedef gboolean(*ObexAgentCompleteFunc) (DBusGMethodInvocation *context,
					  DBusGProxy *transfer, gpointer data);
typedef gboolean(*ObexAgentErrorFunc) (DBusGMethodInvocation *context,
				       DBusGProxy *transfer, const char *message, gpointer data);

void obex_agent_set_authorize_func(ObexAgent *agent, ObexAgentAuthorizeFunc func, gpointer data);
void obex_agent_set_release_func(ObexAgent *agent, ObexAgentReleaseFunc func, gpointer data);
void obex_agent_set_request_func(ObexAgent *agent, ObexAgentRequestFunc func, gpointer data);
void obex_agent_set_progress_func(ObexAgent *agent, ObexAgentProgressFunc func, gpointer data);
void obex_agent_set_complete_func(ObexAgent *agent, ObexAgentCompleteFunc func, gpointer data);
void obex_agent_set_error_func(ObexAgent *agent, ObexAgentErrorFunc func, gpointer data);
G_END_DECLS
#endif				/* __OBEX_AGENT_H */

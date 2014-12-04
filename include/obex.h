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

#ifndef __OBEX_H__
#define __OBEX_H__

#include <glib.h>

#include "common.h"

enum obex_target {
	OBEX_TARGET_UNKNOWN = 0,
	OBEX_FTP,
	OBEX_MAP,
	OBEX_OPP,
	OBEX_PBAP,
	OBEX_SYNC
};

enum obex_role {
	OBEX_SERVER,
	OBEX_CLIENT
};

enum session_state {
	OBEX_SESSION_CREATED = 0,
	OBEX_SESSION_RETRY,
	OBEX_SESSION_FAILED,
	OBEX_SESSION_REFUSED,
	OBEX_SESSION_TIMEOUT,
	OBEX_SESSION_NO_SERVICE
};

enum transfer_state {
	OBEX_TRANSFER_UNKNOWN = 0,
	OBEX_TRANSFER_QUEUED,
	OBEX_TRANSFER_ACTIVE,
	OBEX_TRANSFER_COMPLETE,
	OBEX_TRANSFER_CANCELED,
	OBEX_TRANSFER_ERROR
};

int obex_lib_init(void);
void obex_lib_deinit(void);

typedef void (*agent_cb_t)(
			enum bluez_error_type type,
			void *user_data);
void obex_agent_register_agent(
			const char *agent_path,
			agent_cb_t cb,
			void *user_data);
void obex_agent_unregister_agent(
			const char *agent_path,
			agent_cb_t cb,
			void *user_data);

typedef void (*obex_agent_added_cb_t)(
			void *user_data);
void obex_agent_set_agent_added(
			obex_agent_added_cb_t cb,
			void *user_data);
void obex_agent_unset_agent_added(void);

typedef void (*obex_session_state_cb)(
			const char *session_id,
			const char *session,
			enum session_state state,
			void *data,
			char *error_msg);

int obex_create_session(const char *destination,
			enum obex_target target,
			obex_session_state_cb cb,
			void *data);

void obex_session_remove_session(const char *object_path);

typedef void (*obex_transfer_state_cb)(
			const char *transfer_path,
			enum transfer_state state,
			const char *name,
			guint64 size,
			guint64 transferred,
			void *data,
			char *error_msg);

void obex_session_opp_send_file(const char *session,
			const char *file,
			obex_transfer_state_cb cb,
			void *data);

/* Returned Glist should not be freed and modified */

void obex_transfer_cancel(const char *path);

/* notify specific transfer */
int obex_transfer_set_notify(
			char *transfer_path,
			obex_transfer_state_cb cb, void *data);

void obex_transfer_clear_notify(char *transfer_path);

enum transfer_state obex_transfer_get_property_state(const char *path);

enum transfer_state obex_transfer_get_property_state(const char *path);

char *obex_transfer_get_property_source(const char *path);

char *obex_transfer_get_property_destination(const char *path);

char *obex_transfer_get_property_file_name(const char *path);

char *obex_transfer_get_property_name(const char *path);

int obex_transfer_get_property_size(const char *path, guint64 *size);

int obex_get_transfer_id(const char *transfer_path,
			enum obex_role role);

int obex_agent_get_agent(void);
#endif

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

struct _obex_agent;
typedef struct _obex_agent obex_agent_t;

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
			obex_agent_t *obex_agent,
			void *user_data);
void obex_agent_set_agent_added(
			obex_agent_added_cb_t cb,
			void *user_data);
void obex_agent_unset_agent_added(void);

obex_agent_t *obex_agent_get_agent(void);

struct _obex_session;
typedef struct _obex_session obex_session_t;

typedef void (*obex_session_state_cb)(
			const char *session_id,
			struct _obex_session *session,
			enum session_state state,
			void *data,
			char *error_msg);

int obex_create_session(
			const char *destination,
			enum obex_target target,
			obex_session_state_cb cb,
			void *data);

void obex_session_remove_session(
			struct _obex_session *session);

int obex_session_set_watch(
			obex_session_state_cb cb,
			void *data);

struct _obex_session *obex_session_get_session(
			const char *id);

gchar *obex_session_property_get_destination(
			struct _obex_session *session);

struct _obex_transfer;
typedef struct _obex_transfer obex_transfer_t;

typedef void (*obex_transfer_state_cb)(
			const char *transfer_path,
			struct _obex_transfer *transfer,
			enum transfer_state state,
			guint64 transferred,
			void *data,
			char *error_msg);

void obex_session_opp_send_file(
			struct _obex_session *session,
			const char *file,
			obex_transfer_state_cb cb,
			void *data);

struct _obex_transfer *obex_transfer_get_transfer_from_path(
			const char *path);

/* Returned Glist should not be freed and modified */
const GList *obex_transfer_get_pathes(void);

void obex_transfer_cancel(
			struct _obex_transfer *transfer);

enum transfer_state obex_transfer_property_get_state(
			struct _obex_transfer *transfer);

char *obex_transfer_get_property_source(
			struct _obex_transfer *transfer);

char *obex_transfer_get_property_destination(
			struct _obex_transfer *transfer);

char *obex_transfer_get_property_file_name(
			struct _obex_transfer *transfer);

char *obex_transfer_get_property_name(
			struct _obex_transfer *transfer);

/* get transfer propterty Name directly from obexd synchonized */
char *obex_transfer_get_name(
			struct _obex_transfer *transfer);

int obex_transfer_get_size(struct _obex_transfer *transfer, guint64 *size);

int obex_transfer_property_get_size(
			struct _obex_transfer *transfer,
			guint64 *size);

void obex_transfer_set_property_name(
			struct _obex_transfer *transfer,
			const char *name);

void obex_transfer_set_property_size(
			struct _obex_transfer *transfer,
			guint64 size);

int obex_transfer_get_id(struct _obex_transfer *transfer);

struct _obex_transfer *obex_transfer_get_transfer_from_id(
			int id);

/* notify specific transfer */
int obex_transfer_set_notify(
			struct _obex_transfer *transfer,
			obex_transfer_state_cb cb, void *data);

/* watch all the transfers */
int obex_transfer_set_watch(
			obex_transfer_state_cb cb,
			void *data);

void obex_transfer_clear_watch(void);

int obex_transfer_client_number(void);

int obex_get_transferid_from_path(int role, const char *path);
#endif

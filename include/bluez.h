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

#ifndef __BLUEZ_H__
#define __BLUEZ_H__

#include <glib.h>

#include "common.h"
#include "bluetooth.h"

#define BT_GENERIC_AUDIO_UUID      "00001203-0000-1000-8000-00805f9b34fb"

#define BT_HFP_HS_UUID             "0000111e-0000-1000-8000-00805f9b34fb"
#define BT_ADVANCED_AUDIO_UUID     "0000110d-0000-1000-8000-00805f9b34fb"
#define BT_A2DP_SOURCE_UUID        "0000110a-0000-1000-8000-00805f9b34fb"
#define BT_A2DP_SINK_UUID          "0000110b-0000-1000-8000-00805f9b34fb"

#define BT_HID_UUID                "00001124-0000-1000-8000-00805f9b34fb"

struct _bluez_adapter;
typedef struct _bluez_adapter bluez_adapter_t;

struct _bluez_device;
typedef struct _bluez_device bluez_device_t;

struct _bluez_agent;
typedef struct _bluez_agent bluez_agent_t;

enum bluez_agent_cap {
	DISPLAY_ONLY = 0,
	DISPLAY_YES_NO,
	KEYBOAR_DONLY,
	NO_INPUT_NO_OUTPUT,
	KEYBOARD_DISPLAY
};

void bluez_lib_deinit(void);
int bluez_lib_init(void);

/* adapter functions */
struct _bluez_adapter *bluez_adapter_get_adapter(
				const char *name);

typedef void (*bluez_adapter_added_cb_t)(
				struct _bluez_adapter *adapter,
				void *user_data);
void bluez_adapter_set_adapter_added(
				bluez_adapter_added_cb_t cb,
				void *user_data);
void bluez_adapter_unset_adapter_added(void);

void bluez_adapter_start_discovery(
				struct _bluez_adapter *adapter);
void bluez_adapter_stop_discovery(
				struct _bluez_adapter *adapter);

struct _bluez_device *bluez_adapter_get_device(
				struct _bluez_adapter *adapter,
				const char *path);
struct _bluez_device *bluez_adapter_get_device_by_path(
				struct _bluez_adapter *adapter,
				const char *path);
struct _bluez_device *bluez_adapter_get_device_by_address(
				struct _bluez_adapter *adapter,
				const char *address);
void bluez_adapter_remove_device(
				struct _bluez_adapter *adapter,
				struct _bluez_device *device);

int bluez_adapter_get_property_powered(
				struct _bluez_adapter *adapter,
				gboolean *powered);
void bluez_adapter_set_powered(struct _bluez_adapter *adapter,
				gboolean powered);
typedef void (*bluez_adapter_powered_cb_t)(
				bluez_adapter_t *adapter,
				gboolean powered,
				gpointer user_data);
void bluez_adapter_set_powered_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_powered_cb_t cb,
				gpointer user_data);
void bluez_adapter_unset_powered_changed_cb(
				struct _bluez_adapter *adapter);

typedef void (*bluez_adapter_device_cb_t)(
				struct _bluez_device *device,
				gpointer user_data);
typedef void (*bluez_adapter_discovering_cb_t)(
				struct _bluez_adapter *adapter,
				gboolean discovering,
				gpointer user_data);
void bluez_adapter_set_device_created_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_device_cb_t cb,
				gpointer user_data);
void bluez_adapter_set_device_removed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_device_cb_t cb,
				gpointer user_data);
void bluez_adapter_set_device_discovering_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_discovering_cb_t cb,
				gpointer user_data);
void bluez_adapter_unset_device_discovering_cb(
				struct _bluez_adapter *adapter);
void bluez_adapter_unset_device_created_cb(
				struct _bluez_adapter *adapter);
void bluez_adapter_unset_device_removed_cb(
				struct _bluez_adapter *adapter);

char *bluez_adapter_get_property_alias(
				struct _bluez_adapter *adapter);
void bluez_adapter_set_alias(
				struct _bluez_adapter *adapter,
				const gchar *alias);
typedef void (*bluez_adapter_alias_cb_t)(
				bluez_adapter_t *adapter,
				const gchar *alias,
				gpointer user_data);
void bluez_adapter_set_alias_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_alias_cb_t cb,
				gpointer user_data);
void bluez_adapter_unset_alias_changed_cb(
				struct _bluez_adapter *adpater);

char *bluez_adapter_get_property_address(
				struct _bluez_adapter *adapter);

void bluez_adapter_set_discoverable(
				struct _bluez_adapter *adapter,
				gboolean discoverable);

int bluez_adapter_get_property_discoverable(
				struct _bluez_adapter *adapter,
				gboolean *discoverable);

int bluez_adapter_get_property_discoverable_timeout(
				struct _bluez_adapter *adapter,
				guint32 *time);

int bluez_adapter_get_property_discovering(
				struct _bluez_adapter *adapter,
				gboolean *discovering);

char **bluez_adapter_get_property_uuids(
				struct _bluez_adapter *adapter);

/* Returned Glist should not be freed and modified */
const GList *bluez_adapter_get_devices_path(
				struct _bluez_adapter *adapter);
GList *bluez_adapter_get_devices(
				struct _bluez_adapter *adapter);

/* device functions */
typedef void (*bluez_device_paired_cb_t)(
				struct _bluez_device *device,
				gboolean paired,
				gpointer user_data);
typedef void (*bluez_device_connected_cb_t)(
				struct _bluez_device *device,
				gboolean connected,
				gpointer user_data);
typedef void (*bluez_device_trusted_cb_t)(
				struct _bluez_device *device,
				gboolean trusted,
				gpointer user_data);

void bluez_device_set_paired_changed_cb(
				struct _bluez_device *device,
				bluez_device_paired_cb_t cb,
				gpointer user_data);
void bluez_device_set_connected_changed_cb(
				struct _bluez_device *device,
				bluez_device_connected_cb_t cb,
				gpointer user_data);
void bluez_device_set_trusted_changed_cb(
				struct _bluez_device *device,
				bluez_device_trusted_cb_t cb,
				gpointer user_data);
void bluez_device_unset_paired_changed_cb(
				struct _bluez_device *device);
void bluez_device_unset_connected_changed_cb(
				struct _bluez_device *device);
void bluez_device_unset_trusted_changed_cb(
				struct _bluez_device *device);

void bluez_device_set_trusted(
				struct _bluez_device *device,
				gboolean trusted);
void bluez_device_set_alias(
				struct _bluez_device *device,
				const gchar *alias);

typedef void (*simple_reply_cb_t) (
				enum bluez_error_type type,
				void *user_data);

typedef void (*bluez_audio_state_cb_t)(int result,
				gboolean connected,
				const char *remote_address,
				bt_audio_profile_type_e type,
				void *user_data);

void bluez_set_audio_state_cb(
				bluez_audio_state_cb_t cb,
				gpointer user_data);

void bluez_unset_audio_state_cb();

enum device_pair_state {
	PAIRING_SUCCESS,
	AUTHENTICATION_CANCELED,
	AUTHENTICATION_FAILED,
	AUTHENTICATION_REJECTED,
	AUTHENTICATION_TIMEOUT,
	CONNECTION_ATTEMP_FAILED,
	UNKNOWN_PAIRING_ERROR
};

void bluez_device_pair(struct _bluez_device *device,
				simple_reply_cb_t pair_cb,
				void *user_data);

enum device_profile_state {
	PROFILE_NOT_EXIST,
	PROFILE_CONNECT_SUCCESS,
	PROFILE_ALREADY_CONNECTED,
	PROFILE_CONNECT_FAILED,
	PROFILE_DISCONNECT_SUCCESS,
	PROFILE_DISCONNECT_FAILED,
	PROFILE_NOT_CONNECTED,
	PROFILE_NOT_SUPPORTED
};

typedef void (*profile_connect_cb_t)(
				struct _bluez_device *device,
				enum device_profile_state state);
void bluez_device_connect_profile(
				struct _bluez_device *device,
				const gchar *uuid,
				profile_connect_cb_t pf_connect_cb);

typedef void (*profile_disconnect_cb_t)(
				struct _bluez_device *device,
				enum device_profile_state state);
void bluez_device_disconnect_profile(
				struct _bluez_device *device,
				const gchar *uuid,
				profile_disconnect_cb_t pf_disconnect_cb);

char *bluez_device_property_get_adapter(
				struct _bluez_device *device);

char **bluez_device_get_property_uuids(
				struct _bluez_device *device);

char *bluez_device_get_property_address(
				struct _bluez_device *device);

char *bluez_device_get_property_alias(
				struct _bluez_device *device);

int bluez_device_get_property_class(
				struct _bluez_device *device,
				guint32 *class);

int bluez_device_get_property_paired(
				struct _bluez_device *device,
				gboolean *paired);

int bluez_device_get_property_trusted(
				struct _bluez_device *device,
				gboolean *trusted);

int bluez_device_get_property_connected(
				struct _bluez_device *device,
				gboolean *connected);

int bluez_device_get_property_rssi(
				struct _bluez_device *device,
				gint16 *rssi);

char *bluez_device_get_property_icon(
				struct _bluez_device *device);

/* agent functions */
bluez_agent_t *bluez_agent_get_agent(void);

typedef void (*bluez_agent_added_cb_t)(
				struct _bluez_agent *agent,
				void *user_data);
void bluez_agent_set_agent_added(
				bluez_agent_added_cb_t cb,
				void *user_data);
void bluez_agent_unset_agent_added(void);

typedef void (*handle_agent_cb_t)(
				enum bluez_error_type type,
				void *user_data);

void bluez_agent_register_agent(const gchar *path,
				enum bluez_agent_cap capability,
				simple_reply_cb_t register_agent_cb,
				void *user_data);

void bluez_agent_unregister_agent(
				const gchar *path,
				simple_reply_cb_t unregister_agent_cb,
				void *user_data);

void bluez_agent_request_default_agent(
				const gchar *path);

struct profile_option {
	gchar *name;
	gchar *service;
	gchar *role;
	guint16 channel;
	guint16 psm;
	gboolean require_authentication;
	gboolean require_authorization;
	gboolean auto_connect;
	gchar *service_record;
	guint16 version;
	guint16 features;
};

void bluez_profile_register_profile(
				const gchar *path,
				const gchar *uuid,
				GVariantBuilder *opts,
				simple_reply_cb_t callback,
				void *user_data);

void bluez_profile_unregister_profile(
				const gchar *path,
				simple_reply_cb_t callback,
				void *user_data);

enum bluez_error_type bluez_profile_register_profile_sync(
				const gchar *path,
				const gchar *uuid,
				GVariantBuilder *opts);

enum bluez_error_type  bluez_profile_unregister_profile_sync(
				const gchar *path);

#endif

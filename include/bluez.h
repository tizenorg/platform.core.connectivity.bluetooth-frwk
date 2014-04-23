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
#include "bluetooth-api.h"

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

typedef enum {
	PLAYBACKSTATUS = 0x1,
	SHUFFLE,
	LOOPSTATUS,
	POSITION,
	METADATA
} media_player_property_type;

typedef enum {
	REPEAT_MODE_OFF = 0x01,
	REPEAT_SINGLE_TRACK,
	REPEAT_ALL_TRACK,
	REPEAT_INVALID
} media_player_repeat_status;

typedef enum {
	STATUS_STOPPED = 0x00,
	STATUS_PLAYING,
	STATUS_PAUSED,
	STATUS_INVALID
} media_player_status;

typedef enum {
	SHUFFLE_MODE_OFF = 0x01,
	SHUFFLE_ALL_TRACK,
	SHUFFLE_GROUP,
	SHUFFLE_INVALID
} media_player_shuffle_status;

typedef struct {
	const char *title;
	const char **artist;
	const char *album;
	const char **genre;
	unsigned int tracknumber;
	unsigned int duration;
} media_metadata_attributes_t;

typedef struct {
	media_player_repeat_status loopstatus;
	media_player_status playbackstatus;
	media_player_shuffle_status shuffle;
	gint64 position;
	media_metadata_attributes_t metadata;
} media_player_settings_t;

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

typedef void (*bluez_adapter_discoverable_cb_t)(
				struct _bluez_adapter *adapter,
				gboolean discoverable,
				gpointer user_data);
void bluez_adapter_set_discoverable_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_discoverable_cb_t cb,
				gpointer user_data);
void bluez_adapter_unset_discoverable_changed_cb(
				struct _bluez_adapter *adapter);

typedef void (*bluez_adapter_discoverable_tm_cb_t)(
				struct _bluez_adapter *adapter,
				guint32 timeout,
				gpointer user_data);
void bluez_adapter_set_discoverable_timeout_changed_cb(
				struct _bluez_adapter *adapter,
				bluez_adapter_discoverable_tm_cb_t cb,
				gpointer user_data);
void bluez_adapter_unset_discoverable_timeout_changed_cb(
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

void bluez_adapter_set_discoverable_timeout(
				struct _bluez_adapter *adapter,
				guint32 timeout);
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
int bluez_device_network_connect(
				struct _bluez_device *device,
				const gchar *role);
int bluez_device_network_disconnect(
				struct _bluez_device *device);

int bluez_device_network_get_property_connected(
				struct _bluez_device *device,
				gboolean *connected);

typedef void (*bluez_device_network_connected_cb_t)(
				struct _bluez_device *device,
				gboolean connected,
				gpointer user_data);
void bluez_device_network_set_connected_changed_cb(
				struct _bluez_device *device,
				bluez_device_network_connected_cb_t cb,
				gpointer user_data);
void bluez_device_network_unset_connected_changed_cb(
				struct _bluez_device *device);

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

typedef void (*bluez_set_data_received_changed_t)(
				unsigned int channel,
				const char *data,
				unsigned int size,
				gpointer user_data);

void bluez_set_data_received_changed_cb(
				struct _bluez_device *device,
				bluez_set_data_received_changed_t cb,
				gpointer user_data);

void bluez_unset_data_received_changed_cb(struct _bluez_device *device);

typedef void (*bluez_hdp_state_changed_t)(int result,
				const char *remote_address,
				const char *app_id,
				bt_hdp_channel_type_e type,
				unsigned int channel,
				gpointer user_data);

void bluez_set_hdp_state_changed_cb(
				struct _bluez_device *device,
				bluez_hdp_state_changed_t cb,
				gpointer user_data);

void bluez_unset_hdp_state_changed_cb(struct _bluez_device *device);

typedef void (*bluez_avrcp_repeat_changed_cb_t)(
				const gchar *repeat,
				gpointer user_data);

void bluez_set_avrcp_repeat_changed_cb(
				bluez_avrcp_repeat_changed_cb_t cb,
				gpointer user_data);

void bluez_unset_avrcp_repeat_changed_cb();

typedef void (*bluez_avrcp_shuffle_changed_cb_t)(
				gboolean shuffle_mode,
				gpointer user_data);

void bluez_set_avrcp_shuffle_changed_cb(
				bluez_avrcp_shuffle_changed_cb_t cb,
				gpointer user_data);
void bluez_unset_avrcp_shuffle_changed_cb();

typedef void (*bluez_avrcp_target_cb_t)(
				const char *remote_address,
				gboolean connected,
				gpointer user_data);

void bluez_set_avrcp_target_cb(
				bluez_avrcp_target_cb_t cb,
				gpointer user_data);
void bluez_unset_avrcp_target_cb();

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
void bluez_device_cancel_pair(struct _bluez_device *device,
				simple_reply_cb_t cancel_pair_cb,
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

void bt_media_register_player(struct _bluez_adapter *adapter);

void bt_media_unregister_player(struct _bluez_adapter *adapter);

int bluez_media_player_set_track_info(struct _bluez_adapter *adapter,
				media_metadata_attributes_t *meta_data);

int bluez_media_player_change_property(struct _bluez_adapter *adapter,
				media_player_property_type type,
				unsigned int value);

int bluez_media_player_set_properties(struct _bluez_adapter *adapter,
				media_player_settings_t *properties);

int bluetooth_hdp_activate(unsigned short data_type,
					bt_hdp_role_type_t role,
					bt_hdp_qos_type_t channel_type,
					char **app_handle);

int bluetooth_hdp_deactivate(const char *app_handle);

int bluetooth_hdp_send_data(unsigned int channel_id,
					const char *buffer,
					unsigned int size);

int bluetooth_hdp_connect(const char *app_handle,
			bt_hdp_qos_type_t channel_type,
			const bluetooth_device_address_t *device_address);

int bluetooth_hdp_disconnect(unsigned int channel_id,
			const bluetooth_device_address_t *device_address);

void hdp_internal_handle_disconnect(gpointer user_data,
						GVariant *param);

void hdp_internal_handle_connect(gpointer user_data,
						GVariant *param);

struct _bluez_device {
	char *interface_name;
	char *object_path;
	GDBusInterface *interface;
	GDBusInterface *control_interface;
	GDBusInterface *network_interface;
	GDBusProxy *proxy;
	GDBusProxy *control_proxy;
	GDBusProxy *network_proxy;
	struct _bluez_object *parent;
	struct _device_head *head;

	bluez_device_paired_cb_t device_paired_cb;
	gpointer device_paired_cb_data;
	bluez_device_connected_cb_t device_connected_cb;
	gpointer device_connected_cb_data;
	bluez_device_trusted_cb_t device_trusted_cb;
	gpointer device_trusted_cb_data;
	bluez_device_network_connected_cb_t network_connected_cb;
	gpointer network_connected_cb_data;
	bluez_hdp_state_changed_t hdp_state_changed_cb;
	gpointer hdp_state_changed_cb_data;
	bluez_set_data_received_changed_t data_received_changed_cb;
	gpointer data_received_changed_data;
};

#endif

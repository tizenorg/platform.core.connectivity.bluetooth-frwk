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

#define BT_GENERIC_AUDIO_UUID      "00001203-0000-1000-8000-00805f9b34fb"

#define BT_HFP_HS_UUID             "0000111e-0000-1000-8000-00805f9b34fb"
#define BT_HFP_AG_UUID             "0000111f-0000-1000-8000-00805f9b34fb"
#define BT_ADVANCED_AUDIO_UUID     "0000110d-0000-1000-8000-00805f9b34fb"
#define BT_A2DP_SOURCE_UUID        "0000110a-0000-1000-8000-00805f9b34fb"
#define BT_A2DP_SINK_UUID          "0000110b-0000-1000-8000-00805f9b34fb"
#define BT_HSP_HS_UUID             "00001108-0000-1000-8000-00805f9b34fb"
#define BT_HSP_AG_UUID             "00001112-0000-1000-8000-00805f9b34fb"

#define BT_HID_UUID                "00001124-0000-1000-8000-00805f9b34fb"

typedef enum {
	BLUEZ_ERROR_NONE = 0x00, /**< Successful*/
	BLUEZ_ERROR_CANCELLED, /**< Operation cancelled */
	BLUEZ_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	BLUEZ_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	BLUEZ_ERROR_RESOURCE_BUSY, /**< Device or resource busy */
	BLUEZ_ERROR_TIMED_OUT, /**< Timeout error */
	BLUEZ_ERROR_NOW_IN_PROGRESS, /**< Operation now in progress */
	BLUEZ_ERROR_NOT_INITIALIZED, /**< Local adapter not initialized */
	BLUEZ_ERROR_NOT_ENABLED, /**< Local adapter not enabled */
	BLUEZ_ERROR_ALREADY_DONE, /**< Operation already done  */
	BLUEZ_ERROR_OPERATION_FAILED, /**< Operation failed */
	BLUEZ_ERROR_NOT_IN_PROGRESS, /**< Operation not in progress */
	BLUEZ_ERROR_REMOTE_DEVICE_NOT_BONDED, /**< Remote device not bonded */
	BLUEZ_ERROR_AUTH_REJECTED, /**< Authentication rejected */
	BLUEZ_ERROR_AUTH_FAILED, /**< Authentication failed */
	BLUEZ_ERROR_REMOTE_DEVICE_NOT_FOUND, /**< Remote device not found */
	BLUEZ_ERROR_SERVICE_SEARCH_FAILED, /**< Service search failed */
	BLUEZ_ERROR_REMOTE_DEVICE_NOT_CONNECTED, /**< Remote device is not connected */
	BLUEZ_ERROR_ADAPTER_NOT_FOUND, /**< Adapter not found */
} bluez_error_e;

struct _bluez_adapter;
typedef struct _bluez_adapter bluez_adapter_t;

struct _bluez_device;
typedef struct _bluez_device bluez_device_t;

struct _bluez_gatt_service;
typedef struct _bluez_gatt_service bluez_gatt_service_t;

struct _bluez_gatt_char;
typedef struct _bluez_gatt_char bluez_gatt_char_t;

struct _bluez_gatt_desc;
typedef struct _bluez_gatt_desc bluez_gatt_desc_t;

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
	char *title;
	char **artist;
	char *album;
	char **genre;
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

typedef struct {
	char *remote_address;
	char *remote_name;
	guint32 bt_class;
	gint16 rssi;
	gboolean is_bonded;
	char **service_uuid;
	int service_count;
	unsigned int appearance;
} adapter_device_discovery_info_t;

adapter_device_discovery_info_t *bluez_get_discovery_device_info(
					bluez_device_t *device);

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
int bluez_adapter_set_powered(struct _bluez_adapter *adapter,
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

char *bluez_gatt_service_get_property_uuid(
				struct _bluez_gatt_service *service);

char *bluez_gatt_char_get_property_uuid(
				struct _bluez_gatt_char *characteristic);

char *bluez_gatt_service_get_object_path(
				struct _bluez_gatt_service *service);

char *bluez_gatt_char_get_object_path(
				struct _bluez_gatt_char *characteristic);

char **bluez_gatt_char_property_get_flags(
				struct _bluez_gatt_char *characteristic);

int bluez_gatt_char_get_property_notifying(
				struct _bluez_gatt_char *characteristic,
				gboolean *notifying);

GByteArray *bluez_gatt_char_get_property_value(
				struct _bluez_gatt_char *characteristic);

struct _bluez_gatt_service *bluez_gatt_get_service_by_path(
				const char *service_path);

struct _bluez_gatt_char *bluez_gatt_get_char_by_path(
				const char *gatt_char_path);

GList *bluez_device_get_primary_services(
				struct _bluez_device *device);

char **bluez_gatt_service_get_property_includes(
				struct _bluez_gatt_service *service);

GList *bluez_gatt_service_get_chars(
				struct _bluez_gatt_service *service);

GList *bluez_gatt_service_get_char_paths(
				struct _bluez_gatt_service *service);
typedef void (*char_read_value_cb_t)(
				struct _bluez_gatt_char *characteristic,
				unsigned char *value_array,
				int value_length,
				gpointer user_data);

void bluez_set_char_read_value_cb(char_read_value_cb_t cb,
					gpointer user_data);

void bluez_gatt_read_char_value(struct _bluez_gatt_char *characteristic);

typedef void (*bluez_gatt_char_value_changed_cb_t)(
				bluez_gatt_char_t *characteristic,
				unsigned char *value_array,
				int value_length,
				gpointer user_data);

void bluez_set_char_value_changed_cb(
				struct _bluez_gatt_char *characteristic,
				bluez_gatt_char_value_changed_cb_t cb,
				gpointer user_data);

void bluez_unset_char_value_changed_cb(
				struct _bluez_gatt_char *characteristic);

void bluez_gatt_write_char_value(struct _bluez_gatt_char *characteristic,
				const unsigned char *value,
				int value_length,
				unsigned char request);

typedef void (*char_write_value_cb_t)(
				struct _bluez_gatt_char *characteristic,
				gpointer user_data);

void bluez_set_char_write_value_cb(char_write_value_cb_t cb,
					gpointer user_data);


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
typedef void (*bluez_device_input_connected_cb_t)(
				struct _bluez_device *device,
				gboolean connected,
				gpointer user_data);
void bluez_device_input_set_connected_changed_cb(
				struct _bluez_device *device,
				bluez_device_input_connected_cb_t cb,
				gpointer user_data);
void bluez_device_input_unset_connected_changed_cb(
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

int bluez_device_set_blocked(struct _bluez_device *device,
				gboolean blocked);

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

enum hdp_channel_type {
	HDP_CHANNEL_RELIABLE,
	HDP_CHANNEL_STREAMING,
	HDP_CHANNEL_ANY
};

typedef void (*bluez_hdp_state_changed_t)(int result,
				const char *remote_address,
				const char *app_id,
				enum hdp_channel_type type,
				unsigned int channel,
				gpointer user_data);

void bluez_set_hdp_state_changed_cb(
				struct _bluez_device *device,
				bluez_hdp_state_changed_t cb,
				gpointer user_data);

void bluez_unset_hdp_state_changed_cb(struct _bluez_device *device);

typedef void (*bluez_avrcp_target_cb_t)(
				const char *remote_address,
				gboolean connected,
				gpointer user_data);

void bluez_set_avrcp_target_cb(
				bluez_avrcp_target_cb_t cb,
				gpointer user_data);
void bluez_unset_avrcp_target_cb(void);

typedef void (*bluez_avrcp_shuffle_cb_t)(
				gboolean shuffle,
				gpointer user_data);

void bluez_set_avrcp_shuffle_cb(
				bluez_avrcp_shuffle_cb_t cb,
				gpointer user_data);
void bluez_unset_avrcp_shuffle_cb(void);

typedef void (*bluez_avrcp_repeat_cb_t)(
				const char *repeat,
				gpointer user_data);

void bluez_set_avrcp_repeat_cb(
				bluez_avrcp_repeat_cb_t cb,
				gpointer user_data);
void bluez_unset_avrcp_repeat_cb(void);

typedef void (*bluez_nap_connection_state_cb_t)(gboolean connected,
				const char *remote_address,
				const char *interface_name,
				gpointer user_data);
void bluez_set_nap_connection_state_cb(
				bluez_nap_connection_state_cb_t cb,
				gpointer user_data);
void bluez_unset_nap_connection_state_cb(void);

enum audio_profile_type {
	AUDIO_TYPE_A2DP,
};

typedef void (*bluez_audio_state_cb_t)(int result,
				gboolean connected,
				const char *remote_address,
				enum audio_profile_type type,
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

enum device_state {
	DEVICE_DISCONNECT_SUCCESS,
	DEVICE_CONNECT_SUCCESS,
	DEVICE_ALREADY_CONNECTED,
	DEVICE_CONNECT_FAILED,
	DEVICE_CONNECT_INPROGRESS,
	DEVICE_NOT_READY,
	DEVICE_NOT_CONNECTED
};

typedef void (*device_connect_cb_t)(
				struct _bluez_device *device,
				enum device_state state,
				gpointer user_data);
void bluez_set_device_connect_changed_cb(device_connect_cb_t cb,
					gpointer user_data);

void bluez_device_connect_le(struct _bluez_device *device);

typedef void (*device_disconnect_cb_t)(
				struct _bluez_device *device,
				enum device_state state,
				gpointer user_data);
void bluez_set_device_disconnect_changed_cb(device_disconnect_cb_t cb,
					gpointer user_data);

void bluez_device_disconnect_le(struct _bluez_device *device);

typedef void (*profile_connect_cb_t)(
				struct _bluez_device *device,
				enum device_profile_state state);
void bluez_device_connect_profile(
				struct _bluez_device *device,
				const gchar *uuid,
				profile_connect_cb_t pf_connect_cb);

void bluez_device_connect_all(struct _bluez_device *device,
				profile_connect_cb_t pf_connect_cb);

typedef void (*profile_disconnect_cb_t)(
				struct _bluez_device *device,
				enum device_profile_state state);
void bluez_device_disconnect_profile(
				struct _bluez_device *device,
				const gchar *uuid,
				profile_disconnect_cb_t pf_disconnect_cb);

void bluez_device_disconnect_all(
				struct _bluez_device *device,
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

int bluez_device_get_property_appearance(
				struct _bluez_device *device,
				guint16 *appearance);

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

int bluez_device_input_get_property_connected(
				struct _bluez_device *device,
				gboolean *connected);

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

int bluez_media_player_set_track_info(struct _bluez_adapter *adapter,
				media_metadata_attributes_t *meta_data);

int bluez_media_player_change_property(struct _bluez_adapter *adapter,
				media_player_property_type type,
				unsigned int value);

int bluez_media_player_set_properties(struct _bluez_adapter *adapter,
				media_player_settings_t *properties);

enum hdp_role_type {
	HDP_ROLE_SOURCE,
	HDP_ROLE_SINK
};

int bluez_hdp_activate(unsigned short data_type,
				enum hdp_role_type role,
				enum hdp_channel_type channel_type,
				char **app_handle);

int bluez_hdp_deactivate(const char *app_handle);

int bluez_hdp_send_data(unsigned int channel_id,
				const char *buffer,
				unsigned int size);

int bluez_hdp_connect(const char *app_handle,
				enum hdp_channel_type channel_type,
				const char *device_address);

int bluez_hdp_disconnect(unsigned int channel_id,
				const char *device_address);

void hdp_internal_handle_disconnect(gpointer user_data,
						GVariant *param);

void hdp_internal_handle_connect(gpointer user_data,
						GVariant *param);

gboolean bluez_get_media_type(const char *remote_address);

int bluez_media_register_player(struct _bluez_adapter *adapter);

void bluez_media_unregister_player(struct _bluez_adapter *adapter);

typedef void (*bluez_paired_cb_t)(gchar *address,
				gboolean paired, gpointer user_data);

void bluez_set_paired_changed_cb(bluez_paired_cb_t cb,
						gpointer user_data);

void bluez_unset_paired_changed_cb(void);

int bluez_get_local_info(char **local_version, char **chipset,
				char **firmware, char **stack_version);

#endif

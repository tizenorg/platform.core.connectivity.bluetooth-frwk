/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#ifndef _BT_INTERNAL_TYPES_H_
#define _BT_INTERNAL_TYPES_H_

#include <sys/types.h>
#include <libintl.h>

#include <dlog.h>

#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
	BT_NO_SERVER,
	BT_NATIVE_SERVER,
	BT_CUSTOM_SERVER,
	BT_FTP_SERVER,
} bt_server_type_t;

typedef enum {
	BT_SYNC_REQ,
	BT_ASYNC_REQ
} bt_req_type_t;

typedef enum {
	BT_MANAGER_EVENT = 0x01,
	BT_OBJECT_MANAGER_EVENT,
	BT_ADAPTER_EVENT,
	BT_DEVICE_EVENT,
	BT_HID_EVENT,
	BT_NETWORK_EVENT,
	BT_HEADSET_EVENT,
	BT_AVRCP_EVENT,
	BT_OPP_CLIENT_EVENT,
	BT_OPP_SERVER_EVENT,
	BT_RFCOMM_CLIENT_EVENT,
	BT_RFCOMM_SERVER_EVENT,
	BT_AGENT_EVENT,
	BT_MEDIA_TRANSFER_EVENT,
	/* Will be added */
} bt_event_type_t;

typedef enum {
	BT_BLUEZ_SERVICE = 0x00,
	BT_OBEX_SERVICE,
	BT_AGENT_SERVICE,
} bt_service_type_t;

typedef enum {
	BT_RFCOMM_UUID = 0x00,
	BT_RFCOMM_CHANNEL,
} bt_rfcomm_connect_type_t;

#define BT_ADDRESS_STR_LEN 18
#define BT_DBUS_TIMEOUT_MAX 50000
#define BT_SERVER_ACCEPT_TIMEOUT 2000 /* 2 seconds */
#define BT_FILE_PATH_MAX 256
#define BT_NAME_MAX 256

#define BT_HFP_AUDIO_GATEWAY_UUID "0000111f-0000-1000-8000-00805f9b34fb"
#define BT_A2DP_UUID "0000110D-0000-1000-8000-00805F9B34FB"
#define BT_AVRCP_TARGET_UUID "0000110c-0000-1000-8000-00805f9b34fb"
#define BT_OPP_UUID "00001105-0000-1000-8000-00805f9b34fb"
#define BT_FTP_UUID "00001106-0000-1000-8000-00805f9b34fb"
#define BT_SPP_UUID "00001101-0000-1000-8000-00805f9b34fb"
#define BT_HID_UUID "00001124-0000-1000-8000-00805f9b34fb"
#define BT_PAN_PANU_UUID "00001115-0000-1000-8000-00805f9b34fb"
#define BT_PAN_NAP_UUID "00001116-0000-1000-8000-00805f9b34fb"
#define BT_PAN_GN_UUID "00001117-0000-1000-8000-00805f9b34fb"

#define BT_FUNC_BASE ((int)(0x0000))
#define BT_FUNC_DEVICE_BASE ((int)(BT_FUNC_BASE + 0x0050))
#define BT_FUNC_HID_BASE ((int)(BT_FUNC_DEVICE_BASE + 0x0020))
#define BT_FUNC_NETWORK_BASE ((int)(BT_FUNC_HID_BASE + 0x0020))
#define BT_FUNC_AUDIO_BASE ((int)(BT_FUNC_NETWORK_BASE + 0x0020))
#define BT_FUNC_OOB_BASE ((int)(BT_FUNC_AUDIO_BASE + 0x0020))
#define BT_FUNC_AVRCP_BASE ((int)(BT_FUNC_OOB_BASE + 0x0020))
#define BT_FUNC_OPP_BASE ((int)(BT_FUNC_AVRCP_BASE + 0x0020))
#define BT_FUNC_RFCOMM_BASE ((int)(BT_FUNC_OPP_BASE + 0x0020))

typedef enum {
	BT_CHECK_ADAPTER = BT_FUNC_BASE,
	BT_ENABLE_ADAPTER,
	BT_DISABLE_ADAPTER,
	BT_SET_DISCOVERABLE_TIME,
	BT_GET_DISCOVERABLE_TIME,
	BT_IGNORE_AUTO_PAIRING,
	BT_GET_LOCAL_ADDRESS,
	BT_GET_LOCAL_NAME,
	BT_SET_LOCAL_NAME,
	BT_IS_SERVICE_USED,
	BT_GET_DISCOVERABLE_MODE,
	BT_SET_DISCOVERABLE_MODE,
	BT_START_DISCOVERY,
	BT_CANCEL_DISCOVERY,
	BT_IS_DISCOVERYING,
	BT_GET_BONDED_DEVICES,
	BT_RESET_ADAPTER,
	BT_BOND_DEVICE = BT_FUNC_DEVICE_BASE,
	BT_CANCEL_BONDING,
	BT_UNBOND_DEVICE,
	BT_SEARCH_SERVICE,
	BT_CANCEL_SEARCH_SERVICE,
	BT_GET_BONDED_DEVICE,
	BT_SET_ALIAS,
	BT_SET_AUTHORIZATION,
	BT_IS_DEVICE_CONNECTED,
	BT_HID_CONNECT = BT_FUNC_HID_BASE,
	BT_HID_DISCONNECT,
	BT_NETWORK_ACTIVATE = BT_FUNC_NETWORK_BASE,
	BT_NETWORK_DEACTIVATE,
	BT_NETWORK_CONNECT,
	BT_NETWORK_DISCONNECT,
	BT_AUDIO_CONNECT = BT_FUNC_AUDIO_BASE,
	BT_AUDIO_DISCONNECT,
	BT_AG_CONNECT,
	BT_AG_DISCONNECT,
	BT_AV_CONNECT,
	BT_AV_DISCONNECT,
	BT_GET_SPEAKER_GAIN,
	BT_SET_SPEAKER_GAIN,
	BT_OOB_READ_LOCAL_DATA = BT_FUNC_OOB_BASE,
	BT_OOB_ADD_REMOTE_DATA,
	BT_OOB_REMOVE_REMOTE_DATA,
	BT_AVRCP_SET_TRACK_INFO = BT_FUNC_AVRCP_BASE,
	BT_AVRCP_SET_PROPERTY,
	BT_AVRCP_SET_PROPERTIES,
	BT_OPP_PUSH_FILES = BT_FUNC_OPP_BASE,
	BT_OPP_CANCEL_PUSH,
	BT_OPP_IS_PUSHING_FILES,
	BT_OBEX_SERVER_ALLOCATE,
	BT_OBEX_SERVER_DEALLOCATE,
	BT_OBEX_SERVER_IS_ACTIVATED,
	BT_OBEX_SERVER_ACCEPT_CONNECTION,
	BT_OBEX_SERVER_REJECT_CONNECTION,
	BT_OBEX_SERVER_ACCEPT_FILE,
	BT_OBEX_SERVER_REJECT_FILE,
	BT_OBEX_SERVER_SET_PATH,
	BT_OBEX_SERVER_SET_ROOT,
	BT_OBEX_SERVER_CANCEL_TRANSFER,
	BT_OBEX_SERVER_CANCEL_ALL_TRANSFERS,
	BT_OBEX_SERVER_IS_RECEIVING,
	BT_RFCOMM_CLIENT_CONNECT = BT_FUNC_RFCOMM_BASE,
	BT_RFCOMM_CLIENT_CANCEL_CONNECT,
	BT_RFCOMM_CLIENT_IS_CONNECTED,
	BT_RFCOMM_SOCKET_DISCONNECT,
	BT_RFCOMM_SOCKET_WRITE,
	BT_RFCOMM_CREATE_SOCKET,
	BT_RFCOMM_REMOVE_SOCKET,
	BT_RFCOMM_LISTEN,
	BT_RFCOMM_IS_UUID_AVAILABLE,
	BT_RFCOMM_ACCEPT_CONNECTION,
	BT_RFCOMM_REJECT_CONNECTION,

} bt_function_t;

typedef struct {
	char title[BT_NAME_MAX];
	char artist[BT_NAME_MAX];
	char album[BT_NAME_MAX];
	char genre[BT_NAME_MAX];
	unsigned int total_tracks;
	unsigned int number;
	unsigned int duration;
} media_metadata_t;

#define BT_COMMON_PKG "ug-setting-bluetooth-efl"

/* Need to convert the design ID */
#define BT_STR_NOT_SUPPORT "Not support"

#define BT_FILE_VISIBLE_TIME "file/private/libug-setting-bluetooth-efl/visibility_time"
#define BT_OFF_DUE_TO_FLIGHT_MODE "file/private/bt-service/flight_mode_deactivated"

#define BT_EVENT_SERVICE "org.projectx.bt_event"

#define BT_ADAPTER_PATH "/org/projectx/bt/adapter"
#define BT_DEVICE_PATH "/org/projectx/bt/device"
#define BT_HID_PATH "/org/projectx/bt/hid"
#define BT_HEADSET_PATH "/org/projectx/bt/headset"
#define BT_AVRCP_PATH "/org/projectx/bt/avrcp"
#define BT_NETWORK_PATH "/org/projectx/bt/newtork"
#define BT_OPP_CLIENT_PATH "/org/projectx/bt/opp_client"
#define BT_OPP_SERVER_PATH "/org/projectx/bt/opp_server"
#define BT_RFCOMM_CLIENT_PATH "/org/projectx/bt/rfcomm_client"
#define BT_RFCOMM_SERVER_PATH "/org/projectx/bt/rfcomm_server"


#define BT_ENABLED "Enabled"
#define BT_DISABLED "Disabled"
#define BT_DISCOVERABLE_MODE_CHANGED "DiscoverableModeChanged"
#define BT_DISCOVERABLE_TIMEOUT_CHANGED "DiscoverableTimeoutChanged"
#define BT_ADAPTER_NAME_CHANGED "AdapterNameChanged"
#define BT_DISCOVERY_STARTED "DiscoveryStarted"
#define BT_DISCOVERY_FINISHED "DiscoveryFinished"
#define BT_DEVICE_FOUND "DeviceFound"
#define BT_DEVICE_DISAPPEARED "DeviceDisappeared"
#define BT_DEVICE_CONNECTED "DeviceConnected"
#define BT_DEVICE_DISCONNECTED "DeviceDisconnected"
#define BT_BOND_CREATED "BondCreated"
#define BT_BOND_DESTROYED "BondDestroyed"
#define BT_SERVICE_SEARCHED "ServiceSearched"
#define BT_INPUT_CONNECTED "InputConnected"
#define BT_INPUT_DISCONNECTED "InputDisconnected"
#define BT_HEADSET_CONNECTED "HeadsetConnected"
#define BT_HEADSET_DISCONNECTED "HeadsetDisconnected"
#define BT_STEREO_HEADSET_CONNECTED "StereoHeadsetConnected"
#define BT_STEREO_HEADSET_DISCONNECTED "StereoHeadsetDisconnected"
#define BT_SCO_CONNECTED "ScoConnected"
#define BT_SCO_DISCONNECTED "ScoDisconnected"
#define BT_SPEAKER_GAIN "SpeakerGain"
#define BT_MICROPHONE_GAIN "MicrophoneGain"
#define BT_NETWORK_CONNECTED "NetworkConnected"
#define BT_NETWORK_DISCONNECTED "NetworkDisconnected"
#define BT_NETWORK_SERVER_CONNECTED "NetworkServerConnected"
#define BT_NETWORK_SERVER_DISCONNECTED "NetworkServerDisconnected"
#define BT_OPP_CONNECTED "OppConnected"
#define BT_OPP_DISCONNECTED "OppDisconnected"
#define BT_TRANSFER_STARTED "TransferStarted"
#define BT_TRANSFER_PROGRESS "TransferProgress"
#define BT_TRANSFER_COMPLETED "TransferCompleted"
#define BT_TRANSFER_AUTHORIZED "TransferAuthorized"
#define BT_CONNECTION_AUTHORIZED "ConnectionAuthorized"
#define BT_RFCOMM_SERVER_REMOVED "RfcommServerRemoved"
#define BT_RFCOMM_DATA_RECEIVED "RfcommDataReceived"
#define BT_RFCOMM_CONNECTED "RfcommConnected"
#define BT_RFCOMM_DISCONNECTED "RfcommDisconnected"
#define BT_MEDIA_SHUFFLE_STATUS "MediaShuffleStatus"
#define BT_MEDIA_EQUALIZER_STATUS "MediaEqualizerStatus"
#define BT_MEDIA_REPEAT_STATUS "MediaRepeatStatus"
#define BT_MEDIA_SCAN_STATUS "MediaScanStatus"

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_INTERNAL_TYPES_H_*/


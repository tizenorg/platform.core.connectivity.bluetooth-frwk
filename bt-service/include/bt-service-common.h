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

#ifndef _BT_SERVICE_COMMON_H_
#define _BT_SERVICE_COMMON_H_

#include <sys/types.h>
#include <dlog.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>

#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

#undef LOG_TAG
#define LOG_TAG "BLUETOOTH_FRWK_SERVICE"

#define BT_DBG(fmt, args...) \
        SLOGD(fmt, ##args)
#define BT_ERR(fmt, args...) \
        SLOGE(fmt, ##args)

#define ret_if(expr) \
	do { \
		if (expr) { \
			BT_ERR("(%s) return", #expr); \
			return; \
		} \
	} while (0)

#define retv_if(expr, val) \
	do { \
		if (expr) { \
			BT_ERR("(%s) return", #expr); \
			return (val); \
		} \
	} while (0)

#define BT_CHECK_PARAMETER(arg, func) \
	do { \
		if (arg == NULL) \
		{ \
			BT_ERR("INVALID PARAMETER"); \
			func BLUETOOTH_ERROR_INVALID_PARAM; \
		} \
	} while (0)

#define BT_CHANNEL_LENGTH_MAX 5
#define BT_ADDRESS_LENGTH_MAX 6
#define BT_ADDRESS_STRING_SIZE 18
#define BT_RFCOMM_BUFFER_MAX 1024
#define BT_LOWER_ADDRESS_LENGTH 9

#define BT_AGENT_AUTO_PAIR_BLACKLIST_FILE (APP_SYSCONFDIR"/auto-pair-blacklist")
#define BT_AGENT_NEW_LINE "\r\n"

#define BT_MAX_DBUS_TIMEOUT 45000
#define BT_ENABLE_TIMEOUT 5000 /* 5 seconds */
#define BT_DISCOVERY_FINISHED_DELAY 200

#define MANAGER_EVENT_MATCH_RULE \
			"type='signal'," \
			"interface='%s'," \
			"member='%s'"

#define EVENT_MATCH_RULE \
			"type='signal'," \
			"interface='%s',"

#define BT_TEMINATING_WAIT_TIME 200

#define BT_TIMEOUT_MESSAGE "Did not receive a reply. Possible causes include: " \
			"the remote application did not send a reply, " \
			"the message bus security policy blocked the reply, " \
			"the reply timeout expired, or the network connection " \
			"was broken."

#define BT_BLUEZ_NAME "org.bluez"
#define BT_BLUEZ_PATH "/org/bluez"
#define BT_BLUEZ_HCI_PATH "/org/bluez/hci0"
#define BT_BLUEZ_HCI_DEV_PATH "/org/bluez/hci0/dev"
#define BT_AGENT_NAME "org.bluez.frwk_agent"
#define BT_AGENT_PATH "/org/bluez/agent/frwk_agent"
#define BT_DEVICE_AGENT_PATH "/org/tizen/device_agent"
#define BT_ADAPTER_AGENT_PATH "/org/tizen/adapter_agent"
#define BT_MANAGER_PATH "/"
#define BT_MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"
#define BT_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BT_AGENT_INTERFACE "org.bluez.Agent1"
#define BT_AGENT_MANAGER_INTERFACE "org.bluez.AgentManager1"
#define BT_DEVICE_INTERFACE "org.bluez.Device1"
#define BT_INPUT_INTERFACE "org.bluez.Input"
#define BT_NETWORK_INTERFACE "org.bluez.Network1"
#define BT_NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer1"
#define BT_NETWORK_CLIENT_INTERFACE "org.bluez.Network1"
#define BT_SERIAL_INTERFACE "org.bluez.Serial"
#define BT_SERIAL_MANAGER_INTERFACE "org.bluez.SerialProxyManager"
#define BT_SERIAL_PROXY_INTERFACE "org.bluez.SerialProxy"
#define BT_HFP_AGENT_INTERFACE "Org.Hfp.App.Interface"
#define BT_SINK_INTERFACE "org.bluez.AudioSink"
#define BT_AUDIO_INTERFACE "org.bluez.Audio"
#define BT_OOB_INTERFACE "org.bluez.OutOfBand"
#define BT_MEDIA_INTERFACE "org.bluez.Media1"
#define BT_MEDIA_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"
#define BT_OBEXD_DBUS_NAME "org.bluez.obex"
#define BT_OBEXD_MANAGER_INTERFACE "org.bluez.obex.AgentManager1"
#define BT_OBEXD_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"
#define BT_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define BT_MEDIA_CONTROL_INTERFACE "org.bluez.MediaControl1"
#define MPRIS_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"

#define BT_OBEX_SERVICE_NAME "org.bluez.obex"

#define BT_OBEX_CLIENT_PATH "/org/bluez/obex"
#define BT_OBEX_CLIENT_INTERFACE "org.bluez.obex.Client1"
#define BT_OBEX_OBJECT_PUSH_INTERFACE "org.bluez.obex.ObjectPush1"
#define BT_OBEX_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"
#define BT_OBEX_AGENT_INTERFACE "org.bluez.obex.Agent1"

#define BT_SESSION_BASEPATH_SERVER "/org/bluez/obex/server"
#define BT_SESSION_BASEPATH_CLIENT "/org/bluez/obex/client"

#define BT_FREEDESKTOP_INTERFACE "org.freedesktop.DBus"
#define BT_FREEDESKTOP_PATH "/org/freedesktop/DBus"

#define BT_INTERFACES_ADDED "InterfacesAdded"
#define BT_INTERFACES_REMOVED "InterfacesRemoved"
#define BT_NAME_OWNER_CHANGED "NameOwnerChanged"
#define BT_PROPERTIES_CHANGED "PropertiesChanged"
#define DBUS_INTERFACE_OBJECT_MANAGER "/"

#define GENERIC_AUDIO_UUID      "00001203-0000-1000-8000-00805f9b34fb"

#define HSP_HS_UUID             "00001108-0000-1000-8000-00805f9b34fb"
#define HSP_AG_UUID             "00001112-0000-1000-8000-00805f9b34fb"

#define HFP_HS_UUID             "0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_AG_UUID             "0000111f-0000-1000-8000-00805f9b34fb"

#define ADVANCED_AUDIO_UUID     "0000110d-0000-1000-8000-00805f9b34fb"

#define A2DP_SOURCE_UUID        "0000110a-0000-1000-8000-00805f9b34fb"
#define A2DP_SINK_UUID          "0000110b-0000-1000-8000-00805f9b34fb"

#define AVRCP_REMOTE_UUID       "0000110e-0000-1000-8000-00805f9b34fb"
#define AVRCP_TARGET_UUID       "0000110c-0000-1000-8000-00805f9b34fb"

#define HID_UUID                "00001124-0000-1000-8000-00805f9b34fb"
#define PNP_UUID                "00001200-0000-1000-8000-00805f9b34fb"

#define BT_STOP_DISCOVERY_TIMEOUT 1000*15

typedef enum {
	BT_OBEX_SERVER = 0x00,
	BT_RFCOMM_SERVER = 0x01,
} bt_osp_server_type_t;

typedef struct {
	int rssi;
	int class;
	char *address;
	char *name;
	char **uuids;
	int uuid_count;
	gboolean paired;
	gboolean connected;
	gboolean trust;
} bt_remote_dev_info_t;

/* RFCOMM client /server will use this structure*/
typedef struct {
	int fd;
	GIOChannel *io_channel;
	guint io_event;
	char *dev_node;
	char *address;
	char *uuid;
} bt_rfcomm_info_t;

typedef struct {
	int req_id;
	char *address;
} bt_function_data_t;

DBusConnection *_bt_get_system_conn(void);

DBusGConnection *_bt_get_system_gconn(void);

DBusGConnection *_bt_get_session_gconn(void);

DBusGProxy *_bt_get_manager_proxy(void);

DBusGProxy *_bt_get_adapter_proxy(void);

DBusGProxy *_bt_get_adapter_properties_proxy(void);

char *_bt_get_adapter_path(void);

void _bt_deinit_proxys(void);

void _bt_convert_device_path_to_address(const char *device_path,
						char *device_address);

void _bt_convert_addr_string_to_type(unsigned char *addr,
					const char *address);

void _bt_convert_addr_type_to_string(char *address,
				unsigned char *addr);

void _bt_print_device_address_t(const bluetooth_device_address_t *addr);

void _bt_divide_device_class(bluetooth_device_class_t *device_class,
				unsigned int cod);

void _bt_free_device_info(bt_remote_dev_info_t *dev_info);

int _bt_register_osp_server_in_agent(int type, char *uuid);

int _bt_unregister_osp_server_in_agent(int type, char *uuid);

int _bt_set_socket_non_blocking(int socket_fd);

int _bt_set_non_blocking_tty(int sk);

gboolean _bt_is_headset_class(int dev_class);

char *_bt_get_device_object_path(char *address);

void _bt_deinit_bluez_proxy(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_COMMON_H_*/


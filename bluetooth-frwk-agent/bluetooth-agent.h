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

#ifndef __DEF_BT_AGENT_H_
#define __DEF_BT_AGENT_H_

#include <unistd.h>
#include <dlog.h>

#include <stdio.h>

#include <dbus/dbus-glib.h>

#define BT_AGENT	"BT_AGENT"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_AGENT, "%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_AGENT, "%s():%d "fmt, __func__, __LINE__, ##args)

#define BT_AGENT_PADDING_SIZE 4096
#define BT_MAX_SERVICES_FOR_DEVICE	20     /**< This specifies maximum number of services a
						device can support */
#define BT_MAX_EVENT_STR_LENGTH	50
#define BT_AGENT_ADDR_SIZE	18

struct bt_agent_appdata {
	void *g_connection;
	int ignore_auto_pairing;
	char bonding_addr[BT_AGENT_ADDR_SIZE + 1];	/*bluetooth device address which currently
							bonding is requested to */
};

typedef enum {
	HS_PROFILE_UUID = ((unsigned short)0x1108),		/**<HS*/
	AUDIO_SOURCE_UUID = ((unsigned short)0x110A),		/**<AUDIO SOURCE*/
	AUDIO_SINK_UUID = ((unsigned short)0x110B),		/**<AUDIO SINK*/
	AV_REMOTE_CONTROL_TARGET_UUID = ((unsigned short)0x110C),/**<AV REMOTE CONTROL TARGET*/
	ADVANCED_AUDIO_PROFILE_UUID = ((unsigned short)0x110D),	/**<A2DP*/
	AV_REMOTE_CONTROL_UUID = ((unsigned short)0x110E),	/**<AV REMOTE CONTROL UUID*/
	HF_PROFILE_UUID = ((unsigned short)0x111E),		/**<HF*/
} bt_agent_service_uuid_list_t;

typedef enum {
	BT_AGENT_EVENT_PIN_REQUEST = 0x0001,
	BT_AGENT_EVENT_PASSKEY_CONFIRM_REQUEST = 0x0002,
	BT_AGENT_EVENT_PASSKEY_REQUEST = 0x0004,
	BT_AGENT_EVENT_PASSKEY_DISPLAY_REQUEST = 0x0008,
	BT_AGENT_EVENT_AUTHORIZE_REQUEST = 0x0010,
	BT_AGENT_EVENT_CONFIRM_MODE_REQUEST = 0x0020,
	BT_AGENT_EVENT_APP_CONFIRM_REQUEST = 0x0040,
	BT_AGENT_EVENT_FILE_RECIEVED = 0x0080,
	BT_AGENT_EVENT_KEYBOARD_PASSKEY_REQUEST = 0x0100,
	BT_AGENT_EVENT_TERMINATE = 0x0200,
} bt_agent_event_type_t;

typedef enum {
	BT_AGENT_CHANGED_MODE_ENABLE,
	BT_AGENT_CHANGED_MODE_DISABLE,
} bt_agent_changed_mode_type_t;

typedef enum {
	BT_AGENT_RUN_STATUS_NO_CHANGE = 0x00,	/* No Change BT status*/
	BT_AGENT_RUN_STATUS_ACTIVATE = 0x01,	/* BT Activate*/
	BT_AGENT_RUN_STATUS_DEACTIVATE = 0x02,	/* BT Deactivate*/
	BT_AGENT_RUN_STATUS_SEARCH_TEST = 0x03,	/* BT Search Test*/
	BT_AGENT_RUN_STATUS_TERMINATE = 0x04,	/* BT Terminate*/
	BT_AGENT_RUN_STATUS_MAX = 0x05,	/* Max val*/
} bt_agent_run_status_t;

typedef enum {
	BT_AGENT_ON_CURRENTVIEW = 0x00,	/* Run BT on current view*/
	BT_AGENT_ON_FOREGROUND = 0x01,	/* Run BT on foreground*/
	BT_AGENT_ON_BACKGROUND = 0x02,	/* Run BT on background*/
} bt_agent_on_t;

typedef struct {
	unsigned int service_list_array[BT_MAX_SERVICES_FOR_DEVICE];
	int service_index;
} bt_agent_sdp_info_t;

int _bt_agent_launch_system_popup(bt_agent_event_type_t event_type, const char *device_name,
				 char *passkey, const char *filename);
void _bt_agent_register(DBusGProxy *adapter_proxy);

#endif				/* __DEF_BT_AGENT_H_ */

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


#ifndef _BLUETOOTH_API_COMMON_H_
#define _BLUETOOTH_API_COMMON_H_

#include <stdbool.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <libintl.h>

#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>

#include <dlog.h>
#include <vconf-keys.h>

#include "bluetooth-api.h"

#define BT_FRWK	"BT_FRWK"

#ifndef BT_EXPORT_API
#define BT_EXPORT_API __attribute__((visibility("default")))
#endif

#define PRT(level, fmt, function, args...) \
	SLOG(LOG_DEBUG, BT_FRWK, "%s():%d "fmt, __func__, __LINE__, ##args)
#define DBG(fmt, args...) \
	SLOG(LOG_DEBUG, BT_FRWK, "%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) \
	SLOG(LOG_ERROR, BT_FRWK, "%s():%d "fmt, __func__, __LINE__, ##args)
#define AST(fmt, args...) \
	SLOG(LOG_ERROR, BT_FRWK, "%s():%d "fmt, __func__, __LINE__, ##args)

#define BT_SETTING_DEVICE_NAME "db/setting/device_name"
#define BT_MEMORY_OBEX_NO_AGENT "memory/private/libbluetooth-frwk-0/obex_no_agent"
#define BT_MEMORY_RFCOMM_UUID "memory/private/libbluetooth-frwk-0/uuid"
#define BT_FILE_VISIBLE_TIME "file/private/libug-setting-bluetooth-efl/visibility_time"

#define BLUEZ_SERVICE_NAME "org.bluez"
#define BLUEZ_MANAGER_OBJ_PATH "/"
#define BLUEZ_MANAGER_INTERFACE "org.bluez.Manager"

#define BLUEZ_ADAPTER_INTERFACE "org.bluez.Adapter"
#define BLUEZ_DEVICE_INTERFACE "org.bluez.Device"

#define BT_AGENT_INTERFACE "User.Bluetooth.agent"

#define HCI_SCAN_ENABLE_NO_SCAN                                         0x00
#define HCI_SCAN_ENABLE_INQUIRY_ONLY                                    0x01
#define HCI_SCAN_ENABLE_PAGE_ONLY                                       0x02
#define HCI_SCAN_ENABLE_PAGE_AND_INQUIRY                                0x03

#define BT_ADDRESS_STRING_SIZE 18
#define BT_128_UUID_LEN 36
#define BT_ADAPTER_OBJECT_PATH_MAX 50
#define BT_DISCOVERY_FINISHED_DELAY 200

#define RFKILL_NODE "/dev/rfkill"

#define BLUETOOTH_UUID_POSTFIX "0000-1000-8000-00805f9b34fb"

#define BT_COMMON_PKG "ug-setting-bluetooth-efl"

#define BT_STR_DISABLED_RESTRICTS \
	dgettext(BT_COMMON_PKG, "IDS_BT_BODY_SECURITY_POLICY_RESTRICTS_USE_OF_BLUETOOTH_CONNECTION")

#define BT_STR_HANDS_FREE_RESTRICTS \
	dgettext(BT_COMMON_PKG, "IDS_BT_BODY_SECURITY_POLICY_RESTRICTS_USE_OF_BLUETOOTH_CONNECTION_TO_HANDS_FREE_FEATURES_ONLY")

#define RFKILL_EVENT_SIZE 8

#define BT_PHONE_NUM_LEN 50
#define BT_FILE_BUFFER_MAX 256

#define SLEEP_TIME 50000 /* 50 ms */
#define BLOCK_MAX_TIMEOUT 2000000 /* 2 seconds */

typedef enum {
	BT_STORE_BOOLEAN,
	BT_STORE_INT,
	BT_STORE_STRING,
} bt_store_type_t;

typedef enum {
	BT_STORE_NAME,
	BT_STORE_DISCOVERABLE_MODE,
} bt_store_key_t;


typedef enum {
        RFKILL_TYPE_ALL = 0,
        RFKILL_TYPE_WLAN,
        RFKILL_TYPE_BLUETOOTH,
        RFKILL_TYPE_UWB,
        RFKILL_TYPE_WIMAX,
        RFKILL_TYPE_WWAN,
        RFKILL_TYPE_GPS,
        RFKILL_TYPE_FM,
        NUM_RFKILL_TYPES,
} rfkill_type;

typedef enum {
	BT_ACCEPT,
	BT_REJECT,
	BT_CANCEL,
	BT_TIMEOUT,
} bt_accept_type_t;

typedef struct {
	unsigned int idx;
	unsigned char type;
	unsigned char op;
	unsigned char soft;
	unsigned char hard;
} rfkill_event;

typedef struct {
	const char *match;
	unsigned short match_uuid16;
	const char *match_name;
	unsigned int match_handle;
} match_entries_t;

typedef struct {
	match_entries_t *search_match_ptr;
	bluetooth_device_address_t remote_device_addr;
	int success_search_index;
} bt_info_for_searching_support_service_t;

/**
 *   @internal
 *   This structure has information about BT
 */

typedef struct {
	pid_t application_pid;			/**< Application process id */
	bluetooth_cb_func_ptr bt_cb_ptr; 	/**< Function pointer for
						responsing event to application */

	DBusGConnection *conn;			/**< DBUS bus connection for bluez ipc */
	DBusConnection *sys_conn;
	DBusGProxy *dbus_proxy;			/**< DBUS proxy */
	DBusGProxy *manager_proxy;		/**< bluez manager ipc proxy */
	DBusGProxy *adapter_proxy;		/**< bluez adapter ipc proxy */
	DBusGProxy *agent_proxy;		/**< Agent ipc proxy */
	DBusGProxy *network_server_proxy;
	DBusGProxy *rfcomm_proxy;
	char adapter_path[BT_ADAPTER_OBJECT_PATH_MAX];	/*bluez adapter path*/
	char *connecting_uuid;
	GList *device_proxy_list;			/**< bluez device ipc proxy list */

	bluetooth_adapter_state_t bt_adapter_state;	/*Current bluetooth state*/
	guint bt_change_state_timer;			/**< g_timeout for checking timeout
							of BT status change */
	bluetooth_device_name_t bt_local_name; 		/*Local bluetooth device name*/

	guint bt_discovery_req_timer;			/**< g_timeout for checking timeout of
							BT discovery request */
	guint bt_discovery_res_timer;
	gboolean is_discovery_req;			/**< application request discovery or not*/
	gboolean is_discovering;			/**< Currently discovery state */
	gboolean is_discovery_cancel;			/**< discovery cancel is requested */

	guint bt_bonding_req_timer;			/**< g_timeout for checking timeout of
								 BT discovery request */
	gboolean is_bonding_req;			/*application request bonding or not*/
	gboolean is_headset_bonding;
	char bt_bonding_req_addrstr[BT_ADDRESS_STRING_SIZE]; /**< bluetooth device address which
							currently bonding is requested to */
	gboolean is_headset_pin_req;			/*application request bonding or not*/
	bt_info_for_searching_support_service_t info_for_searching_support_service;  /**< Service
								Seaching Session Infomation */

	gboolean is_service_req;			/**< Request to discover device services */
	void *user_data;

} bt_info_t;

bt_info_t *_bluetooth_internal_get_information(void);
void _bluetooth_internal_event_cb(int event, int result, void *param_data);

void _bluetooth_internal_session_init(void);

bool _bluetooth_internal_is_adapter_enabled(void);

DBusGProxy *_bluetooth_internal_find_device_by_path(const char *dev_path);
DBusGProxy *_bluetooth_internal_add_device(const char *path);

void _bluetooth_change_uuids_to_sdp_info(GValue *value, bt_sdp_info_t *sdp_data);

void _bluetooth_internal_print_bluetooth_device_address_t(const  bluetooth_device_address_t  *addr);
void _bluetooth_internal_convert_addr_string_to_addr_type(bluetooth_device_address_t *addr,
							const char *address);
void _bluetooth_internal_addr_type_to_addr_string(char *address,
						const bluetooth_device_address_t *addr);
void _bluetooth_internal_divide_device_class(bluetooth_device_class_t *device_class,
									unsigned int cod);
void _bluetooth_internal_device_path_to_address(const char *device_path,
					       char *device_address);

int _bluetooth_get_default_adapter_name(bluetooth_device_name_t *dev_name, int size);

int _bluetooth_internal_get_adapter_path(DBusGConnection *conn, char *path);

DBusGProxy *_bluetooth_internal_get_adapter_proxy(DBusGConnection *conn);

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

#ifdef __cplusplus
}
#endif				/* __cplusplus */
#endif				/*_BLUETOOTH_API_COMMON_H_*/


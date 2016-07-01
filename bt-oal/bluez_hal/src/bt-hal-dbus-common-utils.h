/*
 * BLUETOOTH HAL
 *
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
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

#ifndef _BT_HAL_DBUS_COMMON_UTILS_H_
#define _BT_HAL_DBUS_COMMON_UTILS_H_

#include <glib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <dlog.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <glib.h>
#include <dlog.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>

#define BT_HAL_MAX_DBUS_TIMEOUT 45000
#define BT_HAL_TIMEOUT_MESSAGE "Did not receive a reply. Possible causes include: " \
                        "the remote application did not send a reply, " \
                        "the message bus security policy blocked the reply, " \
                        "the reply timeout expired, or the network connection " \
                        "was broken."

#define BT_HAL_DISCOVERY_FINISHED_DELAY 200

#define BT_HAL_ADDRESS_LENGTH_MAX 6
#define BT_HAL_ADDRESS_STRING_SIZE 18
#define BT_HAL_LOWER_ADDRESS_LENGTH 9
#define BT_HAL_AGENT_NEW_LINE "\r\n"

#define BT_HAL_VERSION_LENGTH_MAX       30 /**< This specifies bluetooth device version length */
#define BT_HAL_INTERFACE_NAME_LENGTH        16
#define BT_HAL_DEVICE_NAME_LENGTH_MAX       248 /**< This specifies maximum device name length */
#define BT_HAL_DEVICE_PASSKEY_LENGTH_MAX       50 /**< This specifies maximum length of the passkey */
#define BT_HAL_ADVERTISING_DATA_LENGTH_MAX   31 /**< This specifies maximum AD data length */
#define BT_HAL_SCAN_RESP_DATA_LENGTH_MAX     31 /**< This specifies maximum LE Scan response data length */
#define BT_HAL_MANUFACTURER_DATA_LENGTH_MAX  240 /**< This specifies maximum manufacturer data length */
#define BT_HAL_BLUEZ_NAME "org.bluez"
#define BT_HAL_BLUEZ_PATH "/org/bluez"
#define BT_HAL_MANAGER_PATH "/"
#define BT_HAL_BLUEZ_HCI_PATH "/org/bluez/hci0"

#define BT_HAL_MANAGER_INTERFACE "org.freedesktop.DBus.ObjectManager"
#define BT_HAL_ADAPTER_INTERFACE "org.bluez.Adapter1"
#define BT_HAL_DEVICE_INTERFACE "org.bluez.Device1"
#define BT_HAL_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

#define BT_HAL_HARDWARE_ERROR "HardwareError"
#define BT_HAL_TX_TIMEOUT_ERROR "TxTimeoutError"

#define BT_HAL_FREEDESKTOP_INTERFACE "org.freedesktop.DBus"
#define BT_HAL_FREEDESKTOP_PATH "/org/freedesktop/DBus"

#define BT_HAL_SINK_INTERFACE "org.bluez.AudioSink"
#define BT_HAL_AUDIO_INTERFACE "org.bluez.Audio"
#define BT_HAL_INPUT_INTERFACE "org.bluez.Input1"
#define BT_HAL_AGENT_INTERFACE "org.bluez.Agent1"
#define BT_HAL_AGENT_MANAGER_INTERFACE "org.bluez.AgentManager1"
#define BT_HAL_MEDIA_INTERFACE "org.bluez.Media1"
#define BT_HAL_MEDIA_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"
#define BT_HAL_MEDIATRANSPORT_INTERFACE "org.bluez.MediaTransport1"
#define BT_HAL_MEDIA_CONTROL_INTERFACE "org.bluez.MediaControl1"
#define BT_HAL_PLAYER_CONTROL_INTERFACE "org.bluez.MediaPlayer1"
#define BT_HAL_GATT_CHAR_INTERFACE "org.bluez.GattCharacteristic1"
#define BT_HAL_NETWORK_INTERFACE "org.bluez.Network"
#define BT_HAL_NETWORK_CLIENT_INTERFACE "org.bluez.Network1"
#define BT_HAL_NETWORK_SERVER_INTERFACE "org.bluez.NetworkServer1"
#define BT_HAL_MEDIA_INTERFACE "org.bluez.Media1"
#define BT_HAL_MEDIA_PLAYER_INTERFACE "org.mpris.MediaPlayer2.Player"
#define BT_HAL_OBEX_TRANSFER_INTERFACE "org.bluez.obex.Transfer1"
#define BT_HAL_HEADSET_INTERFACE "org.bluez.Headset"


#define BT_HAL_INTERFACES_ADDED "InterfacesAdded"
#define BT_HAL_INTERFACES_REMOVED "InterfacesRemoved"
#define BT_HAL_NAME_OWNER_CHANGED "NameOwnerChanged"
#define BT_HAL_PROPERTIES_CHANGED "PropertiesChanged"


/**
 * This is Bluetooth error code
 */
#define BT_HAL_ERROR_BASE                   ((int)0)         /**< Error code base */

#define BT_HAL_ERROR_NONE                   ((int)0)         /**< No error #0 */
#define BT_HAL_ERROR_CANCEL                 ((int)BT_HAL_ERROR_BASE - 0x01)
                                                                /**< cancelled */
#define BT_HAL_ERROR_INVALID_CALLBACK       ((int)BT_HAL_ERROR_BASE - 0x02)
                                                                /**< Callback error */
#define BT_HAL_ERROR_INVALID_PARAM          ((int)BT_HAL_ERROR_BASE - 0x03)
                                                                /**< invalid paramerror */
#define BT_HAL_ERROR_INVALID_DATA           ((int)BT_HAL_ERROR_BASE - 0x04)
                                                                /**< invalid data error */
#define BT_HAL_ERROR_MEMORY_ALLOCATION      ((int)BT_HAL_ERROR_BASE - 0x05)
                                                                /**< Memory allocation error */
#define BT_HAL_ERROR_OUT_OF_MEMORY          ((int)BT_HAL_ERROR_BASE - 0x06)
                                                                /**< out of memory error */
#define BT_HAL_ERROR_TIMEOUT                ((int)BT_HAL_ERROR_BASE - 0x07)
                                                                /**< timeout error */
#define BT_HAL_ERROR_NO_RESOURCES           ((int)BT_HAL_ERROR_BASE - 0x08)
                                                                /**< No resource error */
#define BT_HAL_ERROR_INTERNAL               ((int)BT_HAL_ERROR_BASE - 0x09)
                                                                /**< internal error */
#define BT_HAL_ERROR_NOT_SUPPORT            ((int)BT_HAL_ERROR_BASE - 0x0a)
                                                                /**< Not supported error */
#define BT_HAL_ERROR_DEVICE_NOT_ENABLED     ((int)BT_HAL_ERROR_BASE - 0x0b)
                                                                /**< Operation is failed because
                                                                of not enabled BT Adapter */
#define BT_HAL_ERROR_DEVICE_ALREADY_ENABLED  ((int)BT_HAL_ERROR_BASE - 0x0c)
                                                                /**< Enabling is failed because of
                                                                already enabled BT Adapter */
#define BT_HAL_ERROR_DEVICE_BUSY            ((int)BT_HAL_ERROR_BASE - 0x0d)
                                                                /**< Operation is failed because of
                                                                other on going operation */
#define BT_HAL_ERROR_ACCESS_DENIED          ((int)BT_HAL_ERROR_BASE - 0x0e)
                                                                /**< access denied error */
#define BT_HAL_ERROR_MAX_CLIENT             ((int)BT_HAL_ERROR_BASE - 0x0f)
                                                                /**< max client error */
#define BT_HAL_ERROR_NOT_FOUND              ((int)BT_HAL_ERROR_BASE - 0x10)
                                                                /**< not found error */
#define BT_HAL_ERROR_SERVICE_SEARCH_ERROR   ((int)BT_HAL_ERROR_BASE - 0x11)
                                                                /**< service search fail */
#define BT_HAL_ERROR_PARING_FAILED          ((int)BT_HAL_ERROR_BASE - 0x12)
                                                                /**< pairing failed error */
#define BT_HAL_ERROR_NOT_PAIRED             ((int)BT_HAL_ERROR_BASE - 0x13)
                                                                /**< Not paired error */
#define BT_HAL_ERROR_SERVICE_NOT_FOUND      ((int)BT_HAL_ERROR_BASE - 0x14)
                                                                /**< no service error */
#define BT_HAL_ERROR_NOT_CONNECTED          ((int)BT_HAL_ERROR_BASE - 0x15)
                                                                /**< no connection error */
#define BT_HAL_ERROR_ALREADY_CONNECT        ((int)BT_HAL_ERROR_BASE - 0x16)
                                                                /**< alread connected error */
#define BT_HAL_ERROR_CONNECTION_BUSY        ((int)BT_HAL_ERROR_BASE - 0x17)
                                                                /**< connection busy error */
#define BT_HAL_ERROR_CONNECTION_ERROR       ((int)BT_HAL_ERROR_BASE - 0x18)
                                                                /**< connection error */
#define BT_HAL_ERROR_MAX_CONNECTION         ((int)BT_HAL_ERROR_BASE - 0x19)
                                                                /**< max connection error*/
#define BT_HAL_ERROR_NOT_IN_OPERATION       ((int)BT_HAL_ERROR_BASE - 0x1a)
                                                                /**< Not in operation */
#define BT_HAL_ERROR_CANCEL_BY_USER         ((int)BT_HAL_ERROR_BASE - 0x1b)
                                                                /**< Cancelled by user */
#define BT_HAL_ERROR_REGISTRATION_FAILED    ((int)BT_HAL_ERROR_BASE - 0x1c)
                                                                /**< Service record registration failed */
#define BT_HAL_ERROR_IN_PROGRESS            ((int)BT_HAL_ERROR_BASE - 0x1d)
                                                                /**< Operation in progress */
#define BT_HAL_ERROR_AUTHENTICATION_FAILED  ((int)BT_HAL_ERROR_BASE - 0x1e)
                                                                /**< authentication failed error when paring*/
#define BT_HAL_ERROR_HOST_DOWN              ((int)BT_HAL_ERROR_BASE - 0x1f)
                                                                /**< Remote host is down */
#define BT_HAL_ERROR_END_OF_DEVICE_LIST     ((int)BT_HAL_ERROR_BASE - 0x20)
                                                                /**< End of device list */

#define BT_HAL_ERROR_AGENT_ALREADY_EXIST      ((int)BT_HAL_ERROR_BASE - 0x21)
                                                                /**< Obex agent already exists */
#define BT_HAL_ERROR_AGENT_DOES_NOT_EXIST    ((int)BT_HAL_ERROR_BASE - 0x22)
                                                                /**< Obex agent does not exist */

#define BT_HAL_ERROR_ALREADY_INITIALIZED    ((int)BT_HAL_ERROR_BASE - 0x23)
                                                                /**< Already initialized */

#define BT_HAL_ERROR_PERMISSION_DEINED    ((int)BT_HAL_ERROR_BASE - 0x24)
                                                                /**< Permission deined */

#define BT_HAL_ERROR_ALREADY_DEACTIVATED    ((int)BT_HAL_ERROR_BASE - 0x25)
                                                                /**< Nap already done */

#define BT_HAL_ERROR_NOT_INITIALIZED    ((int)BT_HAL_ERROR_BASE - 0x26)
                                                                /**< Not initialized */

#define BT_HAL_ERROR_DEVICE_POLICY_RESTRICTION    ((int)BT_HAL_ERROR_BASE - 0x27)
                                                                /**< Device Policy Restricted */
/**
* Service class part of class of device returned from device discovery
*/
typedef enum {
        BT_HAL_DEVICE_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE = 0x002000,
        BT_HAL_DEVICE_SERVICE_CLASS_POSITIONING = 0x010000,                  /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_NETWORKING = 0x020000,                   /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_RENDERING = 0x040000,                    /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_CAPTURING = 0x080000,                    /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_OBJECT_TRANSFER = 0x100000,              /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_AUDIO = 0x200000,                        /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_TELEPHONY = 0x400000,                    /**<  */
        BT_HAL_DEVICE_SERVICE_CLASS_INFORMATION = 0x800000,                  /**<  */
} bt_hal_device_service_class_t;

/**
 * Major device mask (For device discovery)
 */
typedef enum {
        BT_HAL_DEVICE_MAJOR_MASK_MISC = 0x00,
        BT_HAL_DEVICE_MAJOR_MASK_COMPUTER = 0x0001,
        BT_HAL_DEVICE_MAJOR_MASK_PHONE = 0x0002,
        BT_HAL_DEVICE_MAJOR_MASK_LAN_ACCESS_POINT = 0x0004,
        BT_HAL_DEVICE_MAJOR_MASK_AUDIO = 0x0008,
        BT_HAL_DEVICE_MAJOR_MASK_PERIPHERAL = 0x0010,
        BT_HAL_DEVICE_MAJOR_MASK_IMAGING = 0x0020,
        BT_HAL_DEVICE_MAJOR_MASK_WEARABLE = 0x0040,
        BT_HAL_DEVICE_MAJOR_MASK_TOY = 0x0080,
        BT_HAL_DEVICE_MAJOR_MASK_HEALTH = 0x0100,
} bt_hal_device_major_mask_t;

/**
 * Major device class (part of Class of Device)
 */
typedef enum {
        BT_HAL_DEVICE_MAJOR_CLASS_MISC = 0x00,       /**< Miscellaneous major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_COMPUTER = 0x01,           /**< Computer major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_PHONE = 0x02,              /**< Phone major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT = 0x03,   /**< LAN major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_AUDIO = 0x04,              /**< AUDIO major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_PERIPHERAL = 0x05,         /**< Peripheral major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_IMAGING = 0x06,            /**< Imaging major device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_WEARABLE = 0x07,           /**< Wearable device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_TOY = 0x08,                /**< Toy device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_HEALTH = 0x09,             /**< Health device class*/
        BT_HAL_DEVICE_MAJOR_CLASS_UNCLASSIFIED = 0x1F        /**< Unknown major device class*/
} bt_hal_device_major_class_t;


typedef enum {
	BT_HAL_DEVICE_MINOR_CLASS_UNCLASSIFIED = 0x00,       /**< unclassified minor class */

	/* About Computer Major class */
	BT_HAL_DEVICE_MINOR_CLASS_DESKTOP_WORKSTATION = 0x04,        /**< desktop workstation
									  minor class */
	BT_HAL_DEVICE_MINOR_CLASS_SERVER_CLASS_COMPUTER = 0x08,      /**< server minor class */
	BT_HAL_DEVICE_MINOR_CLASS_LAPTOP = 0x0C,                     /**< laptop minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HANDHELD_PC_OR_PDA = 0x10,         /**< PDA minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PALM_SIZED_PC_OR_PDA = 0x14,       /**< PALM minor class */
	BT_HAL_DEVICE_MINOR_CLASS_WEARABLE_COMPUTER = 0x18,  /**< Wearable PC minor class */

	/* About Phone Major class */
	BT_HAL_DEVICE_MINOR_CLASS_CELLULAR = 0x04,                   /**< Cellular minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CORDLESS = 0x08,                   /**< cordless minor class */
	BT_HAL_DEVICE_MINOR_CLASS_SMART_PHONE = 0x0C,        /**< smart phone minor class */
	BT_HAL_DEVICE_MINOR_CLASS_WIRED_MODEM_OR_VOICE_GATEWAY = 0x10,
	/**< voice gateway minor class */
	BT_HAL_DEVICE_MINOR_CLASS_COMMON_ISDN_ACCESS = 0x14,         /**< ISDN minor class */

	/* About LAN/Network Access Point Major class */
	BT_HAL_DEVICE_MINOR_CLASS_FULLY_AVAILABLE = 0x04,            /**< Fully available minor class */
	BT_HAL_DEVICE_MINOR_CLASS_1_TO_17_PERCENT_UTILIZED = 0x20,   /**< 1-17% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_17_TO_33_PERCENT_UTILIZED = 0x40,  /**< 17-33% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_33_TO_50_PERCENT_UTILIZED = 0x60,  /**< 33-50% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_50_to_67_PERCENT_UTILIZED = 0x80,  /**< 50-67% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_67_TO_83_PERCENT_UTILIZED = 0xA0,  /**< 67-83% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_83_TO_99_PERCENT_UTILIZED = 0xC0,  /**< 83-99% utilized minor class */
	BT_HAL_DEVICE_MINOR_CLASS_NO_SERVICE_AVAILABLE = 0xE0,               /**< No service available minor class */

	/* About Audio/Video Major class */
	BT_HAL_DEVICE_MINOR_CLASS_HEADSET_PROFILE = 0x04,            /**< Headset minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HANDSFREE = 0x08,                  /**< Handsfree minor class*/

	BT_HAL_DEVICE_MINOR_CLASS_MICROPHONE = 0x10,         /**< Microphone minor class */
	BT_HAL_DEVICE_MINOR_CLASS_LOUD_SPEAKER = 0x14,       /**< Loud Speaker minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HEADPHONES = 0x18,         /**< Headphones minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PORTABLE_AUDIO = 0x1C,     /**< Portable Audio minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CAR_AUDIO = 0x20,           /**< Car Audio minor class */
	BT_HAL_DEVICE_MINOR_CLASS_SET_TOP_BOX = 0x24,        /**< Set top box minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HIFI_AUDIO_DEVICE = 0x28,  /**< Hifi minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VCR = 0x2C,                /**< VCR minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VIDEO_CAMERA = 0x30,       /**< Video Camera minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CAM_CORDER = 0x34,         /**< CAM Corder minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VIDEO_MONITOR = 0x38,      /**<Video Monitor minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VIDEO_DISPLAY_AND_LOUD_SPEAKER = 0x3C,
	/**< Video Display and Loud
	  Speaker minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VIDEO_CONFERENCING = 0x40, /**< Video Conferencing minor*/

	BT_HAL_DEVICE_MINOR_CLASS_GAMING_OR_TOY = 0x48,      /**< Gaming or toy minor class */

	/* About Peripheral Major class */
	BT_HAL_DEVICE_MINOR_CLASS_KEY_BOARD = 0x40,          /**< Key board minor class */
	BT_HAL_DEVICE_MINOR_CLASS_POINTING_DEVICE = 0x80,    /**< Pointing Device minor class */
	BT_HAL_DEVICE_MINOR_CLASS_COMBO_KEYBOARD_OR_POINTING_DEVICE = 0xC0,
	/**< Combo Keyboard or pointing
	  device minorclass */

	BT_HAL_DEVICE_MINOR_CLASS_JOYSTICK = 0x04,           /**< JoyStick minor class */
	BT_HAL_DEVICE_MINOR_CLASS_GAME_PAD = 0x08,           /**< Game Pad minor class */
	BT_HAL_DEVICE_MINOR_CLASS_REMOTE_CONTROL = 0x0C,     /**< Remote Control minor class */
	BT_HAL_DEVICE_MINOR_CLASS_SENSING_DEVICE = 0x10,     /**< Sensing Device minor class */
	BT_HAL_DEVICE_MINOR_CLASS_DIGITIZER_TABLET = 0x14,   /**< Digitizer minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CARD_READER = 0x18,        /**< Card Reader minor class */
	BT_HAL_DEVICE_MINOR_CLASS_DIGITAL_PEN = 0x1C,        /**< Digital pen minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HANDHELD_SCANNER = 0x20,   /**< Handheld scanner for bar-codes, RFID minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HANDHELD_GESTURAL_INPUT_DEVICE = 0x24,     /**< Handheld gestural input device minor class */

	/* About Imaging Major class */
	BT_HAL_DEVICE_MINOR_CLASS_DISPLAY = 0x10,            /**< Display minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CAMERA = 0x20,             /**< Camera minor class */
	BT_HAL_DEVICE_MINOR_CLASS_SCANNER = 0x40,            /**< Scanner minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PRINTER = 0x80,            /**< Printer minor class */

	/* About Wearable Major class */
	BT_HAL_DEVICE_MINOR_CLASS_WRIST_WATCH = 0x04,        /**< Wrist watch minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PAGER = 0x08,              /**< Pager minor class */
	BT_HAL_DEVICE_MINOR_CLASS_JACKET = 0x0C,             /**< Jacket minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HELMET = 0x10,             /**< Helmet minor class */
	BT_HAL_DEVICE_MINOR_CLASS_GLASSES = 0x14,            /**< Glasses minor class */

	/* About Toy Major class */
	BT_HAL_DEVICE_MINOR_CLASS_ROBOT = 0x04,              /**< Robot minor class */
	BT_HAL_DEVICE_MINOR_CLASS_VEHICLE = 0x08,            /**< Vehicle minor class */
	BT_HAL_DEVICE_MINOR_CLASS_DOLL_OR_ACTION = 0x0C,     /**< Doll or Action minor class */
	BT_HAL_DEVICE_MINOR_CLASS_CONTROLLER = 0x10,         /**< Controller minor class */
	BT_HAL_DEVICE_MINOR_CLASS_GAME = 0x14,               /**< Game minor class */

	/* About Health Major class */
	BT_HAL_DEVICE_MINOR_CLASS_BLOOD_PRESSURE_MONITOR = 0x04,     /**< Blood Pressure minor class */
	BT_HAL_DEVICE_MINOR_CLASS_THERMOMETER = 0x08,                /**< Thermometer minor class */
	BT_HAL_DEVICE_MINOR_CLASS_WEIGHING_SCALE = 0x0C,             /**< Weighing Scale minor class */
	BT_HAL_DEVICE_MINOR_CLASS_GLUCOSE_METER = 0x10,              /**< Glucose minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PULSE_OXIMETER = 0x14,             /**< Pulse Oximeter minor class */
	BT_HAL_DEVICE_MINOR_CLASS_HEART_OR_PULSE_RATE_MONITOR = 0x18,/**< Heart or pulse rate monitor minor class */
	BT_HAL_DEVICE_MINOR_CLASS_MEDICAL_DATA_DISPLAY = 0x1C,       /**< Medical minor class */
	BT_HAL_DEVICE_MINOR_CLASS_STEP_COUNTER = 0x20,               /**< Step Counter minor class */
	BT_HAL_DEVICE_MINOR_CLASS_BODY_COMPOSITION_ANALYZER = 0x24,  /**< Body composition analyzer minor class */
	BT_HAL_DEVICE_MINOR_CLASS_PEAK_FLOW_MONITOR = 0x28,  /**< Peak flow monitor minor class */
	BT_HAL_DEVICE_MINOR_CLASS_MEDICATION_MONITOR = 0x2C, /**< Medication monitor minor class */
	BT_HAL_DEVICE_MINOR_CLASS_KNEE_PROSTHESIS = 0x30,    /**< Knee prosthesis minor class */
	BT_HAL_DEVICE_MINOR_CLASS_ANKLE_PROSTHESIS = 0x34,   /**< Ankle prosthesis minor class */
} bt_hal_device_minor_class_t;

/**
 * This is Bluetooth device address type, fixed to 6 bytes ##:##:##:##:##:##
 */
typedef struct {
        unsigned char addr[BT_HAL_ADDRESS_LENGTH_MAX];
} bt_hal_device_address_t;


/**
 * structure to hold the device information
 */
typedef struct {
        bt_hal_device_major_class_t major_class; /**< major device class */
        bt_hal_device_minor_class_t minor_class; /**< minor device class */
        bt_hal_device_service_class_t service_class;
                                                    /**< service device class */
} bt_hal_device_class_t;

/**
 * Connected state types
 */
typedef enum {
        BT_HAL_CONNECTED_LINK_NONE = 0x00,
        BT_HAL_CONNECTED_LINK_BREDR = 0x01,
        BT_HAL_CONNECTED_LINK_LE = 0x02,
        BT_HAL_CONNECTED_LINK_BREDR_LE = 0x03,
} bt_hal_connected_link_t;

GDBusProxy *_bt_get_adapter_proxy(void);

GDBusProxy *_bt_get_adapter_properties_proxy(void);

GDBusConnection *_bt_get_system_gconn(void);

void _bt_convert_device_path_to_address(const char *device_path,
                char *device_address);

void _bt_convert_addr_string_to_type(unsigned char *addr, const char *address);

void _bt_convert_addr_type_to_string(char *address, const unsigned char *addr);

void _bt_convert_uuid_string_to_type(unsigned char *uuid, const char *device_uuid);

int _bt_connect_profile(char *address, char *uuid, void *cb, gpointer func_data);

int _bt_disconnect_profile(char *address, char *uuid, void *cb, gpointer func_data);

GDBusProxy *_bt_get_manager_proxy(void);

char *_bt_get_adapter_path(void);

char *_bt_get_device_object_path(char *address);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_HAL_DBUS_COMMON_UTILS_H_ */

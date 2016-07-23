/*
 * Copyright (c) 2015 -2016 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * Contact: Anupam Roy <anupam.r@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#ifndef _BT_HAL_MSG_H_
#define _BT_HAL_MSG_H_

#define HAL_MINIMUM_EVENT		0x81
/*TODO: More events to be added in subsequent patches */

/* HAL Global Macros */
#define HAL_POWER_OFF                   0x00
#define HAL_POWER_ON                    0x01

#define HAL_PROP_ADAPTER_NAME                   0x01
#define HAL_PROP_ADAPTER_ADDR                   0x02
#define HAL_PROP_ADAPTER_UUIDS                  0x03
#define HAL_PROP_ADAPTER_CLASS                  0x04
#define HAL_PROP_ADAPTER_TYPE                   0x05
#define HAL_PROP_ADAPTER_SERVICE_REC            0x06
#define HAL_PROP_ADAPTER_SCAN_MODE              0x07
#define HAL_PROP_ADAPTER_BONDED_DEVICES         0x08
#define HAL_PROP_ADAPTER_DISC_TIMEOUT           0x09


#define HAL_PROP_DEVICE_NAME                    0x01
#define HAL_PROP_DEVICE_ADDR                    0x02
#define HAL_PROP_DEVICE_UUIDS                   0x03
#define HAL_PROP_DEVICE_CLASS                   0x04
#define HAL_PROP_DEVICE_TYPE                    0x05
#define HAL_PROP_DEVICE_SERVICE_REC             0x06

/* Tizen specific HAL Adapter and Device property types.
   These properties have to added to HAL bt_property_type_t enums */

struct hal_prop_device_service_rec {
        uint8_t uuid[16];
        uint16_t channel;
        uint8_t name_len;
        uint8_t name[];
} __attribute__((packed));

#define HAL_PROP_DEVICE_FRIENDLY_NAME            0x0a
#define HAL_PROP_DEVICE_RSSI                     0x0b
#define HAL_PROP_DEVICE_VERSION_INFO             0x0c
/*
 * Tizen specific HAL Adapter and Device property types.
 * These properties have to added to HAL bt_property_type_t enums
 */
#define HAL_PROP_DEVICE_PAIRED                  0x0d
#define HAL_PROP_DEVICE_CONNECTED               0x0e
#define HAL_PROP_DEVICE_TRUSTED                 0x0f
#define HAL_PROP_ADAPTER_PAIRABLE               0x10
#define HAL_PROP_ADAPTER_PAIRABLE_TIMEOUT       0x11
#define HAL_PROP_ADAPTER_VERSION		0x12
#define HAL_PROP_ADAPTER_IPSP_INITIALIZED	0x13
#define HAL_PROP_ADAPTER_MODALIAS		0x14

#define HAL_PROP_DEVICE_MANUFACTURER_DATA_LEN   0x15
#define HAL_PROP_DEVICE_MANUFACTURER_DATA       0x16
#define HAL_PROP_DEVICE_BLE_ADV_DATA            0x18
#define HAL_PROP_ADAPTER_LOCAL_LE_FEAT          0x19

struct hal_prop_device_info {
        uint8_t version;
        uint16_t sub_version;
        uint16_t manufacturer;
} __attribute__((packed));

#define HAL_PROP_DEVICE_TIMESTAMP               0xFF

#define HAL_EV_ADAPTER_STATE_CHANGED    0x00
struct hal_ev_adapter_state_changed {
        uint8_t state;
} __attribute__((packed));


struct hal_property {
        uint8_t  type;
        uint16_t len;
        uint8_t  val[0];
} __attribute__((packed));

#define HAL_EV_ADAPTER_PROPS_CHANGED    0x01
struct hal_ev_adapter_props_changed {
        uint8_t              status;
        uint8_t              num_props;
        struct  hal_property props[0];
} __attribute__((packed));


#define HAL_DISCOVERY_STATE_STOPPED     0x00
#define HAL_DISCOVERY_STATE_STARTED     0x01

#define HAL_EV_DISCOVERY_STATE_CHANGED  0x85
struct hal_ev_discovery_state_changed {
        uint8_t state;
} __attribute__((packed));

#define HAL_EV_REMOTE_DEVICE_PROPS      0x83
struct hal_ev_remote_device_props {
        uint8_t             status;
        uint8_t             bdaddr[6];
        uint8_t             num_props;
        struct hal_property props[0];
} __attribute__((packed));

#define HAL_EV_DEVICE_FOUND             0x84
struct hal_ev_device_found {
        uint8_t             num_props;
        struct hal_property props[0];
} __attribute__((packed));


/* Device callbacks */
#define HAL_EV_PIN_REQUEST              0x86
struct hal_ev_pin_request {
        uint8_t  bdaddr[6];
        uint8_t  name[249];
        uint32_t class_of_dev;
} __attribute__((packed));

#define HAL_EV_SSP_REQUEST              0x87
struct hal_ev_ssp_request {
        uint8_t  bdaddr[6];
        uint8_t  name[249];
        uint32_t class_of_dev;
        uint8_t  pairing_variant;
        uint32_t passkey;
} __attribute__((packed));

#define HAL_BOND_STATE_NONE 0
#define HAL_BOND_STATE_BONDING 1
#define HAL_BOND_STATE_BONDED 2

#define HAL_EV_BOND_STATE_CHANGED       0x88
struct hal_ev_bond_state_changed {
        uint8_t status;
        uint8_t bdaddr[6];
        uint8_t state;
} __attribute__((packed));

#define HAL_EV_AUTHORIZE_REQUEST        0x89
struct hal_ev_authorize_request {
	uint8_t  bdaddr[6];
	uint32_t service_id;
} __attribute__((packed));

#define HAL_ACL_STATE_CONNECTED         0x00
#define HAL_ACL_STATE_DISCONNECTED      0x01

#define HAL_EV_ACL_STATE_CHANGED        0x8A
struct hal_ev_acl_state_changed {
        uint8_t status;
        uint8_t bdaddr[6];
        uint8_t state;
} __attribute__((packed));

#define BT_TRANSPORT_UNKNOWN            0x00
#define BT_TRANSPORT_BR_EDR             0x01
#define BT_TRANSPORT_LE                 0x02

/* HID host events */
#define HAL_HIDHOST_STATE_CONNECTED	0x00
#define HAL_HIDHOST_STATE_CONNECTING	0x01
#define HAL_HIDHOST_STATE_DISCONNECTED	0x02
#define HAL_HIDHOST_STATE_DISCONNECTING	0x03
#define HAL_HIDHOST_STATE_NO_HID	0x07
#define HAL_HIDHOST_STATE_FAILED	0x08
#define HAL_HIDHOST_STATE_UNKNOWN	0x09

#define HAL_EV_HIDHOST_CONN_STATE		0x81
struct hal_ev_hidhost_conn_state {
		uint8_t bdaddr[6];
			uint8_t state;
} __attribute__((packed));

#define HAL_EV_HIDHOST_INFO	0x82
struct hal_ev_hidhost_info {
	uint8_t  bdaddr[6];
	uint8_t  attr;
	uint8_t  subclass;
	uint8_t  app_id;
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
	uint8_t  country;
	uint16_t descr_len;
	uint8_t  descr[884];
} __attribute__((packed));

#define HAL_EV_HIDHOST_PROTO_MODE	0x83
struct hal_ev_hidhost_proto_mode {
	uint8_t bdaddr[6];
	uint8_t status;
	uint8_t mode;
} __attribute__((packed));

#define HAL_EV_HIDHOST_IDLE_TIME	0x84
struct hal_ev_hidhost_idle_time {
	uint8_t bdaddr[6];
	uint8_t status;
	uint32_t idle_rate;
} __attribute__((packed));

#define HAL_EV_HIDHOST_GET_REPORT	0x85
struct hal_ev_hidhost_get_report {
	uint8_t  bdaddr[6];
	uint8_t  status;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_EV_HIDHOST_VIRTUAL_UNPLUG	0x86
struct hal_ev_hidhost_virtual_unplug {
	uint8_t  bdaddr[6];
	uint8_t  status;
} __attribute__((packed));

#define HAL_EV_HIDHOST_HANDSHAKE	0x87
struct hal_ev_hidhost_handshake {
	uint8_t  bdaddr[6];
	uint8_t  status;
} __attribute__((packed));

/* Bluetooth Socket HAL events */
struct hal_ev_sock_connect {
	short   size;
	uint8_t bdaddr[6];
	int     channel;
	int     status;
} __attribute__((packed));
#endif //_BT_HAL_MSG_H_


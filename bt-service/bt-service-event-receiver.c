/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <glib.h>
#include <string.h>
#include <dlog.h>
#include <vconf.h>
#include <vconf-internal-bt-keys.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-main.h"
#include "bt-service-adapter.h"
#include "bt-service-adapter-le.h"
#include "bt-service-device.h"
#include "bt-service-avrcp.h"
#include "bt-service-obex-server.h"
#include "bt-service-rfcomm-server.h"
#include "bt-service-audio.h"
#include "bt-service-agent.h"
#include "bt-service-pbap.h"
#include "bt-service-headset-connection.h"
#include "bt-service-avrcp-controller.h"

#include "bt-service-opp-client.h"

#ifdef TIZEN_DPM_ENABLE
#include "bt-service-dpm.h"
#endif

#define DBUS_TIMEOUT 20 * 1000 /* 20 Sec */
static GDBusConnection *manager_conn;
static GDBusConnection *obexd_conn;
static GDBusConnection *opc_obexd_conn;

static GList *p_cache_list = NULL;

static guint event_id;
guint nap_connected_device_count = 0;
static guint hid_connected_device_count = 0;
static GList *p_adv_ind_list;

typedef struct {
	bt_remote_dev_info_t *dev_info;
} bt_cache_info_t;

/**
 * obexd connection type
 */
typedef enum {
	OBEX_OPP = (1 << 1),
	OBEX_FTP = (1 << 2),
	OBEX_BIP = (1 << 3),
	OBEX_PBAP = (1 << 4),
	OBEX_IRMC = (1 << 5),
	OBEX_PCSUITE = (1 << 6),
	OBEX_SYNCEVOLUTION = 	(1 << 7),
	OBEX_MAS = (1 << 8),
} bluetooth_obex_connection_type_t;

void _bt_handle_property_changed_event(GVariant *msg, const char *object_path);
void _bt_opc_property_changed_event(GVariant *msg, char *path);
int _bt_register_service_event(GDBusConnection *g_conn, int event_type);
void _bt_unregister_service_event(GDBusConnection *g_conn, int event_type);
void _bt_opp_client_event_deinit(void);
void _bt_handle_network_client_event(GVariant *msg_iter,
				const char *path);
void __bt_gatt_char_property_changed_event(GVariant *msg_iter,
				const char *path);

static void __bt_free_bt_le_adv_info_t(bt_le_adv_info_t *adv_info)
{
	g_free(adv_info->addr);
	g_free(adv_info->data);
	g_free(adv_info);
}

static bt_le_adv_info_t *__bt_get_adv_ind_info(char *addr)
{
	retv_if(!addr, NULL);
	bt_le_adv_info_t *adv_info = NULL;
	GList *current = g_list_first((GList *)p_adv_ind_list);
	while (current && current->data) {
		adv_info = (bt_le_adv_info_t *)current->data;
		retv_if(adv_info && !g_strcmp0(adv_info->addr, addr), adv_info);
		current = g_list_next(current);
	}
	return NULL;
}

static void __bt_add_adv_ind_info(bt_le_adv_info_t *adv_info)
{
	ret_if(!adv_info);
	if (__bt_get_adv_ind_info(adv_info->addr) != NULL) {
		BT_ERR("adv_info is already added");
		__bt_free_bt_le_adv_info_t(adv_info);
		return;
	}
	p_adv_ind_list = g_list_append(p_adv_ind_list, adv_info);
}

static void __bt_del_adv_ind_info(char *addr)
{
	ret_if(!addr);
	ret_if(!p_adv_ind_list);
	bt_le_adv_info_t *adv_info = NULL;
	GList *current = g_list_first((GList *)p_adv_ind_list);
	while (current && current->data) {
		adv_info = (bt_le_adv_info_t *)current->data;
		if (adv_info && !g_strcmp0(adv_info->addr, addr)) {
			p_adv_ind_list = g_list_remove(p_adv_ind_list, adv_info);
			__bt_free_bt_le_adv_info_t(adv_info);
			return;
		}
		current = g_list_next(current);
	}
}

static void __bt_free_cache_info(bt_cache_info_t *cache_info)
{
	ret_if(cache_info == NULL);
	_bt_free_device_info(cache_info->dev_info);
	g_free(cache_info);
}

static gboolean __bt_parse_device_properties(GVariant *item,
						bt_remote_dev_info_t *dev_info)
{
	GVariantIter iter;
	gchar *key;
	GVariant *val;
	gsize len = 0;
	if (item == NULL)
		return FALSE;

	g_variant_iter_init(&iter, item);
	while (g_variant_iter_loop(&iter, "{sv}", &key, &val)) {
		if (strcasecmp(key, "Address") == 0)  {
			dev_info->address = g_variant_dup_string(val, &len);
		} else if (strcasecmp(key, "Class") == 0) {
			dev_info->class = g_variant_get_uint32(val);
		} else if (strcasecmp(key, "name") == 0) {
			if (dev_info->name == NULL)
				dev_info->name = g_variant_dup_string(val, &len);
		} else if (strcasecmp(key, "Connected") == 0) {
			dev_info->connected = g_variant_get_uint32(val);
		} else if (strcasecmp(key, "paired") == 0) {
			dev_info->paired = g_variant_get_boolean(val);
		} else if (strcasecmp(key, "Trusted") == 0) {
			dev_info->trust = g_variant_get_boolean(val);
		} else if (strcasecmp(key, "RSSI") == 0) {
			dev_info->rssi = g_variant_get_int16(val);
		} else if (strcasecmp(key, "LastAddrType") == 0) {
			dev_info->addr_type = g_variant_get_byte(val);
		} else if (strcasecmp(key, "UUIDs") == 0) {
			char **uuid_value;
			gsize size = 0;
			int i = 0;
			size = g_variant_get_size(val);

			if (size > 0) {
				uuid_value = (char **)g_variant_get_strv(val, &size);
				if (dev_info->uuids == NULL)
					dev_info->uuids = g_malloc0(sizeof(char *) * size);

				for (i = 0; uuid_value[i] != NULL; i++) {
					dev_info->uuid_count++;
					dev_info->uuids[i] = g_strdup(uuid_value[i]);
				}
				g_free(uuid_value);
			}
		} else if (strcasecmp(key, "ManufacturerDataLen") == 0) {
			g_variant_get(val, "(i)", &dev_info->manufacturer_data_len);
			if (dev_info->manufacturer_data_len > BLUETOOTH_MANUFACTURER_DATA_LENGTH_MAX) {
				BT_ERR("manufacturer_data_len is too long(len = %d)", dev_info->manufacturer_data_len);
				dev_info->manufacturer_data_len = BLUETOOTH_MANUFACTURER_DATA_LENGTH_MAX;
			}

			if (dev_info->manufacturer_data_len == 0)
				dev_info->manufacturer_data = g_strdup("");
		} else if (strcasecmp(key, "ManufacturerData") == 0) {
			int len = 0;
			GVariant *manufacturer_var;
			g_variant_get(val, "@ay", &manufacturer_var);
			len = g_variant_get_size(manufacturer_var);
			if (len > 0) {
				char *manufacturer_data = (char *)g_variant_get_data(manufacturer_var);
				dev_info->manufacturer_data = g_malloc0(len);
				if (dev_info->manufacturer_data)
					memcpy(dev_info->manufacturer_data, manufacturer_data,
						len);
			}
			g_variant_unref(manufacturer_var);
		}
	}

	BT_DBG("-");
	return TRUE;
}

static gboolean __bt_parse_interface(GVariant *msg,
					bt_remote_dev_info_t *dev_info)
{
	char *path = NULL;
	GVariant *optional_param;
	GVariantIter iter;
	GVariant *child;
	char *interface_name = NULL;
	GVariant *inner_iter = NULL;
	g_variant_get(msg, "(&o@a{sa{sv}})",
					&path, &optional_param);
	g_variant_iter_init(&iter, optional_param);

	while ((child = g_variant_iter_next_value(&iter))) {
		g_variant_get(child, "{&s@a{sv}}", &interface_name, &inner_iter);
		if (g_strcmp0(interface_name, BT_DEVICE_INTERFACE) == 0) {
			BT_DBG("Found a device: %s", path);
			if (__bt_parse_device_properties(inner_iter,
				dev_info) == FALSE) {
				g_variant_unref(inner_iter);
				g_variant_unref(child);
				g_variant_unref(optional_param);
				BT_ERR("Fail to parse the properies");
				return FALSE;
			} else {
				g_variant_unref(inner_iter);
				g_variant_unref(child);
				g_variant_unref(optional_param);
				return TRUE;
			}
		}
		g_variant_unref(inner_iter);
	g_variant_unref(child);
	}

	g_variant_unref(optional_param);

	return FALSE;
}

static int __bt_get_owner_info(GVariant *msg, char **name,
				char **previous, char **current)
{
	g_variant_get(msg, "(sss)", name, previous, current);
	return BLUETOOTH_ERROR_NONE;
}

static int __bt_get_agent_signal_info(GVariant *msg, char **address,
				char **name, char **uuid)
{
	g_variant_get(msg, "(sss)", address, name, uuid);
	return BLUETOOTH_ERROR_NONE;
}

void __bt_set_device_values(gboolean connected, int state)
{
	int bt_device_state = VCONFKEY_BT_DEVICE_NONE;

	if (vconf_get_int(VCONFKEY_BT_DEVICE, &bt_device_state) != 0) {
		BT_ERR("vconf_get_int failed");
	}

	if (connected == TRUE)
		bt_device_state |= state;
	else if (bt_device_state & state)
		bt_device_state ^= state;

	if (vconf_set_int(VCONFKEY_BT_DEVICE, bt_device_state) != 0) {
		BT_ERR("vconf_set_int failed");
	}
}

gboolean _bt_discovery_finished_cb(gpointer user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	event_id = 0;
	GVariant *param = NULL;
	if (_bt_get_discovering_property(DISCOVERY_ROLE_BREDR) == FALSE) {
		if (_bt_get_cancel_by_user() == TRUE) {
			result = BLUETOOTH_ERROR_CANCEL_BY_USER;
		}

		_bt_set_cancel_by_user(FALSE);
		_bt_set_discovery_status(FALSE);
		param = g_variant_new("(i)", result);
		_bt_send_event(BT_ADAPTER_EVENT,
			BLUETOOTH_EVENT_DISCOVERY_FINISHED,
			param);
	}

	return FALSE;
}

static gboolean __bt_le_discovery_finished_cb(gpointer user_data)
{
	int result = BLUETOOTH_ERROR_NONE;
	event_id = 0;
	GVariant *param = NULL;
	if (_bt_get_discovering_property(DISCOVERY_ROLE_LE) == FALSE) {
		if (_bt_get_cancel_by_user() == TRUE) {
			result = BLUETOOTH_ERROR_CANCEL_BY_USER;
		}

		_bt_set_cancel_by_user(FALSE);
                _bt_disable_all_scanner_status();
		_bt_set_le_scan_status(FALSE);
		param = g_variant_new("(i)", result);
		_bt_send_event(BT_LE_ADAPTER_EVENT,
			BLUETOOTH_EVENT_LE_DISCOVERY_FINISHED,
			param);
	}

	return FALSE;
}

void __bt_update_remote_cache_devinfo(const char *address, gboolean paired_status)
{
	BT_DBG("+");

	ret_if(address == NULL);

	GList * node;
	bt_cache_info_t *cache_info;
	bt_remote_dev_info_t *dev_info;

	node = g_list_first(p_cache_list);

	while (node != NULL) {
		cache_info = (bt_cache_info_t *)node->data;

		if (cache_info == NULL) {
			node = g_list_next(node);
			continue;
		}

		dev_info = cache_info->dev_info;
		if (strcasecmp(dev_info->address,
					address) == 0) {
			BT_DBG("Device Found");
			if (paired_status == TRUE)
				cache_info->dev_info->paired = TRUE;
			else
				cache_info->dev_info->paired = FALSE;
			break;
		}
		node = g_list_next(node);
	}
	BT_DBG("-");
}

static void __bt_device_remote_connected_properties(
				bt_remote_dev_info_t *remote_dev_info,
				char *address, gboolean connected)
{
	int result = BLUETOOTH_ERROR_NONE;
	int i;
	GVariant *param = NULL;
	BT_DBG("+");

	if (remote_dev_info->uuid_count > 0) {
		for (i = 0; i < remote_dev_info->uuid_count; i++) {
			char *uuid = remote_dev_info->uuids[i];
			if (strcasecmp(uuid, HID_UUID) == 0) {
				int event = BLUETOOTH_EVENT_NONE;

				event = (connected == TRUE) ?
					BLUETOOTH_HID_CONNECTED :
					BLUETOOTH_HID_DISCONNECTED;
				param = g_variant_new("(is)", result,
							address);
				_bt_send_event(BT_HID_EVENT, event,
					param);
				break;
			}
		}
	}

	BT_DBG("-");
}

void _bt_handle_adapter_event(GVariant *msg, const char *member)
{
	BT_DBG("+");

	int result = BLUETOOTH_ERROR_NONE;
	GVariant *param = NULL;
	ret_if(member == NULL);

	if (strcasecmp(member, "DeviceCreated") == 0) {
		char *object_path = NULL;
		char *address;
		bt_remote_dev_info_t *remote_dev_info;

		ret_if(_bt_is_device_creating() == FALSE);

		/* Bonding from remote device */
		address = g_malloc0(BT_ADDRESS_STRING_SIZE);

		g_variant_get(msg, "(&o)", &object_path);
		_bt_convert_device_path_to_address((const char*)object_path, address);

		remote_dev_info = _bt_get_remote_device_info(address);
		if (remote_dev_info == NULL) {
			g_free(address);
			return;
		}

		_bt_free_device_info(remote_dev_info);
		g_free(address);
	} else if (strcasecmp(member, "InterfacesRemoved") == 0) {
		char *object_path = NULL;
		char *address;
		bt_cache_info_t *cache_info;
		bt_remote_dev_info_t *dev_info;
		GList * node;

		/* Bonding from remote device */
		address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		g_variant_get(msg, "(&o)", &object_path);

		/* Fix : NULL_RETURNS */
		if (address == NULL)
			return;

		_bt_convert_device_path_to_address((const char *)object_path, address);

		node = g_list_first(p_cache_list);

		while (node != NULL) {
			cache_info = (bt_cache_info_t *)node->data;

			if (cache_info == NULL) {
				node = g_list_next(node);
				continue;
			}

			dev_info = cache_info->dev_info;
			if (strcasecmp(dev_info->address,
						address) == 0) {
				p_cache_list = g_list_remove(p_cache_list,
						cache_info);
				__bt_free_cache_info(cache_info);
				break;
			}
			node = g_list_next(node);
		}
		g_free(address);
	} else if (strcasecmp(member, "AdvertisingEnabled") == 0) {
		BT_DBG("Advertising Enabled");
		int slot_id;
		int event;
		int adv_handle;
		gboolean status = FALSE;

		g_variant_get(msg, "(ib)", &slot_id, &status);

		BT_DBG("Advertising Enabled : slot_id [%d]  status [%d]", slot_id, status);

		/* Send event to application */
		_bt_set_advertising_status(slot_id, status);

		adv_handle = _bt_get_adv_slot_adv_handle(slot_id);

		if (status)
			event = BLUETOOTH_EVENT_ADVERTISING_STARTED;
		else
			event = BLUETOOTH_EVENT_ADVERTISING_STOPPED;
		param = g_variant_new("(ii)", result,
					adv_handle);

#if 0
		const char *sender;
		sender = _bt_get_adv_slot_owner(slot_id);
		_bt_send_event_to_dest(sender, BT_ADAPTER_EVENT,
				event,
				param);
#else
		_bt_send_event(BT_ADAPTER_EVENT, event, param);
#endif

		if (event == BLUETOOTH_EVENT_ADVERTISING_STOPPED)
			_bt_unregister_adv_slot_owner(slot_id);
	} else if (strcasecmp(member, "RssiEnabled") == 0) {
		BT_DBG("RSSI Enabled");
		gboolean status = FALSE;
		char *address = NULL;
		int link_type;
		g_variant_get(msg, "(sib)", &address, &link_type, &status);

		BT_DBG("RSSI Enabled [%s %d]", address, status);
		param = g_variant_new("(isib)", result,
					address, link_type, status);
		_bt_send_event(BT_DEVICE_EVENT,
				BLUETOOTH_EVENT_RSSI_ENABLED,
				param);
		g_free(address);
	} else if (strcasecmp(member, "RssiAlert") == 0) {
		BT_DBG("RSSI Alert");
		int alert_type;
		int rssi_dbm;
		int link_type;
		char *address = NULL;
		g_variant_get(msg, "(siii)", &address, &link_type, &alert_type, &rssi_dbm);

		BT_DBG("RSSI Alert: [Address %s LinkType %d] [Type %d DBM %d]",
				address, alert_type, rssi_dbm);
		param = g_variant_new("(isiii)", result,
					address, link_type, alert_type, rssi_dbm);
		_bt_send_event(BT_DEVICE_EVENT,
				BLUETOOTH_EVENT_RSSI_ALERT,
				param);
		g_free(address);
	} else if (strcasecmp(member, "RawRssi") == 0) {
		BT_DBG("RSSI Raw");
		int rssi_dbm;
		int link_type;
		char *address = NULL;
		g_variant_get(msg, "(sii)", &address, &link_type, &rssi_dbm);

		BT_DBG("Raw RSSI: [Address %s] [Link Type %d][RSSI DBM %d]",
				address, link_type, rssi_dbm);
		param = g_variant_new("(isii)", result,
					address, link_type, rssi_dbm);
		_bt_send_event(BT_DEVICE_EVENT,
				BLUETOOTH_EVENT_RAW_RSSI,
				param);
		g_free(address);
	} else if (strcasecmp(member, BT_HARDWARE_ERROR) == 0) {
		BT_ERR_C("Hardware error received from BLUEZ");
		_bt_recover_adapter();
	} else if (strcasecmp(member, BT_TX_TIMEOUT_ERROR) == 0) {
		BT_ERR_C("Tx timeout error received from BLUEZ");
		_bt_recover_adapter();
	}
	BT_DBG("-");
}

static void __bt_adapter_property_changed_event(GVariant *msg, const char *path)
{
	GDBusProxy *adapter_proxy;
	int mode = 0;
	int result = BLUETOOTH_ERROR_NONE;
	GVariantIter value_iter;
	GVariant *val = NULL;
	GError *err = NULL;
	char *property = NULL;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((g_variant_iter_loop(&value_iter, "{sv}", &property, &val))) {
		BT_INFO("Property %s", property);

		if (strcasecmp(property, "Discovering") == 0) {
			gboolean discovering = FALSE;
			g_variant_get(val, "b", &discovering);
			/* Send event to application */
			BT_DBG("Discovering %d", discovering);
			if (discovering == TRUE) {
				_bt_set_discovery_status(TRUE);
				param = g_variant_new("(i)", result);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_DISCOVERY_STARTED,
					param);
			} else {
				ret_if(event_id > 0);

				adapter_proxy = _bt_get_adapter_proxy();
				ret_if(adapter_proxy == NULL);

				/* Need to stop searching */
				g_dbus_proxy_call_sync(adapter_proxy, "StopDiscovery",
					NULL,
					G_DBUS_CALL_FLAGS_NONE,
					DBUS_TIMEOUT, NULL,
					&err);
				if (err) {
					BT_ERR("Dbus Error : %s", err->message);
					g_clear_error(&err);
				}

				event_id = g_timeout_add(BT_DISCOVERY_FINISHED_DELAY,
				  (GSourceFunc)_bt_discovery_finished_cb, NULL);
			}
		} else if (strcasecmp(property, "LEDiscovering") == 0) {
			gboolean le_discovering = FALSE;

			g_variant_get(val, "b", &le_discovering);
			/* Send event to application */
			if (le_discovering == TRUE) {
				_bt_set_le_scan_status(TRUE);
				param = g_variant_new("(i)", result);
				_bt_send_event(BT_LE_ADAPTER_EVENT,
				BLUETOOTH_EVENT_LE_DISCOVERY_STARTED,
				param);
			} else {
				ret_if(event_id > 0);

				adapter_proxy = _bt_get_adapter_proxy();
				ret_if(adapter_proxy == NULL);

				/* Need to stop searching */
				g_dbus_proxy_call_sync(adapter_proxy, "StopLEDiscovery",
					NULL,
					G_DBUS_CALL_FLAGS_NONE,
					DBUS_TIMEOUT, NULL,
					&err);
				if (err) {
					BT_ERR("Dbus Error %s", err->message);
					g_clear_error(&err);
				}

				event_id = g_timeout_add(BT_DISCOVERY_FINISHED_DELAY,
						(GSourceFunc)__bt_le_discovery_finished_cb, NULL);
				}
		} else if (strcasecmp(property, "Name") == 0) {
			char *name = NULL;
			g_variant_get(val, "s", &name);
			param = g_variant_new("(is)", result, name);
			/* Send event to application */
			_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_LOCAL_NAME_CHANGED,
				param);
			g_free(name);
		} else if (strcasecmp(property, "Alias") == 0) {
			char *alias = NULL;
			g_variant_get(val, "s", &alias);
			param = g_variant_new("(is)", result, alias);
			/* Send event to application */
			_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_LOCAL_NAME_CHANGED,
				param);
			g_free(alias);
		} else if (strcasecmp(property, "Discoverable") == 0) {
			gboolean discoverable = FALSE;

			g_variant_get(val, "b", &discoverable);
			BT_DBG("discoverable %d", discoverable);

			if (discoverable == FALSE) {
				if (_bt_get_discoverable_timeout_property() > 0) {
					int time = 0;
					adapter_proxy = _bt_get_adapter_properties_proxy();
					ret_if(adapter_proxy == NULL);
					g_dbus_proxy_call_sync(adapter_proxy, "Set",
					g_variant_new("(ssv)", BT_ADAPTER_INTERFACE,
						"DiscoverableTimeout",
						g_variant_new("i", time)),
					G_DBUS_CALL_FLAGS_NONE,
					DBUS_TIMEOUT, NULL,
					&err);

					if (err != NULL) {
						BT_ERR("StopLEDiscovery Failed: %s", err->message);
						g_error_free(err);
					}
				}

				mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;

				/* Send event to application */
				BT_INFO("[Connectable]");
				param = g_variant_new("(in)", result, mode);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
					param);
			} else {
				_bt_get_discoverable_mode(&mode);

				/* Event will be sent by "DiscoverableTimeout" signal */
				if (mode != BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE) {
					g_free(property);
					g_variant_unref(val);
					return;
				}

				/* Send event to application */
				BT_INFO("[General Discoverable]");
				param = g_variant_new("(in)", result, mode);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
					param);
			}
		} else if (strcasecmp(property, "DiscoverableTimeout") == 0) {
			_bt_get_discoverable_mode(&mode);

			/* Event was already sent by "Discoverable" signal */
			if (mode == BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE ||
				mode == BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE) {
				g_free(property);
				g_variant_unref(val);
				return;
			}

			/* Send event to application */
			BT_INFO("[Limited Discoverable (Timeout %u secs)]",
			_bt_get_discoverable_timeout_property());
			param = g_variant_new("(in)", result, mode);
			_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED,
				param);
		} else if (strcasecmp(property, "Powered") == 0) {
			/* TODO: Need to check this operation!! */
			gboolean powered = FALSE;
			int bt_state;

			g_variant_get(val, "b", &powered);
			BT_DBG("Powered = %d", powered);
			if (powered == FALSE) {
#ifdef USB_BLUETOOTH
				_bt_handle_adapter_removed();
#else
				if (vconf_get_int(VCONFKEY_BT_STATUS, &bt_state) == 0 &&
				bt_state != VCONFKEY_BT_STATUS_OFF) {
					_bt_disable_adapter();
				}
#endif
				if (vconf_get_int(VCONFKEY_BT_LE_STATUS, &bt_state) == 0 &&
					bt_state != VCONFKEY_BT_LE_STATUS_OFF) {
					_bt_set_le_disabled(BLUETOOTH_ERROR_NONE);
				}
			} else {
#ifdef USB_BLUETOOTH
				_bt_handle_adapter_added();
#endif
			}
		} else if (strcasecmp(property, "Connectable") == 0) {
			gboolean connectable = FALSE;

			g_variant_get(val, "b", &connectable);

			BT_DBG("Connectable property is changed : %d", connectable);
			param = g_variant_new("(b)", connectable);
			_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_CONNECTABLE_CHANGED,
				param);
			if (_bt_adapter_get_status() == BT_DEACTIVATING &&
			_bt_adapter_get_le_status() == BT_LE_ACTIVATED &&
			connectable == 0)
			_bt_set_disabled(BLUETOOTH_ERROR_NONE);
		} else if (strcasecmp(property, "SupportedLEFeatures") == 0) {
			char *name = NULL;
			char *value = NULL;
			GVariantIter *iter = NULL;
			g_variant_get(val, "as", &iter);
			if (iter) {
				while (g_variant_iter_loop(iter, "s", &name)) {
					BT_DBG("name = %s", name);
					g_variant_iter_loop(iter, "s", &value);
					BT_DBG("Value = %s", value);
					if (FALSE == _bt_update_le_feature_support(name, value))
						BT_INFO("Fail to update LE feature info");
				}
				g_variant_iter_free(iter);
			}
		} else if (strcasecmp(property, "IpspInitStateChanged") == 0) {
			gboolean ipsp_initialized = FALSE;

			g_variant_get(val, "b", &ipsp_initialized);
			BT_DBG("IPSP init state changed: %d", ipsp_initialized);
			param = g_variant_new("(b)", ipsp_initialized);

			/* Send event to application */
			_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_IPSP_INIT_STATE_CHANGED,
					param);
		}
	}
}

static void __bt_obex_property_changed_event(GVariant *msg, const char *path)
{
	BT_DBG("+");

	GVariantIter value_iter;
	GVariant *child = NULL, *val = NULL;
	char *property = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((child = g_variant_iter_next_value(&value_iter))) {
		g_variant_get(child, "{sv}", &property, &val);

		ret_if(property == NULL);

		BT_DBG("property :%s", property);

		if (strcasecmp(property, "Status") == 0) {
			char  *status;
			g_variant_get(val, "s", &status);

			if (strcasecmp(status, "active") == 0) {
				_bt_obex_transfer_started(path);
			} else if (strcasecmp(status, "complete") == 0) {
				_bt_obex_transfer_completed(path, TRUE);
				_bt_pbap_obex_transfer_completed(path, TRUE);
			} else if (strcasecmp(status, "error") == 0) {
				_bt_obex_transfer_completed(path, FALSE);
				_bt_pbap_obex_transfer_completed(path, FALSE);
			}
			g_free(status);
		} else if (strcasecmp(property, "Transferred") == 0) {
			static int transferred  = 0;
			g_variant_get(val, "t", &transferred);

			_bt_obex_transfer_progress(path, transferred);
		}
		g_free(property);
		g_variant_unref(val);
		g_variant_unref(child);
	}
	BT_DBG("-");
}

static void __bt_device_property_changed_event(GVariant *msg, const char *path)
{
	BT_DBG("+");

	int event;
	int result = BLUETOOTH_ERROR_NONE;
	GVariantIter value_iter;
	GVariant *val;
	char *property = NULL;
	char *address;
	GVariant *param = NULL;
	bt_remote_dev_info_t *remote_dev_info;
	g_variant_iter_init(&value_iter, msg);
	while ((g_variant_iter_loop(&value_iter, "{sv}", &property, &val))) {
		BT_DBG("Property %s", property);
		if (strcasecmp(property, "Connected") == 0) {
			guint connected = 0;

			g_variant_get(val, "i", &connected);

			event = (connected != BLUETOOTH_CONNECTED_LINK_NONE) ?
				BLUETOOTH_EVENT_DEVICE_CONNECTED :
				BLUETOOTH_EVENT_DEVICE_DISCONNECTED;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("connected: %d", connected);
			BT_DBG("address: %s", address);

			remote_dev_info = _bt_get_remote_device_info(address);

			if (remote_dev_info != NULL) {
				__bt_device_remote_connected_properties(
						remote_dev_info, address,
						connected != BLUETOOTH_CONNECTED_LINK_NONE ?
						TRUE : FALSE);
				_bt_free_device_info(remote_dev_info);
			}
			param = g_variant_new("(is)", result, address);
			/* Send event to application */
			_bt_send_event(BT_DEVICE_EVENT,
					event,
					param);
			g_free(address);
		} else if (strcasecmp(property, "RSSI") == 0) {
			bt_remote_dev_info_t *remote_dev_info;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);
			BT_DBG("address: %s", address);

			remote_dev_info = _bt_get_remote_device_info(address);
			if (remote_dev_info == NULL) {
				g_free(property);
				g_variant_unref(val);
				g_free(address);
				return;
			}
			BT_DBG("Address type  %d", remote_dev_info->addr_type);

			if (remote_dev_info->addr_type == 0) {
				BT_DBG("Name %s", remote_dev_info->name);

#ifdef TIZEN_DPM_ENABLE
				if (_bt_dpm_get_bluetooth_desktop_connectivity_state() ==
							DPM_RESTRICTED) {
					bluetooth_device_class_t device_class;
					_bt_divide_device_class(&device_class, remote_dev_info->class);

					if (device_class.major_class ==
						BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER) {
						_bt_free_device_info(remote_dev_info);
						g_free(property);
						g_variant_unref(val);
						g_free(address);
						return;
					}
				}
#endif

				GVariant *uuids = NULL;
				GVariantBuilder *builder = NULL;
				int i = 0;
				builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
				for (i = 0; i < remote_dev_info->uuid_count; i++) {
					g_variant_builder_add(builder, "s",
						remote_dev_info->uuids[i]);
				}
				uuids = g_variant_new("as", builder);
				g_variant_builder_unref(builder);
				GVariant *manufacturer_data =  NULL;
				manufacturer_data = g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
									remote_dev_info->manufacturer_data,
									remote_dev_info->manufacturer_data_len,
									TRUE,
									NULL, NULL);
				param = g_variant_new("(isunsbub@asn@ay)", result,
							remote_dev_info->address,
							remote_dev_info->class,
							remote_dev_info->rssi,
							remote_dev_info->name,
							remote_dev_info->paired,
							remote_dev_info->connected,
							remote_dev_info->trust,
							uuids,
							remote_dev_info->manufacturer_data_len,
							manufacturer_data);

				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND,
					param);
				g_free(address);
			}
			_bt_free_device_info(remote_dev_info);
		} else if (strcasecmp(property, "GattConnected") == 0) {
			gboolean gatt_connected = FALSE;

			g_variant_get(val, "b", &gatt_connected);

			event = gatt_connected ? BLUETOOTH_EVENT_GATT_CONNECTED :
					BLUETOOTH_EVENT_GATT_DISCONNECTED;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("gatt_connected: %d", gatt_connected);
			BT_DBG("address: %s", address);
			param = g_variant_new("(is)", result, address);
			/* Send event to application */
			_bt_send_event(BT_DEVICE_EVENT,
					event,
					param);
			g_free(address);
		} else if (strcasecmp(property, "Paired") == 0) {
			gboolean paired = FALSE;
			bt_remote_dev_info_t *remote_dev_info;
			g_variant_get(val, "b", &paired);
			_bt_agent_set_canceled(FALSE);
			/* BlueZ sends paired signal for each paired device */
			/* during activation, We should ignore this, otherwise*/
			/* application thinks that a new device got paired */
			if (_bt_adapter_get_status() != BT_ACTIVATED) {
				BT_DBG("BT is not activated, so ignore this");
				g_free(property);
				g_variant_unref(val);
				return;
			}

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			remote_dev_info = _bt_get_remote_device_info(address);
			if (remote_dev_info == NULL) {
				g_free(property);
				g_variant_unref(val);
				g_free(address);
				return;
			}

			if (paired == FALSE) {
				BT_INFO("Unpaired: %s", address);
				__bt_update_remote_cache_devinfo(address, FALSE);
				param = g_variant_new("(is)", result, address);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED,
					param);
			} else {
				BT_INFO("Paired: %s", address);
				__bt_update_remote_cache_devinfo(address, TRUE);

				if (_bt_is_device_creating() == TRUE) {
					BT_DBG("Try to Pair by me");
					_bt_free_device_info(remote_dev_info);
					g_free(address);
					g_free(property);
					g_variant_unref(val);
					return;
				}
				GVariant *uuids = NULL;
				GVariantBuilder *builder = NULL;
				int i = 0;
				builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
				for (i = 0; i < remote_dev_info->uuid_count; i++) {
					g_variant_builder_add(builder, "s",
						remote_dev_info->uuids[i]);
				}
				uuids = g_variant_new("as", builder);
				g_variant_builder_unref(builder);
				GVariant *manufacturer_data =  NULL;
				manufacturer_data = g_variant_new_from_data(G_VARIANT_TYPE_BYTESTRING,
									remote_dev_info->manufacturer_data,
									remote_dev_info->manufacturer_data_len,
									TRUE,
									NULL, NULL);

				param = g_variant_new("(isunsbub@asn@ay)", result,
							address, remote_dev_info->class,
							remote_dev_info->rssi,
							remote_dev_info->name,
							remote_dev_info->paired,
							remote_dev_info->connected,
							remote_dev_info->trust,
							uuids,
							remote_dev_info->manufacturer_data_len,
							manufacturer_data);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_BONDING_FINISHED,
					param);
			}
			_bt_free_device_info(remote_dev_info);
			g_free(address);
		} else if (strcasecmp(property, "LegacyPaired") == 0) {
			gboolean paired = FALSE;
			bt_remote_dev_info_t *remote_dev_info;

			if (_bt_adapter_get_status() != BT_ACTIVATED) {
				BT_DBG("BT is not activated, so ignore this");
				g_free(property);
				g_variant_unref(val);
				return;
			}

			g_variant_get(val, "b", &paired);
			address = g_malloc0(BT_ADDRESS_STRING_SIZE);
			BT_DBG("LegacyPaired: %d", paired);
			_bt_convert_device_path_to_address(path, address);

			remote_dev_info = _bt_get_remote_device_info(address);
			if (remote_dev_info == NULL) {
				g_free(address);
				g_free(property);
				g_variant_unref(val);
				return;
			}

			BT_DBG("LegacyPairing Failed with %s. Show Error Popup",
					remote_dev_info->name);
			_bt_launch_system_popup(BT_AGENT_EVENT_LEGACY_PAIR_FAILED_FROM_REMOTE,
						remote_dev_info->name, NULL, NULL, NULL);

			_bt_free_device_info(remote_dev_info);
			g_free(address);
		} else if (strcasecmp(property, "Trusted") == 0) {
			gboolean trusted = FALSE;

			g_variant_get(val, "b", &trusted);

			event = trusted ? BLUETOOTH_EVENT_DEVICE_AUTHORIZED :
					BLUETOOTH_EVENT_DEVICE_UNAUTHORIZED;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("trusted: %d", trusted);
			BT_DBG("address: %s", address);
			param = g_variant_new("(is)", result, address);
			/* Send event to application */
			_bt_send_event(BT_DEVICE_EVENT,
					event,
					param);
			g_free(address);
		} else if (strcasecmp(property, "IpspConnected") == 0) {
			gboolean connected = FALSE;

			g_variant_get(val, "b", &connected);


			event = connected ? BLUETOOTH_EVENT_IPSP_CONNECTED :
					BLUETOOTH_EVENT_IPSP_DISCONNECTED;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("Ipspconnected: %d", connected);
			BT_DBG("address: %s", address);
			param = g_variant_new("(is)", result, address);

			/* Send event to application */
			_bt_send_event(BT_DEVICE_EVENT,
					event,
					param);
			g_free(address);
		}
	}
	BT_DBG("-");
}

static void __bt_media_control_changed_event(GVariant *msg, const char *path)
{
	int event;
	int result = BLUETOOTH_ERROR_NONE;
	GVariantIter value_iter;
	char *property = NULL;
	char *address;
	GVariant *val = NULL;
	GVariant *child = NULL;
	bt_remote_dev_info_t *remote_dev_info;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((child = g_variant_iter_next_value(&value_iter))) {
		g_variant_get(child, "{sv}", &property, &val);
		BT_INFO("Property %s", property);
		if (strcasecmp(property, "Connected") == 0) {
			gboolean connected = FALSE;

			g_variant_get(val, "b", &connected);

			event = connected ? BLUETOOTH_EVENT_AVRCP_CONNECTED :
					BLUETOOTH_EVENT_AVRCP_DISCONNECTED;

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("connected: %d", connected);
			BT_DBG("address: %s", address);

			remote_dev_info = _bt_get_remote_device_info(address);

			if (remote_dev_info != NULL) {
				__bt_device_remote_connected_properties(
				remote_dev_info, address, connected);
				_bt_free_device_info(remote_dev_info);
			}
			param = g_variant_new("(is)", result, address);
			/* Send event to application */
			_bt_send_event(BT_AVRCP_EVENT,
				event,
				param);
			g_free(address);
		}
		g_free(property);
		g_variant_unref(child);
		g_variant_unref(val);
	}
	BT_DBG("-");
}

void _bt_handle_property_changed_event(GVariant *msg, const char *object_path)
{
	char *interface_name = NULL;
	GVariant *val = NULL;

	g_variant_get(msg, "(&s@a{sv}@as)", &interface_name, &val, NULL);

	if (strcasecmp(interface_name, BT_ADAPTER_INTERFACE) == 0) {
		__bt_adapter_property_changed_event(val,
					object_path);
	} else if (strcasecmp(interface_name, BT_DEVICE_INTERFACE) == 0) {
		__bt_device_property_changed_event(val, object_path);
	} else if (strcasecmp(interface_name, BT_OBEX_TRANSFER_INTERFACE) == 0) {
		BT_DBG("BT_OBEX_TRANSFER_INTERFACE");
		__bt_obex_property_changed_event(val,
					object_path);
	} else if (strcasecmp(interface_name, BT_MEDIA_CONTROL_INTERFACE) == 0) {
		__bt_media_control_changed_event(val,
					object_path);
	} else if (strcasecmp(interface_name, BT_PLAYER_CONTROL_INTERFACE) == 0) {
		_bt_handle_avrcp_control_event(val,
					object_path);
	} else if (strcasecmp(interface_name, BT_NETWORK_CLIENT_INTERFACE) == 0) {
		BT_DBG("BT_NETWORK_CLIENT_INTERFACE");
		_bt_handle_network_client_event(val,
					object_path);
	} else if (strcasecmp(interface_name, BT_GATT_CHAR_INTERFACE) == 0) {
		__bt_gatt_char_property_changed_event(val,
					object_path);
	}
	g_variant_unref(val);
}

void __bt_opc_property_changed_event(GVariant *msg,
						const char *path)
{
	GVariantIter value_iter;
	char *property = NULL;
	GVariant *val = NULL;
	GVariant *child = NULL;

	g_variant_iter_init(&value_iter, msg);
	while ((child = g_variant_iter_next_value(&value_iter))) {
		g_variant_get(child, "{sv}", &property, &val);
		ret_if(property == NULL);

		if (strcasecmp(property, "Status") == 0) {
			char *status = NULL;
			g_variant_get(val, "s", &status);
			BT_DBG("Status is %s", status);

			if (strcasecmp(status, "active") == 0) {
				_bt_obex_client_started(path);
			} else if (strcasecmp(status, "complete") == 0) {
				_bt_obex_client_completed(path, TRUE);
			} else if (strcasecmp(status, "error") == 0) {
				_bt_obex_client_completed(path, FALSE);
			}
			g_free(status);
		} else if (strcasecmp(property, "Transferred") == 0) {
			static int transferred  = 0;
			g_variant_get(val, "t", &transferred);

			_bt_obex_client_progress(path, transferred);
		} else {
			BT_DBG("property : [%s]", property);
		}
		g_free(property);
		g_variant_unref(child);
		g_variant_unref(val);
	}
}

void _bt_opc_property_changed_event(GVariant *msg, char *path)
{
	char *interface_name = NULL;
	GVariant *value = NULL;
	g_variant_get(msg, "(&s@a{sv}@as)", &interface_name, &value, NULL);
	BT_INFO("interface_name = %s", interface_name);
	if (strcasecmp(interface_name, BT_OBEX_TRANSFER_INTERFACE) == 0) {
		__bt_opc_property_changed_event(value,
					path);
	} else {
		BT_DBG("interface_name : [%s]", interface_name);
	}
	g_variant_unref(value);
}


void _bt_handle_input_event(GVariant *msg, const char *path)
{
	int result = BLUETOOTH_ERROR_NONE;
	gboolean property_flag = FALSE;
	GVariantIter value_iter;
	char *property = NULL;
	GVariant *child = NULL, *val = NULL;
	bt_remote_dev_info_t *remote_dev_info;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((child = g_variant_iter_next_value(&value_iter))) {
		g_variant_get(child, "{sv}", &property, &val);

		ret_if(property == NULL);

		if (strcasecmp(property, "Connected") == 0) {
			int event = BLUETOOTH_EVENT_NONE;
			char *address;
			g_variant_get(val, "b", &property_flag);

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			event = (property_flag == TRUE) ?
					BLUETOOTH_HID_CONNECTED :
					BLUETOOTH_HID_DISCONNECTED;
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_HID_EVENT, event,
				param);
			/* Check HID connection type (Keyboard or Mouse) and update the status */
			remote_dev_info = _bt_get_remote_device_info(address);

			if (property_flag == TRUE) {
				hid_connected_device_count++;
				__bt_set_device_values(TRUE,
						VCONFKEY_BT_DEVICE_HID_CONNECTED);
			} else {
				hid_connected_device_count--;
				if (hid_connected_device_count == 0)
					__bt_set_device_values(FALSE,
							VCONFKEY_BT_DEVICE_HID_CONNECTED);
			}

			if (remote_dev_info != NULL) {
				BT_DBG("HID device class [%x]", remote_dev_info->class);
				if (remote_dev_info->class &
					BLUETOOTH_DEVICE_MINOR_CLASS_KEY_BOARD) {
#ifdef ENABLE_TIZEN_2_4
					__bt_set_device_values(property_flag,
						VCONFKEY_BT_DEVICE_HID_KEYBOARD_CONNECTED);
#endif

				}

				if (remote_dev_info->class &
						BLUETOOTH_DEVICE_MINOR_CLASS_POINTING_DEVICE) {
#ifdef ENABLE_TIZEN_2_4
					__bt_set_device_values(property_flag,
							VCONFKEY_BT_DEVICE_HID_MOUSE_CONNECTED);
#endif
				}
				_bt_free_device_info(remote_dev_info);
			}
			g_free(address);
		}
		g_free(property);
		g_variant_unref(val);
		g_variant_unref(child);
	 }
}

void _bt_handle_network_server_event(GVariant *msg, const char *member)
{
	int result = BLUETOOTH_ERROR_NONE;
	char *address = NULL;
	char *device = NULL;
	GVariant *param = NULL;
	ret_if(member == NULL);
	if (strcasecmp(member, "PeerConnected") == 0) {
		g_variant_get(msg, "(ss)", &device, &address);

		__bt_set_device_values(TRUE,
				VCONFKEY_BT_DEVICE_PAN_CONNECTED);
		param = g_variant_new("(iss)", result, device, address);
		_bt_send_event(BT_NETWORK_EVENT, BLUETOOTH_EVENT_NETWORK_SERVER_CONNECTED,
			param);
		g_free(device);
		g_free(address);
		 nap_connected_device_count++;
	} else if (strcasecmp(member, "PeerDisconnected") == 0) {
		g_variant_get(msg, "(ss)", &device, &address);
		nap_connected_device_count--;
		if (nap_connected_device_count == 0)
			__bt_set_device_values(FALSE,
				VCONFKEY_BT_DEVICE_PAN_CONNECTED);
		param = g_variant_new("(iss)", result, device, address);
		_bt_send_event(BT_NETWORK_EVENT, BLUETOOTH_EVENT_NETWORK_SERVER_DISCONNECTED,
			param);
		g_free(device);
		g_free(address);
	}
}

void _bt_handle_network_client_event(GVariant *msg,
				const char *path)
{
	BT_DBG("+");

	int result = BLUETOOTH_ERROR_NONE;
	gboolean property_flag = FALSE;
	char *property = NULL;
	GVariant *val = NULL;
	GVariantIter value_iter;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((g_variant_iter_loop(&value_iter, "{sv}", &property, &val))) {
		if (strcasecmp(property, "Connected") == 0) {
			int event = BLUETOOTH_EVENT_NONE;
			char *address;

			g_variant_get(val, "b", &property_flag);
			address = g_malloc0(BT_ADDRESS_STRING_SIZE);

			_bt_convert_device_path_to_address(path, address);

			BT_DBG("property_flag %d", property_flag);
			if (property_flag == TRUE) {
				event = BLUETOOTH_EVENT_NETWORK_CONNECTED;
				nap_connected_device_count++;
				__bt_set_device_values(TRUE,
					VCONFKEY_BT_DEVICE_PAN_CONNECTED);
			} else {
				event = BLUETOOTH_EVENT_NETWORK_DISCONNECTED;
				nap_connected_device_count--;
				if (nap_connected_device_count == 0)
					__bt_set_device_values(FALSE,
						VCONFKEY_BT_DEVICE_PAN_CONNECTED);
			}
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_NETWORK_EVENT, event,
				param);

			g_free(address);
		}
	}
	BT_DBG("-");
}

void __bt_gatt_char_property_changed_event(GVariant *msg,
				const char *path)
{
	GVariantIter value_iter;
	char *property = NULL;
	char * char_handle = NULL;
	GVariant *val = NULL;
	int result = BLUETOOTH_ERROR_NONE;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	char_handle = g_strdup(path);
	while ((g_variant_iter_loop(&value_iter, "{sv}", &property, &val))) {
		BT_INFO("Property %s", property);

		ret_if(property == NULL);

		if (strcasecmp(property, "Notifying") == 0) {
			gboolean property_flag = FALSE;
			g_variant_get(val, "b", &property_flag);
			if (property_flag == TRUE)
				BT_DBG("notifying is enabled");
			else
				BT_DBG("notifying is disabled");
		} else if (strcasecmp(property, "ChangedValue") == 0) {
			int len = 0;
			GByteArray *gp_byte_array = NULL;
			BT_INFO("Type '%s'\n", g_variant_get_type_string(val));

			if (val) {
				gp_byte_array = g_byte_array_new();
				len = g_variant_get_size(val);
				BT_DBG("Len = %d", len);
				g_byte_array_append(gp_byte_array,
					(const guint8 *) g_variant_get_data(val), len);
				if (gp_byte_array->len != 0) {
					GVariant *byte_array = NULL;
					byte_array = g_variant_new_from_data(
								G_VARIANT_TYPE_BYTESTRING,
								gp_byte_array->data,
								gp_byte_array->len,
								TRUE, NULL, NULL);
					param = g_variant_new("(is@ay)", result, char_handle,
								byte_array);

					/* Send event only registered client */
					_bt_send_char_value_changed_event(param);
				}
				g_byte_array_free(gp_byte_array, TRUE);
			}
		}
	}
	g_free(char_handle);
}

void _bt_handle_gatt_event(GVariant *msg, const char *member, const char *path)
{
	ret_if(path == NULL);

	if (strcasecmp(member, "GattValueChanged") == 0) {

#if 0 // Debug Only
		/*** Debug only ***/
		GVariant *value = NULL;
		int value_len = 0;
		char *buffer = NULL;

		g_variant_get(msg, "(is@ay)", NULL, NULL, &value);
		value_len = g_variant_get_size(value);
		if (value_len > 0) {
			char buf[8 * 5 + 1] = { 0 };
			int i;
			int to;
			buffer = (char *)g_variant_get_data(value);
			to = value_len > (sizeof(buf) / 5) ? sizeof(buf) / 5 : value_len;

			for (i = 0; i < to; i++)
				snprintf(&buf[i * 5], 6, "0x%02x ", buffer[i]);
			buf[i * 5] = '\0';
			BT_DBG("GATT Val[%d] %s", value_len, buf);
		}
		g_variant_unref(value);
		/******/
#endif

		/* Send event only registered client */
		_bt_send_char_value_changed_event(msg);
	}
}


void _bt_handle_device_event(GVariant *msg, const char *member, const char *path)
{
	int event = 0;
	int result = BLUETOOTH_ERROR_NONE;
	char *address;
	char *dev_name;
	const char *property = NULL;
	GVariant *param = NULL;
	ret_if(path == NULL);

	if (strcasecmp(member, "PropertyChanged") == 0) {

		g_variant_get(msg, "(s)", &property);

		ret_if(property == NULL);

		if (strcasecmp(property, "GattConnected") == 0) {
			gboolean connected = FALSE;
			char *address;
			address = g_malloc0(BT_ADDRESS_STRING_SIZE);
			ret_if(address == NULL);

			_bt_convert_device_path_to_address(path, address);
			g_variant_get(msg, "(b)", &connected);

			event = connected ? BLUETOOTH_EVENT_GATT_CONNECTED :
					BLUETOOTH_EVENT_GATT_DISCONNECTED;
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_DEVICE_EVENT,
					event,
					param);
			g_free(address);
		} else if (strcasecmp(property, "Paired") == 0) {
			gboolean paired = FALSE;
			bt_remote_dev_info_t *remote_dev_info;
			g_variant_get(msg, "(b)", &paired);

			ret_if(paired == FALSE);

			/* BlueZ sends paired signal for each paired device */
			/* during activation, We should ignore this, otherwise*/
			/* application thinks that a new device got paired */
			if (_bt_adapter_get_status() != BT_ACTIVATED) {
				BT_DBG("BT is not activated, so ignore this");
				return;
			}

			if (_bt_is_device_creating() == TRUE) {
				BT_DBG("Try to Pair by me");
				return;
			}

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);
			ret_if(address == NULL);

			_bt_convert_device_path_to_address(path, address);

			remote_dev_info = _bt_get_remote_device_info(address);
			if (remote_dev_info == NULL) {
				g_free(address);
				return;
			}
			GVariant *uuids = NULL;
			GVariantBuilder *builder = NULL;
			int i = 0;
			builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
			for (i = 0; i < remote_dev_info->uuid_count; i++) {
				g_variant_builder_add(builder, "s",
					remote_dev_info->uuids[i]);
			}
			uuids = g_variant_new("as", builder);
			g_variant_builder_unref(builder);
			GVariant *manufacturer_data = NULL;
			manufacturer_data = g_variant_new_from_data(
						G_VARIANT_TYPE_BYTESTRING,
						remote_dev_info->manufacturer_data,
						remote_dev_info->manufacturer_data_len,
						TRUE, NULL, NULL);
			param = g_variant_new("(isunsbub@asn@ay)", result,
						address,
						remote_dev_info->class,
						remote_dev_info->rssi,
						remote_dev_info->name,
						remote_dev_info->paired,
						remote_dev_info->connected,
						remote_dev_info->trust,
						uuids,
						remote_dev_info->manufacturer_data_len,
						manufacturer_data);
			_bt_send_event(BT_ADAPTER_EVENT,
				BLUETOOTH_EVENT_BONDING_FINISHED,
				param);
			_bt_free_device_info(remote_dev_info);
			g_free(address);

		} else if (strcasecmp(property, "UUIDs") == 0) {
			/* Once we get the updated uuid information after
			 * reverse service search, update it to application */

			bt_remote_dev_info_t *remote_dev_info;

			ret_if(_bt_is_device_creating() == TRUE);

			address = g_malloc0(BT_ADDRESS_STRING_SIZE);
			ret_if(address == NULL);

			_bt_convert_device_path_to_address(path, address);

			remote_dev_info = _bt_get_remote_device_info(address);
			if (remote_dev_info == NULL) {
				g_free(address);
				return;
			}

			BT_DBG("UUID's count = %d", remote_dev_info->uuid_count);
			if (remote_dev_info->paired && remote_dev_info->uuid_count) {
				GVariant *uuids = NULL;
				GVariantBuilder *builder = NULL;
				int i = 0;
				builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
				for (i = 0; i < remote_dev_info->uuid_count; i++) {
					g_variant_builder_add(builder, "s",
						remote_dev_info->uuids[i]);
				}
				uuids = g_variant_new("as", builder);
				g_variant_builder_unref(builder);
				GVariant *manufacture_data = g_variant_new_from_data((const GVariantType *)"ay",
						remote_dev_info->manufacturer_data, remote_dev_info->manufacturer_data_len,
						TRUE, NULL, NULL);

				param = g_variant_new("(isunsbub@asn@ay)", result,
							address, remote_dev_info->class,
							remote_dev_info->rssi,
							remote_dev_info->name,
							remote_dev_info->paired,
							remote_dev_info->connected,
							remote_dev_info->trust,
							uuids,
							remote_dev_info->manufacturer_data_len,
							manufacture_data);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_SERVICE_SEARCHED,
					param);
			}

			_bt_free_device_info(remote_dev_info);
			g_free(address);
		}
	} else if (strcasecmp(member, "DeviceConnected") == 0) {
		unsigned char addr_type = 0;

		g_variant_get(msg, "(y)", &addr_type);

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		ret_if(address == NULL);

		_bt_convert_device_path_to_address(path, address);
		dev_name = _bt_get_bonded_device_name(address);

		BT_INFO("Address : %s Type : %d", address, addr_type);
		BT_ERR_C("Connected [%s] [%s]", !addr_type ? "BREDR" : "LE",
				!addr_type ? dev_name : address);
		g_free(dev_name);

		_bt_logging_connection(TRUE, addr_type);
#ifdef ENABLE_TIZEN_2_4
		journal_bt_connected();
#endif
		param = g_variant_new("(isy)", result, address, addr_type);
		/*Send event to application*/
		_bt_send_event(BT_DEVICE_EVENT,
					BLUETOOTH_EVENT_DEVICE_CONNECTED,
					param);
		g_free(address);
	} else if (strcasecmp(member, "Disconnected") == 0) {
		unsigned char disc_reason = 0;
		unsigned char addr_type = 0;
		gboolean sending = FALSE;

		g_variant_get(msg, "(yy)", &addr_type, &disc_reason);

		result = disc_reason;

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		ret_if(address == NULL);

		_bt_convert_device_path_to_address(path, address);
		dev_name = _bt_get_bonded_device_name(address);
#ifdef ENABLE_TIZEN_2_4
		journal_bt_disconnected();
#endif

		/* 0x00 BDADDR_BRDER
		      0x01 BDADDR_LE_PUBLIC
		      0x02 BDADDR_LE_RANDOM */
		BT_INFO("Address : %s Type : %d", address, addr_type);
		BT_ERR_C("Disconnected [%s] [%d : %s] [%s]", !addr_type ? "BREDR" : "LE",
				disc_reason, _bt_convert_disc_reason_to_string(disc_reason),
				!addr_type ? dev_name : address);
		g_free(dev_name);

		_bt_headset_set_local_connection(FALSE);
		_bt_logging_connection(FALSE, addr_type);

		/*Check for any OPP transfer on the device and cancel
		 * the transfer
		 */
		_bt_obex_check_pending_transfer(address);
		_bt_opp_client_is_sending(&sending);
		if (sending == TRUE)
			_bt_opp_client_check_pending_transfer(address);
		param = g_variant_new("(isy)", result, address, addr_type);
		_bt_send_event(BT_DEVICE_EVENT,
					BLUETOOTH_EVENT_DEVICE_DISCONNECTED,
					param);
		g_free(address);
	} else if (strcasecmp(member, "ProfileStateChanged") == 0) {
		int state = 0;
		char *profile_uuid = NULL;
		bt_headset_wait_t *wait_list;

		g_variant_get(msg, "(si)", &profile_uuid, &state);

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		ret_if(address == NULL);

		_bt_convert_device_path_to_address(path, address);

		BT_DBG("Address: %s", address);
		BT_DBG("Profile UUID: %s", profile_uuid);
		BT_DBG("State: %d", state);

		if ((strcmp(profile_uuid, A2DP_SINK_UUID) == 0)  &&
			(state == BT_PROFILE_STATE_CONNECTED)) {

			int event = BLUETOOTH_EVENT_AV_CONNECTED;
			char connected_address[BT_ADDRESS_STRING_SIZE + 1];
			bluetooth_device_address_t device_address;
			gboolean connected;
			bt_headset_wait_t *wait_list;

			__bt_set_device_values(TRUE,
				VCONFKEY_BT_DEVICE_A2DP_HEADSET_CONNECTED);

			__bt_connection_manager_set_state(address, event);

			if (_bt_headset_get_local_connection() == FALSE)
				_bt_start_timer_for_connection(address, BT_AUDIO_HSP);
			else {
				/* Connection Started from local device therefore no need to
				 * intiate connection for pending profile */
				_bt_headset_set_local_connection(FALSE);
			}
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_HEADSET_EVENT, event,
				param);
			connected = _bt_is_headset_type_connected(BT_AUDIO_A2DP,
						connected_address);
			if (connected) {
				if (g_strcmp0(connected_address, address) != 0) {
					_bt_convert_addr_string_to_type(
						device_address.addr,
						connected_address);
					_bt_audio_disconnect(0, BT_AUDIO_A2DP,
						&device_address, NULL);
				}
			}

			_bt_add_headset_to_list(BT_AUDIO_A2DP,
						BT_STATE_CONNECTED, address);

			wait_list = _bt_get_audio_wait_data();
			if (wait_list != NULL &&
				(g_strcmp0(wait_list->address, address) == 0))
				_bt_rel_wait_data();

		} else if ((strcmp(profile_uuid, A2DP_SINK_UUID) == 0)  &&
			(state == BT_PROFILE_STATE_DISCONNECTED)) {

			int event = BLUETOOTH_EVENT_AV_DISCONNECTED;

			if (!_bt_is_service_connected(address, BT_AUDIO_A2DP)) {
				g_free(address);
				g_free(profile_uuid);
				return;
			}

			__bt_set_device_values(FALSE,
				VCONFKEY_BT_DEVICE_A2DP_HEADSET_CONNECTED);

			__bt_connection_manager_set_state(address, event);
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_HEADSET_EVENT, event,
				param);
			/* Remove data from the connected list */
			_bt_remove_headset_from_list(BT_AUDIO_A2DP, address);
			wait_list = _bt_get_audio_wait_data();

			if (wait_list == NULL) {
				g_free(address);
				g_free(profile_uuid);
				return;
			}

			if (((wait_list->type == BT_AUDIO_ALL) &&
				(wait_list->ag_flag == TRUE)) ||
				(wait_list->type == BT_AUDIO_A2DP) ||
				(wait_list->disconnection_type == BT_AUDIO_A2DP)) {
				bluetooth_device_address_t device_address;
				_bt_convert_addr_string_to_type(
							device_address.addr,
							wait_list->address);

				_bt_audio_connect(wait_list->req_id,
							wait_list->type,
							&device_address,
							wait_list->out_param1);
			}
		} else if (strcmp(profile_uuid, AVRCP_TARGET_UUID) == 0) {

			if (state == BT_PROFILE_STATE_CONNECTED) {
				int event = BLUETOOTH_EVENT_AVRCP_CONTROL_CONNECTED;
				char connected_address[BT_ADDRESS_STRING_SIZE + 1];
				bluetooth_device_address_t device_address;
				gboolean connected;
				param = g_variant_new("(is)", result, address);
				_bt_send_event(BT_AVRCP_CONTROL_EVENT, event,
					param);
				connected = _bt_is_headset_type_connected(
							BT_AVRCP,
							connected_address);
				if (connected) {
					if (g_strcmp0(connected_address,
								address) != 0) {
						_bt_convert_addr_string_to_type(
							device_address.addr,
							connected_address);
						_bt_audio_disconnect(0,
							BT_AVRCP,
							&device_address, NULL);
					}
				}
				BT_DBG("device Path: %s", path);
				_bt_add_headset_to_list(BT_AVRCP,
						BT_STATE_CONNECTED, address);
			} else if (state == BT_PROFILE_STATE_DISCONNECTED) {
				int event = BLUETOOTH_EVENT_AVRCP_CONTROL_DISCONNECTED;
				param = g_variant_new("(is)", result, address);
				_bt_send_event(BT_AVRCP_CONTROL_EVENT, event,
					param);
				/* Remove data from the connected list */
				_bt_remove_headset_from_list(BT_AVRCP, address);
				}
		} else if (strcasecmp(profile_uuid, A2DP_SOURCE_UUID) == 0) {
			if (state == BT_PROFILE_STATE_CONNECTED) {
				int event = BLUETOOTH_EVENT_AV_SOURCE_CONNECTED;
				BT_INFO("A2DP Source is connected");
				_bt_send_event(BT_A2DP_SOURCE_EVENT, event,
					g_variant_new("(is)", result, address));
			} else if (state == BT_PROFILE_STATE_DISCONNECTED) {
				int event = BLUETOOTH_EVENT_AV_SOURCE_DISCONNECTED;
				BT_INFO("A2DP Source Disconnected");
				_bt_send_event(BT_A2DP_SOURCE_EVENT, event,
						g_variant_new("(is)", result, address));
			}
		} else if ((strcmp(profile_uuid, HID_UUID) == 0) &&
			((state == BT_PROFILE_STATE_CONNECTED) ||
				(state == BT_PROFILE_STATE_DISCONNECTED))) {
			int event;
			if (state == BT_PROFILE_STATE_CONNECTED)
				event = BLUETOOTH_HID_CONNECTED;
			else
				event = BLUETOOTH_HID_DISCONNECTED;
			param = g_variant_new("(is)", result, address);
			_bt_send_event(BT_HID_EVENT, event,
				param);

			if (state == BT_PROFILE_STATE_CONNECTED)
				__bt_set_device_values(TRUE,
					VCONFKEY_BT_DEVICE_HID_CONNECTED);
			else
				__bt_set_device_values(FALSE,
					VCONFKEY_BT_DEVICE_HID_CONNECTED);
		}
		g_free(address);
		g_free(profile_uuid);
	} else if (strcasecmp(member, "AdvReport") == 0) {

		bt_remote_le_dev_info_t *le_dev_info = NULL;
		char *buffer = NULL;
		int buffer_len = 0;
		bt_le_adv_info_t *adv_info = NULL;
		GVariant *value = NULL;
		ret_if(_bt_is_le_scanning() == FALSE);

		le_dev_info = g_malloc0(sizeof(bt_remote_le_dev_info_t));
		if (le_dev_info == NULL)
			return;

		g_variant_get(msg, "(syyii@ay)", &le_dev_info->address,
						&le_dev_info->addr_type,
						&le_dev_info->adv_type,
						&le_dev_info->rssi,
						&le_dev_info->adv_data_len,
						&value);
		buffer_len = g_variant_get_size(value);
		if (buffer_len > 0)
			buffer = (char *)g_variant_get_data(value);

		le_dev_info->adv_data = g_memdup(buffer, buffer_len);
		if (le_dev_info->adv_data == NULL &&
			le_dev_info->adv_type != BT_LE_ADV_SCAN_RSP) {
			_bt_free_le_device_info(le_dev_info);
			g_variant_unref(value);
			return;
		}

		if (_bt_get_le_scan_type() == BT_LE_PASSIVE_SCAN) {
			_bt_send_scan_result_event(le_dev_info, NULL);
			_bt_free_le_device_info(le_dev_info);
			g_variant_unref(value);
			return;
		}

		if (le_dev_info->adv_type != BT_LE_ADV_SCAN_RSP) {       /* ADV_IND */
			adv_info = g_malloc0(sizeof(bt_le_adv_info_t));
			if (adv_info == NULL) {
				_bt_free_le_device_info(le_dev_info);
				g_variant_unref(value);
				return;
			}

			adv_info->addr = g_strdup(le_dev_info->address);
			adv_info->data_len = le_dev_info->adv_data_len;
			adv_info->data = g_malloc0(le_dev_info->adv_data_len);
			if (adv_info->data) {
				memcpy(adv_info->data, le_dev_info->adv_data,
						le_dev_info->adv_data_len);

				__bt_add_adv_ind_info(adv_info);
			}

		} else {     /* SCAN_RSP */
			adv_info = __bt_get_adv_ind_info(le_dev_info->address);
			if (adv_info) {
				_bt_send_scan_result_event(le_dev_info, adv_info);
				__bt_del_adv_ind_info(le_dev_info->address);
			}
		}
		_bt_free_le_device_info(le_dev_info);
		g_variant_unref(value);
	} else if  (strcasecmp(member, "LEDataLengthChanged") == 0) {
		int tx_octets = 0;
		int tx_time = 0;
		int rx_octets = 0;
		int rx_time = 0;

		g_variant_get(msg, "(qqqq)",
				tx_octets, tx_time, rx_octets, rx_time);

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);
		_bt_convert_device_path_to_address(path, address);

		param = g_variant_new("(isqqqq)", result, address, tx_octets, tx_time,
				rx_octets, rx_time);
		/* Send event to application */
		_bt_send_event(BT_DEVICE_EVENT, event, param);
		g_free(address);
	}

}

void __bt_set_audio_values(gboolean connected, char *address)
{
	char *name = NULL;
	int bt_device_state = VCONFKEY_BT_DEVICE_NONE;

	/*  Set the headset name */
	if (connected == TRUE) {
		name = _bt_get_bonded_device_name(address);
	} else {
		name = g_strdup("");
	}

	if (vconf_set_str(VCONFKEY_BT_HEADSET_NAME,
					name) != 0) {
		BT_ERR("vconf_set_str failed");
	}

	g_free(name);

	/*  Set the headset state */
	if (vconf_get_int(VCONFKEY_BT_DEVICE,
				&bt_device_state) != 0) {
		BT_ERR("vconf_get_str failed");
	}

#ifdef TIZEN_SUPPORT_DUAL_HF
	if ((connected == TRUE) &&
		(FALSE == __bt_is_companion_device(address))) {
		bt_device_state |= VCONFKEY_BT_DEVICE_HEADSET_CONNECTED;
	} else if ((bt_device_state & VCONFKEY_BT_DEVICE_HEADSET_CONNECTED) &&
			(FALSE == __bt_is_companion_device(address))) {
		bt_device_state ^= VCONFKEY_BT_DEVICE_HEADSET_CONNECTED;
	}
#else
	if (connected == TRUE) {
		bt_device_state |= VCONFKEY_BT_DEVICE_HEADSET_CONNECTED;
	} else if (bt_device_state & VCONFKEY_BT_DEVICE_HEADSET_CONNECTED) {
		bt_device_state ^= VCONFKEY_BT_DEVICE_HEADSET_CONNECTED;
	}
#endif

	if (vconf_set_int(VCONFKEY_BT_DEVICE,
				bt_device_state) != 0) {
		BT_ERR("vconf_set_int failed");
	}
}

void _bt_handle_headset_event(GVariant *msg, const char *path)
{
	int result = BLUETOOTH_ERROR_NONE;
	gboolean property_flag = FALSE;
	char *property = NULL;
	GVariant *value = NULL;
	GVariant *param = NULL;
	g_variant_get(msg, "(sv)", &property, &value);

	ret_if(property == NULL);

	BT_DBG("Property = %s \n", property);
	/* We allow only 1 headset connection (HSP or HFP)*/
	if (strcasecmp(property, "Connected") == 0) {
		int event = BLUETOOTH_EVENT_NONE;
		bt_headset_wait_t *wait_list;
		char *address;
		g_variant_get(value, "b", &property_flag);

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);

		/* Fix : NULL_RETURNS */
		if (address == NULL)
			return;

		_bt_convert_device_path_to_address(path, address);

		if (property_flag == TRUE) {
			event = BLUETOOTH_EVENT_AG_CONNECTED;
			if (_bt_headset_get_local_connection() == FALSE)
				_bt_start_timer_for_connection(address, BT_AUDIO_A2DP);
			else
				_bt_headset_set_local_connection(FALSE);
		} else {
			int previous_state;

			event = BLUETOOTH_EVENT_AG_DISCONNECTED;

			previous_state = _bt_get_device_state_from_list(BT_AUDIO_HSP, address);
			if (previous_state == BT_STATE_DISCONNECTING)
				_bt_send_hf_local_term_event(address);
		}
		/* Set the State machine here */
		__bt_connection_manager_set_state(address, event);
		__bt_set_audio_values(property_flag, address);
		param = g_variant_new("(is)", result, address);
		_bt_send_event(BT_HEADSET_EVENT, event,
			param);

		if (event == BLUETOOTH_EVENT_AG_DISCONNECTED) {
			/* Remove data from the connected list */
			_bt_remove_headset_from_list(BT_AUDIO_HSP, address);

			wait_list = _bt_get_audio_wait_data();
			if (wait_list == NULL) {
				g_free(address);
				return;
			}

			bluetooth_device_address_t device_address;

			_bt_set_audio_wait_data_flag(TRUE);

			_bt_convert_addr_string_to_type(device_address.addr,
							wait_list->address);
			_bt_audio_connect(wait_list->req_id, wait_list->type,
					&device_address, wait_list->out_param1);
			_bt_rel_wait_data();
		} else if (event == BLUETOOTH_EVENT_AG_CONNECTED) {
			/* Add data to the connected list */
			_bt_add_headset_to_list(BT_AUDIO_HSP,
						BT_STATE_CONNECTED, address);

			wait_list = _bt_get_audio_wait_data();
			if (wait_list != NULL &&
				(g_strcmp0(wait_list->address, address) == 0))
			_bt_rel_wait_data();

			BT_INFO("Check A2DP pending connect");
			_bt_audio_check_pending_connect();
		}
		g_free(address);
	} else if (strcasecmp(property, "State") == 0) {
		char *state = NULL;

		g_variant_get(value, "s", &state);

		/* This code assumes we support only 1 headset connection */
		/* Need to use the headset list, if we support multi-headsets */
		if (strcasecmp(state, "Playing") == 0) {
			BT_DBG("Playing: Sco Connected");
		} else if (strcasecmp(state, "connected") == 0 ||
				strcasecmp(state, "disconnected") == 0) {
			BT_DBG("connected/disconnected: Sco Disconnected");
		} else {
			BT_ERR("Not handled state - %s", state);
			g_free(state);
			return;
		}
		g_free(state);
	} else if (strcasecmp(property, "SpeakerGain") == 0) {
		guint16 spkr_gain;
		char *address;

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);

		_bt_convert_device_path_to_address(path, address);

		g_variant_get(value, "i", &spkr_gain);
		param = g_variant_new("(isq)", result, address, spkr_gain);
		_bt_send_event(BT_HEADSET_EVENT, BLUETOOTH_EVENT_AG_SPEAKER_GAIN,
			param);

		g_free(address);
	} else if (strcasecmp(property, "MicrophoneGain") == 0) {
		guint16 mic_gain;
		char *address;

		address = g_malloc0(BT_ADDRESS_STRING_SIZE);

		_bt_convert_device_path_to_address(path, address);

		g_variant_get(value, "i", &mic_gain);
		param = g_variant_new("(isq)", result, address, mic_gain);
		_bt_send_event(BT_HEADSET_EVENT, BLUETOOTH_EVENT_AG_MIC_GAIN,
			param);
		g_free(address);
	}

	if (property)
		g_free(property);
	g_variant_unref(value);
 }

void _bt_handle_sink_event(GVariant *msg, const char *path)
{
	GVariantIter value_iter;
	char *property = NULL;

	bt_headset_wait_t *wait_list;

	GVariant *child = NULL;
	GVariant *val = NULL;
	GVariant *param = NULL;
	g_variant_iter_init(&value_iter, msg);
	while ((child = g_variant_iter_next_value(&value_iter))) {

		g_variant_get(child, "{sv}", &property, &val);

		ret_if(property == NULL);

		BT_DBG("Property = %s \n", property);


		if (strcasecmp(property, "State") == 0) {
			int result = BLUETOOTH_ERROR_NONE;
			char *value;

			g_variant_get(val, "s", &value);
			BT_DBG("value: %s", value);

			if (g_strcmp0(value, "disconnected") == 0) {
				char *address;

				address = g_malloc0(BT_ADDRESS_STRING_SIZE);

				_bt_convert_device_path_to_address(path, address);

				__bt_set_device_values(FALSE,
					VCONFKEY_BT_DEVICE_A2DP_HEADSET_CONNECTED);
				param = g_variant_new("(is)", result, address);
				_bt_send_event(BT_HEADSET_EVENT,
					BLUETOOTH_EVENT_AV_DISCONNECTED,
					param);

				/* Remove data from the connected list */
				_bt_remove_headset_from_list(BT_AUDIO_A2DP, address);
				wait_list = _bt_get_audio_wait_data();
				if (wait_list == NULL) {
					g_free(value);
					g_free(property);
					g_variant_unref(val);
					g_variant_unref(child);
					g_free(address);
					return;
				}

				if (((wait_list->type == BT_AUDIO_ALL) &&
					(wait_list->ag_flag == TRUE)) ||
					(wait_list->type == BT_AUDIO_A2DP) ||
					(wait_list->disconnection_type == BT_AUDIO_A2DP)) {
					bluetooth_device_address_t device_address;
					_bt_convert_addr_string_to_type(
								device_address.addr,
								wait_list->address);

					_bt_audio_connect(wait_list->req_id,
								wait_list->type,
								&device_address,
								wait_list->out_param1);
				}
				g_free(address);
			} else if (strcasecmp(value, "Connected") == 0) {
				char *address;
				char connected_address[BT_ADDRESS_STRING_SIZE + 1];
				bluetooth_device_address_t device_address;
				gboolean connected;

				address = g_malloc0(BT_ADDRESS_STRING_SIZE);

				_bt_convert_device_path_to_address(path, address);

				__bt_set_device_values(TRUE,
						VCONFKEY_BT_DEVICE_A2DP_HEADSET_CONNECTED);
				param = g_variant_new("(is)", result, address);
				_bt_send_event(BT_HEADSET_EVENT,
					BLUETOOTH_EVENT_AV_CONNECTED,
					param);
				/* Check for existing Media device to disconnect */
				connected = _bt_is_headset_type_connected(BT_AUDIO_A2DP,
									connected_address);
				if (connected) {
					/* Match connected device address */
					if (g_strcmp0(connected_address, address) != 0) {
						/* Convert BD adress from string type */
						_bt_convert_addr_string_to_type(
								device_address.addr,
								connected_address);
						_bt_audio_disconnect(0, BT_AUDIO_A2DP,
								&device_address, NULL);
					}
				}

				/* Add data to the connected list */
				_bt_add_headset_to_list(BT_AUDIO_A2DP,
						BT_STATE_CONNECTED, address);

				g_free(address);
			}
			g_free(value);
		}
		g_free(property);
		g_variant_unref(val);
		g_variant_unref(child);
	}
}

void _bt_handle_agent_event(GVariant *msg, const char *member)
{
	int result = BLUETOOTH_ERROR_NONE;
	char *address = NULL;
	char *name = NULL;
	char *uuid = NULL;
	GVariant *param = NULL;
	ret_if(member == NULL);

	if (strcasecmp(member, "ObexAuthorize") == 0) {
		__bt_get_agent_signal_info(msg, &address, &name, &uuid);
		param = g_variant_new("(iss)", result, address, name);
		_bt_send_event(BT_OPP_SERVER_EVENT,
			BLUETOOTH_EVENT_OBEX_SERVER_CONNECTION_AUTHORIZE,
			param);
		g_free(address);
		g_free(name);
	} else if (strcasecmp(member, "RfcommAuthorize") == 0) {
		bt_rfcomm_server_info_t *server_info;

		__bt_get_agent_signal_info(msg, &address, &name, &uuid);

		server_info = _bt_rfcomm_get_server_info_using_uuid(uuid);
		ret_if(server_info == NULL);
		ret_if(server_info->server_type != BT_CUSTOM_SERVER);
		param = g_variant_new("(isssn)", result, address, uuid, name,
					server_info->control_fd);
		_bt_send_event(BT_RFCOMM_SERVER_EVENT,
			BLUETOOTH_EVENT_RFCOMM_AUTHORIZE,
			param);
		g_free(address);
		g_free(uuid);
		g_free(name);
	}
}

static int __bt_get_object_path(GVariant *msg, char **path)
{
	g_variant_get(msg, "(o*)", path, NULL);
	if (*path == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	return BLUETOOTH_ERROR_NONE;
}

static void __bt_devices_list_free(void)
{
	bt_cache_info_t *cache_info;
	GList *node;

	node = g_list_first(p_cache_list);

	while (node != NULL) {
		cache_info = (bt_cache_info_t *)node->data;
		p_cache_list = g_list_remove(p_cache_list, cache_info);
		__bt_free_cache_info(cache_info);

		node = g_list_next(node);
	}
}

static int __bt_parse_event(GVariant *msg)
{
	GVariantIter iter;
	GVariant *child;
	char *interface_name = NULL;
	GVariant *inner_iter = NULL;

	g_variant_iter_init(&iter, msg);

	while ((child = g_variant_iter_next_value(&iter))) {
		g_variant_get(child, "{&s@a{sv}}", &interface_name, &inner_iter);
		if (g_strcmp0(interface_name,
				BT_DEVICE_INTERFACE) == 0) {
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_DEVICE_EVENT;
		} else if (g_strcmp0(interface_name,
				BT_MEDIATRANSPORT_INTERFACE) == 0) {
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_MEDIA_TRANSFER_EVENT;
		} else if (g_strcmp0(interface_name,
				BT_PLAYER_CONTROL_INTERFACE) == 0) {
			g_variant_unref(inner_iter);
			g_variant_unref(child);
			return BT_AVRCP_CONTROL_EVENT;
		}
		g_variant_unref(inner_iter);
		g_variant_unref(child);
	}

	return 0;
}

static  void __bt_manager_event_filter(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	bt_event_type_t bt_event = 0x00;
	int result = BLUETOOTH_ERROR_NONE;
	GVariant *value;
	char *obj_path = NULL;
	GVariant *param = NULL;
	if (signal_name == NULL)
		return;
	if (strcasecmp(signal_name, "InterfacesAdded") == 0) {
		g_variant_get(parameters, "(&o@a{sa{sv}})", &obj_path, &value);

		if (strcasecmp(obj_path, BT_BLUEZ_HCI_PATH) == 0) {
#ifdef USB_BLUETOOTH
			BT_DBG("Enable Adapter");
			_bt_enable_adapter();
#else
			_bt_handle_adapter_added();
#endif
		} else {
			bt_event = __bt_parse_event(value);
			if (bt_event == BT_DEVICE_EVENT) {
				bt_cache_info_t *cache_info;
				bt_remote_dev_info_t *dev_info;

				ret_if(_bt_is_discovering() == FALSE &&
						_bt_is_le_scanning() == FALSE);

				cache_info = g_malloc0(sizeof(bt_cache_info_t));
				ret_if(cache_info == NULL);

				dev_info = g_malloc0(sizeof(bt_remote_dev_info_t));
				if (dev_info == NULL) {
					__bt_free_cache_info(cache_info);
					return;
				}

				cache_info->dev_info = dev_info;

				if (__bt_parse_interface(parameters, dev_info) == FALSE) {
					BT_ERR("Fail to parse the properies");
					__bt_free_cache_info(cache_info);
					g_variant_unref(value);
					return;
				}

				if (dev_info->addr_type != BDADDR_BREDR) {
					/* Whenever emit the property changed from bluez,
						some property doesn't reach to bt-service.
						So LE device is handled as AdvReport signal */
					__bt_free_cache_info(cache_info);
					g_variant_unref(value);
					return;
				}

				if (dev_info->name == NULL)
					/* If Remote device name is NULL or still RNR is not done
					 * then display address as name.
					 */
					dev_info->name = g_strdup(dev_info->address);

#ifdef TIZEN_DPM_ENABLE
				if (_bt_dpm_get_bluetooth_desktop_connectivity_state() ==
							DPM_RESTRICTED) {
					bluetooth_device_class_t device_class;
					_bt_divide_device_class(&device_class, dev_info->class);
					BT_DBG("[%s]device_class.major_class : %d", dev_info->name, device_class.major_class);

					if (device_class.major_class ==
						BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER) {
						__bt_free_cache_info(cache_info);
						g_variant_unref(value);
						return;
					}
				}
#endif

				GVariant *uuids = NULL;
				GVariantBuilder *builder = NULL;
				int i = 0;
				builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
				for (i = 0; i < dev_info->uuid_count; i++) {
					g_variant_builder_add(builder, "s",
						dev_info->uuids[i]);
				}
				uuids = g_variant_new("as", builder);
				g_variant_builder_unref(builder);
				GVariant *manufacturer_data = NULL;
				manufacturer_data = g_variant_new_from_data(
							G_VARIANT_TYPE_BYTESTRING,
							dev_info->manufacturer_data,
							dev_info->manufacturer_data_len,
							TRUE, NULL, NULL);
				param = g_variant_new("(isunsbub@asn@ay)", result,
							dev_info->address,
							dev_info->class,
							dev_info->rssi,
							dev_info->name,
							dev_info->paired,
							dev_info->connected,
							dev_info->trust,
							uuids,
							dev_info->manufacturer_data_len,
							manufacturer_data);
				_bt_send_event(BT_ADAPTER_EVENT,
					BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND,
					 param);
				p_cache_list = g_list_append(p_cache_list, cache_info);
			} else if (bt_event == BT_AVRCP_CONTROL_EVENT) {
				BT_DBG("Device path : %s ", obj_path);
				_bt_set_control_device_path(obj_path);
			}
		}
		g_variant_unref(value);
	} else if (strcasecmp(signal_name, "InterfacesRemoved") == 0) {
#ifdef USB_BLUETOOTH
		BT_DBG("InterfacesRemoved");
		_bt_handle_adapter_removed();
#endif
		if (g_strcmp0(interface_name, BT_MEDIATRANSPORT_INTERFACE) == 0) {
			bt_event = BT_MEDIA_TRANSFER_EVENT;
		} else if (g_strcmp0(interface_name, BT_DEVICE_INTERFACE) == 0) {
			bt_event = BT_DEVICE_EVENT;
		} else if (g_strcmp0(interface_name, BT_PLAYER_CONTROL_INTERFACE) == 0) {
			bt_event = BT_AVRCP_CONTROL_EVENT;
		}
		if ((bt_event != 0) && (bt_event != BT_MEDIA_TRANSFER_EVENT)) {
			_bt_handle_adapter_event(parameters, signal_name);
			if (bt_event == BT_AVRCP_CONTROL_EVENT) {
				BT_INFO("Object Path %s", obj_path);
				_bt_remove_control_device_path(obj_path);
			}
		}
	} else if (strcasecmp(signal_name, "NameOwnerChanged") == 0) {
		gboolean value;
		char *name = NULL;
		char *previous = NULL;
		char *current = NULL;

		if (__bt_get_owner_info(parameters, &name, &previous, &current)) {
			BT_ERR("Fail to get the owner info");
			return;
		}

		if (*current != '\0') {
			g_free(current);
			if (name)
				g_free(name);
			if (previous)
				g_free(previous);
			return;
		}

		if (strcasecmp(name, BT_BLUEZ_NAME) == 0) {
			BT_DBG("Bluetoothd is terminated");
			if (_bt_adapter_get_status() == BT_ACTIVATED)
				 __bt_disable_cb();

			_bt_handle_adapter_removed();
			__bt_devices_list_free();
		}

		_bt_obex_server_check_allocation(&value);

		if (value == TRUE) {
			/* Check if the obex server was terminated abnormally */
			_bt_obex_server_check_termination(name);
		}

		_bt_rfcomm_server_check_existence(&value);

		if (value == TRUE) {
			/* The obex server was terminated abnormally */
			_bt_rfcomm_server_check_termination(name);
		}

		/* Stop advertising started by terminated process */
		_bt_stop_advertising_by_terminated_process(name);
		/* Stop LE Scan */
		_bt_stop_le_scan(name);
		g_free(name);
		g_free(previous);
		g_free(current);
	} else if (g_strcmp0(interface_name, BT_PROPERTIES_INTERFACE) == 0) {
		const char *path = object_path;

		if (strncmp(path, BT_MEDIA_OBJECT_PATH,
				strlen(BT_MEDIA_OBJECT_PATH)) == 0)
			return;

		_bt_handle_property_changed_event(parameters, object_path);
	} else if (g_strcmp0(interface_name, BT_ADAPTER_INTERFACE) == 0) {
		_bt_handle_adapter_event(parameters, signal_name);
	} else if (g_strcmp0(interface_name, BT_INPUT_INTERFACE) == 0) {
		_bt_handle_input_event(parameters, object_path);
	} else if (g_strcmp0(interface_name, BT_NETWORK_SERVER_INTERFACE) == 0) {
		_bt_handle_network_server_event(parameters, signal_name);
	} else if (g_strcmp0(interface_name, BT_HEADSET_INTERFACE) == 0) {
		_bt_handle_headset_event(parameters, object_path);
	} else if (g_strcmp0(interface_name, BT_SINK_INTERFACE) == 0) {
		_bt_handle_sink_event(parameters, object_path);
	} else if (g_strcmp0(interface_name, BT_AGENT_INTERFACE) == 0) {
		_bt_handle_agent_event(parameters, signal_name);
	} else if (g_strcmp0(interface_name, BT_DEVICE_INTERFACE) == 0) {
		_bt_handle_device_event(parameters, signal_name, object_path);
	} else if (g_strcmp0(interface_name, BT_GATT_CHAR_INTERFACE) == 0) {
		_bt_handle_gatt_event(parameters, signal_name, object_path);
	}

	return;
}

static gboolean __bt_is_obexd_event(GVariant *msg, const char *interface)
{

	if (g_strcmp0(interface, BT_PROPERTIES_INTERFACE) == 0) {
		char *interface_name = NULL;

		g_variant_get(msg, "(&s@a{sv}@as)", &interface_name, NULL, NULL);
		retv_if(interface_name == NULL, FALSE);

		if (strcasecmp(interface_name, BT_OBEX_TRANSFER_INTERFACE) == 0) {
			BT_DBG("BT_OBEX_TRANSFER_INTERFACE");
			return TRUE;
		}
	}

	return FALSE;
}

static  void __bt_obexd_event_filter(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	const char *member = signal_name;
	char *obj_path = NULL;
	ret_if(member == NULL);

	if (strcasecmp(member, "InterfacesAdded") == 0) {
		if (__bt_get_object_path(parameters, &obj_path)) {
			BT_ERR("Fail to get the path");
			return;
		}
		BT_INFO("object_path = [%s]", object_path);

		/*Handle OPP_SERVER_CONNECTED_EVENT here */
		if (strncmp(obj_path, BT_SESSION_BASEPATH_SERVER,
				strlen(BT_SESSION_BASEPATH_SERVER)) != 0) {
			g_free(obj_path);
			return;
		}

		if (g_strrstr(obj_path, "session") && g_strrstr(obj_path, "transfer")) {
			BT_DBG("Obex_Server_Session_Transfer connected");
			_bt_obex_transfer_connected();
		}
		g_free(obj_path);
	} else if (strcasecmp(member, "InterfacesRemoved") == 0) {
		/*Handle OPP_SERVER_DISCONNECTED_EVENT here */
		if (__bt_get_object_path(parameters, &obj_path)) {
			BT_ERR("Fail to get the path");
			return;
		}
		BT_INFO("object_path = [%s]", object_path);

		if (strncmp(obj_path, BT_SESSION_BASEPATH_CLIENT,
				strlen(BT_SESSION_BASEPATH_CLIENT)) == 0) {
			BT_DBG("Call PBAP Disconnected");
			_bt_obex_pbap_client_disconnect(obj_path);
		}

		if (strncmp(obj_path, BT_SESSION_BASEPATH_SERVER,
				strlen(BT_SESSION_BASEPATH_SERVER)) != 0) {
			g_free(obj_path);
			return;
		}

		if (g_strrstr(obj_path, "session") && g_strrstr(obj_path, "transfer")) {
			BT_DBG("Obex_Server_Session_Transfer disconnected");
			_bt_obex_transfer_disconnected();
		}
		g_free(obj_path);
	} else if (__bt_is_obexd_event(parameters, interface_name) == TRUE) {
		const char *path = object_path;

		if (strncmp(path, BT_SESSION_BASEPATH_SERVER,
				strlen(BT_SESSION_BASEPATH_SERVER)) != 0 &&
			strncmp(path, BT_SESSION_BASEPATH_CLIENT,
				strlen(BT_SESSION_BASEPATH_CLIENT)) != 0) {
			BT_DBG("DBUS_HANDLER_RESULT_NOT_YET_HANDLED");
			return;
		}

		_bt_handle_property_changed_event(parameters, path);
	}
	BT_DBG("-");
	return;
}

static gboolean __bt_is_obexd_client_event(GVariant *msg, const char *interface)
{
	BT_DBG("+");

	if (g_strcmp0(interface, BT_PROPERTIES_INTERFACE) == 0) {
		char *interface_name = NULL;

		g_variant_get(msg, "(&s@a{sv}@as)", &interface_name, NULL, NULL);

		retv_if(interface_name == NULL, FALSE);

		if (strcasecmp(interface_name,
					BT_OBEX_TRANSFER_INTERFACE) == 0) {
			BT_DBG("-");
			return TRUE;
		}
	}

	BT_DBG("-");

	return FALSE;
}

static  void __bt_opc_event_filter(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	const char *member = signal_name;
	char *obj_path = NULL;
	if (strcasecmp(member, "InterfacesAdded") == 0) {
		BT_DBG("InterfacesAdded");
	} else if (strcasecmp(member, "InterfacesRemoved") == 0) {

		if (__bt_get_object_path(parameters, &obj_path)) {
			BT_ERR("Fail to get the path");
			return;
		}

		BT_DBG("object_path = %s", obj_path);

		if (strncmp(obj_path, BT_SESSION_BASEPATH_CLIENT,
				strlen(BT_SESSION_BASEPATH_CLIENT)) != 0
				|| strstr(obj_path, "transfer") == NULL) {
			g_free(obj_path);
			return;
		} else if (strncmp(obj_path, BT_SESSION_BASEPATH_CLIENT,
				strlen(BT_SESSION_BASEPATH_CLIENT)) == 0) {
			BT_DBG("Going to call opc disconnected");
			_bt_opc_disconnected(obj_path);
		}

		_bt_sending_files();
		g_free(obj_path);
	} else if (__bt_is_obexd_client_event(parameters, interface_name) == TRUE) {
		char *path = (char *)object_path;
		BT_INFO("object_path %s", path);
		if (strncmp(path, BT_SESSION_BASEPATH_CLIENT,
			strlen(BT_SESSION_BASEPATH_CLIENT)) != 0) {
			BT_DBG("NOT BT_SESSION_BASEPATH_CLIENT");
			return;
		}

		_bt_opc_property_changed_event(parameters, path);
	}

	return;
}

int _bt_opp_client_event_init(void)
{
	GError *error = NULL;

	if (opc_obexd_conn == NULL) {
		opc_obexd_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);

		if (!opc_obexd_conn) {
			if (error) {
				BT_ERR("Unable to connect to dbus: %s", error->message);
				g_clear_error(&error);
			}
		return BLUETOOTH_ERROR_INTERNAL;
		}
	}

	if (_bt_register_service_event(opc_obexd_conn,
			BT_OPP_CLIENT_EVENT) != BLUETOOTH_ERROR_NONE) {
			g_object_unref(opc_obexd_conn);
			opc_obexd_conn = NULL;
			return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

void _bt_opp_client_event_deinit(void)
{
	if (opc_obexd_conn) {
		_bt_unregister_service_event(opc_obexd_conn,
						BT_OPP_CLIENT_EVENT);
		 g_object_unref(opc_obexd_conn);
		 opc_obexd_conn = NULL;
	}
}

int _bt_register_manager_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_interface_added_id = -1;
	static int subs_interface_removed_id = -1;
	static int subs_name_owner_id = -1;
	static int subs_property_id = -1;
	static int subs_adapter_id = -1;
	static int subs_gatt_id = -1;

	if (subscribe) {
		if (subs_interface_added_id == -1) {
			subs_interface_added_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_ADDED, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_interface_removed_id == -1) {
			subs_interface_removed_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_REMOVED, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_name_owner_id == -1) {
			subs_name_owner_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_FREEDESKTOP_INTERFACE,
				BT_NAME_OWNER_CHANGED, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_property_id == -1) {
			subs_property_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_PROPERTIES_INTERFACE,
				BT_PROPERTIES_CHANGED, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_adapter_id == -1) {
			subs_adapter_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_ADAPTER_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_gatt_id == -1) {
			subs_gatt_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_GATT_CHAR_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_interface_added_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_interface_added_id);
			subs_interface_added_id = -1;
		}
		if (subs_interface_removed_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_interface_removed_id);
			subs_interface_removed_id = -1;
		}
		if (subs_name_owner_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_name_owner_id);
			subs_name_owner_id = -1;
		}
		if (subs_property_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_property_id);
			subs_property_id = -1;
		}
		if (subs_adapter_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn, subs_adapter_id);
			subs_adapter_id = -1;
		}
		if (subs_gatt_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn, subs_gatt_id);
			subs_gatt_id = -1;
		}
	}
	return 0;
}

int _bt_register_device_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_device_id = -1;

	if (subscribe) {
		if (subs_device_id == -1) {
			subs_device_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_DEVICE_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_device_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_device_id);
			subs_device_id = -1;
		}
	}
	return 0;
}

int _bt_register_input_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_input_id = -1;

	if (subscribe) {
		if (subs_input_id == -1) {
			subs_input_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_INPUT_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_input_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_input_id);
			subs_input_id = -1;
		}
	}
	return 0;
}

int _bt_register_network_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_serv_id = -1;
	static int subs_client_id = -1;

	if (subscribe) {
		if (subs_serv_id == -1) {
			subs_serv_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_NETWORK_SERVER_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_client_id == -1) {
			subs_client_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_NETWORK_CLIENT_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_serv_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_serv_id);
			subs_serv_id = -1;
		}
		if (subs_client_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_client_id);
			subs_client_id = -1;
		}
	}
	return 0;
}

int _bt_register_audio_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_headset_id = -1;
	static int subs_sink_id = -1;

	if (subscribe) {
		if (subs_headset_id == -1) {
			subs_headset_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_HEADSET_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
		if (subs_sink_id == -1) {
			subs_sink_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_SINK_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_manager_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_headset_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_headset_id);
			subs_headset_id = -1;
		}
		if (subs_sink_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_sink_id);
			subs_sink_id = -1;
		}
	}
	return 0;
}

int _bt_register_opp_server_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_opp_server_interface_added_id = -1;
	static int subs_opp_server_interface_removed_id = -1;
	static int subs_opp_server_property_id = -1;


	if (subscribe) {
		if (subs_opp_server_interface_added_id == -1) {
			subs_opp_server_interface_added_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_ADDED, NULL, NULL, 0,
				__bt_obexd_event_filter,
				NULL, NULL);
		}
		if (subs_opp_server_interface_removed_id == -1) {
			subs_opp_server_interface_removed_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_REMOVED, NULL, NULL, 0,
				__bt_obexd_event_filter,
				NULL, NULL);
		}
		if (subs_opp_server_property_id == -1) {
			subs_opp_server_property_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_PROPERTIES_INTERFACE,
				BT_PROPERTIES_CHANGED, NULL, NULL, 0,
				__bt_obexd_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_opp_server_interface_added_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_server_interface_added_id);
			subs_opp_server_interface_added_id = -1;
		}
		if (subs_opp_server_interface_removed_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_server_interface_removed_id);
			subs_opp_server_interface_removed_id = -1;
		}
		if (subs_opp_server_property_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_server_property_id);
			subs_opp_server_property_id = -1;
		}
	}
	return 0;
}

int _bt_register_opp_client_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_opp_client_interface_added_id = -1;
	static int subs_opp_client_interface_removed_id = -1;
	static int subs_opp_client_property_id = -1;


	if (subscribe) {
		if (subs_opp_client_interface_added_id == -1) {
			subs_opp_client_interface_added_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_ADDED, NULL, NULL, 0,
				__bt_opc_event_filter,
				NULL, NULL);
		}
		if (subs_opp_client_interface_removed_id == -1) {
			subs_opp_client_interface_removed_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_MANAGER_INTERFACE,
				BT_INTERFACES_REMOVED, NULL, NULL, 0,
				__bt_opc_event_filter,
				NULL, NULL);
		}
		if (subs_opp_client_property_id == -1) {
			subs_opp_client_property_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_PROPERTIES_INTERFACE,
				BT_PROPERTIES_CHANGED, NULL, NULL, 0,
				__bt_opc_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_opp_client_interface_added_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_client_interface_added_id);
			subs_opp_client_interface_added_id = -1;
		}
		if (subs_opp_client_interface_removed_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_client_interface_removed_id);
			subs_opp_client_interface_removed_id = -1;
		}
		if (subs_opp_client_property_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_opp_client_property_id);
			subs_opp_client_property_id = -1;
		}
	}
	return 0;
}

int _bt_register_a2dp_subscribe_signal(GDBusConnection *conn,
		int subscribe)
{
	if (conn == NULL)
		return -1;

	static int subs_a2dp_source_id = -1;
	static int subs_a2dp_sink_id = -1;

	if (subscribe) {
		if (subs_a2dp_source_id == -1) {
			subs_a2dp_source_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_A2DP_SOURCE_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_opc_event_filter,
				NULL, NULL);
		}
		if (subs_a2dp_sink_id == -1) {
			subs_a2dp_sink_id = g_dbus_connection_signal_subscribe(conn,
				NULL, BT_SINK_INTERFACE,
				NULL, NULL, NULL, 0,
				__bt_opc_event_filter,
				NULL, NULL);
		}
	} else {
		if (subs_a2dp_source_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_a2dp_source_id);
			subs_a2dp_source_id = -1;
		}
		if (subs_a2dp_sink_id != -1) {
			g_dbus_connection_signal_unsubscribe(conn,
					subs_a2dp_sink_id);
			subs_a2dp_sink_id = -1;
		}
	}
	return 0;
}

int _bt_register_service_event(GDBusConnection *g_conn, int event_type)
{
	BT_DBG("+");

	retv_if(g_conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	switch (event_type) {
	case BT_MANAGER_EVENT:
		_bt_register_manager_subscribe_signal(g_conn, TRUE);
		break;
	case BT_DEVICE_EVENT:
		_bt_register_device_subscribe_signal(g_conn, TRUE);
		break;
	case BT_HID_EVENT:
		_bt_register_input_subscribe_signal(g_conn, TRUE);
		break;
	case BT_NETWORK_EVENT:
		_bt_register_network_subscribe_signal(g_conn, TRUE);
		break;
	case BT_HEADSET_EVENT:
		_bt_register_audio_subscribe_signal(g_conn, TRUE);
		break;

	case BT_OPP_SERVER_EVENT:
		BT_ERR("BT_OPP_SERVER_EVENT: register service event");
		_bt_register_opp_server_subscribe_signal(g_conn, TRUE);
		break;
	case BT_OPP_CLIENT_EVENT:
		BT_ERR("BT_OPP_CLIENT_EVENT: register service event");
		_bt_register_opp_client_subscribe_signal(g_conn, TRUE);
		break;
	case BT_A2DP_SOURCE_EVENT:
		BT_INFO("A2dp Source event");
		_bt_register_a2dp_subscribe_signal(g_conn, TRUE);
		break;
	default:
		BT_ERR("Unknown event");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

void _bt_unregister_service_event(GDBusConnection *g_conn, int event_type)
{
	BT_DBG("+");

	ret_if(g_conn == NULL);

	switch (event_type) {
	case BT_MANAGER_EVENT:
		_bt_register_manager_subscribe_signal(g_conn, FALSE);
		_bt_register_device_subscribe_signal(g_conn, FALSE);
		_bt_register_input_subscribe_signal(g_conn, FALSE);
		_bt_register_network_subscribe_signal(g_conn, FALSE);
		_bt_register_audio_subscribe_signal(g_conn, FALSE);
		break;
	case BT_OPP_SERVER_EVENT:
		_bt_register_opp_server_subscribe_signal(g_conn, FALSE);
		break;
	case BT_OPP_CLIENT_EVENT:
		_bt_register_opp_client_subscribe_signal(g_conn, FALSE);
		break;
	default:
		BT_ERR("Unknown event");
		return;
	}

	BT_DBG("-");
}

static int __bt_init_manager_receiver(void)
{
	BT_DBG("+");

	GError *error = NULL;

	if (manager_conn == NULL) {
		manager_conn =  g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error != NULL) {
			BT_ERR("ERROR: Can't get on system bus [%s]", error->message);
			g_clear_error(&error);
		}
		retv_if(manager_conn == NULL, BLUETOOTH_ERROR_INTERNAL);
	}

	if (_bt_register_service_event(manager_conn,
				BT_MANAGER_EVENT) != BLUETOOTH_ERROR_NONE)
		goto fail;
	if (_bt_register_service_event(manager_conn,
				BT_DEVICE_EVENT) != BLUETOOTH_ERROR_NONE)
		goto fail;

	if (_bt_register_service_event(manager_conn,
				BT_HID_EVENT) != BLUETOOTH_ERROR_NONE)
		goto fail;

	if (_bt_register_service_event(manager_conn,
				BT_HEADSET_EVENT) != BLUETOOTH_ERROR_NONE)
		goto fail;

	if (_bt_register_service_event(manager_conn,
				BT_NETWORK_EVENT) != BLUETOOTH_ERROR_NONE)
		goto fail;
	return BLUETOOTH_ERROR_NONE;
fail:
	if (manager_conn) {
		g_object_unref(manager_conn);
		manager_conn = NULL;
	}

	BT_DBG("-");

	return BLUETOOTH_ERROR_INTERNAL;
}

static int __bt_init_obexd_receiver(void)
{
	BT_DBG("+");
#ifndef TIZEN_TV /* TODO: obexd doesn't work in TV profile. It should be resolved later. */
	GError *error = NULL;

	if (obexd_conn == NULL) {
		obexd_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
		if (error != NULL) {
			BT_ERR("ERROR: Can't get on session bus [%s]", error->message);
			g_clear_error(&error);
		}
		retv_if(obexd_conn == NULL, BLUETOOTH_ERROR_INTERNAL);
	}

	if (_bt_register_service_event(obexd_conn,
				BT_OPP_SERVER_EVENT) != BLUETOOTH_ERROR_NONE) {
		BT_ERR("Error while registering service event");
		g_object_unref(obexd_conn);
		obexd_conn = NULL;
		return BLUETOOTH_ERROR_INTERNAL;
	}
#endif
	BT_DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

/* To receive the event from bluez */
int _bt_init_service_event_receiver(void)
{
	BT_DBG("+");

	int result;

	result = __bt_init_manager_receiver();
	retv_if(result != BLUETOOTH_ERROR_NONE, result);

	result = __bt_init_obexd_receiver();
	if (result != BLUETOOTH_ERROR_NONE)
		BT_ERR("Fail to init obexd receiver");

	BT_DBG("-");

	return BLUETOOTH_ERROR_NONE;
}

void _bt_deinit_service_event_receiver(void)
{
	BT_DBG("+");

	_bt_unregister_service_event(manager_conn, BT_MANAGER_EVENT);

	_bt_unregister_service_event(obexd_conn, BT_OPP_SERVER_EVENT);

	if (manager_conn) {
		g_object_unref(manager_conn);
		manager_conn = NULL;
	}

	if (obexd_conn) {
		g_object_unref(obexd_conn);
		obexd_conn = NULL;
	}

	if (event_id > 0)
		g_source_remove(event_id);

	BT_DBG("-");
}

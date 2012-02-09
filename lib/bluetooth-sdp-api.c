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

/**
*This file implements bluetooth sdp api based on bluez
*@file	bluetooth-sdp-api.c
*/
/*:Associate with "Bluetooth" */

#include "bluetooth-sdp-api.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

/* This array should be optimized with the real bluetooth stack */
static match_entries_t supported_service_info[] = {
	{"00001101-0000-1000-8000-00805f9b34fb", 0x1101, "SPP", 0},
	{"00001103-0000-1000-8000-00805f9b34fb", 0x1103, "DUN", 0},
	{"00001105-0000-1000-8000-00805f9b34fb", 0x1105, "OPP", 0},
	{"00001106-0000-1000-8000-00805f9b34fb", 0x1106, "FTP", 0},
	{"00001112-0000-1000-8000-00805f9b34fb", 0x1112, "HS_AG", 0},
	{"00001108-0000-1000-8000-00805f9b34fb", 0x1108, "HS", 0},
	{"0000110b-0000-1000-8000-00805f9b34fb", 0x110b, "AUDIO_SINK", 0},
	{"0000110c-0000-1000-8000-00805f9b34fb", 0x110c, "AV_REMOTE_CONTROL_TARGET", 0},
	{"0000110e-0000-1000-8000-00805f9b34fb", 0x110e, "AV_REMOTE_CONTROL_UUID", 0},

	{"00001118-0000-1000-8000-00805f9b34fb", 0x1118, "DIRECT_PRINTING_SVCLASS_ID", 0},
	{"0000111a-0000-1000-8000-00805f9b34fb", 0x111a, "OBEX_IMAGING", 0},
	{"0000111b-0000-1000-8000-00805f9b34fb", 0x111b, "IMAGING_RESPONDER_SVCLASS_ID", 0},
	{"0000111f-0000-1000-8000-00805f9b34fb", 0x111f, " HF_AG", 0},
	{"0000111e-0000-1000-8000-00805f9b34fb", 0x111e, "HF", 0},
	{"00001122-0000-1000-8000-00805f9b34fb", 0x1122, "BASIC_PRINTING", 0},
	{"0000112D-0000-1000-8000-00805f9b34fb", 0x112D, "SAP", 0},
	{"00001130-0000-1000-8000-00805f9b34fb", 0x1130, "PBAP", 0},
	{0}
};

static gboolean __bluetooth_internal_get_remote_service_handle(DBusGProxy *device_proxy,
		bt_info_for_searching_support_service_t *bt_info_for_searching_support_service);

static void __bluetooth_internal_request_search_supported_services(const bluetooth_device_address_t *device_address);

static void __bluetooth_internal_get_remote_device_uuids_cb(DBusGProxy *proxy, DBusGProxyCall *call,
							  gpointer user_data)
{
	GError *err = NULL;
	char **array_ptr = NULL;
	char **array_list;
	int ret = 0;

	const gchar *address;
	bt_sdp_info_t device_uuids;

	GHashTable *hash;
	GValue *value = { 0 };
	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;

	DBG("+\n");

	dbus_g_proxy_end_call(proxy, call, &err,
			     	dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);

	device_uuids.service_index = 0;

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n", err->message);
		g_error_free(err);
		ret = -2;
		goto done;
	}

	if (hash != NULL) {
		value = g_hash_table_lookup(hash, "UUIDs");
		array_ptr = value ? g_value_get_boxed(value) : NULL;

		value = g_hash_table_lookup(hash, "Address");
		address = value ? g_value_get_string(value) : NULL;

		if (address) {
			DBG("%s", address);
		}
		_bluetooth_internal_convert_addr_string_to_addr_type(&device_uuids.device_addr,
								    address);
	}

	if (NULL == array_ptr) {
		DBG("Error occured in parsing services\n");
		ret = -2;
		goto done;
	}

	array_list = array_ptr;

	while (device_uuids.service_index < BLUETOOTH_MAX_SERVICES_FOR_DEVICE) {
		if (*array_ptr) {
			g_strlcpy(device_uuids.uuids[device_uuids.service_index], *array_ptr, BLUETOOTH_UUID_STRING_MAX);

			device_uuids.service_list_array[device_uuids.service_index] =
			    strtoll(*array_ptr, NULL, 16);
			DBG("Find UUID [%#x]\n",
			    device_uuids.service_list_array[device_uuids.service_index]);
		} else
			break;

		array_ptr++;
		device_uuids.service_index++;
	}

	g_strfreev(array_list);

 done:
	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info->bt_cb_ptr) {
		bt_event.event = BLUETOOTH_EVENT_SERVICE_SEARCHED;
		if (0 > ret) {
			bt_event.result = BLUETOOTH_ERROR_SERVICE_SEARCH_ERROR;
			device_uuids.service_index = 0x00;
		} else {
			bt_event.result = BLUETOOTH_ERROR_NONE;
		}

		bt_event.param_data = &device_uuids;

		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}

	DBG("-\n");

	return;
}

static void __bluetooth_internal_device_created_for_sdp_cb(DBusGProxy *proxy, DBusGProxyCall *call,
							 gpointer user_data)
{
	GError *err = NULL;
	const char *path = NULL;

	DBG("+\n");

	dbus_g_proxy_end_call(proxy, call, &err, DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);
	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n", err->message);
		g_error_free(err);
	} else {
		DBusGProxy *device_proxy = NULL;
		device_proxy = _bluetooth_internal_find_device_by_path(path);

		if (device_proxy == NULL) {
			_bluetooth_internal_add_device(path);
		}

		if (!dbus_g_proxy_begin_call(device_proxy, "GetProperties",
			(DBusGProxyCallNotify) __bluetooth_internal_get_remote_device_uuids_cb,
			NULL, NULL, G_TYPE_INVALID)) {
		}
	}

	DBG("-\n");

	return;
}

static void __bluetooth_internal_sdp_fail_cb(const bt_sdp_info_t *sdp_data, int error_code)
{

	bluetooth_event_param_t bt_event = { 0, };
	bt_info_t *bt_internal_info = NULL;
	bt_internal_info = _bluetooth_internal_get_information();

	bt_event.event = BLUETOOTH_EVENT_SERVICE_SEARCHED;
	bt_event.result = error_code;
	bt_event.param_data = (void *)sdp_data;
	if (bt_internal_info->bt_cb_ptr) {
		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}
}

static int __bluetooth_internal_parse_sdp_xml(const char *buf_name, int size,
						bt_sdp_info_t *xml_parsed_sdp);

static gboolean __bluetooth_internal_get_service_rec_handle_from_node(xmlNodePtr xml_node,
								unsigned int *record_handle);
static gboolean __bluetooth_internal_get_service_class_id_list_from_node(xmlNodePtr xml_node,
								       bt_sdp_info_t *sdp_info);

static gboolean __bluetooth_internal_get_service_class_id_list_from_node(xmlNodePtr xml_node,
									bt_sdp_info_t *sdp_info)
{
	xmlNodePtr local_node;
	xmlAttr *uuid_attr;
	xmlNodePtr uuid_node;

	if (xml_node == NULL || sdp_info == NULL)
		return FALSE;

	local_node = xml_node->next;

	while (local_node) {
		if (!strcmp((char *)local_node->name, "sequence")) {
			DBG("\t\t %s\n", local_node->name);
			uuid_node = local_node->xmlChildrenNode;
			uuid_node = uuid_node->next;

			if (uuid_node) {
				uuid_attr = uuid_node->properties;
				DBG("\t\t\t%s, %s\n", uuid_node->name,
				    uuid_attr->children->content);

				if (sdp_info->service_index < BLUETOOTH_MAX_SERVICES_FOR_DEVICE) {
					DBG("sdp_info->service_index %d", sdp_info->service_index);
					g_strlcpy(sdp_info->uuids[sdp_info->service_index],
							(const gchar *)uuid_attr->children->content,
							BLUETOOTH_UUID_STRING_MAX);

					sdp_info->service_list_array[sdp_info->service_index] =
							strtol((char *)uuid_attr->children->content,
											 NULL, 0);
					sdp_info->service_index++;
				} else {
					DBG("service index(%d) is more than"
							"BLUETOOTH_MAX_SERVICES_FOR_DEVICE",
									sdp_info->service_index);
				}

			}
		}
		local_node = local_node->next;
	}
	return TRUE;
}

static gboolean __bluetooth_internal_get_service_rec_handle_from_node(xmlNodePtr xml_node,
								unsigned int *record_handle) {
	xmlNodePtr local_node;
	xmlAttr *local_attr;

	if (xml_node == NULL || record_handle == NULL)
		return FALSE;

	local_node = xml_node->next;

	if (local_node) {
		if (!strcmp((char *)local_node->name, "uint32")) {
			local_attr = local_node->properties;
			DBG("\t\t%s, %s\n", local_node->name, local_attr->children->content);
			*record_handle = strtol((char *)local_attr->children->content, NULL, 0);
		}
	}
	return TRUE;
}

static int __bluetooth_internal_parse_xml_parse_record(xmlNodePtr cur,
						     bt_sdp_info_t *xml_parsed_sdp_data)
{
	xmlNodePtr icur;

	icur = cur;
	icur = icur->xmlChildrenNode;
	xmlAttr *attr = NULL;

	unsigned int attribute_value = 0;
	unsigned int record_handle = 0;

	while (icur) {
		attr = icur->properties;

		if (strcmp((char *)icur->name, "attribute")) {
			icur = icur->next;
			continue;
		}

		DBG("%s\n", icur->name);
		while (attr) {
			if (strcmp((char *)attr->name, "id")) {
				attr = attr->next;
				continue;
			}
			DBG("\t%s, %s\n", attr->name, attr->children->content);
			attribute_value = strtol((char *)attr->children->content, NULL, 0);

			switch (attribute_value) {
			case SERVICE_RECORD_HANDLE:
				DBG("\tSERVICE_RECORD_HANDLE:\n");
				__bluetooth_internal_get_service_rec_handle_from_node
				    (icur->xmlChildrenNode, &record_handle);
				DBG("\tRecord Handle 0x%04x \n", record_handle);
				break;

			case SERVICE_CLASS_ID_LIST:
				DBG("\tSERVICE_CLASS_ID_LIST:\n");
				__bluetooth_internal_get_service_class_id_list_from_node
				    (icur->xmlChildrenNode, xml_parsed_sdp_data);
				break;

			case PROTOCOL_DESCRIPOTR_LIST:
				break;

			case BLUETOOTH_PROFILE_DESCRIPTOR_LIST:
				break;

			default:
				break;

			}
			attr = attr->next;
		}
		icur = icur->next;
	}
	return TRUE;
}

static int __bluetooth_internal_parse_sdp_xml(const char *buf_name, int size,
					    bt_sdp_info_t *xml_parsed_sdp)
{
	xmlDocPtr doc;
	xmlNodePtr first;
	xmlNodePtr base;
	xmlInitParser();

	char *check = NULL;

	DBG("+\n");

	/*Below check is done for proper parsing of BPP service UUID, in case of BPP '&' gets
	appended to text value parameter of service list, when '&' containing data  is passed
	to function "xmlParseMemory()" parse error occurs. so '&' is replaced with blank space ' '*/
	if (buf_name != NULL) {
		check = strchr(buf_name, '&');
		if (check != NULL) {
			*check = ' ';
		}
	}

	if (size != 0) {
		doc = xmlParseMemory(buf_name, size);
	} else
		return -1;

	if (doc == NULL) {
		DBG("Document not parsed successfully.\n");
		return -1;
	}

	DBG("Document parsed successfully.\n");

	first = xmlDocGetRootElement(doc);

	if (first == NULL) {
		DBG("Root element = NULL \n");
		xmlFreeDoc(doc);
		return -1;
	}

	base = first;
	if (base == NULL) {
		DBG("empty document\n");
		xmlFreeDoc(doc);

		xmlCleanupParser();
		return -1;
	} else {
		DBG("Root - %s\n", first->name);
	}
	while (base != NULL) {
		DBG(" Main While %s\n", base->name);

		__bluetooth_internal_parse_xml_parse_record(base, xml_parsed_sdp);
		base = base->next;

	}

	xmlFreeDoc(doc);

	xmlCleanupParser();
	DBG("-\n");

	return 0;
}

static void __bluetooth_internal_discover_services_cb(DBusGProxy *proxy, DBusGProxyCall *call,
						    gpointer user_data)
{
	GError *err = NULL;
	GHashTable *hash;
	GHashTable *property_hash;
	GValue *value;
	const char *dev_path = NULL;
	static bt_sdp_info_t sdp_data;
	bt_info_t *bt_internal_info = NULL;
	bluetooth_event_param_t bt_event = { 0, };

	bt_info_for_searching_support_service_t *bt_info_for_searching_support_service =
	    (bt_info_for_searching_support_service_t *) user_data;

	dbus_g_proxy_end_call(proxy, call, &err,
			      dbus_g_type_get_map("GHashTable", G_TYPE_UINT, G_TYPE_STRING), &hash,
			      G_TYPE_INVALID);

	bt_internal_info = _bluetooth_internal_get_information();

	if (err != NULL) {
		DBG("Error occured in Proxy call [%s]\n", err->message);
		sdp_data.service_index = 0;

		if (!strcmp("Operation canceled", err->message)) {
			__bluetooth_internal_sdp_fail_cb(&sdp_data,
						       BLUETOOTH_ERROR_CANCEL_BY_USER);
		} else if (!strcmp("In Progress", err->message)) {
			__bluetooth_internal_sdp_fail_cb(&sdp_data,
						       BLUETOOTH_ERROR_IN_PROGRESS);
		} else if (!strcmp("Host is down", err->message)) {
			__bluetooth_internal_sdp_fail_cb(&sdp_data,
						       BLUETOOTH_ERROR_HOST_DOWN);
		} else {
			__bluetooth_internal_sdp_fail_cb(&sdp_data,
						       BLUETOOTH_ERROR_CONNECTION_ERROR);
		}

		bt_internal_info->is_service_req = FALSE;

		g_error_free(err);
		return;
	}

	if (bt_internal_info->is_service_req == FALSE) {
		/* This flag is unset in __bluetooth_internal_device_property_changed function.
		    If the UUIDs was updated, __bluetooth_internal_device_property_changed func
		    was called first. So we don't need to send the callback event.
		*/
		DBG("Searched event is already sent");
		return;
	}

	bt_internal_info->is_service_req = FALSE;

	/* If there is no changes in device's UUIDs, device_property_changed func is not called.
	    In this case, we use the UUIDs value in device's property. */

	dev_path = dbus_g_proxy_get_path(proxy);

	memcpy(&sdp_data.device_addr,
		       &bt_info_for_searching_support_service->remote_device_addr,
		       sizeof(bluetooth_device_address_t));

	dbus_g_proxy_call(proxy, "GetProperties", NULL,
			G_TYPE_INVALID,
			dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
			&property_hash, G_TYPE_INVALID);

	if (property_hash != NULL) {
		value = g_hash_table_lookup(property_hash, "UUIDs");
		_bluetooth_change_uuids_to_sdp_info(value, &sdp_data);
	}

	if (bt_internal_info->bt_cb_ptr) {
		bt_event.event = BLUETOOTH_EVENT_SERVICE_SEARCHED;
		DBG("service_index %d\n", sdp_data.service_index);
		if (sdp_data.service_index < 0) {
			bt_event.result = BLUETOOTH_ERROR_SERVICE_SEARCH_ERROR;
			sdp_data.service_index = 0;
		} else if (sdp_data.service_index == 0) {
				/*This is for some carkit, printer.*/
			__bluetooth_internal_request_search_supported_services(
				&bt_info_for_searching_support_service->remote_device_addr);
			return;
		} else {
			bt_event.result = BLUETOOTH_ERROR_NONE;
			bt_event.param_data = &sdp_data;
		}

		bt_internal_info->bt_cb_ptr(bt_event.event, &bt_event, bt_internal_info->user_data);
	}

	DBG("-\n");

	return;
}

BT_EXPORT_API int bluetooth_search_service(const bluetooth_device_address_t *device_address)
{
	bt_info_t *bt_internal_info = NULL;
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };

	GError *error = NULL;
	const char *path = NULL;
	DBusGProxy *device_proxy = NULL;
	bt_info_for_searching_support_service_t *bt_info_for_searching_support_service = NULL;

	DBG("+");
	if (NULL == device_address) {
		DBG("Device address is NULL\n");
		return BLUETOOTH_ERROR_SERVICE_SEARCH_ERROR;
	}
	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info == NULL)
		return BLUETOOTH_ERROR_NO_RESOURCES;

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	bt_info_for_searching_support_service =
	    &bt_internal_info->info_for_searching_support_service;

	_bluetooth_internal_addr_type_to_addr_string(address, device_address);
	DBG("bluetooth address [%s]\n", address);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", &error,
			  G_TYPE_STRING, address, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);

	if (error != NULL && !strcmp(error->message, "Device does not exist")) {
		DBG("FindDevice Call Error %s[%s]", error->message, address);
		g_error_free(error);

		if (!dbus_g_proxy_begin_call_with_timeout(bt_internal_info->adapter_proxy,
			"CreateDevice",
		     	(DBusGProxyCallNotify) __bluetooth_internal_device_created_for_sdp_cb, NULL,
		    	 NULL, 5000, G_TYPE_STRING, address, G_TYPE_INVALID)) {
			DBG("Could not call CreateDevice dbus proxy\n");
			return BLUETOOTH_ERROR_INTERNAL;
		}

	} else {
		if (path == NULL) {
			DBG("No device created\n");

			return BLUETOOTH_ERROR_NOT_PAIRED;
		}

		device_proxy = _bluetooth_internal_find_device_by_path(path);

		if (device_proxy == NULL) {
			DBG("We don't have device proxy in our internal device proxy list\n");
			_bluetooth_internal_add_device(path);
		}

		bt_info_for_searching_support_service =
		    &bt_internal_info->info_for_searching_support_service;

		bt_info_for_searching_support_service->search_match_ptr = NULL;
		memcpy(&bt_info_for_searching_support_service->remote_device_addr, device_address,
		       sizeof(bluetooth_device_address_t));

		_bluetooth_internal_print_bluetooth_device_address_t
		    (&bt_info_for_searching_support_service->remote_device_addr);

		if (!dbus_g_proxy_begin_call_with_timeout(device_proxy, "DiscoverServices",
				(DBusGProxyCallNotify) __bluetooth_internal_discover_services_cb,
				(void *)bt_info_for_searching_support_service,
				NULL, 40000, G_TYPE_STRING, "", G_TYPE_INVALID)) {
			DBG("Could not call dbus proxy\n");
			return BLUETOOTH_ERROR_NONE;
		}

		bt_internal_info->is_service_req = TRUE;

	}

	return BLUETOOTH_ERROR_NONE;
}

static gboolean __bluetooth_internal_get_remote_service_handle(DBusGProxy *device_proxy,
		bt_info_for_searching_support_service_t *bt_info_for_searching_support_service)
{

	const char *wanted_uuid = NULL;
	DBG("+\n");

	if (device_proxy == NULL || bt_info_for_searching_support_service == NULL) {
		DBG("Bad Input parameter \n");
		return FALSE;
	}

	wanted_uuid = bt_info_for_searching_support_service->search_match_ptr->match;
	DBG("__bluetooth_internal_get_remote_service_handle address[%s]\n",
	    dbus_g_proxy_get_path(device_proxy));

	if (!dbus_g_proxy_begin_call_with_timeout(device_proxy, "DiscoverServices",
				(DBusGProxyCallNotify) __bluetooth_internal_discover_services_cb,
				bt_info_for_searching_support_service, NULL,
				25000, G_TYPE_STRING, wanted_uuid, G_TYPE_INVALID)) {
	}

	return TRUE;
}

static void __bluetooth_internal_request_search_supported_services(const bluetooth_device_address_t *device_address)
{
	bt_info_t *bt_internal_info = NULL;
	DBusGProxy *device_proxy;
	const char *path;
	char addr[BT_ADDRESS_STRING_SIZE] = { 0 };
	GError *err = NULL;
	bt_info_for_searching_support_service_t *bt_info_for_searching_support_service;

	DBG("+\n");
	if (device_address == NULL) {
		DBG("device_address is NULL -\n");
		return;
	}

	_bluetooth_internal_session_init();
	bt_internal_info = _bluetooth_internal_get_information();

	bt_info_for_searching_support_service =
	    &bt_internal_info->info_for_searching_support_service;
	_bluetooth_internal_addr_type_to_addr_string(addr, device_address);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", &err,
			  G_TYPE_STRING, addr, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in FindDevice Proxy call [%s]\n", err->message);
		g_error_free(err);
		return;
	}

	device_proxy = _bluetooth_internal_find_device_by_path(path);

	bt_info_for_searching_support_service->search_match_ptr = supported_service_info;
	memcpy(&bt_info_for_searching_support_service->remote_device_addr, device_address,
	       sizeof(bluetooth_device_address_t));
	_bluetooth_internal_print_bluetooth_device_address_t(&bt_info_for_searching_support_service->remote_device_addr);

	__bluetooth_internal_get_remote_service_handle(device_proxy,
						     bt_info_for_searching_support_service);

	DBG("-\n");
}

BT_EXPORT_API int bluetooth_cancel_service_search(void)
{
	bt_info_t *bt_internal_info = NULL;
	DBusGProxy *device_proxy;
	const char *path;
	char addr[BT_ADDRESS_STRING_SIZE] = { 0 };
	GError *err = NULL;
	bt_info_for_searching_support_service_t *bt_info_for_searching_support_service;

	DBG("+\n");

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE) {
		DBG("Currently not enabled");
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;
	}

	bt_internal_info = _bluetooth_internal_get_information();

	if (bt_internal_info == NULL)
		return BLUETOOTH_ERROR_NO_RESOURCES;

	if (bt_internal_info->adapter_proxy == NULL)
		return BLUETOOTH_ERROR_INTERNAL;

	bt_info_for_searching_support_service =
	    &bt_internal_info->info_for_searching_support_service;
	_bluetooth_internal_addr_type_to_addr_string(addr,
				&bt_info_for_searching_support_service->remote_device_addr);

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", &err,
			  G_TYPE_STRING, addr, G_TYPE_INVALID,
			  DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID);

	if (err != NULL) {
		DBG("Error occured in FindDevice Proxy call [%s]\n", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	device_proxy = _bluetooth_internal_find_device_by_path(path);

	if (!device_proxy)
		return BLUETOOTH_ERROR_NOT_PAIRED;

	dbus_g_proxy_call(device_proxy, "CancelDiscovery", &err, G_TYPE_INVALID, G_TYPE_INVALID);
	if (err != NULL) {
		DBG("Error occured in CancelDiscovery Proxy call [%s]\n", err->message);
		g_error_free(err);
		return BLUETOOTH_ERROR_NOT_IN_OPERATION;
	}

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

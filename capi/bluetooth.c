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

#include <stdbool.h>
#include <string.h>
#include <gio/gio.h>
#include <dbus/dbus.h>
#include <gio/gunixfdlist.h>

#include "common.h"
#include "bluez.h"
#include "bluetooth-service.h"

#include "bluetooth.h"

#define ERROR_INTERFACE "org.tizen.comms.Error"
#define SPP_PROFILE_PATH "/bluetooth/profile/spp"

#define DEVICE_SERVICE_CLASS_DISCOVERABLE_MODE	0x002000

#define BT_SPP_BUFFER_MAX 1024

static bool initialized;
static bool bt_service_init;

static bluez_adapter_t *default_adapter;

static void profile_connect_callback(bluez_device_t *device,
					enum device_profile_state state);

static void profile_disconnect_callback(bluez_device_t *device,
					enum device_profile_state state);

struct device_created_cb_node {
	bt_adapter_device_discovery_state_changed_cb cb;
	void *user_data;
};

struct adapter_discovering_cb_node {
	bt_adapter_device_discovery_state_changed_cb cb;
	void *user_data;
};

struct device_destroy_unpaired_cb_node {
	bt_adapter_device_discovery_state_changed_cb cb;
	void *user_data;
};

struct adapter_state_cb_node {
	bt_adapter_state_changed_cb cb;
	void *user_data;
};

struct device_bond_cb_node {
	bt_device_bond_created_cb cb;
	void *user_data;
};

struct device_destroy_paired_cb_node {
	bt_device_bond_destroyed_cb cb;
	void *user_data;
};

struct device_auth_cb_node {
	bt_device_authorization_changed_cb cb;
	void *user_data;
};

struct adapter_name_cb_node {
	bt_adapter_name_changed_cb cb;
	void *user_data;
};

struct device_connected_state_cb_node {
	bt_device_connection_state_changed_cb cb;
	void *user_data;
};

struct spp_connection_requested_cb_node {
	bt_spp_connection_requested_cb cb;
	void *user_data;
};

struct spp_data_received_cb_node {
	bt_spp_data_received_cb cb;
	void *user_data;
};

struct avrcp_target_connection_state_changed_node {
	bt_avrcp_target_connection_state_changed_cb cb;
	void *user_data;
};

struct audio_connection_state_changed_cb_node {
	bt_audio_connection_state_changed_cb cb;
	void *user_data;
};

static struct adapter_name_cb_node *adapter_name_node;
static struct device_created_cb_node *device_created_node;
static struct adapter_state_cb_node *adapter_state_node;
static struct adapter_discovering_cb_node *adapter_discovering_node;
static struct device_destroy_unpaired_cb_node *unpaired_device_removed_node;
static struct device_bond_cb_node *device_bond_node;
static struct device_auth_cb_node *device_auth_node;
static struct device_destroy_paired_cb_node *paired_device_removed_node;
static struct device_connected_state_cb_node *device_connected_state_node;
static struct spp_connection_requested_cb_node *spp_connection_requested_node;
static struct spp_data_received_cb_node *spp_data_received_node;
static struct avrcp_target_connection_state_changed_node
					*avrcp_target_state_node;
static struct audio_connection_state_changed_cb_node *audio_state_node;

static gboolean generic_device_removed_set;

static void divide_device_class(bt_class_s *bt_class, unsigned int class)
{
	bt_class->major_device_class =
			(unsigned short)(class & 0x00001F00) >> 8;
	bt_class->minor_device_class =
			(unsigned short)((class & 0x000000FC));
	bt_class->major_service_class_mask =
			(unsigned long)((class & 0x00FF0000));

	if (class & 0x002000) {
		bt_class->major_service_class_mask |=
			DEVICE_SERVICE_CLASS_DISCOVERABLE_MODE;
	}
}

static bt_adapter_device_discovery_info_s *get_discovery_device_info(
						bluez_device_t *device)
{
	guint len;
	signed short rssi;
	int paired;
	char *alias, *address, *icon;
	char **uuids;
	unsigned int class;
	bt_adapter_device_discovery_info_s *device_info;

	if (device == NULL)
		return NULL;

	device_info = g_new0(bt_adapter_device_discovery_info_s, 1);
	if (device_info == NULL) {
		ERROR("no memory.");
		return NULL;
	}

	address = bluez_device_get_property_address(device);
	alias = bluez_device_get_property_alias(device);
	uuids = bluez_device_get_property_uuids(device);
	icon = bluez_device_get_property_icon(device);
	bluez_device_get_property_class(device, &class);
	bluez_device_get_property_rssi(device, &rssi);
	bluez_device_get_property_paired(device, &paired);

	len = g_strv_length(uuids);

	device_info->service_count = len;
	device_info->remote_address = address;
	device_info->remote_name = alias;
	device_info->icon = icon;
	device_info->rssi = rssi;
	device_info->is_bonded = paired;
	device_info->service_uuid = uuids;

	divide_device_class(&device_info->bt_class, class);

	return device_info;
}

static void free_discovery_device_info(
		bt_adapter_device_discovery_info_s *discovery_device_info)
{
	int i;

	if (discovery_device_info == NULL)
		return ;

	g_free(discovery_device_info->remote_address);
	g_free(discovery_device_info->remote_name);
	g_free(discovery_device_info->icon);

	for (i = 0; i < discovery_device_info->service_count; ++i)
		g_free(discovery_device_info->service_uuid[i]);

	g_free(discovery_device_info->service_uuid);
	g_free(discovery_device_info);
}

static bt_device_info_s *get_device_info(bluez_device_t *device)
{
	guint len;
	int paired, connected, trusted;
	char *alias, *address, *icon;
	char **uuids;
	unsigned int class;
	bt_device_info_s *device_info;

	if (device == NULL) {
		ERROR("device is NULL");
		return NULL;
	}

	device_info = g_new0(bt_device_info_s, 1);
	if (device_info == NULL) {
		ERROR("no memory");
		return NULL;
	}

	address = bluez_device_get_property_address(device);
	alias = bluez_device_get_property_alias(device);
	uuids = bluez_device_get_property_uuids(device);
	icon = bluez_device_get_property_icon(device);
	bluez_device_get_property_class(device, &class);
	bluez_device_get_property_paired(device, &paired);
	bluez_device_get_property_connected(device, &connected);
	bluez_device_get_property_trusted(device, &trusted);

	len = g_strv_length(uuids);

	device_info->service_count = len;
	device_info->remote_address = address;
	device_info->remote_name = alias;
	device_info->icon = icon;
	device_info->is_bonded = paired;
	device_info->is_connected = connected;
	device_info->is_authorized = trusted;
	device_info->service_uuid = uuids;

	divide_device_class(&device_info->bt_class, class);

	return device_info;
}

static void free_device_info(bt_device_info_s *device_info)
{
	gsize i;

	if (device_info == NULL)
		return;

	g_free(device_info->remote_address);
	g_free(device_info->remote_name);
	for (i = 0; i < device_info->service_count; ++i)
		g_free(device_info->service_uuid[i]);

	g_free(device_info->service_uuid);
	g_free(device_info);
}

void adapter_powered_changed(bluez_adapter_t *adater,
					gboolean powered,
					void *user_data)
{
	struct adapter_state_cb_node *data =
			(struct adapter_state_cb_node *)user_data;

	DBG("Powered: %d", powered);

	if (powered == true)
		data->cb(BT_ERROR_NONE, BT_ADAPTER_ENABLED, data->user_data);
	else
		data->cb(BT_ERROR_NONE, BT_ADAPTER_DISABLED, data->user_data);
}

static void bluez_paired_device_removed(bluez_device_t *device,
						void *user_data)
{
	int paired;
	char *device_addr;
	char *address;
	struct device_destroy_paired_cb_node *data = user_data;

	DBG("");

	if (data == NULL)
		return;

	address = bluez_device_get_property_address(device);
	bluez_device_get_property_paired(device, &paired);

	device_addr = address;

	/* CAPI function bt_device_bond_destroyed_cb
	 * parameter 2 is char *, not the const char *
	 * so device_addr should free by user
	 */
	if (data->cb)
		data->cb(BT_SUCCESS, device_addr, data->user_data);
}

static void bluez_unpaired_device_removed(bluez_device_t *device,
							void *user_data)
{
	bt_adapter_device_discovery_info_s *discovery_device_info;
	struct device_destroy_unpaired_cb_node *node = user_data;

	if (node == NULL)
		return;

	discovery_device_info = get_discovery_device_info(device);

	if (node->cb)
		node->cb(BT_SUCCESS, BT_ADAPTER_DEVICE_DISCOVERY_REMOVED,
				discovery_device_info, node->user_data);

	free_discovery_device_info(discovery_device_info);
}

static void handle_generic_device_removed(bluez_device_t *device, void *user_data)
{
	int paired;

	if (device == NULL)
		return;

	bluez_device_get_property_paired(device, &paired);
	if (paired == false)
		bluez_unpaired_device_removed(device, unpaired_device_removed_node);
	else
		bluez_paired_device_removed(device, paired_device_removed_node);
}

static void set_device_removed_generic_callback(bluez_adapter_t *adapter)
{
	bluez_adapter_set_device_removed_cb(adapter,
				handle_generic_device_removed, NULL);

	generic_device_removed_set = TRUE;
}

static void bluez_avrcp_target_state_changed(struct _bluez_device *device,
					gboolean connected,
					void *user_data)
{
	bt_device_info_s *device_info;
	struct avrcp_target_connection_state_changed_node *data =
							user_data;

	DBG("");

	device_info = get_device_info(device);

	if (data->cb)
		(data->cb)(connected, device_info->remote_address,
							data->user_data);

	free_device_info(device_info);
}

static void bluez_audio_state_changed(int result,
					gboolean connected,
					const char *remote_address,
					bt_audio_profile_type_e type,
					void *user_data)
{
	struct audio_connection_state_changed_cb_node *data =
							user_data;

	DBG("");

	if (data->cb)
		(data->cb)(result, connected, remote_address, type,
						data->user_data);
}

static void device_paired_changed(bluez_device_t *device,
					int paired,
					void *user_data)
{
	bt_device_info_s *device_bond_info;
	struct device_bond_cb_node *data = user_data;

	DBG("");

	device_bond_info = get_device_info(device);

	data->cb(BT_SUCCESS, device_bond_info, data->user_data);

	free_device_info(device_bond_info);
}

static void device_connected_changed(bluez_device_t *device,
					int connected, void *user_data)
{
	struct device_connected_state_cb_node *node = user_data;
	char *device_address;

	DBG("");

	device_address = bluez_device_get_property_address(device);

	node->cb(connected, device_address, node->user_data);

	g_free(device_address);
}

static void device_auth_changed(bluez_device_t *device,
					int trusted, void *user_data)
{
	struct device_auth_cb_node *node = user_data;
	bt_device_authorization_e authorization;
	char *device_address;

	DBG("");

	authorization = trusted ? BT_DEVICE_UNAUTHORIZED:
				BT_DEVICE_AUTHORIZED;

	device_address = bluez_device_get_property_address(device);

	node->cb(authorization, device_address, node->user_data);

	g_free(device_address);
}

static unsigned int dev_property_callback_flags;

enum bluez_device_property_callback_flag {
	DEV_PROP_FLAG_PAIR = 0x01,
	DEV_PROP_FLAG_CONNECT = 0x02,
	DEV_PROP_FLAG_AUTH = 0x04
};

static void set_device_property_changed_callback(bluez_device_t *device)
{
	if (dev_property_callback_flags & DEV_PROP_FLAG_PAIR)
		bluez_device_set_paired_changed_cb(device,
					device_paired_changed,
					device_bond_node);

	if (dev_property_callback_flags & DEV_PROP_FLAG_CONNECT)
		bluez_device_set_connected_changed_cb(device,
					device_connected_changed,
					device_connected_state_node);

	if (dev_property_callback_flags & DEV_PROP_FLAG_AUTH)
		bluez_device_set_trusted_changed_cb(device,
					device_auth_changed,
					device_auth_node);
}

static void unset_device_property_changed_callback(bluez_device_t *device)
{
	if (dev_property_callback_flags ^ DEV_PROP_FLAG_PAIR)
		bluez_device_unset_paired_changed_cb(device);

	if (dev_property_callback_flags ^ DEV_PROP_FLAG_CONNECT)
		bluez_device_unset_connected_changed_cb(device);

	if (dev_property_callback_flags ^ DEV_PROP_FLAG_AUTH)
		bluez_device_unset_trusted_changed_cb(device);
}

static void foreach_device_property_callback(GList *list, unsigned int flag)
{
	bluez_device_t *device;
	GList *iter, *next;

	for (iter = g_list_first(list); iter; iter = next) {
		next = g_list_next(iter);

		device = iter->data;

		if (dev_property_callback_flags & flag)
			set_device_property_changed_callback(device);
		else
			unset_device_property_changed_callback(device);
	}
}

static void bluez_device_created(bluez_device_t *device, void *user_data)
{
	bt_adapter_device_discovery_info_s *discovery_device_info;
	struct device_created_cb_node *node = user_data;

	DBG("");
	discovery_device_info = get_discovery_device_info(device);

	DBG("name: %s, uuid: %p, uuid_count: %d", discovery_device_info->remote_name,
						discovery_device_info->service_uuid,
						discovery_device_info->service_count);

	node->cb(BT_SUCCESS, BT_ADAPTER_DEVICE_DISCOVERY_FOUND,
				discovery_device_info, node->user_data);

	set_device_property_changed_callback(device);

	free_discovery_device_info(discovery_device_info);
}

static void bluez_adapter_discovering_changed(bluez_adapter_t *adapter,
						int discovering,
						void *user_data)
{
	bt_adapter_device_discovery_state_e state;
	struct adapter_discovering_cb_node *node = user_data;

	DBG("");

	state = discovering ? BT_ADAPTER_DEVICE_DISCOVERY_STARTED :
				BT_ADAPTER_DEVICE_DISCOVERY_FINISHED;

	if (node->cb)
		node->cb(BT_SUCCESS, state, NULL, node->user_data);
}

void adapter_name_changed(bluez_adapter_t *adapter,
				const gchar *name,
				void *user_data)
{
	struct adapter_name_cb_node *data =
			(struct adapter_name_cb_node *)user_data;
	gchar *adapter_name = g_strdup(name);

	DBG("Name: %s", name);

	data->cb(adapter_name, data->user_data);

	g_free(adapter_name);
}

static void _bt_update_bluetooth_callbacks(void)
{
	DBG("default_adpater: %p", default_adapter);

	if (default_adapter == NULL)
		return;

	if (adapter_state_node)
		bluez_adapter_set_powered_changed_cb(default_adapter,
					adapter_powered_changed,
					adapter_state_node);

	if (adapter_name_node)
		bluez_adapter_set_alias_changed_cb(default_adapter,
					adapter_name_changed,
					adapter_name_node);

	if (device_created_node)
		bluez_adapter_set_device_created_cb(default_adapter,
					bluez_device_created,
					device_created_node);
	if (adapter_discovering_node)
		bluez_adapter_set_device_discovering_cb(default_adapter,
					bluez_adapter_discovering_changed,
					adapter_discovering_node);

	if (generic_device_removed_set == FALSE)
		set_device_removed_generic_callback(default_adapter);

	if (audio_state_node)
		bluez_set_audio_state_cb(
					bluez_audio_state_changed,
					audio_state_node);

	if (avrcp_target_state_node)
		bluez_set_avrcp_target_cb(
					bluez_avrcp_target_state_changed,
					avrcp_target_state_node);
}

static void setup_bluez_lib(void)
{
	gboolean powered;
	int err;

	DBG("");

	err = bluez_lib_init();
	if (err) {
		ERROR("Bluz-lib init error");
		return;
	}

	default_adapter = bluez_adapter_get_adapter(DEFAULT_ADAPTER_NAME);
	if (default_adapter == NULL) {
		ERROR("Can't find adapter %s", DEFAULT_ADAPTER_NAME);
		bluez_lib_deinit();
		return;
	}

	_bt_update_bluetooth_callbacks();

	initialized = true;

	DBG("Set bluetooth powered state");
	if (adapter_state_node == NULL)
		return;

	bluez_adapter_get_property_powered(default_adapter, &powered);
	if (powered)
		adapter_powered_changed(default_adapter, powered,
						adapter_state_node);

	DBG("");
}
static void destroy_bluez_lib(void)
{
	bluez_lib_deinit();

	default_adapter = NULL;

	initialized = false;
}

void _bt_service_bt_in_service_watch(uint in_service, void *user_data)
{
	if (in_service)
		setup_bluez_lib();
}

int bt_initialize(void)
{
	int in_service;

	if (bt_service_init)
		return BT_SUCCESS;

	comms_lib_init();

	comms_manager_set_bt_in_service_watch(
				_bt_service_bt_in_service_watch, NULL);


	comms_manager_get_property_bt_in_service(&in_service);
	if (in_service)
		setup_bluez_lib();

	bt_service_init = TRUE;

	return BT_SUCCESS;
}

int bt_deinitialize(void)
{
	if (bt_service_init == false)
		return BT_SUCCESS;

	destroy_bluez_lib();

	comms_manager_remove_bt_in_service_watch();

	bt_service_init = FALSE;

	return BT_SUCCESS;
}

int bt_adapter_enable(void)
{
	DBG("");

	if (bt_service_init == false)
		return BT_ERROR_NOT_INITIALIZED;

	comms_manager_enable_bluetooth();

	return BT_SUCCESS;
}

int bt_adapter_disable(void)
{
	DBG("");

	if (bt_service_init == false)
		return BT_ERROR_NOT_INITIALIZED;

	comms_manager_disable_bluetooth();

	return BT_SUCCESS;
}

int bt_adapter_get_state(bt_adapter_state_e *adapter_state)
{
	int powered;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (adapter_state == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	bluez_adapter_get_property_powered(default_adapter, &powered);
	if (powered == true)
		*adapter_state = BT_ADAPTER_ENABLED;
	else
		*adapter_state = BT_ADAPTER_DISABLED;

	return BT_SUCCESS;
}

int bt_adapter_get_address(char **local_address)
{
	char *address;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (local_address == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	address = bluez_adapter_get_property_address(default_adapter);
	if (address == NULL)
		return BT_ERROR_OPERATION_FAILED;

	*local_address = address;

	return BT_SUCCESS;
}

int bt_adapter_get_name(char **local_name)
{
	char *name;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (local_name == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	name = bluez_adapter_get_property_alias(default_adapter);
	if (name == NULL)
		return BT_ERROR_OPERATION_FAILED;

	*local_name = name;

	return BT_SUCCESS;
}

int bt_adapter_set_name(const char *local_name)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (local_name == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	bluez_adapter_set_alias(default_adapter, local_name);

	return BT_SUCCESS;
}

int bt_adapter_set_name_changed_cb(bt_adapter_name_changed_cb callback,
					void *user_data)
{
	struct adapter_name_cb_node *node_data;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (adapter_name_node) {
		DBG("Powered state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct adapter_name_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	adapter_name_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_adapter_get_visibility(bt_adapter_visibility_mode_e *mode,
				int *duration)
{
	int discoverable;
	unsigned int timeout;
	int err;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (mode == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	err = bluez_adapter_get_property_discoverable(default_adapter,
								&discoverable);
	if (err)
		return BT_ERROR_OPERATION_FAILED;

	err = bluez_adapter_get_property_discoverable_timeout(default_adapter,
								&timeout);
	if (err)
		return BT_ERROR_OPERATION_FAILED;

	if (!discoverable){
		*mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
		return BT_SUCCESS;
	}

	*mode = (timeout == 0) ?
			BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE :
			BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE;

	return BT_SUCCESS;
}

int bt_adapter_set_visibility(bt_adapter_visibility_mode_e discoverable_mode,
				int duration)
{
	int discoverable;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	switch (discoverable_mode) {
	case BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE:
		discoverable = false;
		break;
	case BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE:
	case BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE:
		discoverable = true;
		break;
	default:
		return BT_ERROR_INVALID_PARAMETER;
	}

	bluez_adapter_set_discoverable(default_adapter, discoverable);

	/* TODO: Set start timer */

	return BT_SUCCESS;
}

int bt_adapter_start_device_discovery(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	bluez_adapter_start_discovery(default_adapter);

	return BT_SUCCESS;
}

int bt_adapter_stop_device_discovery(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	bluez_adapter_stop_discovery(default_adapter);

	return BT_SUCCESS;
}

int bt_adapter_is_discovering(bool *is_discovering)
{
	int discovering;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (is_discovering == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	bluez_adapter_get_property_discovering(default_adapter, &discovering);

	*is_discovering = discovering;

	return BT_SUCCESS;
}

int bt_adapter_is_service_used(const char *service_uuid, bool *used)
{
	guint length, index;
	char **uuids;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (used == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	uuids = bluez_adapter_get_property_uuids(default_adapter);
	length = g_strv_length(uuids);

	*used = false;
	for (index = 0; index < length; ++index) {
		if (strcasecmp(uuids[index], service_uuid) == 0) {
			*used = true;
			break;
		}
	}

	g_strfreev(uuids);

	return BT_SUCCESS;
}

int bt_adapter_set_device_discovery_state_changed_cb(
			bt_adapter_device_discovery_state_changed_cb callback,
			void *user_data)
{
	struct device_created_cb_node *created_node;
	struct adapter_discovering_cb_node *discovering_node;
	struct device_destroy_unpaired_cb_node *removed_node;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (device_created_node) {
		DBG("Discovery state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	created_node = g_new0(struct device_created_cb_node, 1);
	if (created_node == NULL) {
		ERROR("no memory.");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	created_node->cb = callback;
	created_node->user_data = user_data;

	device_created_node = created_node;

	if (adapter_discovering_node) {
		DBG("Device discovering changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	discovering_node = g_new0(struct adapter_discovering_cb_node, 1);
	if (discovering_node == NULL) {
		ERROR("no memory.");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	discovering_node->cb = callback;
	discovering_node->user_data = user_data;

	adapter_discovering_node = discovering_node;

	if (unpaired_device_removed_node) {
		DBG("Device removed changed callback already set");
		return BT_ERROR_ALREADY_DONE;
	}

	removed_node = g_new0(struct device_destroy_unpaired_cb_node, 1);
	if (removed_node == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	removed_node->cb = callback;
	removed_node->user_data = user_data;

	unpaired_device_removed_node = removed_node;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_adapter_set_state_changed_cb(bt_adapter_state_changed_cb callback,
					void *user_data)
{
	struct adapter_state_cb_node *node_data;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (adapter_state_node) {
		DBG("Powered state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct adapter_state_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	adapter_state_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_adapter_unset_state_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!adapter_state_node)
		return BT_SUCCESS;

	bluez_adapter_unset_powered_changed_cb(default_adapter);

	g_free(adapter_state_node);
	adapter_state_node = NULL;

	return BT_SUCCESS;
}

int bt_adapter_unset_device_discovery_state_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (device_created_node) {
		bluez_adapter_unset_device_created_cb(default_adapter);

		g_free(device_created_node);
		device_created_node = NULL;
	}

	if (adapter_discovering_node) {
		bluez_adapter_unset_device_discovering_cb(default_adapter);

		g_free(adapter_discovering_node);
		adapter_discovering_node = NULL;
	}

	if (paired_device_removed_node == NULL &&
			generic_device_removed_set == TRUE) {
		bluez_adapter_unset_device_removed_cb(default_adapter);

		generic_device_removed_set = FALSE;

		g_free(unpaired_device_removed_node);
		unpaired_device_removed_node = NULL;
	}

	return BT_SUCCESS;
}

int bt_adapter_reset(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_adapter_foreach_bonded_device(bt_adapter_bonded_device_cb callback,
					void *user_data)
{
	int paired;
	bluez_device_t *device;
	bt_device_info_s *device_bond_info;
	GList *list, *iter;
	GList *next = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	list = bluez_adapter_get_devices(default_adapter);
	for (iter = g_list_first(list); iter; iter = next) {
		device = iter->data;

		next = g_list_next(iter);

		if (device == NULL)
			continue;

		bluez_device_get_property_paired(device, &paired);
		if (paired == false)
			continue;

		device_bond_info = get_device_info(device);
		DBG("device name: %s", device_bond_info->remote_name);

		callback(device_bond_info, user_data);

		free_device_info(device_bond_info);
	}

	g_list_free(list);

	return BT_SUCCESS;
}

int bt_adapter_get_bonded_device_info(const char *remote_address,
					bt_device_info_s **device_info)
{
	bluez_device_t *device;
	int paired;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !device_info)
		return BT_ERROR_INVALID_PARAMETER;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_get_property_paired(device, &paired);
	if (paired == false)
		return BT_ERROR_REMOTE_DEVICE_NOT_BONDED;

	*device_info = get_device_info(device);

	return BT_SUCCESS;
}

int bt_adapter_free_device_info(bt_device_info_s *device_info)
{
	if (!device_info)
		return BT_ERROR_INVALID_PARAMETER;

	free_device_info(device_info);

	return BT_SUCCESS;
}

/* Device Function */

static void bt_device_paired_cb(enum bluez_error_type error,
                                       void *user_data)
{
       bt_error_e capi_error = BT_SUCCESS;
       char *remote_address = user_data;
       bt_device_info_s *device_info;
       bluez_device_t *device;

       device = bluez_adapter_get_device_by_address(default_adapter,
                                                       remote_address);
       if (!device) {
               ERROR("no %s device", remote_address);
               return;
       }

       if (!device_bond_node)
               return;

       switch (error) {
       case ERROR_INVALID_ARGUMENTS:
               capi_error = BT_ERROR_INVALID_PARAMETER;
               break;
       case ERROR_FAILED:
               capi_error = BT_ERROR_OPERATION_FAILED;
               break;
       case ERROR_AUTH_CANCELED:
               break;
       case ERROR_AUTH_FAILED:
               capi_error = BT_ERROR_AUTH_FAILED;
               break;
       case ERROR_AUTH_REJECT:
               capi_error = BT_ERROR_AUTH_REJECTED;
               break;
       case ERROR_AUTH_TIMEOUT:
               capi_error = BT_ERROR_TIMED_OUT;
               break;
       case ERROR_AUTH_ATTEMPT_FAILED:
               capi_error = BT_ERROR_AUTH_FAILED;
               break;
       default:
               WARN("Unknown error type with device pair");
       }

       device_info = get_device_info(device);

       device_bond_node->cb(capi_error, device_info,
                               device_bond_node->user_data);

	free_device_info(device_info);
}

int bt_device_create_bond(const char *remote_address)
{
	comms_bluetooth_device_pair(remote_address,
				bt_device_paired_cb, strdup(remote_address));

	return BT_SUCCESS;
}

int bt_device_destroy_bond(const char *remote_address)
{
	bluez_device_t *device;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_adapter_remove_device(default_adapter, device);

	return BT_SUCCESS;
}

int bt_device_set_alias(const char *remote_address, const char *alias)
{
	bluez_device_t *device;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !alias)
		return BT_ERROR_INVALID_PARAMETER;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_set_alias(device, alias);

	return BT_SUCCESS;
}

int bt_device_set_authorization(const char *remote_address,
				bt_device_authorization_e authorization_state)
{
	int trusted;
	bluez_device_t *device;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address)
		return BT_ERROR_INVALID_PARAMETER;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	trusted = (authorization_state == BT_DEVICE_AUTHORIZED) ?
						false : true;

	bluez_device_set_trusted(device, trusted);

	return BT_SUCCESS;
}

int bt_device_set_bond_created_cb(bt_device_bond_created_cb callback,
							void *user_data)
{
	struct device_bond_cb_node *node;
	GList *list;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (device_bond_node) {
		DBG("Device bond callback already set.");
		return BT_SUCCESS;
	}

	node = g_new0(struct device_bond_cb_node, 1);
	if (node == NULL) {
		ERROR("no memeroy");
		return BT_ERROR_OPERATION_FAILED;
	}

	node->cb = callback;
	node->user_data = user_data;

	device_bond_node = node;

	dev_property_callback_flags |= DEV_PROP_FLAG_PAIR;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_PAIR);

	return BT_SUCCESS;
}

int bt_device_unset_bond_created_cb(void)
{
	GList *list;
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!device_bond_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_PAIR;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_PAIR);

	g_free(device_bond_node);
	device_bond_node = NULL;

	return BT_SUCCESS;
}

int bt_device_set_bond_destroyed_cb(bt_device_bond_destroyed_cb callback,
							void *user_data)
{
	struct device_destroy_paired_cb_node *node;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (paired_device_removed_node) {
		DBG("Device bonded-destroy callback already set");
		return BT_ERROR_ALREADY_DONE;
	}

	node = g_new0(struct device_destroy_paired_cb_node, 1);
	if (node == NULL) {
		ERROR("no memeroy");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node->cb = callback;
	node->user_data = user_data;

	paired_device_removed_node = node;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_device_unset_bond_destroyed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (unpaired_device_removed_node == NULL &&
			generic_device_removed_set == TRUE) {
		bluez_adapter_unset_device_removed_cb(default_adapter);

		generic_device_removed_set = FALSE;
	}

	g_free(paired_device_removed_node);
	paired_device_removed_node = NULL;

	return BT_SUCCESS;
}

int bt_device_set_authorization_changed_cb(
			bt_device_authorization_changed_cb callback,
						void *user_data)
{
	struct device_auth_cb_node *node;
	GList *list;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (device_auth_node) {
		DBG("Device bond callback already set.");
		return BT_SUCCESS;
	}

	node = g_new0(struct device_auth_cb_node, 1);
	if (node == NULL) {
		ERROR("no memeroy");
		return BT_ERROR_OPERATION_FAILED;
	}

	node->cb = callback;
	node->user_data = user_data;

	device_auth_node = node;

	dev_property_callback_flags |= DEV_PROP_FLAG_AUTH;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_AUTH);

	return BT_SUCCESS;
}

int bt_device_unset_authorization_changed_cb(void)
{
	GList *list;
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!device_auth_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_AUTH;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_AUTH);

	g_free(device_auth_node);
	device_auth_node = NULL;

	return BT_SUCCESS;
}

int bt_device_set_service_searched_cb(bt_device_service_searched_cb callback,
							void *user_data)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_device_unset_service_searched_cb(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_device_set_connection_state_changed_cb(
				bt_device_connection_state_changed_cb callback,
				void *user_data)
{
	struct device_connected_state_cb_node *node_data;
	GList *list;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (device_connected_state_node) {
		DBG("Device connected state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct device_connected_state_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	device_connected_state_node = node_data;

	dev_property_callback_flags |= DEV_PROP_FLAG_CONNECT;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_CONNECT);

	return BT_SUCCESS;
}

int bt_device_unset_connection_state_changed_cb(void)
{
	GList *list;
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!device_connected_state_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_CONNECT;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_CONNECT);

	g_free(device_connected_state_node);
	device_connected_state_node = NULL;

	return BT_SUCCESS;
}

/* Audio Function */

int bt_audio_initialize(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_audio_deinitialize(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_audio_connect(const char *remote_address,
				bt_audio_profile_type_e type)
{
	bluez_device_t *device;
	char *uuid = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	switch (type) {
	case BT_AUDIO_PROFILE_TYPE_HSP_HFP:
		uuid = BT_HFP_HS_UUID;
		break;
	case BT_AUDIO_PROFILE_TYPE_A2DP:
		uuid = BT_A2DP_SINK_UUID;
		break;
	case BT_AUDIO_PROFILE_TYPE_ALL:
		uuid = BT_GENERIC_AUDIO_UUID;
		break;
	default:
		DBG("Unknown role");
		return BT_ERROR_INVALID_PARAMETER;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_connect_profile(device, uuid,
				profile_connect_callback);

	return BT_SUCCESS;
}

int bt_audio_disconnect(const char *remote_address,
				bt_audio_profile_type_e type)
{
	bluez_device_t *device;
	char *uuid = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	switch (type) {
	case BT_AUDIO_PROFILE_TYPE_HSP_HFP:
		uuid = BT_HFP_HS_UUID;
		break;
	case BT_AUDIO_PROFILE_TYPE_A2DP:
		uuid = BT_A2DP_SINK_UUID;
		break;
	case BT_AUDIO_PROFILE_TYPE_ALL:
		uuid = BT_GENERIC_AUDIO_UUID;
		break;
	default:
		DBG("Unknown role");
		return BT_ERROR_INVALID_PARAMETER;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_disconnect_profile(device, uuid,
				profile_disconnect_callback);

	return BT_SUCCESS;
}

int bt_audio_set_connection_state_changed_cb(
			bt_audio_connection_state_changed_cb callback,
			void *user_data)
{
	struct audio_connection_state_changed_cb_node *node_data = NULL;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (audio_state_node) {
		DBG("audio state callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct audio_connection_state_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	audio_state_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_audio_unset_connection_state_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!audio_state_node)
		return BT_SUCCESS;

	bluez_unset_audio_state_cb();

	g_free(audio_state_node);
	audio_state_node = NULL;

	return BT_SUCCESS;
}

int bt_avrcp_target_initialize(
			bt_avrcp_target_connection_state_changed_cb callback,
			void *user_data)
{
	struct avrcp_target_connection_state_changed_node *node_data = NULL;

	DBG("default_adpater: %p", default_adapter);

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (avrcp_target_state_node) {
		DBG("avrcp target callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data =
		g_new0(struct avrcp_target_connection_state_changed_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	avrcp_target_state_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int bt_avrcp_target_deinitialize(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!avrcp_target_state_node)
		return BT_SUCCESS;

	bluez_unset_avrcp_target_cb();

	g_free(avrcp_target_state_node);
	avrcp_target_state_node = NULL;

	return BT_SUCCESS;
}

/* Hid function */
int bt_hid_host_initialize(
		bt_hid_host_connection_state_changed_cb connection_cb,
		void *user_data)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int bt_hid_host_deinitialize(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

static void profile_connect_callback(bluez_device_t *device,
					enum device_profile_state state)
{
	switch (state) {
	case PROFILE_CONNECT_SUCCESS:
		DBG("Connect profile: %s", "PROFILE_CONNECT_SUCCESS");
		break;
	case PROFILE_NOT_EXIST:
		DBG("Connect profile: %s", "PROFILE_NOT_EXIST");
		break;
	case PROFILE_ALREADY_CONNECTED:
		DBG("Connect profile: %s", "PROFILE_ALREADY_CONNECTED");
		break;
	case PROFILE_CONNECT_FAILED:
		DBG("Connect profile: %s", "PROFILE_CONNECT_FAILED");
		break;
	default:
		ERROR("Unknown error code");
		break;
	}
}

int bt_hid_host_connect(const char *remote_address)
{
	bluez_device_t *device;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_connect_profile(device, BT_HID_UUID,
				profile_connect_callback);

	return BT_SUCCESS;
}

static void profile_disconnect_callback(bluez_device_t *device,
					enum device_profile_state state)
{
	switch (state) {
	case PROFILE_DISCONNECT_SUCCESS:
		DBG("Connect profile: %s", "PROFILE_DISCONNECT_SUCCESS");
		break;
	case PROFILE_NOT_EXIST:
		DBG("Connect profile: %s", "PROFILE_NOT_EXIST");
		break;
	case PROFILE_NOT_CONNECTED:
		DBG("Connect profile: %s", "PROFILE_NOT_CONNECTED");
		break;
	case PROFILE_NOT_SUPPORTED:
		DBG("Connect profile: %s", "PROFILE_NOT_SUPPORTED");
		break;
	case PROFILE_DISCONNECT_FAILED:
		DBG("Connect profile: %s", "PROFILE_DISCONNECT_FAILED");
		break;
	default:
		ERROR("Unknown error code");
		break;
	}
}

int bt_hid_host_disconnect(const char *remote_address)
{
	bluez_device_t *device;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_disconnect_profile(device, BT_HID_UUID,
				profile_disconnect_callback);

	return BT_SUCCESS;
}

/* Agent Function */

#define BLUEZ_AGENT_SERVICE "org.bluezlib.agent"
#define AGENT_INTERFACE "org.bluez.Agent1"
#define AGENT_OBJECT_PATH "/org/bluezlib/agent"

static bt_agent *this_agent;

static GDBusNodeInfo *introspection_data;

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.Agent1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='RequestPinCode'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' direction='out'/>"
	"    </method>"
	"    <method name='DisplayPinCode'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' name='pincode' direction='in'/>"
	"    </method>"
	"    <method name='RequestPasskey'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' direction='out'/>"
	"    </method>"
	"    <method name='RequestConfirmation'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' name='passkey' direction='in'/>"
	"    </method>"
	"    <method name='RequestAuthorization'>"
	"      <arg type='o' name='device' direction='in'/>"
	"    </method>"
	"    <method name='AuthorizeService'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='s' name='uuid' direction='in'/>"
	"    </method>"
	"    <method name='Cancel'>"
	"    </method>"
	"  </interface>"
	"</node>";

static void handle_release(GDBusMethodInvocation *invocation)
{
	DBG("");

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_display_pincode(const gchar *device_path,
					const char *pincode,
					GDBusMethodInvocation *invocation)
{
	gchar *device_name;
	bluez_device_t *device;

	DBG("");

	if (default_adapter == NULL) {
		ERROR("No default adapter");
		return;
	}

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	if (this_agent && this_agent->display_pincode)
		this_agent->display_pincode(device_name, pincode, invocation);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void request_pincode_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
	gchar *device_name;
	bluez_device_t *device;

	DBG("");

	if (default_adapter == NULL) {
		ERROR("No default adapter");
		return;
	}

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	if (this_agent && this_agent->request_pincode)
		this_agent->request_pincode(device_name, invocation);
}

static void request_passkey_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
	gchar *device_name;
	bluez_device_t *device;

	DBG("");

	if (default_adapter == NULL) {
		ERROR("No default adapter");
		return;
	}

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	if (this_agent && this_agent->request_passkey)
		this_agent->request_passkey(device_name, invocation);
}

static void request_confirmation_handler(const gchar *device_path,
					guint32 passkey,
					GDBusMethodInvocation *invocation)
{
	gchar *device_name;
	bluez_device_t *device;

	DBG("");

	if (default_adapter == NULL) {
		ERROR("No default adapter");
		return;
	}

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	if (this_agent && this_agent->request_confirm)
		this_agent->request_confirm(device_name, passkey, invocation);
}

static void request_authorize_service_handler(const gchar *device_path,
					const gchar *uuid,
					GDBusMethodInvocation *invocation)
{
	struct spp_connection_requested_cb_node *node_data;
	gchar *device_name;
	bluez_device_t *device;

	DBG("");

	if (default_adapter == NULL) {
		ERROR("No default adapter");
		return;
	}

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	node_data = spp_connection_requested_node;
	if (node_data)
		node_data->cb(uuid, device_name, invocation,
				node_data->user_data);

	g_free(device_name);
}

static void request_authorization_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
	if (!this_agent)
		return;

	if (!this_agent->cancel)
		return;

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void cancel_handler(GDBusMethodInvocation *invocation)
{
	if (!this_agent)
		return;

	if (!this_agent->cancel)
		return;

	this_agent->cancel();

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_method_call(GDBusConnection *connection,
				const gchar *sender,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *method_name,
				GVariant *parameters,
				GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0) {
		handle_release(invocation);

		return;
	}

	if (g_strcmp0(method_name, "DisplayPinCode") == 0) {
		gchar *device_path = NULL, *pincode =  NULL;
		g_variant_get(parameters, "(os)", &device_path, &pincode);

		handle_display_pincode(device_path, pincode, invocation);

		g_free(device_path);
		g_free(pincode);

		return;
	}

	if (g_strcmp0(method_name, "RequestPinCode") == 0) {
		gchar *device_path = NULL;
		g_variant_get(parameters, "(o)", &device_path);

		request_pincode_handler(device_path, invocation);

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "RequestPasskey") == 0) {
		gchar *device_path = NULL;
		g_variant_get(parameters, "(o)", &device_path);

		request_passkey_handler(device_path, invocation);

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "RequestConfirmation") == 0) {
		gchar *device_path = NULL;
		guint32 passkey = 0;
		g_variant_get(parameters, "(ou)", &device_path, &passkey);

		request_confirmation_handler(device_path, passkey, invocation);

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "AuthorizeService") == 0) {
		gchar *device_path, *uuid;
		g_variant_get(parameters, "(os)", &device_path, &uuid);

		request_authorize_service_handler(device_path,
						uuid, invocation);

		g_free(device_path);
		g_free(uuid);

		return;
	}

	if (g_strcmp0(method_name, "RequestAuthorization") == 0) {
		gchar *device_path;
		g_variant_get(parameters, "(o)", &device_path);

		request_authorization_handler(device_path, invocation);

		g_free(device_path);

		return;
	}

	if (g_strcmp0(method_name, "Cancel") == 0) {
		cancel_handler(invocation);

		return;
	}
}

static const GDBusInterfaceVTable interface_handle = {
	handle_method_call,
	NULL,
	NULL
};

static guint bluetooth_agent_id;
static guint profile_id;
static GDBusConnection *conn;

static void release_dbus_connection(void)
{
	g_object_unref(conn);
	conn = NULL;
}

static void release_name_on_dbus(const char *name)
{
	GVariant *ret;
	guint32 request_name_reply;
	GError *error = NULL;

	if (bluetooth_agent_id || profile_id)
		return;

	ret = g_dbus_connection_call_sync(conn,
					"org.freedesktop.DBus",
					"/org/freedesktop/DBus",
					"org.freedesktop.DBus",
					"ReleaseName",
					g_variant_new("(s)", name),
					G_VARIANT_TYPE("(u)"),
					G_DBUS_CALL_FLAGS_NONE,
					-1, NULL, &error);
	if (ret == NULL) {
		WARN("%s", error->message);
		return;
	}

	g_variant_get(ret, "(u)", &request_name_reply);
	g_variant_unref(ret);

	if (request_name_reply != 1) {
		WARN("Unexpected reply");
		return;
	}

	release_dbus_connection();

	return;
}

static int request_name_on_dbus(const char *name)
{
	GDBusConnection *connection;
	GVariant *ret;
	guint32 request_name_reply;
	GError *error = NULL;

	if (conn)
		return 0;

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (connection == NULL) {
		DBG("%s", error->message);
		return -1;
	}

	ret = g_dbus_connection_call_sync(connection,
					"org.freedesktop.DBus",
					"/org/freedesktop/DBus",
					"org.freedesktop.DBus",
					"RequestName",
					g_variant_new("(su)",
						name,
						G_BUS_NAME_OWNER_FLAGS_NONE),
					G_VARIANT_TYPE("(u)"),
					G_DBUS_CALL_FLAGS_NONE,
					-1, NULL, &error);
	if (ret == NULL) {
		WARN("%s", error->message);
		goto failed;
	}

	g_variant_get(ret, "(u)", &request_name_reply);
	g_variant_unref(ret);

	/* RequestName will return the uint32 value:
	 * 1: DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
	 * 2: BUS_REQUEST_NAME_REPLY_IN_QUEUE
	 * 3: DBUS_REQUEST_NAME_REPLY_EXISTS
	 * 4: DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
	 * Also see dbus doc
	 */
	if (request_name_reply != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		DBG("Lost name");

		release_name_on_dbus(name);

		goto failed;
	}

	conn = connection;

	return 0;

failed:
	g_object_unref(connection);

	return -1;
}

static int create_agent(void)
{
	int ret;

	introspection_data =
		g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	ret = request_name_on_dbus(BLUEZ_AGENT_SERVICE);
	if (ret != 0)
		return -1;

	DBG("%s requested success", BLUEZ_AGENT_SERVICE);

	bluetooth_agent_id = g_dbus_connection_register_object(
						conn,
						AGENT_OBJECT_PATH,
						introspection_data->
							interfaces[0],
						&interface_handle,
						NULL,
						NULL,
						NULL);

	if (bluetooth_agent_id == 0)
		return -1;

	comms_bluetooth_register_pairing_agent(AGENT_OBJECT_PATH,
							NULL, NULL);

	return 0;
}

static int destory_agent(void)
{
	if (bluetooth_agent_id > 0) {
		comms_bluetooth_unregister_pairing_agent(AGENT_OBJECT_PATH,
								NULL, NULL);

		g_dbus_connection_unregister_object(conn, bluetooth_agent_id);

		bluetooth_agent_id = 0;

		release_name_on_dbus(BLUEZ_AGENT_SERVICE);
	}

	return 0;
}

int bt_agent_register(bt_agent *agent)
{
	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (agent == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (bluetooth_agent_id > 0)
		return BT_ERROR_ALREADY_DONE;

	if (this_agent != NULL)
		return BT_ERROR_ALREADY_DONE;

	create_agent();

	this_agent = agent;

	return BT_SUCCESS;
}

int bt_agent_unregister(void)
{
	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	destory_agent();

	this_agent = NULL;

	return BT_SUCCESS;
}

static void bt_agent_simple_accept(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void bt_agent_simple_reject(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
			ERROR_INTERFACE ".Rejected",
			"RejectedByUser");
}

void bt_agent_confirm_accept(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_accept(invocation);
}

void bt_agent_confirm_reject(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_reject(invocation);
}

void bt_agent_pincode_reply(const char *pin_code, bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", pin_code));
}

void bt_agent_pincode_cancel(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	g_dbus_method_invocation_return_dbus_error(invocation,
			ERROR_INTERFACE ".Canceled",
			"CanceledByUser");
}

struct spp_context {
	gchar *uuid;
	gchar *spp_path;
	GIOChannel *channel;
	bt_spp_new_connection_cb new_connection;
	void *new_connection_data;
};

GList *spp_ctx_list;

static GDBusNodeInfo *profile_xml_data;

static struct spp_context *create_spp_context(void)
{
	struct spp_context *spp_ctx;

	spp_ctx = g_try_new0(struct spp_context, 1);
	if (spp_ctx == NULL) {
		DBG("no memroy");
		return NULL;
	}

	return spp_ctx;
}

static void free_spp_context(struct spp_context *spp_ctx)
{
	if (spp_ctx == NULL)
		return;

	if (spp_ctx->uuid)
		g_free(spp_ctx->uuid);

	if (spp_ctx->spp_path)
		g_free(spp_ctx->spp_path);

	g_free(spp_ctx);
}

static struct spp_context *find_spp_context_from_uuid(const char *uuid)
{
	struct spp_context *spp_ctx;
	GList *list, *next;

	for (list = g_list_first(spp_ctx_list); list; list = next) {
		next = g_list_next(list);

		spp_ctx = list->data;

		if (spp_ctx && !g_strcmp0(spp_ctx->uuid, uuid))
			return spp_ctx;
	}

	return NULL;
}

static struct spp_context *find_spp_context_from_fd(int fd)
{
	struct spp_context *spp_ctx;
	GList *list, *next;
	int spp_fd;

	for (list = g_list_first(spp_ctx_list); list; list = next) {
		next = g_list_next(list);

		spp_ctx = list->data;

		spp_fd = g_io_channel_unix_get_fd(spp_ctx->channel);

		if (spp_ctx && spp_fd == fd)
			return spp_ctx;
	}

	return NULL;
}

static const gchar profile_xml[] =
	"<node>"
	"  <interface name='org.bluez.Profile1'>"
	"    <method name='Release'>"
	"    </method>"
	"    <method name='NewConnection'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='h' name='fd' direction='in'/>"
	"      <arg type='a{sv}' name='opts' direction='in'/>"
	"    </method>"
	"    <method name='RequestDisconnection'>"
	"      <arg type='o' name='device' direction='in'/>"
	"    </method>"
	"  </interface>"
	"</node>";

static gboolean received_data(GIOChannel *channel, GIOCondition con,
							gpointer user_data)
{
	bt_spp_received_data spp_data;
	struct spp_context *spp_ctx;
	GIOStatus status;
	gsize rbytes = 0;

	spp_ctx = user_data;
	if (spp_ctx == NULL) {
		WARN("no spp find");
		return FALSE;
	}

	if (!spp_data_received_node)
		goto done;

	spp_data.socket_fd = g_io_channel_unix_get_fd(channel);
	spp_data.data = g_try_new0(gchar, BT_SPP_BUFFER_MAX);

	status = g_io_channel_read_chars(channel, spp_data.data,
				BT_SPP_BUFFER_MAX - 1, &rbytes, NULL);
	if (status == G_IO_STATUS_ERROR) {
		DBG("read channel error");
		return FALSE;
	}

	spp_data.data_size = rbytes;

	if (spp_data_received_node->cb)
		spp_data_received_node->cb(&spp_data,
				spp_data_received_node->user_data);

	g_free(spp_data.data);

done:
	return TRUE;
}

static void notify_new_connection(gchar *device_path, gint fd,
					struct spp_context *spp_ctx)
{
	bluez_device_t *device;
	gchar *device_name;

	device = bluez_adapter_get_device_by_path(default_adapter,
						device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);

	if (spp_ctx->new_connection)
		spp_ctx->new_connection(spp_ctx->uuid, device_name,
					fd, spp_ctx->new_connection_data);

	g_free(device_name);
}

static void handle_new_connection(gchar *device_path, gint fd,
					GDBusMethodInvocation *invocation,
					void *user_data)
{
	struct spp_context *spp_ctx;
	GIOChannel *channel;

	spp_ctx = user_data;
	if (spp_ctx == NULL) {
		DBG("no spp context");
		return;
	}

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL) {
		ERROR("Create connection channel error");
		g_dbus_method_invocation_return_value(invocation, NULL);
		goto done;
	}

	spp_ctx->channel = channel;

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_add_watch(channel, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						received_data, user_data);

done:
	notify_new_connection(device_path, fd, spp_ctx);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_request_disconnection(gchar *device_path,
					GDBusMethodInvocation *invocation,
					void *user_data)
{
	DBG("device path %s", device_path);

	/* TODO: We should close the fd */

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_profile_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0)
		handle_release(invocation);
	else if (g_strcmp0(method_name, "NewConnection") == 0) {
		GDBusMessage *msg;
		GUnixFDList *fd_list;
		GVariantIter *opts;
		gchar *device_path;
		gint32 fd_index;
		gint fd;

		g_variant_get(parameters, "(oha{sv})",
					&device_path, &fd_index, &opts);

		msg = g_dbus_method_invocation_get_message(invocation);

		fd_list = g_dbus_message_get_unix_fd_list(msg);

		fd = g_unix_fd_list_get(fd_list, fd_index, NULL);

		handle_new_connection(device_path, fd, invocation, user_data);

		g_free(device_path);
		g_variant_iter_free(opts);
	} else if (g_strcmp0(method_name, "RequestDisconnection") == 0) {
		gchar *device_path;

		g_variant_get(parameters, "(o)", &device_path);

		handle_request_disconnection(device_path,
					invocation, user_data);

		g_free(device_path);
	} else
		DBG("Unknown method name %s", method_name);
}

static const GDBusInterfaceVTable profile_interface = {
	handle_profile_method_call,
	NULL,
	NULL
};

static int register_profile_agent(const gchar *path,
				struct spp_context *spp_ctx)
{
	int ret;

	if (profile_id > 0)
		return BT_SUCCESS;

	ret = request_name_on_dbus(BLUEZ_AGENT_SERVICE);
	if (ret != 0)
		goto failed;

	profile_xml_data = g_dbus_node_info_new_for_xml(profile_xml, NULL);

	profile_id = g_dbus_connection_register_object(conn, spp_ctx->spp_path,
					profile_xml_data->interfaces[0],
					&profile_interface,
					spp_ctx, NULL, NULL);

	if (profile_id == 0)
		goto failed;

	return BT_SUCCESS;

failed:
	return BT_ERROR_OPERATION_FAILED;
}

static void unregister_profile_agent(void)
{
	g_dbus_connection_unregister_object(conn, profile_id);

	g_dbus_node_info_unref(profile_xml_data);

	profile_id = 0;
}

gchar *generate_object_path_from_uuid(const gchar *prefix, const gchar *uuid)
{
	gchar *path, *iter;

	path = g_strdup_printf("%s/%s", prefix, uuid);

	iter = path;

	while (*iter) {
		if (*iter == '-')
			*iter = '_';

		iter++;
	}

	return path;
}

int bt_spp_create_rfcomm(const char *uuid,
			bt_spp_new_connection_cb new_connection_cb,
			void *user_data)
{
	enum bluez_error_type err_type;
	struct spp_context *spp_ctx;
	GVariantBuilder *opts;
	gchar *path;
	int ret;

	if (uuid == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	spp_ctx = create_spp_context();
	if (spp_ctx == NULL)
		return BT_ERROR_OUT_OF_MEMORY;

	path = generate_object_path_from_uuid(SPP_PROFILE_PATH, uuid);

	spp_ctx->spp_path = path;
	spp_ctx->uuid = g_strdup(uuid);
	spp_ctx->new_connection = new_connection_cb;
	spp_ctx->new_connection_data = user_data;

	ret = register_profile_agent(path, spp_ctx);
	if (ret != BT_SUCCESS) {
		free_spp_context(spp_ctx);
		return ret;
	}

	opts = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(opts, "{sv}", "Name",
					g_variant_new("s", "spp"));
	g_variant_builder_add(opts, "{sv}", "Version",
					g_variant_new("q", 1));

	err_type = bluez_profile_register_profile_sync(path, uuid, opts);

	if (err_type == ERROR_INVALID_ARGUMENTS) {
		unregister_profile_agent();

		release_name_on_dbus(BLUEZ_AGENT_SERVICE);

		free_spp_context(spp_ctx);

		return BT_ERROR_OPERATION_FAILED;
	}

	spp_ctx_list = g_list_append(spp_ctx_list, spp_ctx);

	return BT_SUCCESS;
}

int bt_spp_destroy_rfcomm(const char *uuid)
{
	struct spp_context *spp_ctx;

	if (uuid == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	spp_ctx = find_spp_context_from_uuid(uuid);
	if (spp_ctx == NULL) {
		WARN("no specified uuid");
		return BT_ERROR_OPERATION_FAILED;
	}

	bluez_profile_unregister_profile(spp_ctx->spp_path, NULL, NULL);

	unregister_profile_agent();

	release_name_on_dbus(BLUEZ_AGENT_SERVICE);

	spp_ctx_list = g_list_remove(spp_ctx_list, spp_ctx);

	g_io_channel_shutdown(spp_ctx->channel, TRUE, NULL);

	g_io_channel_unref(spp_ctx->channel);

	free_spp_context(spp_ctx);

	return BT_SUCCESS;
}

int bt_spp_connect_rfcomm(const char *remote_address,
					const char *service_uuid)
{
	bluez_device_t *device;

	DBG("");

	if (!remote_address || !service_uuid)
		return BT_ERROR_INVALID_PARAMETER;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_connect_profile(device, service_uuid,
					profile_connect_callback);

	return BT_SUCCESS;
}

int bt_spp_disconnect_rfcomm(const char *remote_address,
					const char *service_uuid)
{
	bluez_device_t *device;

	DBG("");

	if (!remote_address || !service_uuid)
		return BT_ERROR_INVALID_PARAMETER;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_disconnect_profile(device, service_uuid,
					profile_disconnect_callback);

	return BT_SUCCESS;
}

int bt_spp_accept(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_accept(invocation);

	return BT_SUCCESS;
}

int bt_spp_reject(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_reject(invocation);

	return BT_SUCCESS;
}

int bt_spp_set_connection_requested_cb(bt_spp_connection_requested_cb callback,
					void *user_data)
{
	struct spp_connection_requested_cb_node *node_data;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (spp_connection_requested_node) {
		DBG("spp connection requested callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct spp_connection_requested_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	spp_connection_requested_node = node_data;

	return BT_SUCCESS;
}

int bt_spp_unset_connection_requested_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!spp_connection_requested_node)
		return BT_SUCCESS;

	g_free(spp_connection_requested_node);
	spp_connection_requested_node = NULL;

	return BT_SUCCESS;
}

int bt_spp_send_data(int fd, const char *data, int length)
{
	struct spp_context *spp_ctx;
	gsize written = 0, count = 0;
	GIOStatus status;

	if (fd < 0)
		return BT_ERROR_INVALID_PARAMETER;

	spp_ctx = find_spp_context_from_fd(fd);
	if (spp_ctx == NULL) {
		WARN("no specified fd");
		return BT_ERROR_OPERATION_FAILED;
	}

	do {
		status = g_io_channel_write_chars(spp_ctx->channel, data,
						length, &count, NULL);

		written += count;

	} while (status != G_IO_STATUS_ERROR && written < length);

	if (status == G_IO_STATUS_ERROR)
		return BT_ERROR_OPERATION_FAILED;

	return BT_SUCCESS;
}

int bt_spp_set_data_received_cb(bt_spp_data_received_cb callback,
						void *user_data)
{
	struct spp_data_received_cb_node *node_data;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (spp_data_received_node) {
		DBG("SPP data received callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct spp_data_received_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	spp_data_received_node = node_data;

	return BT_SUCCESS;
}

int bt_spp_unset_data_received_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!spp_data_received_node)
		return BT_SUCCESS;

	g_free(spp_data_received_node);
	spp_data_received_node = NULL;

	return BT_SUCCESS;
}

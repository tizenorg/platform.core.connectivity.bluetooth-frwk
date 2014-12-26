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
#include "uuid.h"

#include "bluetooth.h"
#include "ntb-bluetooth.h"

#define ERROR_INTERFACE "org.tizen.comms.Error"
#define SPP_PROFILE_PATH "/bluetooth/profile/spp"

#define DEVICE_SERVICE_CLASS_DISCOVERABLE_MODE	0x002000

#define BT_STOP_DISCOVERY_TIMEOUT (1000*15)

#define BT_SPP_BUFFER_MAX 1024
#define BLUETOOTH_IDENT_LEN 6
#define CONNMAN_DBUS_NAME "net.connman"
#define CONNMAN_BLUETOOTH_SERVICE_PREFIX "/net/connman/service/bluetooth_"
#define CONNMAN_BLUETOOTH_TECHNOLOGY_PATH "/net/connman/technology/bluetooth"
#define CONNMAN_BLUETOTOH_TECHNOLOGY_INTERFACE "net.connman.Technology"

#define BLUEZ_AGENT_SERVICE "org.bluezlib.agent"
#define AGENT_INTERFACE "org.bluez.Agent1"
#define AGENT_OBJECT_PATH "/org/bluezlib/agent"

#define WRITE_REQUEST "write"
#define WRITE_COMMAND "write-without-response"

#define NEARD_AGENT_INTERFACE "org.neard.HandoverAgent"
#define NEARD_AGENT_PATH "/org/bluez/neard_handover_agent"

#define NEARD_SIZE 100
#define NEARD_CLASS 0x0D
#define NEARD_HASH 0x0E
#define NEARD_RANDOMIZER 0x0F

#define ADDRESS_LEN 20
static char pairing_address[ADDRESS_LEN];

#ifdef TIZEN_3
static GDBusMethodInvocation *reply_invocation;
#endif

static bool initialized;
static bool bt_service_init;

static guint bluetooth_agent_id;
static guint profile_id;
static GDBusConnection *conn;
static guint bluetooth_ext_agent_id;
static guint adapter_recover_timeout_id;

static bluez_adapter_t *default_adapter;

static guint event_id;

static void profile_connect_callback(bluez_device_t *device,
					enum device_profile_state state);

static void profile_disconnect_callback(bluez_device_t *device,
					enum device_profile_state state);

static GDBusConnection *get_system_dbus_connect(void);

static int request_name_on_dbus(const char *name);
static void release_name_on_dbus(const char *name);

static gboolean received_data(GIOChannel *channel, GIOCondition con,
							gpointer user_data);

typedef void (*bt_spp_new_connection_cb)(
			const char *uuid,
			const char *device_name,
			int fd,
			void *user_data);

struct spp_channel {
	GIOChannel *channel;
	guint io_watch;
	gchar *remote_address;
	gint io_shutdown;
};

struct spp_context {
	int fd;
	gchar *uuid;
	gchar *spp_path;
	GIOChannel *channel;
	GList *chan_list;
	bt_spp_new_connection_cb new_connection;
	void *new_connection_data;

	int max_pending;
	void *requestion;
	gboolean is_accept;
	bt_socket_role_e role;
};

typedef void (*bt_spp_connection_requested_cb) (
			const char *uuid,
			const char *remote_address,
			bt_req_t *requestion,
			void *user_data);

static int bt_spp_create_rfcomm(
			const char *uuid,
			bt_spp_new_connection_cb new_connection_cb,
			void *user_data);

static int bt_spp_destroy_rfcomm(const char *uuid);

static int bt_spp_connect_rfcomm(
			const char *remote_address,
			const char *service_uuid);

static int bt_spp_disconnect_rfcomm(
			const char *remote_address,
			const char *service_uuid);

static int bt_spp_accept(bt_req_t *requestion);

static int bt_spp_reject(bt_req_t *requestion);

typedef void (*bt_spp_connection_requested_cb) (
			const char *uuid,
			const char *remote_address,
			bt_req_t *requestion,
			void *user_data);

typedef struct {
	int socket_fd;  /**< The socket fd */
	int data_size;  /**< The length of the received data */
	char *data;     /**< The received data */
} bt_spp_received_data;

typedef void (*bt_spp_data_received_cb)(bt_spp_received_data *data,
			void *user_data);

static int bt_spp_set_data_received_cb(
			bt_spp_data_received_cb callback,
			void *user_data);

static int bt_spp_unset_data_received_cb(void);

struct device_connect_cb_node {
	bt_device_gatt_state_changed_cb cb;
	void *user_data;
};

struct device_disconnect_cb_node {
	bt_device_gatt_state_changed_cb cb;
	void *user_data;
};

struct device_created_cb_node {
	bt_adapter_device_discovery_state_changed_cb cb;
	void *user_data;
};

struct adapter_discovering_cb_node {
	bt_adapter_device_discovery_state_changed_cb cb;
	void *user_data;
};

struct adapter_visibility_duration_cb_node {
	bt_adapter_visibility_duration_changed_cb cb;
	void *user_data;
};

struct adapter_visibility_mode_cb_node {
	bt_adapter_visibility_mode_changed_cb cb;
	void *user_data;
};

struct bt_adapter_connectable_changed_cb_node {
	bt_adapter_connectable_changed_cb cb;
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

struct device_service_search_cb_node {
	bt_device_service_searched_cb cb;
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

struct avrcp_repeat_mode_changed_node {
	bt_avrcp_repeat_mode_changed_cb cb;
	void *user_data;
};

struct avrcp_set_shuffle_mode_changed_node {
	bt_avrcp_shuffle_mode_changed_cb cb;
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

struct panu_connection_state_changed_cb_node {
	bt_panu_connection_state_changed_cb cb;
	void *user_data;
};

struct hdp_connection_changed_cb_node {
	bt_hdp_connected_cb conn_cb;
	bt_hdp_disconnected_cb disconn_cb;
	void *user_data;
};

struct hdp_set_data_received_cb_node {
	bt_hdp_data_received_cb cb;
	void *user_data;
};

struct socket_connection_requested_cb_node {
	bt_socket_connection_requested_cb cb;
	void *user_data;
};

struct socket_connection_state_changed_cb_node {
	bt_socket_connection_state_changed_cb cb;
	void *user_data;
};

struct hid_host_connection_state_changed_cb_node {
	bt_hid_host_connection_state_changed_cb cb;
	void *user_data;
};

struct nap_connection_state_changed_cb_node {
	bt_nap_connection_state_changed_cb cb;
	void *user_data;
};

struct char_read_value_cb_node {
	bt_gatt_characteristic_read_cb cb;
	void *user_data;
};

struct char_write_value_cb_node {
	bt_gatt_characteristic_write_cb cb;
	void *user_data;
};

struct char_changed_cb_node {
	bt_gatt_characteristic_changed_cb cb;
	char *object_path;
	void *user_data;
};

static struct device_connect_cb_node *device_connect_node;
static struct device_disconnect_cb_node *device_disconnect_node;
static struct avrcp_repeat_mode_changed_node *avrcp_repeat_node;
static struct avrcp_set_shuffle_mode_changed_node *avrcp_shuffle_node;
static struct adapter_name_cb_node *adapter_name_node;
static struct device_created_cb_node *device_created_node;
static struct adapter_state_cb_node *adapter_state_node;
static struct adapter_discovering_cb_node *adapter_discovering_node;
static struct adapter_visibility_duration_cb_node
					*adapter_visibility_duration_node;
static struct bt_adapter_connectable_changed_cb_node
					*bt_adapter_connectable_changed_node;
static struct adapter_visibility_mode_cb_node *adapter_visibility_mode_node;
static struct device_destroy_unpaired_cb_node *unpaired_device_removed_node;
static struct device_bond_cb_node *device_bond_node;
static struct device_auth_cb_node *device_auth_node;
static struct device_destroy_paired_cb_node *paired_device_removed_node;
static struct device_connected_state_cb_node *device_connected_state_node;
static struct device_service_search_cb_node *device_service_search_node;
static struct spp_connection_requested_cb_node *spp_connection_requested_node;
static struct spp_data_received_cb_node *spp_data_received_node;
static struct avrcp_target_connection_state_changed_node
					*avrcp_target_state_node;
static struct audio_connection_state_changed_cb_node *audio_state_node;
static struct panu_connection_state_changed_cb_node *panu_state_node;
static struct hdp_connection_changed_cb_node *hdp_state_node;
static struct hdp_set_data_received_cb_node *hdp_set_data_received_node;

static struct socket_connection_requested_cb_node
					*socket_connection_requested_node;
static struct socket_connection_state_changed_cb_node
					*socket_connection_state_node;
static struct hid_host_connection_state_changed_cb_node *hid_host_state_node;
static struct nap_connection_state_changed_cb_node
				*nap_connection_state_changed_node;
static struct char_read_value_cb_node *char_read_value_node;
static struct char_write_value_cb_node *char_write_value_node;

static gboolean generic_device_removed_set;

static GList *char_changed_node_list;

static int bt_device_get_privileges(const char *remote_address)
{
	int user_privilieges;

	DBG("address = %s", remote_address);

	user_privilieges = comms_bluetooth_get_user_privileges_sync(
						remote_address);

	return user_privilieges;
}

static int service_by_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct char_changed_cb_node *node_data = a;
	const char *service_path = b;
	const char *object_path = node_data->object_path;

	return strcmp(service_path, object_path);
}

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
		adapter_device_discovery_info_t *device_discovery_info)
{
	bt_adapter_device_discovery_info_s *device_info;

	device_info = g_new0(bt_adapter_device_discovery_info_s, 1);
	if (device_info == NULL) {
		ERROR("no memory.");
		return NULL;
	}

	device_info->service_count = device_discovery_info->service_count;
	device_info->remote_address = device_discovery_info->remote_address;
	device_info->remote_name = device_discovery_info->remote_name;
	device_info->rssi = device_discovery_info->rssi;
	device_info->is_bonded = device_discovery_info->is_bonded;
	device_info->service_uuid = device_discovery_info->service_uuid;
	device_info->appearance = device_discovery_info->appearance;

	divide_device_class(&device_info->bt_class,
					device_discovery_info->bt_class);

	return device_info;
}

static void free_discovery_device_info(
		bt_adapter_device_discovery_info_s *discovery_device_info)
{
	if (discovery_device_info == NULL)
		return ;

	g_free(discovery_device_info);
}

static bt_device_info_s *get_device_info(bluez_device_t *device)
{
	guint len;
	int paired, connected, trusted;
	char *alias, *address;
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
	bluez_device_get_property_class(device, &class);
	bluez_device_get_property_paired(device, &paired);
	bluez_device_get_property_connected(device, &connected);
	bluez_device_get_property_trusted(device, &trusted);

	len = g_strv_length(uuids);

	device_info->service_count = len;
	device_info->remote_address = address;
	device_info->remote_name = alias;
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
	char *device_addr;
	struct device_destroy_paired_cb_node *data = user_data;
	adapter_device_discovery_info_t *device_info;

	DBG("");

	if (data == NULL)
		return;

	device_info = bluez_get_discovery_device_info(device);

	device_addr = device_info->remote_address;

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
	adapter_device_discovery_info_t *device_info;

	if (node == NULL)
		return;

	device_info = bluez_get_discovery_device_info(device);

	discovery_device_info = get_discovery_device_info(device_info);

	if (node->cb)
		node->cb(BT_SUCCESS, BT_ADAPTER_DEVICE_DISCOVERY_REMOVED,
				discovery_device_info, node->user_data);

	free_discovery_device_info(discovery_device_info);
}

static void handle_generic_device_removed(bluez_device_t *device, void *user_data)
{
	adapter_device_discovery_info_t *device_info;

	DBG("");

	device_info = bluez_get_discovery_device_info(device);

	if (device_info == NULL)
		return;

	if (device_info->is_bonded == false)
		bluez_unpaired_device_removed(device, unpaired_device_removed_node);
	else
		bluez_paired_device_removed(device, paired_device_removed_node);
}

static void set_device_removed_generic_callback(bluez_adapter_t *adapter)
{

	DBG("");

	bluez_adapter_set_device_removed_cb(adapter,
				handle_generic_device_removed, NULL);

	generic_device_removed_set = TRUE;
}

static bt_avrcp_repeat_mode_e loopstatus_to_enum(const gchar *repeat)
{
	DBG("repeat = %s", repeat);

	if (g_strcmp0(repeat, "None") == 0)
		return BT_AVRCP_REPEAT_MODE_OFF;
	else if (g_strcmp0(repeat, "Track") == 0)
		return BT_AVRCP_REPEAT_MODE_SINGLE_TRACK;
	else if (g_strcmp0(repeat, "Playlist") == 0)
		return BT_AVRCP_REPEAT_MODE_ALL_TRACK;
	return 0x00;
}

static void bluez_avrcp_repeat_changed(const gchar *repeat,
					void *user_data)
{
	bt_avrcp_repeat_mode_e repeat_mode;
	struct avrcp_repeat_mode_changed_node *data = user_data;

	repeat_mode = loopstatus_to_enum(repeat);

	if (data->cb)
		data->cb(repeat_mode, data->user_data);
}

static bt_avrcp_repeat_mode_e shuffle_to_enum(gboolean shuffle)
{
	if (shuffle) {
		DBG("shuffle is true");
		return BT_AVRCP_SHUFFLE_MODE_ALL_TRACK;
	} else {
		DBG("shuffle is false");
		return BT_AVRCP_SHUFFLE_MODE_OFF;
	}
}

static void bluez_avrcp_shuffle_changed(gboolean shuffle,
					void *user_data)
{
	bt_avrcp_shuffle_mode_e shuffle_mode;
	struct avrcp_set_shuffle_mode_changed_node *data =
						user_data;

	shuffle_mode = shuffle_to_enum(shuffle);

	if (data->cb)
		data->cb(shuffle_mode, data->user_data);
}

static void bluez_nap_connection_changed(gboolean connected,
				const char *remote_address,
				const char *interface_name,
				void *user_data)
{
	struct nap_connection_state_changed_cb_node *data =
						user_data;

	if (data->cb)
		data->cb(connected, remote_address,
			interface_name, data->user_data);
}

static void bluez_char_read_received_changed(
				struct _bluez_gatt_char *characteristic,
				unsigned char *value_array,
				int value_length,
				void *user_data)
{
	struct char_read_value_cb_node *data = user_data;

	if (data->cb)
		data->cb(value_array, value_length,
			data->user_data);

	g_free(char_read_value_node);
	char_read_value_node = NULL;
}

static void bluez_char_write_received_changed(
				struct _bluez_gatt_char *characteristic,
				void *user_data)
{
	struct char_write_value_cb_node *data = user_data;
	char *gatt_char_path;

	gatt_char_path = bluez_gatt_char_get_object_path(characteristic);

	if (data->cb)
		data->cb(gatt_char_path);

	g_free(char_write_value_node);
	char_write_value_node = NULL;
}

static void bluez_char_value_changed(
				struct _bluez_gatt_char *characteristic,
				unsigned char *value_array,
				int value_length,
				void *user_data)
{
	struct char_changed_cb_node *data = user_data;
	char *gatt_char_path;

	gatt_char_path = bluez_gatt_char_get_object_path(characteristic);

	if (data->cb)
		data->cb(gatt_char_path,
			value_array, value_length,
			data->user_data);
}

static void bluez_set_data_received_changed(
				unsigned int channel,
				const char *data,
				unsigned int size,
				void *user_data)
{
	struct hdp_set_data_received_cb_node *data_node =
						user_data;

	if (data_node->cb)
		data_node->cb(channel, data, size,
				data_node->user_data);
}

static void bluez_hdp_state_changed(int result,
				const char *remote_address,
				const char *app_id,
				enum hdp_channel_type type,
				unsigned int channel,
				void *user_data)
{
	struct hdp_connection_changed_cb_node *data = user_data;
	bt_hdp_channel_type_e channel_type;

	if (app_id == NULL)
		return;

	if (type == HDP_CHANNEL_RELIABLE)
		channel_type = BT_HDP_CHANNEL_TYPE_RELIABLE;
	else
		channel_type = BT_HDP_CHANNEL_TYPE_STREAMING;

	if (data->conn_cb)
		data->conn_cb(result, remote_address, app_id,
				channel_type, channel, data->user_data);

	if (data->disconn_cb)
		data->disconn_cb(result, remote_address,
				channel, data->user_data);
}

static void bluez_avrcp_target_state_changed(const char *remote_address,
					gboolean connected,
					void *user_data)
{
	struct avrcp_target_connection_state_changed_node *data =
							user_data;

	DBG("");

	if (data->cb)
		(data->cb)(connected, remote_address,
						data->user_data);
}

static void bluez_audio_state_changed(int result,
					gboolean connected,
					const char *remote_address,
					enum audio_profile_type type,
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
	bt_device_connection_info_s conn_info;
	char *device_address;

	DBG("");

	device_address = bluez_device_get_property_address(device);
	conn_info.remote_address = device_address;
	conn_info.link = BT_DEVICE_CONNECTION_LINK_DEFAULT;
	conn_info.disconn_reason = BT_DEVICE_DISCONNECT_REASON_UNKNOWN;

	node->cb(connected, &conn_info, node->user_data);

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

static void device_panu_connected_changed(bluez_device_t *device,
					int connected, void *user_data)
{
	struct panu_connection_state_changed_cb_node *node = user_data;
	char *device_address;

	DBG("");

	device_address = bluez_device_get_property_address(device);

	node->cb(BT_SUCCESS, connected, device_address,
			BT_PANU_SERVICE_TYPE_NAP, node->user_data);

	g_free(device_address);
}

static void device_hid_connected_changed(bluez_device_t *device,
					int connected, void *user_data)
{
	struct hid_host_connection_state_changed_cb_node *node = user_data;
	char *device_address;

	DBG("");

	device_address = bluez_device_get_property_address(device);

	node->cb(BT_SUCCESS, connected, device_address, node->user_data);

	g_free(device_address);
}

static unsigned int dev_property_callback_flags;

enum bluez_device_property_callback_flag {
	DEV_PROP_FLAG_PAIR = 0x01,
	DEV_PROP_FLAG_CONNECT = 0x02,
	DEV_PROP_FLAG_AUTH = 0x04,
	DEV_PROP_FLAG_PANU_CONNECT = 0x08,
	DEV_PROP_FLAG_HDP_CONNECT = 0x10,
	DEV_PROP_FLAG_HDP_DATA = 0x20,
	DEV_PROP_FLAG_HID_CONNECT = 0x40
};

static void set_device_property_changed_callback(bluez_device_t *device)
{
	DBG("");

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

	if (dev_property_callback_flags & DEV_PROP_FLAG_PANU_CONNECT)
		bluez_device_network_set_connected_changed_cb(device,
					device_panu_connected_changed,
					panu_state_node);

	if (dev_property_callback_flags & DEV_PROP_FLAG_HDP_CONNECT)
		bluez_set_hdp_state_changed_cb(device,
					bluez_hdp_state_changed,
					hdp_state_node);

	if (dev_property_callback_flags & DEV_PROP_FLAG_HDP_DATA)
		bluez_set_data_received_changed_cb(device,
					bluez_set_data_received_changed,
					hdp_set_data_received_node);

	if (dev_property_callback_flags & DEV_PROP_FLAG_HID_CONNECT)
		bluez_device_input_set_connected_changed_cb(device,
					device_hid_connected_changed,
					hid_host_state_node);

}

static void unset_device_property_changed_callback(bluez_device_t *device)
{
	DBG("");

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_PAIR))
		bluez_device_unset_paired_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_CONNECT))
		bluez_device_unset_connected_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_AUTH))
		bluez_device_unset_trusted_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_PANU_CONNECT))
		bluez_device_network_unset_connected_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_HDP_CONNECT))
		bluez_unset_hdp_state_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_HDP_DATA))
		bluez_unset_data_received_changed_cb(device);

	if (!(dev_property_callback_flags & DEV_PROP_FLAG_HID_CONNECT))
		bluez_device_input_unset_connected_changed_cb(device);
}

static void foreach_device_property_callback(GList *list, unsigned int flag)
{
	bluez_device_t *device;
	GList *iter, *next;

	DBG("");

	for (iter = g_list_first(list); iter; iter = next) {
		next = g_list_next(iter);

		device = iter->data;

		if (dev_property_callback_flags & flag)
			set_device_property_changed_callback(device);
		else
			unset_device_property_changed_callback(device);
	}
}

static void foreach_characteristic_property_callback(GList *list,
						void *user_data)
{
	struct char_changed_cb_node *node_data = user_data;
	bluez_gatt_char_t *characteristic;
	GList *iter, *next;

	DBG("");

	for (iter = g_list_first(list); iter; iter = next) {
		next = g_list_next(iter);

		characteristic = iter->data;

		if (node_data)
			bluez_set_char_value_changed_cb(characteristic,
						bluez_char_value_changed,
						node_data);
		else
			bluez_unset_char_value_changed_cb(characteristic);
	}

}

static void bluez_device_created(bluez_device_t *device, void *user_data)
{
	bt_adapter_device_discovery_info_s *discovery_device_info;
	struct device_created_cb_node *node = user_data;
	adapter_device_discovery_info_t *device_info;

	DBG("");

	device_info = bluez_get_discovery_device_info(device);

	discovery_device_info = get_discovery_device_info(device_info);

	DBG("name: %s, uuid: %p, uuid_count: %d", discovery_device_info->remote_name,
						discovery_device_info->service_uuid,
						discovery_device_info->service_count);

	if (node && node->cb)
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
	bt_adapter_device_discovery_info_s *discovery_device_info;
	GList *device_list, *list, *next;
	bluez_device_t *device;

	DBG("");

	state = discovering ? BT_ADAPTER_DEVICE_DISCOVERY_STARTED :
				BT_ADAPTER_DEVICE_DISCOVERY_FINISHED;

	if (!node || !node->cb)
		return;

	node->cb(BT_SUCCESS, state, NULL, node->user_data);

	/*
	 * BlueZ 5.x may contain some discovering device a short time.
	 * When UI start discovery, the last discovering device may
	 * not dispear, also notify tham.
	 */
	if (state != BT_ADAPTER_DEVICE_DISCOVERY_STARTED)
		return;

	device_list = bluez_adapter_get_devices(default_adapter);
	for (list = g_list_first(device_list); list; list = next) {
		adapter_device_discovery_info_t *device_info;

		DBG("device discoverying changed");

		next = g_list_next(list);

		device = list->data;

		device_info = bluez_get_discovery_device_info(device);

		discovery_device_info = get_discovery_device_info(device_info);

		node->cb(BT_SUCCESS, BT_ADAPTER_DEVICE_DISCOVERY_FOUND,
				discovery_device_info, node->user_data);

		set_device_property_changed_callback(device);

		free_discovery_device_info(discovery_device_info);
	}
}

void adapter_name_changed(bluez_adapter_t *adapter,
				const gchar *name,
				void *user_data)
{
	struct adapter_name_cb_node *data =
			(struct adapter_name_cb_node *)user_data;
	gchar *adapter_name = g_strdup(name);

	data->cb(adapter_name, data->user_data);

	g_free(adapter_name);
}

static void discoverable_timeout_changed(bluez_adapter_t *adapter,
					guint32 timeout, void *user_data)
{
	struct adapter_visibility_duration_cb_node *node = user_data;

	node->cb(timeout, node->user_data);
}

static void adapter_discoverable_changed(bluez_adapter_t *adapter,
				gboolean discoverable, void *user_data)
{
	struct adapter_visibility_mode_cb_node *node = user_data;
	bt_adapter_visibility_mode_e discoverable_mode;
	unsigned int discoverable_timeout;

	if (!discoverable){
		discoverable_mode =
			BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
		goto done;
	}

	discoverable_timeout = comms_manager_get_bt_adapter_visibale_time();
	if (discoverable_timeout == -1) {
		node->cb(BT_ERROR_OPERATION_FAILED, 0, node->user_data);
		return;
	}

	discoverable_mode = (discoverable_timeout == 0) ?
			BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE :
			BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE;

done:
	node->cb(BT_SUCCESS, discoverable_mode, node->user_data);
}

static void bluez_device_connect_changed(bluez_device_t *device,
					enum device_state state,
					gpointer user_data)
{
	struct device_connect_cb_node *data = user_data;

	switch (state) {
	case DEVICE_CONNECT_SUCCESS:
		DBG("Connect device: %s", "DEVICE_CONNECT_SUCCESS");
		break;
	case DEVICE_NOT_READY:
		DBG("Connect device: %s", "DEVICE_NOT_READY");
		break;
	case DEVICE_ALREADY_CONNECTED:
		DBG("Connect device: %s", "DEVICE_ALREADY_CONNECTED");
		break;
	case DEVICE_CONNECT_FAILED:
		DBG("Connect device: %s", "DEVICE_CONNECT_FAILED");
		break;
	case DEVICE_CONNECT_INPROGRESS:
		DBG("Connect device: %s", "DEVICE_CONNECT_INPROGRESS");
		break;
	default:
		ERROR("Unknown error code");
		break;
	}

	if (data->cb)
		data->cb(state, data->user_data);

}

static void bluez_device_disconnect_changed(bluez_device_t *device,
					enum device_state state,
					gpointer user_data)
{
	struct device_disconnect_cb_node *data = user_data;

	switch (state) {
	case DEVICE_DISCONNECT_SUCCESS:
		DBG("Disconnect device: %s", "DEVICE_DISCONNECT_SUCCESS");
		break;
	case DEVICE_NOT_CONNECTED:
		DBG("Disconnect device: %s", "DEVICE_NOT_CONNECTED");
		break;
	default:
		ERROR("Unknown error code");
		break;
	}

	if (data->cb)
		data->cb(state, data->user_data);
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

	if (adapter_visibility_duration_node)
		bluez_adapter_set_discoverable_timeout_changed_cb(
					default_adapter,
					discoverable_timeout_changed,
					adapter_visibility_duration_node);

	if (adapter_visibility_mode_node)
		bluez_adapter_set_discoverable_changed_cb(default_adapter,
					adapter_discoverable_changed,
					adapter_visibility_mode_node);

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

	if (avrcp_repeat_node)
		bluez_set_avrcp_repeat_cb(
					bluez_avrcp_repeat_changed,
					avrcp_repeat_node);

	if (avrcp_shuffle_node)
		bluez_set_avrcp_shuffle_cb(
					bluez_avrcp_shuffle_changed,
					avrcp_shuffle_node);

	if (device_connect_node)
		bluez_set_device_connect_changed_cb(
					bluez_device_connect_changed,
					device_connect_node);

	if (device_disconnect_node)
		bluez_set_device_disconnect_changed_cb(
					bluez_device_disconnect_changed,
					device_disconnect_node);

	if (nap_connection_state_changed_node)
		bluez_set_nap_connection_state_cb(
					bluez_nap_connection_changed,
					nap_connection_state_changed_node);

	if (char_read_value_node)
		bluez_set_char_read_value_cb(
					bluez_char_read_received_changed,
					char_read_value_node);

	if (char_write_value_node)
		bluez_set_char_write_value_cb(
					bluez_char_write_received_changed,
					char_write_value_node);
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
	DBG("%d", in_service);
}

int ntb_bt_initialize(void)
{
	if (bt_service_init)
		return BT_SUCCESS;

	comms_lib_init();

	comms_manager_set_bt_in_service_watch(
				_bt_service_bt_in_service_watch, NULL);

	bt_service_init = TRUE;

	char_changed_node_list = NULL;

	setup_bluez_lib();

	return BT_SUCCESS;
}

int ntb_bt_deinitialize(void)
{
	if (bt_service_init == false)
		return BT_SUCCESS;

	destroy_bluez_lib();

	comms_manager_remove_bt_in_service_watch();

	bt_service_init = FALSE;

	return BT_SUCCESS;
}

int ntb_bt_adapter_enable(void)
{
	DBG("");

	if (bt_service_init == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (adapter_recover_timeout_id)
		return BT_ERROR_NOW_IN_PROGRESS;

	comms_manager_enable_bluetooth();

	return BT_SUCCESS;
}

int ntb_bt_adapter_disable(void)
{
	DBG("");

	if (bt_service_init == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (adapter_recover_timeout_id > 0) {
		g_source_remove(adapter_recover_timeout_id);
		adapter_recover_timeout_id = 0;
	}

	comms_manager_disable_bluetooth();

	return BT_SUCCESS;
}

int ntb_bt_adapter_get_state(bt_adapter_state_e *adapter_state)
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

int ntb_bt_adapter_get_address(char **local_address)
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

int ntb_bt_adapter_get_name(char **local_name)
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

int ntb_bt_adapter_set_name(const char *local_name)
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

int ntb_bt_adapter_set_name_changed_cb(bt_adapter_name_changed_cb callback,
					void *user_data)
{
	struct adapter_name_cb_node *node_data;

	DBG("");

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

int ntb_bt_adapter_unset_name_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!adapter_name_node)
		return BT_SUCCESS;

	bluez_adapter_unset_alias_changed_cb(default_adapter);

	g_free(adapter_name_node);
	adapter_name_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_adapter_get_visibility(bt_adapter_visibility_mode_e *mode,
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

	timeout = comms_manager_get_bt_adapter_visibale_time();
	if (timeout == -1)
		return BT_ERROR_OPERATION_FAILED;

	if (duration)
		*duration = 0;

	if (!discoverable){
		*mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
		return BT_SUCCESS;
	}

	*mode = (timeout == 0) ?
			BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE :
			BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE;

	if (*mode == BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE
			&& duration != NULL)
		*duration = timeout;

	return BT_SUCCESS;
}

int ntb_bt_adapter_set_visibility(bt_adapter_visibility_mode_e discoverable_mode,
				int duration)
{
	int discoverable;
	bool connectable;
	int ret;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	switch (discoverable_mode) {
	case BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE:
		discoverable = false;
		duration = 0;
		break;
	case BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE:
		discoverable = true;
		break;
	case BT_ADAPTER_VISIBILITY_MODE_GENERAL_DISCOVERABLE:
		discoverable = true;
		duration = 0;
		break;
	default:
		return BT_ERROR_INVALID_PARAMETER;
	}

	ret = ntb_bt_adapter_get_connectable(&connectable);
	if (ret != 0)
		return BT_ERROR_OPERATION_FAILED;

	if (connectable) {
		bluez_adapter_set_discoverable_timeout(default_adapter,
							duration);

		bluez_adapter_set_discoverable(default_adapter,
							discoverable);
	} else {
		DBG("connectable is set");
		return BT_ERROR_OPERATION_FAILED;
	}

	return BT_SUCCESS;
}

static gboolean bt_stop_discovery_timeout_cb(gpointer user_data)
{
	event_id = 0;

	ntb_bt_adapter_stop_device_discovery();

	return FALSE;
}

static void bt_stop_discovery_timeout(void)
{
	if (event_id > 0)
		return;

	event_id = g_timeout_add(BT_STOP_DISCOVERY_TIMEOUT,
		(GSourceFunc)bt_stop_discovery_timeout_cb, NULL);
}

int ntb_bt_adapter_start_device_discovery(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	bluez_adapter_start_discovery(default_adapter);

	bt_stop_discovery_timeout();

	return BT_SUCCESS;
}

int ntb_bt_adapter_stop_device_discovery(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	bluez_adapter_stop_discovery(default_adapter);

	return BT_SUCCESS;
}

int ntb_bt_adapter_is_discovering(bool *is_discovering)
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

int ntb_bt_adapter_is_service_used(const char *service_uuid, bool *used)
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

int ntb_bt_adapter_set_device_discovery_state_changed_cb(
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

int ntb_bt_adapter_set_state_changed_cb(bt_adapter_state_changed_cb callback,
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

int ntb_bt_adapter_set_visibility_duration_changed_cb(
			bt_adapter_visibility_duration_changed_cb callback,
			void *user_data)
{
	struct adapter_visibility_duration_cb_node *node_data;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (adapter_visibility_duration_node) {
		DBG("duration changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct adapter_visibility_duration_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	adapter_visibility_duration_node = node_data;

	_bt_update_bluetooth_callbacks();
	return BT_SUCCESS;
}

int ntb_bt_adapter_set_visibility_mode_changed_cb(
			bt_adapter_visibility_mode_changed_cb callback,
			void *user_data)
{
	struct adapter_visibility_mode_cb_node *node_data;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (adapter_visibility_mode_node) {
		DBG("visibility mode changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct adapter_visibility_mode_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	adapter_visibility_mode_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int ntb_bt_adapter_unset_state_changed_cb(void)
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

int ntb_bt_adapter_unset_device_discovery_state_changed_cb(void)
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

	if (unpaired_device_removed_node) {
		g_free(unpaired_device_removed_node);
		unpaired_device_removed_node = NULL;
	}

	if (paired_device_removed_node == NULL &&
			generic_device_removed_set == TRUE) {
		bluez_adapter_unset_device_removed_cb(default_adapter);

		generic_device_removed_set = FALSE;
	}

	return BT_SUCCESS;
}

int ntb_bt_adapter_unset_visibility_duration_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!adapter_visibility_duration_node)
		return BT_SUCCESS;

	bluez_adapter_unset_discoverable_timeout_changed_cb(default_adapter);

	g_free(adapter_visibility_duration_node);
	adapter_visibility_duration_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_adapter_unset_visibility_mode_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!adapter_visibility_mode_node)
		return BT_SUCCESS;

	bluez_adapter_unset_discoverable_changed_cb(default_adapter);

	g_free(adapter_visibility_mode_node);
	adapter_visibility_mode_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_adapter_reset(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int ntb_bt_adapter_foreach_bonded_device(bt_adapter_bonded_device_cb callback,
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

int ntb_bt_adapter_get_bonded_device_info(const char *remote_address,
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

int ntb_bt_adapter_free_device_info(bt_device_info_s *device_info)
{
	if (!device_info)
		return BT_ERROR_INVALID_PARAMETER;

	free_device_info(device_info);

	return BT_SUCCESS;
}

int ntb_bt_adapter_get_version(char **version)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	return BT_ERROR_NOT_SUPPORTED;
}

int ntb_bt_adapter_get_local_info(char **chipset, char **firmware,
				char **stack_version, char **profiles)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	return BT_ERROR_NOT_SUPPORTED;
}

gboolean get_neard_data(const unsigned char *peir, unsigned char **hash,
		unsigned char **randomizer, int *hash_len, int *randomizer_len)
{
	int head_len = sizeof(uint16_t) + 6;

	DBG("");

	peir += head_len;

	while (*peir != 0) {
		peir++;
		if (*peir == NEARD_CLASS) {
			peir += 4;
		} else if (*peir == NEARD_HASH) {
			memcpy(*hash, peir, 16);
			*hash_len = 16;
			peir += 17;
		} else if (*peir == NEARD_RANDOMIZER) {
			memcpy(*randomizer, peir, 16);
			*randomizer_len = 16;
			peir += 17;
			return TRUE;
		}
	}

	return FALSE;
}

int bt_adapter_get_local_oob_data(unsigned char **hash,
				unsigned char **randomizer,
				int *hash_len, int *randomizer_len)
{
	GVariant *val, *result;
	GDBusConnection *connection;
	GVariantBuilder *builder;
	GError *error = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (hash == NULL || randomizer == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return BT_ERROR_OPERATION_FAILED;

	val = g_variant_new("s", "active");
	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	g_variant_builder_add(builder, "{sv}", "State", val);

	result = g_dbus_connection_call_sync(connection, BLUEZ_NAME,
				NEARD_AGENT_PATH,
				NEARD_AGENT_INTERFACE,
				"RequestOOB",
				g_variant_new("(a{sv})", builder),
				NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	if (result != NULL) {
		if (g_variant_is_of_type(val, G_VARIANT_TYPE("(a{sv})"))) {
			GVariantIter *iter;
			GVariant *item;

			g_variant_get(result, "(a{sv})", &iter);
			while ((item = g_variant_iter_next_value(iter))) {
				const unsigned char *peir;
				gboolean is_fin;
				gchar *key;
				GVariant *value;
				gsize n_elts;

				g_variant_get(item, "{sv}", &key, &value);
				if (g_strcmp0("EIR", key) == 0) {
					g_variant_get(value, "(ay)", &peir);
					peir = g_variant_get_fixed_array(value,
						&n_elts, sizeof(unsigned char));
					if (peir == NULL || n_elts < 0) {
						DBG("Err");
						goto done;
					}
					is_fin = get_neard_data(peir,
							hash, randomizer,
							hash_len,
							randomizer_len);
					if (!is_fin) {
						DBG("is_fin failed");
						goto done;
					}
				}
			}
		}
	}

	return BT_SUCCESS;
done:
	return BT_ERROR_OPERATION_FAILED;
}

unsigned char *set_neard_data(const char *remote_address,
			unsigned char *hash, unsigned char *randomizer,
			int hash_len, int randomizer_len)
{
	unsigned char *peir = g_malloc0(NEARD_SIZE);
	unsigned char *data = peir;
	unsigned char *baddr;

	DBG("");

	if (data == NULL) {
		DBG("failed");
		return NULL;
	}

	data += sizeof(uint16_t);

	baddr = convert_address_to_baddr(remote_address);
	if (baddr == NULL) {
		DBG("baddr failed");
		g_free(peir);
		return NULL;
	}

	memcpy(data, baddr, 6);
	data += 6;
	g_free(baddr);

	*data++ = 17;
	*data++ = NEARD_HASH;

	memcpy(data, hash, hash_len);
	data += 16;

	*data++ = 17;
	*data++ = NEARD_RANDOMIZER;

	memcpy(data, randomizer, randomizer_len);
	data += 16;

	return peir;
}

int bt_adapter_set_remote_oob_data(const char *remote_address,
				unsigned char *hash,
				unsigned char *randomizer,
				int hash_len, int randomizer_len)
{
	GVariant *val;
	GDBusConnection *connection;
	GVariantBuilder *builder;
	unsigned char *peir;
	GError *error = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL ||
			hash == NULL || randomizer == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return BT_ERROR_OPERATION_FAILED;

	peir = set_neard_data(remote_address, hash, randomizer,
					hash_len, randomizer_len);

	if (peir == NULL) {
		DBG("peir failed");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE_ARRAY);
	val = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, peir,
				G_N_ELEMENTS(peir), sizeof(peir[0]));
	g_variant_builder_add(builder, "{sv}", "EIR", val);

	val = g_variant_new("s", "active");
	g_variant_builder_add(builder, "{sv}", "State", val);

	g_dbus_connection_call_sync(connection, BLUEZ_NAME,
				NEARD_AGENT_PATH,
				NEARD_AGENT_INTERFACE,
				"PushOOB",
				g_variant_new("(a{sv})", builder),
				NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	g_free(peir);
	return BT_SUCCESS;
}

int bt_adapter_remove_remote_oob_data(const char *remote_address)
{
	GDBusConnection *connection;
	GError *error = NULL;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return BT_ERROR_OPERATION_FAILED;

	g_dbus_connection_call_sync(connection, BLUEZ_NAME,
				NEARD_AGENT_PATH,
				NEARD_AGENT_INTERFACE,
				"Release",
				NULL,
				NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	return BT_SUCCESS;
}

int ntb_bt_device_get_service_mask_from_uuid_list(char **uuids,
					int no_of_service,
					bt_service_class_t *service_mask_list)
{
	int i = 0;
	char **parts = NULL;
	bt_service_class_t service_mask = 0;

	DBG("");

	if (*uuids == NULL || service_mask_list == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	DBG("no_of_service = %d", no_of_service);

	for (i = 0; i < no_of_service; i++) {
		parts = g_strsplit(uuids[i], "-", -1);
		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			continue;
		}

		if (!g_strcmp0(SPP_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_SPP_SERVICE_MASK;
		else if (!g_strcmp0(LAP_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_LAP_SERVICE_MASK;
		else if (!g_strcmp0(DUN_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_DUN_SERVICE_MASK;
		else if (!g_strcmp0(OBEX_SYNC_SERVICE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_SYNC_SERVICE_MASK;
		else if (!g_strcmp0(OBEX_PUSH_SERVICE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_OPP_SERVICE_MASK;
		else if (!g_strcmp0(OBEX_FILE_TRANSFER_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_FTP_SERVICE_MASK;
		else if (!g_strcmp0(HS_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_HSP_SERVICE_MASK;
		else if (!g_strcmp0(CTP_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_CTP_SERVICE_MASK;
		else if (!g_strcmp0(AUDIO_SOURCE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(AUDIO_SINK_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_A2DP_SERVICE_MASK;
		else if (!g_strcmp0(VIDEO_SOURCE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(VIDEO_SINK_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(AV_REMOTE_CONTROL_TARGET_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(ADVANCED_AUDIO_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_A2DP_SERVICE_MASK;
		else if (!g_strcmp0(AV_REMOTE_CONTROL_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_AVRCP_SERVICE_MASK;
		else if (!g_strcmp0(ICP_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_ICP_SERVICE_MASK;
		else if (!g_strcmp0(FAX_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_FAX_SERVICE_MASK;
		else if (!g_strcmp0(HEADSET_AG_SERVICE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(PAN_PANU_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_PANU_SERVICE_MASK;
		else if (!g_strcmp0(PAN_NAP_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NAP_SERVICE_MASK;
		else if (!g_strcmp0(PAN_GN_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_GN_SERVICE_MASK;
		else if (!g_strcmp0(REFERENCE_PRINTING_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(OBEX_IMAGING_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(OBEX_IMAGING_RESPONDER_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_BIP_SERVICE_MASK;
		else if (!g_strcmp0(HF_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_HFP_SERVICE_MASK;
		else if (!g_strcmp0(HFG_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(
				DIRECT_PRINTING_REFERENCE_OBJ_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(BASIC_PRINTING_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(HID_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_HID_SERVICE_MASK;
		else if (!g_strcmp0(SIM_ACCESS_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_SAP_SERVICE_MASK;
		else if (!g_strcmp0(OBEX_PBAP_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_PBAP_SERVICE_MASK;
		else if (!g_strcmp0(OBEX_BPPS_PROFILE_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_BPP_SERVICE_MASK;
		else if (!g_strcmp0(PNP_INFORMATION_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(OBEX_PRINTING_STATUS_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_BPP_SERVICE_MASK;
		else if (!g_strcmp0(HCR_PROFILE_UUID_HEAD, parts[0]))
			service_mask |= BT_SC_NONE;
		else if (!g_strcmp0(OBEX_SYNCML_TRANSFER_UUID_HEAD,
							parts[0]))
			service_mask |= BT_SC_NONE;

		g_strfreev(parts);
	}

	*service_mask_list = service_mask;

	return BT_ERROR_NONE;
}

static gboolean adapter_recover_timeout_cb(gpointer user_data)
{
	DBG("");

	adapter_recover_timeout_id = 0;
	ntb_bt_adapter_enable();

	return FALSE;
}

int ntb_bt_adapter_recover(void)
{
	DBG("");

	if (adapter_recover_timeout_id != 0)
		return BT_ERROR_NOW_IN_PROGRESS;

	if (ntb_bt_adapter_disable() == BT_SUCCESS) {
		adapter_recover_timeout_id = g_timeout_add(2000,
					adapter_recover_timeout_cb, NULL);
	} else
		return BT_ERROR_INVALID_PARAMETER;

	return BT_SUCCESS;
}

static void adapter_connectable_watch(int result,
				gboolean connectable, void *user_data)
{
	DBG("result = %d, connectable = %d", result, connectable);
	if (bt_adapter_connectable_changed_node &&
				bt_adapter_connectable_changed_node->cb)
		bt_adapter_connectable_changed_node->cb(
				result, connectable,
				bt_adapter_connectable_changed_node->user_data);
}

int ntb_bt_adapter_set_connectable_changed_cb(
	bt_adapter_connectable_changed_cb callback, void *user_data)
{
	struct bt_adapter_connectable_changed_cb_node *node_data;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (bt_adapter_connectable_changed_node) {
		DBG("visibility mode changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct bt_adapter_connectable_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	bt_adapter_connectable_changed_node = node_data;

	adapter_connectable_set_service_watch(adapter_connectable_watch, NULL);

	return BT_SUCCESS;
}

int ntb_bt_adapter_unset_connectable_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!bt_adapter_connectable_changed_node)
		return BT_SUCCESS;

	adapter_connectable_remove_service_watch();

	g_free(bt_adapter_connectable_changed_node);
	bt_adapter_connectable_changed_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_adapter_get_connectable(bool *connectable)
{
	int ret;
	gboolean conn;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (connectable == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	ret = comms_manager_get_connectable(&conn);

	if (ret != 0)
		return BT_ERROR_OPERATION_FAILED;

	*connectable = (bool)conn;

	return BT_SUCCESS;
}

int ntb_bt_adapter_set_connectable(bool connectable)
{
	int ret;

	DBG("connectable = %d", connectable);

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	ret = comms_manager_set_connectable(connectable);

	if (ret != 0)
		return BT_ERROR_OPERATION_FAILED;

	return BT_SUCCESS;
}

/* Device Function */

int ntb_bt_device_create_bond_by_type(const char *remote_address,
				bt_device_connection_link_type_e conn_type)
{
	/*at current, bluez doesn't support the feature*/
	return BT_ERROR_NOT_SUPPORTED;
}

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

	/* Pair a device success, will report through DISCOVERY EVENT */
	if (error == ERROR_NONE)
		return;

	switch (error) {
	case ERROR_INVALID_ARGUMENTS:
		capi_error = BT_ERROR_INVALID_PARAMETER;
		break;
	case ERROR_FAILED:
		capi_error = BT_ERROR_OPERATION_FAILED;
		break;
	case ERROR_AUTH_CANCELED:
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

int ntb_bt_device_create_bond(const char *remote_address)
{
	int user_privilieges;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	memset(pairing_address, 0, ADDRESS_LEN);
	strcpy(pairing_address, remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		memset(pairing_address, 0, ADDRESS_LEN);
		return BT_ERROR_NOT_ENABLED;
	} else if (user_privilieges == 1) {
		DBG("user has paired with remote and use");
		memset(pairing_address, 0, ADDRESS_LEN);
		return BT_SUCCESS;
	} else if (user_privilieges == 2) {
		comms_bluetooth_device_pair(remote_address,
			bt_device_paired_cb, strdup(remote_address));

		return BT_SUCCESS;
	}

	return BT_ERROR_NOT_ENABLED;
}

int ntb_bt_device_cancel_bonding(void)
{
	enum bluez_error_type error_type;
	int powered;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (strlen(pairing_address) == 0) {
		DBG("not need to cancel bonding");
		return BT_ERROR_NOT_ENABLED;
	}

	user_privilieges = bt_device_get_privileges(pairing_address);

	memset(pairing_address, 0, ADDRESS_LEN);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	bluez_adapter_get_property_powered(default_adapter, &powered);
	if (powered == FALSE)
		return BT_ERROR_NOT_ENABLED;

	error_type = comms_bluetooth_device_cancel_pairing_sync();
	if (error_type == ERROR_NONE)
		return BT_SUCCESS;
	else if (error_type == ERROR_DOES_NOT_EXIST)
		return BT_ERROR_NOT_IN_PROGRESS;
	else
		return BT_ERROR_OPERATION_FAILED;
}

int ntb_bt_device_destroy_bond(const char *remote_address)
{
	bluez_device_t *device;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	memset(pairing_address, 0, ADDRESS_LEN);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_adapter_remove_device(default_adapter, device);

	comms_bluetooth_remove_user_privileges_sync(remote_address);

	return BT_SUCCESS;
}

int ntb_bt_device_set_alias(const char *remote_address, const char *alias)
{
	bluez_device_t *device;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !alias) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_set_alias(device, alias);

	return BT_SUCCESS;
}

int ntb_bt_device_set_authorization(const char *remote_address,
				bt_device_authorization_e authorization_state)
{
	int trusted;
	bluez_device_t *device;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	trusted = (authorization_state == BT_DEVICE_AUTHORIZED) ?
						false : true;

	bluez_device_set_trusted(device, trusted);

	return BT_SUCCESS;
}

static bt_device_sdp_info_s *get_device_sdp_info(bluez_device_t *device)
{
	bt_device_sdp_info_s *sdp_info;
	char *address;
	char **uuids;
	guint len;

	sdp_info = g_new0(bt_device_sdp_info_s, 1);
	if (sdp_info == NULL) {
		ERROR("no memeory");
		return NULL;
	}

	address = bluez_device_get_property_address(device);
	uuids = bluez_device_get_property_uuids(device);

	len = g_strv_length(uuids);

	sdp_info->remote_address = address;
	sdp_info->service_uuid = uuids;
	sdp_info->service_count = len;

	return sdp_info;
}

static void free_device_sdp_info(bt_device_sdp_info_s *sdp_info)
{
	gsize i;

	if (sdp_info == NULL)
		return;

	g_free(sdp_info->remote_address);
	for (i = 0; i < sdp_info->service_count; ++i)
		g_free(sdp_info->service_uuid[i]);

	g_free(sdp_info->service_uuid);
	g_free(sdp_info);
}

int ntb_bt_device_start_service_search(const char *remote_address)
{
	bluez_device_t *device = NULL;
	bt_device_sdp_info_s *sdp_info;
	int powered, paired;
	char *address;
	GList *list, *iter, *next;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	bluez_adapter_get_property_powered(default_adapter, &powered);
	if (powered == FALSE)
		return BT_ERROR_NOT_ENABLED;

	if (!device_service_search_node)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	for (iter = g_list_first(list); iter; iter = next) {
		bluez_device_t *dev;
		dev = iter->data;

		next = g_list_next(iter);

		if (dev == NULL)
			continue;

		address = bluez_device_get_property_address(dev);
		if (!g_strcmp0(remote_address, address)) {
			device = dev;
			g_free(address);
			break;
		}

		g_free(address);
	}

	g_list_free(list);

	if (device == NULL)
		return BT_ERROR_SERVICE_SEARCH_FAILED;

	bluez_device_get_property_paired(device, &paired);
	if (paired == FALSE)
		return BT_ERROR_REMOTE_DEVICE_NOT_BONDED;

	sdp_info = get_device_sdp_info(device);

	device_service_search_node->cb(BT_SUCCESS, sdp_info,
				device_service_search_node->user_data);

	free_device_sdp_info(sdp_info);

	return BT_SUCCESS;
}

int ntb_bt_device_cancel_service_search(void)
{
	/*
	 * BlueZ 5.x don't support cancel device service search
	 * So only return SUCCESS.
	 */

	return BT_SUCCESS;
}

int ntb_bt_device_set_bond_created_cb(bt_device_bond_created_cb callback,
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

int ntb_bt_device_unset_bond_created_cb(void)
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

int ntb_bt_device_set_bond_destroyed_cb(bt_device_bond_destroyed_cb callback,
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

int ntb_bt_device_unset_bond_destroyed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (paired_device_removed_node) {
		g_free(paired_device_removed_node);
		paired_device_removed_node = NULL;
	}

	if (unpaired_device_removed_node == NULL &&
			generic_device_removed_set == TRUE) {
		bluez_adapter_unset_device_removed_cb(default_adapter);

		generic_device_removed_set = FALSE;
	}

	return BT_SUCCESS;
}

int ntb_bt_device_set_authorization_changed_cb(
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
		ERROR("no memory");
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

int ntb_bt_device_unset_authorization_changed_cb(void)
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

int ntb_bt_device_set_service_searched_cb(bt_device_service_searched_cb callback,
							void *user_data)
{
	struct device_service_search_cb_node *node;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (device_service_search_node) {
		DBG("Device service serach callback already set.");
		return BT_SUCCESS;
	}

	node = g_new0(struct device_service_search_cb_node, 1);
	if (node == NULL) {
		ERROR("no memeroy");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node->cb = callback;
	node->user_data = user_data;

	device_service_search_node = node;

	return BT_SUCCESS;
}

int ntb_bt_device_unset_service_searched_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!device_service_search_node)
		return BT_SUCCESS;

	g_free(device_service_search_node);
	device_service_search_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_device_set_connection_state_changed_cb(
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

int ntb_bt_device_unset_connection_state_changed_cb(void)
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

int ntb_bt_audio_initialize(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int ntb_bt_audio_deinitialize(void)
{
	DBG("Not implement");

	return BT_SUCCESS;
}

int ntb_bt_audio_connect(const char *remote_address,
				bt_audio_profile_type_e type)
{
	bluez_device_t *device;
	char *uuid = NULL;
	int user_privilieges, len;
	adapter_device_discovery_info_t *device_info;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

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

	if (type != BT_AUDIO_PROFILE_TYPE_ALL)
		bluez_device_connect_profile(device, uuid,
					profile_connect_callback);
	else
		goto done;

	return BT_SUCCESS;

done:
	device_info = bluez_get_discovery_device_info(device);
	if (!device_info || !device_info->service_uuid) {
		DBG("device info = NULL");
		return BT_ERROR_OPERATION_FAILED;
	}

	for (len = 0; len < device_info->service_count; len++) {
		if (!g_strcmp0(device_info->service_uuid[len],
						BT_HFP_HS_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_A2DP_SINK_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_A2DP_SOURCE_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HFP_AG_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HSP_AG_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HSP_HS_UUID)) {
			bluez_device_connect_profile(device,
					device_info->service_uuid[len],
					profile_connect_callback);
		}
	}

	return BT_SUCCESS;
}

int ntb_bt_audio_disconnect(const char *remote_address,
				bt_audio_profile_type_e type)
{
	bluez_device_t *device;
	char *uuid = NULL;
	int user_privilieges, len;
	adapter_device_discovery_info_t *device_info;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

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

	if (type != BT_AUDIO_PROFILE_TYPE_ALL)
		bluez_device_disconnect_profile(device, uuid,
				profile_disconnect_callback);
	else
		goto done;

	return BT_SUCCESS;

done:
	device_info = bluez_get_discovery_device_info(device);
	if (!device_info || !device_info->service_uuid) {
		DBG("device info = NULL");
		return BT_ERROR_OPERATION_FAILED;
	}

	for (len = 0; len < device_info->service_count; len++) {
		if (!g_strcmp0(device_info->service_uuid[len],
						BT_HFP_HS_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_A2DP_SINK_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_A2DP_SOURCE_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HFP_AG_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HSP_AG_UUID)
			|| !g_strcmp0(device_info->service_uuid[len],
						BT_HSP_HS_UUID)) {
			bluez_device_disconnect_profile(device,
					device_info->service_uuid[len],
					profile_disconnect_callback);
		}
	}

	return BT_SUCCESS;
}

int ntb_bt_audio_set_connection_state_changed_cb(
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

int ntb_bt_audio_unset_connection_state_changed_cb(void)
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

int ntb_bt_avrcp_target_initialize(
			bt_avrcp_target_connection_state_changed_cb callback,
			void *user_data)
{
	struct avrcp_target_connection_state_changed_node *node_data = NULL;
	int ret;

	DBG("default_adpater: %p", default_adapter);

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (avrcp_target_state_node) {
		DBG("avrcp target callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	ret = bluez_media_register_player(default_adapter);

	if (ret != 0)
		return BT_ERROR_OPERATION_FAILED;

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

int ntb_bt_avrcp_target_deinitialize(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!avrcp_target_state_node)
		return BT_SUCCESS;

	bluez_unset_avrcp_target_cb();

	g_free(avrcp_target_state_node);
	avrcp_target_state_node = NULL;

	bluez_media_unregister_player(default_adapter);

	return BT_SUCCESS;
}

int ntb_bt_avrcp_set_repeat_mode_changed_cb(
		bt_avrcp_repeat_mode_changed_cb callback,
		void *user_data)
{
	static struct avrcp_repeat_mode_changed_node *node_data;

	DBG("default_adpater: %p", default_adapter);

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (avrcp_repeat_node) {
		DBG("repeat mode callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct avrcp_repeat_mode_changed_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	avrcp_repeat_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int ntb_bt_avrcp_unset_repeat_mode_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!avrcp_repeat_node)
		return BT_SUCCESS;

	bluez_unset_avrcp_repeat_cb();

	g_free(avrcp_repeat_node);
	avrcp_repeat_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_avrcp_set_shuffle_mode_changed_cb(
		bt_avrcp_shuffle_mode_changed_cb callback,
		void *user_data)
{
	struct avrcp_set_shuffle_mode_changed_node *node_data = NULL;

	DBG("default_adpater: %p", default_adapter);

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (avrcp_shuffle_node) {
		DBG("repeat mode callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct avrcp_set_shuffle_mode_changed_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	avrcp_shuffle_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int ntb_bt_avrcp_unset_shuffle_mode_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!avrcp_shuffle_node)
		return BT_SUCCESS;

	bluez_unset_avrcp_shuffle_cb();

	g_free(avrcp_shuffle_node);
	avrcp_shuffle_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_avrcp_target_notify_repeat_mode(bt_avrcp_repeat_mode_e mode)
{
	int ret;

	DBG("");

	if (default_adapter == NULL) {
		DBG("no adapter");
		return BT_ERROR_ADAPTER_NOT_FOUND;
	}

	ret = bluez_media_player_change_property(default_adapter,
						LOOPSTATUS, mode);

	if (ret == 0)
		return BT_ERROR_NONE;
	else
		return BT_ERROR_OPERATION_FAILED;
}

int ntb_bt_avrcp_target_notify_shuffle_mode(bt_avrcp_shuffle_mode_e mode)
{
	int ret;

	DBG("");

	if (default_adapter == NULL) {
		DBG("no adapter");
		return BT_ERROR_ADAPTER_NOT_FOUND;
	}

	ret = bluez_media_player_change_property(default_adapter,
						SHUFFLE, mode);

	if (ret == 0)
		return BT_ERROR_NONE;
	else
		return BT_ERROR_OPERATION_FAILED;
}

int ntb_bt_avrcp_target_notify_player_state(bt_avrcp_player_state_e state)
{
	int ret;

	DBG("");

	if (default_adapter == NULL) {
		DBG("no adapter");
		return BT_ERROR_ADAPTER_NOT_FOUND;
	}

	ret = bluez_media_player_change_property(default_adapter,
						PLAYBACKSTATUS, state);

	if (ret == 0)
		return BT_ERROR_NONE;
	else
		return BT_ERROR_OPERATION_FAILED;
}

int ntb_bt_avrcp_target_notify_position(unsigned int position)
{
	int ret;

	DBG("");

	if (default_adapter == NULL) {
		DBG("no adapter");
		return BT_ERROR_ADAPTER_NOT_FOUND;
	}

	ret = bluez_media_player_change_property(default_adapter,
						POSITION, position);

	if (ret == 0)
		return BT_ERROR_NONE;
	else
		return BT_ERROR_OPERATION_FAILED;
}

static void _bt_avrcp_metadata_free(media_metadata_attributes_t *metadata)
{
	if (metadata == NULL)
		return;

	if (metadata->title)
		g_free(metadata->title);

	if (metadata->artist) {
		g_free(metadata->artist[0]);
		g_free(metadata->artist);
	}

	if (metadata->genre) {
		g_free(metadata->genre[0]);
		g_free(metadata->genre);
	}

	if (metadata->album)
		g_free(metadata->album);
}

int ntb_bt_avrcp_target_notify_track(const char *title, const char *artist,
		const char *album, const char *genre, unsigned int track_num,
		unsigned int total_tracks, unsigned int duration)
{
	int ret;
	media_metadata_attributes_t metadata;

	DBG("");

	if (default_adapter == NULL) {
		DBG("no adapter");
		return BT_ERROR_ADAPTER_NOT_FOUND;
	}

	metadata.title = g_strdup(title);
	metadata.artist = g_malloc0(sizeof(char *));
	if (metadata.artist != NULL)
		metadata.artist[0] = g_strdup(artist);
	metadata.genre = g_malloc0(sizeof(char *));
	if (metadata.genre != NULL)
		metadata.genre[0] = g_strdup(genre);
	metadata.album = g_strdup(album);
	metadata.tracknumber = track_num;
	metadata.duration = duration;

	ret = bluez_media_player_set_track_info(default_adapter,
							&metadata);

	_bt_avrcp_metadata_free(&metadata);

	if (ret == 0)
		return BT_ERROR_NONE;
	else
	return BT_ERROR_OPERATION_FAILED;
}

int ntb_bt_avrcp_target_notify_equalizer_state(bt_avrcp_equalizer_state_e state)
{
	/*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

int ntb_bt_avrcp_target_notify_scan_mode(bt_avrcp_scan_mode_e mode)
{
	/*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

int ntb_bt_avrcp_set_equalizer_state_changed_cb(
				bt_avrcp_equalizer_state_changed_cb callback,
				void *user_data)
{
	/*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

int ntb_bt_avrcp_unset_equalizer_state_changed_cb(void)
{
	/*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

int ntb_bt_avrcp_set_scan_mode_changed_cb(bt_avrcp_scan_mode_changed_cb callback,
				void *user_data)
{
	/*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

int ntb_bt_avrcp_unset_scan_mode_changed_cb(void)
{
	 /*bluez-5.X doesn't provide the property*/
	return BT_SUCCESS;
}

/* Hid function */
int ntb_bt_hid_host_initialize(
		bt_hid_host_connection_state_changed_cb connection_cb,
		void *user_data)
{
	struct hid_host_connection_state_changed_cb_node *node_data;
	GList *list;

	DBG("");

	if (connection_cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (hid_host_state_node) {
		DBG("hid host connected state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct hid_host_connection_state_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = connection_cb;
	node_data->user_data = user_data;

	hid_host_state_node = node_data;

	dev_property_callback_flags |= DEV_PROP_FLAG_HID_CONNECT;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HID_CONNECT);

	g_list_free(list);

	return BT_SUCCESS;
}

int ntb_bt_hid_host_deinitialize(void)
{
	GList *list;
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!hid_host_state_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_HID_CONNECT;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HID_CONNECT);

	g_free(hid_host_state_node);
	hid_host_state_node = NULL;

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

int ntb_bt_hid_host_connect(const char *remote_address)
{
	bluez_device_t *device;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

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

int ntb_bt_hid_host_disconnect(const char *remote_address)
{
	bluez_device_t *device;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_disconnect_profile(device, BT_HID_UUID,
				profile_disconnect_callback);

	return BT_SUCCESS;
}

GList *spp_ctx_list;

static GDBusNodeInfo *profile_xml_data;

static struct spp_context *create_spp_context(void)
{
	struct spp_context *spp_ctx, *spp_last;
	GList *list;

	spp_ctx = g_try_new0(struct spp_context, 1);
	if (spp_ctx == NULL) {
		DBG("no memroy");
		return NULL;
	}

	if (g_list_length(spp_ctx_list) != 0) {
		list = g_list_last(spp_ctx_list);
		spp_last = list->data;
		spp_ctx->fd = spp_last->fd + 1;
	} else
		spp_ctx->fd = 1;

	return spp_ctx;
}

static void free_spp_channel(struct spp_context *spp_ctx,
					struct spp_channel *spp_chan)
{
	if (spp_chan == NULL || spp_ctx == NULL)
		return;

	spp_ctx->chan_list = g_list_remove(spp_ctx->chan_list, spp_chan);

	if (spp_chan->io_watch)
		g_source_remove(spp_chan->io_watch);

	if (spp_chan->remote_address)
		g_free(spp_chan->remote_address);

	g_free(spp_chan);
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

static struct spp_context *find_spp_context_from_socketfd(int socket_fd)
{
	struct spp_context *spp_ctx;
	GList *list, *next;

	for (list = g_list_first(spp_ctx_list); list; list = next) {
		next = g_list_next(list);

		spp_ctx = list->data;

		if (spp_ctx && (spp_ctx->fd == socket_fd))
			return spp_ctx;
	}

	return NULL;
}

static struct spp_context *find_spp_context_from_fd(int fd)
{
	struct spp_context *spp_ctx;
	struct spp_channel *spp_chan;
	GList *list, *next;
	GList *list_chan, *next_chan;
	int spp_fd;

	for (list = g_list_first(spp_ctx_list); list; list = next) {
		next = g_list_next(list);

		spp_ctx = list->data;

		for (list_chan = g_list_first(spp_ctx->chan_list);
				list_chan; list_chan = next_chan) {
			next_chan = g_list_next(list_chan);

			spp_chan = list_chan->data;
			spp_fd = g_io_channel_unix_get_fd(spp_chan->channel);

			if (spp_ctx && spp_fd == fd) {
				spp_ctx->channel = spp_chan->channel;
				return spp_ctx;
			}
		}
	}

	return NULL;
}

static struct spp_channel *find_spp_channel_from_fd(
				struct spp_context *spp_ctx, int fd)
{
	struct spp_channel *spp_chan;
	GList *list_chan, *next_chan;
	int spp_fd;

	for (list_chan = g_list_first(spp_ctx->chan_list);
				list_chan; list_chan = next_chan) {
		next_chan = g_list_next(list_chan);

		spp_chan = list_chan->data;
		spp_fd = g_io_channel_unix_get_fd(spp_chan->channel);
		if (spp_chan && spp_fd == fd)
			return spp_chan;
	}

	return NULL;
}

static struct spp_channel *find_spp_channel_from_address(
			struct spp_context *spp_ctx, gchar *address)
{
	struct spp_channel *spp_chan;
	GList *list_chan, *next_chan;

	for (list_chan = g_list_first(spp_ctx->chan_list);
				list_chan; list_chan = next_chan) {
		next_chan = g_list_next(list_chan);

		spp_chan = list_chan->data;
		if (spp_chan)
			if (g_strcmp0(spp_chan->remote_address,
							address) == 0)
				return spp_chan;
	}

	return NULL;
}

static struct spp_channel *find_spp_channel_from_channel(
					struct spp_context *spp_ctx,
					GIOChannel *channel)
{
	struct spp_channel *spp_chan;
	GList *list_chan, *next_chan;

	for (list_chan = g_list_first(spp_ctx->chan_list);
				list_chan; list_chan = next_chan) {
		next_chan = g_list_next(list_chan);

		spp_chan = list_chan->data;
		if (spp_chan && spp_chan->channel == channel)
			return spp_chan;
	}

	return NULL;
}

static struct spp_channel *create_spp_channel(GIOChannel *channel,
					guint io_watch, char *address)
{
	struct spp_channel *spp_chan;

	spp_chan = g_try_new0(struct spp_channel, 1);
	if (spp_chan == NULL) {
		DBG("no memory");
		return NULL;
	}

	spp_chan->channel = channel;
	spp_chan->io_watch = io_watch;
	if (address)
		spp_chan->remote_address = g_strdup(address);

	return spp_chan;
}

/* Agent Function */

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
	"    <method name='DisplayPasskey'>"
	"      <arg type='o' name='device' direction='in'/>"
	"      <arg type='u' name='passkey' direction='in'/>"
	"      <arg type='q' name='entered' direction='in'/>"
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
	"      <arg type='h' name='fd' direction='in'/>"
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
  DBG("");

#ifndef TIZEN_3
	gchar *device_name;
	bluez_device_t *device;

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
#endif
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void request_pincode_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
  DBG("");

#ifdef TIZEN_3
  reply_invocation = invocation;
#else
  gchar *device_name;
	bluez_device_t *device;

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
#endif
}

static void request_passkey_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
	DBG("");

#ifdef TIZEN_3
  reply_invocation = invocation;
#else
  gchar *device_name;
  bluez_device_t *device;

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
#endif
}

static void handle_display_passkey(const gchar *device_path,
					guint32 passkey,
					guint16 entered,
					GDBusMethodInvocation *invocation)
{
	DBG("");

#ifndef TIZEN_3
	gchar *device_name;
	bluez_device_t *device;

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

	if (this_agent && this_agent->display_passkey)
		this_agent->display_passkey(device_name,
					    passkey, entered, invocation);
#endif
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void request_confirmation_handler(const gchar *device_path,
					guint32 passkey,
					GDBusMethodInvocation *invocation)
{
  DBG("");

#ifdef TIZEN_3
  reply_invocation = invocation;
#else
	gchar *device_name;
	bluez_device_t *device;

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
#endif
}

static void handle_spp_authorize_request(bluez_device_t *device,
					struct spp_context *spp_ctx,
					GDBusMethodInvocation *invocation)
{
	char *device_name, *device_address;
	struct spp_channel *spp_chan;
	GIOChannel *channel;
	GDBusMessage *msg;
	GUnixFDList *fd_list;
	guint io;
	gint fd;

	DBG("");

	if (spp_ctx->max_pending <= 0 ||
			(g_list_length(spp_ctx->chan_list) >=
					spp_ctx->max_pending)) {
		bt_spp_reject(invocation);
		return;
	}

	msg = g_dbus_method_invocation_get_message(invocation);

	fd_list = g_dbus_message_get_unix_fd_list(msg);
	fd = g_unix_fd_list_get(fd_list, (gint)0, NULL);
	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	io = g_io_add_watch(channel,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					received_data, (void *)spp_ctx);

	device_name = bluez_device_get_property_alias(device);
	device_address = bluez_device_get_property_address(device);

	spp_chan = create_spp_channel(channel, io, device_address);

	if (spp_chan) {
		spp_ctx->chan_list = g_list_append(spp_ctx->chan_list,
								spp_chan);
		spp_ctx->channel = channel;
	} else {
		bt_spp_reject(invocation);
		g_source_remove(io);
		goto failed;
	}

	if (spp_connection_requested_node)
		spp_connection_requested_node->cb(
				spp_ctx->uuid, device_name, invocation,
				spp_connection_requested_node->user_data);

	spp_ctx->requestion = invocation;
	spp_ctx->role = BT_SOCKET_SERVER;

	if (socket_connection_requested_node)
		socket_connection_requested_node->cb(
			spp_ctx->fd, (const char *)device_address,
			socket_connection_requested_node->user_data);

	if (spp_ctx->new_connection)
		spp_ctx->new_connection(spp_ctx->uuid, device_name,
			fd, spp_ctx->new_connection_data);

	if (socket_connection_state_node) {
		bt_socket_connection_s connection;

		connection.socket_fd = fd;
		connection.remote_address = device_address;
		connection.service_uuid = spp_ctx->uuid;
		connection.local_role = spp_ctx->role;
		if (spp_ctx->role == BT_SOCKET_CLIENT)
			connection.server_fd = -1;
		else
			connection.server_fd = spp_ctx->fd;

		socket_connection_state_node->cb(
			BT_SUCCESS, BT_SOCKET_CONNECTED, &connection,
			socket_connection_state_node->user_data);
	}

	if (spp_ctx->is_accept)
		bt_spp_accept(invocation);

failed:
	if (device_name)
		g_free(device_name);

	if (device_address)
		g_free(device_address);
}

static void request_authorize_service_handler(const gchar *device_path,
					const gchar *uuid,
					GDBusMethodInvocation *invocation)
{
	struct spp_context *spp_ctx;
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

	spp_ctx = find_spp_context_from_uuid(uuid);
	if (spp_ctx != NULL) {
		handle_spp_authorize_request(device, spp_ctx, invocation);
		return;
	}
#ifdef TIZEN_3
  reply_invocation = invocation;
#else
	gchar *device_name;

	/* Other profile Authorize request */
	if (!this_agent || !this_agent->authorize_service)
		return;

	device_name = bluez_device_get_property_alias(device);

	this_agent->authorize_service(device_name, uuid, invocation);

	g_free(device_name);
#endif
}

static void request_authorization_handler(const gchar *device_path,
					GDBusMethodInvocation *invocation)
{
#ifndef TIZEN_3
	if (!this_agent)
		return;

	if (!this_agent->cancel)
		return;
#endif
	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void cancel_handler(GDBusMethodInvocation *invocation)
{
#ifndef TIZEN_3
	if (!this_agent)
		return;

	if (!this_agent->cancel)
		return;

	this_agent->cancel();
#endif
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

	if (g_strcmp0(method_name, "DisplayPasskey") == 0) {
		gchar *device_path = NULL;
		guint32 passkey = 0;
		guint16 entered = 0;

		g_variant_get(parameters, "(ouq)",
					device_path, &passkey, &entered);
		handle_display_passkey(device_path,
					passkey, entered, invocation);

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
		gint32 fd_index;

		g_variant_get(parameters, "(osh)", &device_path,
						&uuid, &fd_index);

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

	if (bluetooth_ext_agent_id)
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

static GDBusConnection *get_system_dbus_connect(void)
{
	GError *error = NULL;

	if (conn)
		return conn;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (conn == NULL) {
		DBG("%s", error->message);

		g_error_free(error);
	}

	return conn;
}

static int request_name_on_dbus(const char *name)
{
	GDBusConnection *connection;
	GVariant *ret;
	guint32 request_name_reply;
	GError *error = NULL;

	if (bluetooth_agent_id || profile_id)
		return 0;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return -1;

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
		g_error_free(error);

		goto failed;
	}

	g_variant_get(ret, "(u)", &request_name_reply);
	g_variant_unref(ret);

	/* RequestName will return the uint32 value:
	 * 1: DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
	 * 2: DBUS_REQUEST_NAME_REPLY_IN_QUEUE
	 * 3: DBUS_REQUEST_NAME_REPLY_EXISTS
	 * 4: DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
	 * Also see dbus doc
	 */
	if (request_name_reply == DBUS_REQUEST_NAME_REPLY_IN_QUEUE
		|| request_name_reply == DBUS_REQUEST_NAME_REPLY_EXISTS
		|| request_name_reply ==
				DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER) {
		bluetooth_ext_agent_id = 1;
		return 0;
	}

	if (request_name_reply != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		DBG("Lost name");

		release_name_on_dbus(name);

		goto failed;
	}

	if (bluetooth_ext_agent_id > 0)
		bluetooth_ext_agent_id = 0;

	return 0;

failed:
	g_object_unref(connection);

	return -1;
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

static int create_agent(void)
{
	int ret;

	if (bluetooth_agent_id)
		return BT_ERROR_ALREADY_DONE;

	ret = comms_bluetooth_register_pairing_agent_sync(
					AGENT_OBJECT_PATH, NULL);

	if (ret != BT_SUCCESS)
		return BT_ERROR_OPERATION_FAILED;

	introspection_data =
		g_dbus_node_info_new_for_xml(introspection_xml, NULL);

	ret = request_name_on_dbus(BLUEZ_AGENT_SERVICE);
	if (ret != 0)
		goto done;

	DBG("%s requested success", BLUEZ_AGENT_SERVICE);

	bluetooth_agent_id = g_dbus_connection_register_object(conn,
					AGENT_OBJECT_PATH,
					introspection_data->interfaces[0],
					&interface_handle, NULL, NULL, NULL);

	if (bluetooth_agent_id == 0)
		goto done;

	return 0;
done:
	comms_bluetooth_unregister_pairing_agent(AGENT_OBJECT_PATH,
							NULL, NULL);
	return -1;
}

int ntb_bt_agent_register(bt_agent *agent)
{
	int ret;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (agent == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (bluetooth_agent_id > 0)
		return BT_ERROR_ALREADY_DONE;

	if (this_agent != NULL)
		return BT_ERROR_ALREADY_DONE;

	ret = create_agent();
	if (ret != BT_SUCCESS)
		return ret;

	this_agent = agent;

	return BT_SUCCESS;
}

#ifdef TIZEN_3
int ntb_bt_agent_register_sync(void)
{
	int ret;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (bluetooth_agent_id > 0)
		return BT_ERROR_ALREADY_DONE;

	if (this_agent != NULL)
		return BT_ERROR_ALREADY_DONE;

	ret = create_agent();
	if (ret != BT_SUCCESS)
		return ret;

	return BT_SUCCESS;
}
#endif

int ntb_bt_agent_unregister(void)
{
	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	destory_agent();

#ifndef TIZEN_3
	this_agent = NULL;
#endif
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

void ntb_bt_agent_confirm_accept(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_accept(invocation);
}

#ifdef TIZEN_3
void ntb_bt_agent_reply_sync(bt_agent_accept_type_t reply)
{
  DBG("reply [%d]", reply);

  if (reply == BT_AGENT_ACCEPT)
    g_dbus_method_invocation_return_value(reply_invocation, NULL);
  else if (reply == BT_AGENT_REJECT)
    g_dbus_method_invocation_return_dbus_error(reply_invocation,
          ERROR_INTERFACE ".Rejected",
          "RejectedByUser");
  else
    g_dbus_method_invocation_return_dbus_error(reply_invocation,
          ERROR_INTERFACE ".Canceled",
          "CanceledByUser");

  reply_invocation = NULL;
}
#endif

void ntb_bt_agent_confirm_reject(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_reject(invocation);
}

void ntb_bt_agent_pincode_reply(const char *pin_code, bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(s)", pin_code));
}

void ntb_bt_agent_pincode_cancel(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	g_dbus_method_invocation_return_dbus_error(invocation,
			ERROR_INTERFACE ".Canceled",
			"CanceledByUser");
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
	struct spp_channel *spp_chan;
	GIOStatus status;
	gsize rbytes = 0;

	DBG("");

	spp_ctx = user_data;
	if (spp_ctx == NULL) {
		WARN("no spp find");
		return FALSE;
	}

	if (con & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		spp_chan = find_spp_channel_from_channel(spp_ctx, channel);
		if (spp_chan) {
			if (socket_connection_state_node) {
				bt_socket_connection_s connection;
				connection.socket_fd =
					g_io_channel_unix_get_fd(channel);
				connection.remote_address =
					spp_chan->remote_address;
				connection.service_uuid = spp_ctx->uuid;
				connection.local_role = spp_ctx->role;
				if (spp_ctx->role == BT_SOCKET_CLIENT)
					connection.server_fd = -1;
				else
					connection.server_fd = spp_ctx->fd;
				socket_connection_state_node->cb(
				BT_SUCCESS, BT_SOCKET_DISCONNECTED, &connection,
				socket_connection_state_node->user_data);
			}

			free_spp_channel(spp_ctx, spp_chan);

			if (spp_chan->io_shutdown != 1) {
				g_io_channel_shutdown(channel,
							TRUE, NULL);
				g_io_channel_unref(channel);
			}
		}
		return FALSE;
	}

	if (!(con & G_IO_IN)) {
		DBG("not G_IO_IN");
		return FALSE;
	}

	if (!spp_data_received_node) {
		DBG("not spp_data_received_node");
		goto done;
	}

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

static void notify_disconnection_state(gchar *device_path,
					struct spp_context *spp_ctx)
{
	struct spp_channel *spp_chan;
	bluez_device_t *device;
	gchar *device_name, *address;

	DBG("");

	device = bluez_adapter_get_device_by_path(default_adapter,
							device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);
	address = bluez_device_get_property_address(device);

	spp_chan = find_spp_channel_from_address(spp_ctx, address);

	if (spp_chan == NULL) {
		DBG("no find spp_chan");
		g_free(device_name);
		g_free(address);
		return;
	}

	g_io_channel_shutdown(spp_chan->channel, TRUE, NULL);
	g_io_channel_unref(spp_chan->channel);
	spp_chan->io_shutdown = 1;

	g_free(device_name);
	g_free(address);
}

static void notify_connection_state(gchar *device_path,
				GIOChannel *channel, guint io,
				struct spp_context *spp_ctx)
{
	struct spp_channel *spp_chan;
	bluez_device_t *device;
	gchar *device_name, *address;
	int fd;

	device = bluez_adapter_get_device_by_path(default_adapter,
						device_path);
	if (device == NULL) {
		ERROR("Can't find device %s", device_path);
		return;
	}

	device_name = bluez_device_get_property_alias(device);
	address = bluez_device_get_property_address(device);

	spp_chan = create_spp_channel(channel, io, address);

	if (spp_chan)
		spp_ctx->chan_list = g_list_append(spp_ctx->chan_list,
							spp_chan);
	else {
		DBG("no memory");
		g_free(device_name);
		g_free(address);
		return;
	}

	fd = g_io_channel_unix_get_fd(spp_chan->channel);

	if (spp_ctx->new_connection)
		spp_ctx->new_connection(spp_ctx->uuid, device_name,
			fd, spp_ctx->new_connection_data);

	if (socket_connection_state_node) {
		bt_socket_connection_s connection;

		connection.socket_fd = fd;
		connection.remote_address = address;
		connection.service_uuid = spp_ctx->uuid;
		connection.local_role = spp_ctx->role;
		if (spp_ctx->role == BT_SOCKET_CLIENT)
			connection.server_fd = -1;
		else
			connection.server_fd = spp_ctx->fd;

		socket_connection_state_node->cb(
			BT_SUCCESS, BT_SOCKET_CONNECTED, &connection,
			socket_connection_state_node->user_data);
	}

	g_free(device_name);
	g_free(address);
}

static void handle_new_connection(gchar *device_path, gint fd,
					GDBusMethodInvocation *invocation,
					void *user_data)
{
	struct spp_context *spp_ctx;
	GIOChannel *channel;
	guint io;

	DBG("");

	spp_ctx = user_data;
	if (spp_ctx == NULL) {
		DBG("no spp context");
		return;
	}

	if (spp_ctx->role == BT_SOCKET_SERVER) {
		g_dbus_method_invocation_return_value(invocation, NULL);
		return;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	io = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						received_data, user_data);

	notify_connection_state(device_path, channel, io, spp_ctx);

	g_dbus_method_invocation_return_value(invocation, NULL);
}

static void handle_request_disconnection(gchar *device_path,
					GDBusMethodInvocation *invocation,
					void *user_data)
{
	struct spp_context *spp_ctx = user_data;

	DBG("device path %s", device_path);

	notify_disconnection_state(device_path, spp_ctx);

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

static int bt_spp_create_rfcomm(const char *uuid,
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

static int bt_spp_destroy_rfcomm(const char *uuid)
{
	struct spp_context *spp_ctx;
	struct spp_channel *spp_chan;
	GList *list_chan, *next_chan;

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

	for (list_chan = g_list_first(spp_ctx->chan_list);
				list_chan; list_chan = next_chan) {
		next_chan = g_list_next(list_chan);

		spp_chan = list_chan->data;
		if (spp_chan) {
			if (spp_chan->channel) {
				g_io_channel_shutdown(spp_chan->channel,
							TRUE, NULL);
				g_io_channel_unref(spp_chan->channel);
				spp_chan->io_shutdown = 1;
			}
		}
	}

	free_spp_context(spp_ctx);

	return BT_SUCCESS;
}

static int bt_spp_connect_rfcomm(const char *remote_address,
					const char *service_uuid)
{
	bluez_device_t *device;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !service_uuid) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_connect_profile(device, service_uuid,
					profile_connect_callback);

	return BT_SUCCESS;
}

static int bt_spp_disconnect_rfcomm(const char *remote_address,
					const char *service_uuid)
{
	bluez_device_t *device;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !service_uuid) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_disconnect_profile(device, service_uuid,
					profile_disconnect_callback);

	return BT_SUCCESS;
}

static int bt_spp_accept(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_accept(invocation);

	return BT_SUCCESS;
}

static int bt_spp_reject(bt_req_t *requestion)
{
	GDBusMethodInvocation *invocation = requestion;

	bt_agent_simple_reject(invocation);

	return BT_SUCCESS;
}

static int bt_spp_send_data(int fd, const char *data, int length)
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

static int bt_spp_set_data_received_cb(bt_spp_data_received_cb callback,
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

static int bt_spp_unset_data_received_cb(void)
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

int ntb_bt_socket_create_rfcomm(const char *service_uuid, int *socket_fd)
{
	struct spp_context *spp_ctx;
	int ret;

	if (!service_uuid || !socket_fd)
		return BT_ERROR_INVALID_PARAMETER;

	ret = bt_spp_create_rfcomm(service_uuid, NULL, NULL);
	if (ret != BT_SUCCESS)
		return ret;

	spp_ctx = find_spp_context_from_uuid(service_uuid);
	if (spp_ctx == NULL)
		return BT_ERROR_OPERATION_FAILED;

	*socket_fd = spp_ctx->fd;
	spp_ctx->role = BT_SOCKET_SERVER;

	return BT_SUCCESS;
}

int ntb_bt_socket_destroy_rfcomm(int socket_fd)
{
	struct spp_context *spp_ctx;

	spp_ctx = find_spp_context_from_socketfd(socket_fd);
	if (!spp_ctx)
		return BT_ERROR_OPERATION_FAILED;

	return bt_spp_destroy_rfcomm(spp_ctx->uuid);
}

int ntb_bt_socket_connect_rfcomm(const char *remote_address,
				const char *service_uuid)
{
	struct spp_context *spp_ctx;
	int ret;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !service_uuid) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	spp_ctx = find_spp_context_from_uuid(service_uuid);
	if (spp_ctx)
		goto done;

	/* BlueZ 5.x should create_rfcomm using a specify UUID,
	 * then it can connect remote device.
	 */
	ret = bt_spp_create_rfcomm(service_uuid, NULL, NULL);
	if (ret != BT_SUCCESS)
		return ret;

	spp_ctx = find_spp_context_from_uuid(service_uuid);
	if (!spp_ctx)
		return BT_ERROR_OPERATION_FAILED;

done:
	spp_ctx->role = BT_SOCKET_CLIENT;

	return bt_spp_connect_rfcomm(remote_address, service_uuid);
}

int ntb_bt_socket_disconnect_rfcomm(int socket_fd)
{
	struct spp_context *spp_ctx;
	struct spp_channel *spp_chan;

	spp_ctx = find_spp_context_from_fd(socket_fd);
	if (!spp_ctx)
		return BT_ERROR_OPERATION_FAILED;

	spp_chan = find_spp_channel_from_fd(spp_ctx, socket_fd);

	return bt_spp_disconnect_rfcomm(spp_chan->remote_address,
						spp_ctx->uuid);
}

int ntb_bt_socket_listen(int socket_fd, int max_pending_connections)
{
	struct spp_context *spp_ctx;

	spp_ctx = find_spp_context_from_socketfd(socket_fd);
	if (spp_ctx == NULL)
		return BT_ERROR_OPERATION_FAILED;

	if (max_pending_connections > 0)
		spp_ctx->max_pending = max_pending_connections;
	else
		spp_ctx->max_pending = -1;

	return BT_SUCCESS;
}

int ntb_bt_socket_listen_and_accept_rfcomm(int socket_fd,
				int max_pending_connections)
{
	struct spp_context *spp_ctx;

	spp_ctx = find_spp_context_from_socketfd(socket_fd);
	if (spp_ctx == NULL)
		return BT_ERROR_OPERATION_FAILED;

	if (max_pending_connections > 0)
		spp_ctx->max_pending = max_pending_connections;
	else
		spp_ctx->max_pending = -1;

	spp_ctx->is_accept = true;

	return BT_SUCCESS;
}

int ntb_bt_socket_accept(int requested_socket_fd)
{
	struct spp_context *spp_ctx;

	spp_ctx = find_spp_context_from_socketfd(requested_socket_fd);
	if (spp_ctx == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bt_spp_accept(spp_ctx->requestion);

	return BT_SUCCESS;
}

int ntb_bt_socket_reject(int socket_fd)
{
	struct spp_context *spp_ctx;

	spp_ctx = find_spp_context_from_socketfd(socket_fd);
	if (spp_ctx == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bt_spp_reject(spp_ctx->requestion);

	return BT_SUCCESS;
}

int ntb_bt_socket_send_data(int socket_fd, const char *data, int length)
{
	return bt_spp_send_data(socket_fd, data, length);
}

int ntb_bt_socket_set_data_received_cb(bt_socket_data_received_cb callback,
							void *user_data)
{
	return bt_spp_set_data_received_cb(
				(bt_spp_data_received_cb)callback, user_data);
}

int ntb_bt_socket_set_connection_requested_cb(
				bt_socket_connection_requested_cb callback,
				void *user_data)
{
	struct socket_connection_requested_cb_node *node_data;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (spp_connection_requested_node) {
		DBG("socket connection requested callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct socket_connection_requested_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	socket_connection_requested_node = node_data;

	return BT_SUCCESS;
}

int ntb_bt_socket_set_connection_state_changed_cb(
			bt_socket_connection_state_changed_cb callback,
			void *user_data)
{
	struct socket_connection_state_changed_cb_node *node_data;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (socket_connection_state_node) {
		DBG("socket connection state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct socket_connection_state_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	socket_connection_state_node = node_data;

	return BT_SUCCESS;
}

int ntb_bt_socket_unset_connection_requested_cb(void)
{
	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!socket_connection_requested_node)
		return BT_SUCCESS;

	g_free(socket_connection_requested_node);
	socket_connection_requested_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_socket_unset_data_received_cb(void)
{
	return bt_spp_unset_data_received_cb();
}

int ntb_bt_socket_unset_connection_state_changed_cb(void)
{
	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!socket_connection_state_node)
		return BT_SUCCESS;

	g_free(socket_connection_state_node);
	socket_connection_state_node = NULL;

	return BT_SUCCESS;
}

static void address2ident(const char *name, char *ident)
{
	unsigned int index;

	for (index = 0; index < BLUETOOTH_IDENT_LEN; ++index) {
		ident[index * 2] = name[index * 3];
		ident[index * 2 + 1] = name[index * 3 + 1];
	}

	ident[BLUETOOTH_IDENT_LEN * 2] = '\0';
}

char *get_connman_service_path(const char *adapter_name,
				const char *remote_name)
{
	char adapter_ident[BLUETOOTH_IDENT_LEN * 2 + 1] = { 0 };
	char remote_ident[BLUETOOTH_IDENT_LEN * 2 + 1] = { 0 };
	unsigned int len;
	char *path;

	len = strlen(CONNMAN_BLUETOOTH_SERVICE_PREFIX) +
			BLUETOOTH_IDENT_LEN * 4 + 2;

	path = calloc(len, sizeof(char));
	if (path == NULL)
		return NULL;

	address2ident(adapter_name, adapter_ident);
	address2ident(remote_name, remote_ident);

	sprintf(path, "%s%s%s%s", CONNMAN_BLUETOOTH_SERVICE_PREFIX,
				adapter_ident, "_", remote_ident);

	return path;
}

int ntb_bt_panu_connect(const char *remote_address, bt_panu_service_type_e type)
{
	GDBusConnection *connection;
	bt_device_info_s *device_bond_info;
	char *path, *adapter_address;
	bluez_device_t *device;
	bool is_bonded;
	GError *error = NULL;
	int ret;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);

	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	device_bond_info = get_device_info(device);
	is_bonded = device_bond_info->is_bonded;
	free_device_info(device_bond_info);

	if (is_bonded == FALSE)
		return BT_ERROR_REMOTE_DEVICE_NOT_BONDED;

	adapter_address = bluez_adapter_get_property_address(default_adapter);
	if (adapter_address == NULL)
		return BT_ERROR_OPERATION_FAILED;

	path = get_connman_service_path(adapter_address, remote_address);
	if (path == NULL) {
		free(adapter_address);
		return BT_ERROR_OPERATION_FAILED;
	}

	DBG("path %s", path);

	connection = get_system_dbus_connect();
	if (connection == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_dbus_connection_call_sync(connection, CONNMAN_DBUS_NAME, path,
					"net.connman.Service", "Connect",
					NULL, NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		ret = BT_ERROR_OPERATION_FAILED;

		goto done;
	}

	ret = BT_SUCCESS;

done:
	free(path);
	free(adapter_address);

	return ret;
}

int ntb_bt_panu_disconnect(const char *remote_address)
{
	GDBusConnection *connection;
	char *path, *adapter_address;
	bluez_device_t *device;
	int connected, ret;
	GError *error = NULL;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);

	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	bluez_device_network_get_property_connected(device, &connected);
	if (connected == FALSE)
		return BT_ERROR_REMOTE_DEVICE_NOT_CONNECTED;

	adapter_address = bluez_adapter_get_property_address(default_adapter);
	if (adapter_address == NULL)
		return BT_ERROR_OPERATION_FAILED;

	path = get_connman_service_path(adapter_address, remote_address);
	if (path == NULL) {
		free(adapter_address);
		return BT_ERROR_OPERATION_FAILED;
	}

	DBG("path %s", path);

	connection = get_system_dbus_connect();
	if (connection == NULL) {
		ret = BT_ERROR_OPERATION_FAILED;
		goto done;
	}

	g_dbus_connection_call_sync(connection, CONNMAN_DBUS_NAME, path,
					"net.connman.Service", "Disconnect",
					NULL, NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		ret = BT_ERROR_OPERATION_FAILED;

		goto done;
	}

	ret = BT_SUCCESS;

done:
	free(path);
	free(adapter_address);

	return ret;
}

int ntb_bt_panu_set_connection_state_changed_cb(
				bt_panu_connection_state_changed_cb callback,
				void *user_data)
{
	struct panu_connection_state_changed_cb_node *node_data;
	GList *list;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (panu_state_node) {
		DBG("network connected state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct panu_connection_state_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	panu_state_node = node_data;

	dev_property_callback_flags |= DEV_PROP_FLAG_PANU_CONNECT;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_PANU_CONNECT);

	g_list_free(list);

	return BT_SUCCESS;
}

int ntb_bt_panu_unset_connection_state_changed_cb(void)
{
	GList *list;
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!panu_state_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_PANU_CONNECT;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_PANU_CONNECT);

	g_free(panu_state_node);
	panu_state_node = NULL;

	return BT_SUCCESS;
}

static int connman_set_tethering(bool tethering)
{
	GDBusConnection *connection;
	GVariant *tethering_val;
	GError *error = NULL;

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	connection = get_system_dbus_connect();
	if (connection == NULL)
		return BT_ERROR_OPERATION_FAILED;

	tethering_val = g_variant_new("b", tethering);

	g_dbus_connection_call_sync(connection, CONNMAN_DBUS_NAME,
				CONNMAN_BLUETOOTH_TECHNOLOGY_PATH,
				CONNMAN_BLUETOTOH_TECHNOLOGY_INTERFACE,
				"SetProperty",
				g_variant_new("(sv)",
					"Tethering", tethering_val),
				NULL, 0, -1, NULL, &error);

	if (error) {
		DBG("error %s", error->message);
		g_error_free(error);
		return BT_ERROR_OPERATION_FAILED;
	}

	return BT_SUCCESS;
}

int ntb_bt_nap_activate(void)
{
	return connman_set_tethering(true);
}

int ntb_bt_nap_deactivate(void)
{
	return connman_set_tethering(false);
}

int ntb_bt_hdp_register_sink_app(unsigned short data_type, char **app_id)
{
	int result = BT_ERROR_NONE;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	result = bluez_hdp_activate(data_type,
			HDP_ROLE_SINK, HDP_CHANNEL_ANY, app_id);
	return result;
}

int ntb_bt_hdp_unregister_sink_app(const char *app_id)
{
	int result = BT_ERROR_NONE;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	result = bluez_hdp_deactivate(app_id);

	return result;
}

int ntb_bt_hdp_send_data(unsigned int channel, const char *data,
						unsigned int size)
{
	int result = BT_ERROR_NONE;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	result = bluez_hdp_send_data(channel, data, size);

	return result;
}

int ntb_bt_hdp_connect_to_source(const char *remote_address, const char *app_id)
{
	int result = BT_ERROR_NONE;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	result = bluez_hdp_connect(app_id, HDP_CHANNEL_ANY, remote_address);

	return result;
}

int ntb_bt_hdp_disconnect(const char *remote_address, unsigned int channel)
{
	int result = BT_ERROR_NONE;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	result = bluez_hdp_disconnect(channel, remote_address);

	return result;
}

int ntb_bt_hdp_set_connection_state_changed_cb(bt_hdp_connected_cb connected_cb,
		bt_hdp_disconnected_cb disconnected_cb, void *user_data)
{
	struct hdp_connection_changed_cb_node *node_data = NULL;
	GList *list;

	if (connected_cb == NULL || disconnected_cb == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (hdp_state_node) {
		DBG("hdp state callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct hdp_connection_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->conn_cb = connected_cb;
	node_data->disconn_cb = disconnected_cb;
	node_data->user_data = user_data;

	hdp_state_node = node_data;

	dev_property_callback_flags |= DEV_PROP_FLAG_HDP_CONNECT;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HDP_CONNECT);

	g_list_free(list);

	return BT_SUCCESS;
}

int ntb_bt_hdp_unset_connection_state_changed_cb(void)
{
	GList *list;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!hdp_state_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_HDP_CONNECT;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HDP_CONNECT);

	g_free(hdp_state_node);
	hdp_state_node = NULL;

	return BT_SUCCESS;
}

int ntb_bt_hdp_set_data_received_cb(bt_hdp_data_received_cb callback,
							void *user_data)
{
	struct hdp_set_data_received_cb_node *node_data = NULL;
	GList *list;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (hdp_set_data_received_node) {
		DBG("hdp set data receive dnode callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct hdp_set_data_received_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	hdp_set_data_received_node = node_data;

	dev_property_callback_flags |= DEV_PROP_FLAG_HDP_DATA;

	if (!default_adapter)
		return BT_SUCCESS;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HDP_DATA);

	g_list_free(list);

	return BT_SUCCESS;
}

int ntb_bt_hdp_unset_data_received_cb(void)
{
	GList *list;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (!hdp_set_data_received_node)
		return BT_SUCCESS;

	dev_property_callback_flags &= ~DEV_PROP_FLAG_HDP_DATA;

	list = bluez_adapter_get_devices(default_adapter);
	foreach_device_property_callback(list, DEV_PROP_FLAG_HDP_DATA);

	g_free(hdp_set_data_received_node);
	hdp_set_data_received_node = NULL;

	return BT_SUCCESS;
}

int bt_device_connect_le(bt_device_gatt_state_changed_cb callback,
			const char *remote_address)
{
	bluez_device_t *device;
	struct device_connect_cb_node *node_data = NULL;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	if (device_connect_node) {
		DBG("device disconnect callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data =
		g_new0(struct device_connect_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = NULL;

	device_connect_node = node_data;

	_bt_update_bluetooth_callbacks();

	bluez_device_connect_le(device);

	return BT_SUCCESS;
}

int bt_device_disconnect_le(bt_device_gatt_state_changed_cb callback,
			const char *remote_address)
{
	bluez_device_t *device;
	struct device_disconnect_cb_node *node_data = NULL;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	if (device_disconnect_node) {
		DBG("device disconnect callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data =
		g_new0(struct device_disconnect_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = NULL;

	device_disconnect_node = node_data;

	_bt_update_bluetooth_callbacks();

	bluez_device_disconnect_le(device);

	return BT_SUCCESS;
}

int ntb_bt_nap_set_connection_state_changed_cb(
				bt_nap_connection_state_changed_cb callback,
				void *user_data)
{
	struct nap_connection_state_changed_cb_node *node_data;

	DBG("");

	if (callback == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (nap_connection_state_changed_node) {
		DBG("Powered state changed callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct nap_connection_state_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;

	nap_connection_state_changed_node = node_data;

	_bt_update_bluetooth_callbacks();

	return BT_SUCCESS;
}

int ntb_bt_nap_unset_connection_state_changed_cb(void)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!nap_connection_state_changed_node)
		return BT_SUCCESS;

	bluez_unset_nap_connection_state_cb();

	g_free(nap_connection_state_changed_node);
	nap_connection_state_changed_node = NULL;

	return BT_SUCCESS;
}

static gboolean spp_is_device_connected(const char *address)
{
	struct spp_context *spp_ctx;
	GList *list, *next;

	DBG("");

	for (list = g_list_first(spp_ctx_list); list; list = next) {
		next = g_list_next(list);

		spp_ctx = list->data;
		if (spp_ctx)
			if (find_spp_channel_from_address(spp_ctx,
						(gchar *)address))
				return true;
	}

	return false;
}

int ntb_bt_device_foreach_connected_profiles(
			const char *remote_address,
			bt_device_connected_profile callback,
			void *user_data)
{
	bluez_device_t *device;
	bt_device_info_s *device_info;
	gboolean rfcomm_connected;
	gboolean is_type;
	gboolean hid_connected = false;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (!remote_address || !callback) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	device_info = get_device_info(device);

	if (device_info->is_connected == false)
		return  BT_ERROR_REMOTE_DEVICE_NOT_CONNECTED;

	rfcomm_connected = spp_is_device_connected(remote_address);
	if (rfcomm_connected)
		callback(BT_PROFILE_RFCOMM, user_data);

	is_type = bluez_get_media_type(remote_address);

	/*not check hfp and hsp connected, hfp is not ready*/
	/*todo hfp and hsp checking*/

	if (is_type)
		callback(BT_PROFILE_A2DP, user_data);

	if (!(bluez_device_input_get_property_connected(device,
					&hid_connected))) {
		if (hid_connected)
			callback(BT_PROFILE_HID, user_data);
	}

	free_device_info(device_info);

	return BT_SUCCESS;
}

int ntb_bt_gatt_foreach_primary_services(const char *remote_address,
				bt_gatt_primary_service_cb callback,
				void *user_data)
{
	bluez_device_t *device;
	GList *primary_services, *list, *next;
	char *service_path;
	int user_privilieges;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (remote_address == NULL) {
		DBG("address = NULL");
		return BT_ERROR_INVALID_PARAMETER;
	}

	user_privilieges = bt_device_get_privileges(remote_address);

	if (user_privilieges == 0) {
		DBG("user not privilieges to pair and use");
		/*todo: This point will check if Cynara allow user
			use the remote device
			if ok, return BT_SUCCESS.
		*/
		return BT_ERROR_NOT_ENABLED;
	}

	device = bluez_adapter_get_device_by_address(default_adapter,
							remote_address);
	if (device == NULL)
		return BT_ERROR_OPERATION_FAILED;

	primary_services = bluez_device_get_primary_services(device);
	if (primary_services == NULL)
		return BT_ERROR_OPERATION_FAILED;

	for (list = g_list_first(primary_services); list; list = next) {
		service_path = list->data;

		next = g_list_next(list);

		if (!callback((bt_gatt_attribute_h)service_path, user_data))
			break;
	}

	g_list_free(primary_services);

	return BT_SUCCESS;
}

int ntb_bt_gatt_discover_characteristics(bt_gatt_attribute_h service,
				bt_gatt_characteristics_discovered_cb callback,
				void *user_data)
{
	bluez_gatt_service_t *gatt_service;
	GList *characteristics, *list, *next;
	guint total;
	const char *service_path = service;
	char *gatt_char_path;
	int index = 0;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (service_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_service = bluez_gatt_get_service_by_path(service_path);
	if (gatt_service == NULL)
		return BT_ERROR_OPERATION_FAILED;

	characteristics = bluez_gatt_service_get_char_paths(gatt_service);
	if (characteristics == NULL)
		return BT_ERROR_OPERATION_FAILED;

	total = g_list_length(characteristics);

	for (list = g_list_first(characteristics); list; list = next) {
		gatt_char_path = list->data;

		next = g_list_next(list);

		if (!callback(0, index, (int)total,
			(bt_gatt_attribute_h)gatt_char_path, user_data))
			break;

		index++;
	}

	g_list_free(characteristics);

	return BT_SUCCESS;

}

int ntb_bt_gatt_get_service_uuid(bt_gatt_attribute_h service, char **uuid)
{
	bluez_gatt_service_t *gatt_service;
	const char *service_path = service;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (service_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_service = bluez_gatt_get_service_by_path(service_path);
	if (gatt_service == NULL)
		return BT_ERROR_OPERATION_FAILED;

	*uuid = bluez_gatt_service_get_property_uuid(gatt_service);

	return BT_SUCCESS;
}

int ntb_bt_gatt_foreach_included_services(bt_gatt_attribute_h service,
				bt_gatt_included_service_cb callback,
				void *user_data)
{
	bluez_gatt_service_t *gatt_service;
	guint length, index;
	const char *service_path = service;
	char **includes;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (service_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_service = bluez_gatt_get_service_by_path(service_path);
	if (gatt_service == NULL)
		return BT_ERROR_OPERATION_FAILED;

	includes = bluez_gatt_service_get_property_includes(gatt_service);
	if (includes == NULL) {
		DBG("No include services found in this service handle");
		return BT_SUCCESS;
	}

	length = g_strv_length(includes);

	for (index = 0; index < length; index++) {
		if (!callback((bt_gatt_attribute_h)includes[index], user_data))
			break;
	}

	for (index = 0; index < length; index++)
		g_free(includes[index]);

	g_free(includes);

	return BT_SUCCESS;
}

int ntb_bt_gatt_set_characteristic_changed_cb(bt_gatt_attribute_h service,
				bt_gatt_characteristic_changed_cb callback,
				void *user_data)
{
	bluez_gatt_service_t *gatt_service;
	const char *service_path = service;
	struct char_changed_cb_node *node_data;
	GList *characteristics;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (service_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (char_changed_node_list) {
		if (g_list_find_custom(char_changed_node_list,
					service_path,
					service_by_path_cmp)){
			DBG("changed callback already set in this service.");
			return BT_ERROR_ALREADY_DONE;
		}
	}

	gatt_service = bluez_gatt_get_service_by_path(service_path);
	if (gatt_service == NULL)
		return BT_ERROR_OPERATION_FAILED;

	characteristics = bluez_gatt_service_get_chars(gatt_service);
	if (characteristics == NULL)
		return BT_ERROR_OPERATION_FAILED;

	node_data = g_new0(struct char_changed_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = user_data;
	node_data->object_path =
		bluez_gatt_service_get_object_path(gatt_service);

	char_changed_node_list =
		g_list_append(char_changed_node_list, node_data);

	foreach_characteristic_property_callback(characteristics, node_data);

	return BT_SUCCESS;
}

int ntb_bt_gatt_unset_characteristic_changed_cb(bt_gatt_attribute_h service)
{
	bluez_gatt_service_t *gatt_service;
	const char *service_path = service;
	struct char_changed_cb_node *node_data;
	GList *found, *characteristics;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (service_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	if (char_changed_node_list) {
		found = g_list_find_custom(char_changed_node_list,
					service_path,
					service_by_path_cmp);
		if (found)
			node_data = found->data;
		else {
			DBG("changed callback already unset in this service.");
			return BT_ERROR_ALREADY_DONE;
		}

	} else
		return BT_ERROR_OPERATION_FAILED;

	gatt_service = bluez_gatt_get_service_by_path(service_path);
	if (gatt_service == NULL)
		return BT_ERROR_OPERATION_FAILED;

	characteristics = bluez_gatt_service_get_chars(gatt_service);
	if (characteristics == NULL)
		return BT_ERROR_OPERATION_FAILED;

	char_changed_node_list =
			g_list_remove(char_changed_node_list, found);

	g_free(node_data);

	foreach_characteristic_property_callback(characteristics, NULL);

	return BT_SUCCESS;
}

int ntb_bt_gatt_get_characteristic_declaration(bt_gatt_attribute_h characteristic,
				char **uuid, unsigned char **value,
				int *value_length)
{
	bluez_gatt_char_t *gatt_char;
	const char *gatt_char_path = characteristic;
	GByteArray *gb_array;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (gatt_char_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_char = bluez_gatt_get_char_by_path(gatt_char_path);
	if (gatt_char == NULL)
		return BT_ERROR_OPERATION_FAILED;

	*uuid = bluez_gatt_char_get_property_uuid(gatt_char);

	gb_array = bluez_gatt_char_get_property_value(gatt_char);
	if (gb_array == NULL) {
		DBG("Characterisitc is not sync with remote device,"
			" please read value");
		*value_length = 0;

		return BT_SUCCESS;
	}

	*value = g_malloc0(gb_array->len * sizeof(unsigned char));

	memcpy(*value, gb_array->data, gb_array->len);

	*value_length = gb_array->len;

	g_byte_array_unref(gb_array);

	return BT_SUCCESS;
}

int ntb_bt_gatt_set_characteristic_value_request(bt_gatt_attribute_h characteristic,
				const unsigned char *value,
				int value_length,
				unsigned char request,
				bt_gatt_characteristic_write_cb callback)
{
	bluez_gatt_char_t *gatt_char;
	const char *gatt_char_path = characteristic;
	struct char_write_value_cb_node *node_data;
	guint length, index;
	char **flags;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (gatt_char_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_char = bluez_gatt_get_char_by_path(gatt_char_path);
	if (gatt_char == NULL)
		return BT_ERROR_OPERATION_FAILED;

	flags = bluez_gatt_char_property_get_flags(gatt_char);
	length = g_strv_length(flags);

	for (index = 0; index < length; ++index) {
		if (((strcmp(flags[index], WRITE_REQUEST) == 0) &&
			request) ||
			((strcmp(flags[index], WRITE_COMMAND) == 0) &&
			!request))
			break;

		if (index == length - 1)
			return BT_ERROR_OPERATION_FAILED;
	}

	if (request) {
		if (char_write_value_node) {
			DBG("characteristic write callback already set.");
			return BT_ERROR_ALREADY_DONE;
		}

		node_data = g_new0(struct char_write_value_cb_node, 1);
		if (node_data == NULL) {
			ERROR("no memory");
			return BT_ERROR_OUT_OF_MEMORY;
		}

		node_data->cb = callback;
		node_data->user_data = NULL;

		char_write_value_node = node_data;

		_bt_update_bluetooth_callbacks();
	}

	bluez_gatt_write_char_value(gatt_char, value, value_length, request);

	g_strfreev(flags);

	return BT_SUCCESS;

}

int ntb_bt_gatt_clone_attribute_handle(bt_gatt_attribute_h *clone,
				bt_gatt_attribute_h origin)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (origin == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	*clone = g_strdup((char *)origin);

	return BT_SUCCESS;
}

int ntb_bt_gatt_destroy_attribute_handle(bt_gatt_attribute_h handle)
{
	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (handle == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	g_free(handle);

	return BT_SUCCESS;
}

int ntb_bt_gatt_read_characteristic_value(bt_gatt_attribute_h characteristic,
		bt_gatt_characteristic_read_cb callback)
{
	bluez_gatt_char_t *gatt_char;
	const char *gatt_char_path = characteristic;
	struct char_read_value_cb_node *node_data;

	DBG("");

	if (initialized == false)
		return BT_ERROR_NOT_INITIALIZED;

	if (default_adapter == NULL)
		return BT_ERROR_ADAPTER_NOT_FOUND;

	if (gatt_char_path == NULL)
		return BT_ERROR_INVALID_PARAMETER;

	gatt_char = bluez_gatt_get_char_by_path(gatt_char_path);
	if (gatt_char == NULL)
		return BT_ERROR_OPERATION_FAILED;

	if (char_read_value_node) {
		DBG("characteristic read callback already set.");
		return BT_ERROR_ALREADY_DONE;
	}

	node_data = g_new0(struct char_read_value_cb_node, 1);
	if (node_data == NULL) {
		ERROR("no memory");
		return BT_ERROR_OUT_OF_MEMORY;
	}

	node_data->cb = callback;
	node_data->user_data = NULL;

	char_read_value_node = node_data;

	_bt_update_bluetooth_callbacks();

	bluez_gatt_read_char_value(gatt_char);

	return BT_SUCCESS;
}

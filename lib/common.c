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
#include <gio/gio.h>
#include <dbus/dbus.h>
#include <gio/gunixfdlist.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include "common.h"
#include "uuid.h"

struct error_map_t {
	const gchar *error_key_str;
	enum bluez_error_type type;
} error_map[] = {
	{"Error.DoesNotExist:", 	ERROR_DOES_NOT_EXIST},
	{"Error.InvalidArguments",	ERROR_INVALID_ARGUMENTS},
	{"Error.AlreadyExists", 	ERROR_ALREADY_EXISTS},
	{"Error.Failed", 		ERROR_FAILED},
	{"Error.AuthenticationFailed",	ERROR_AUTH_FAILED},
	{"Error.AuthenticationCanceled",ERROR_AUTH_CANCELED},
	{"Error.AuthenticationRejected",ERROR_AUTH_REJECT},
	{"Error.AuthenticationTimeout",	ERROR_AUTH_TIMEOUT},
	{"Error.ConnectionAttemptFailed",ERROR_AUTH_ATTEMPT_FAILED},
	{NULL, 				ERROR_NONE},
};

static GDBusConnection *conn;

enum bluez_error_type get_error_type(GError *error)
{
	int i = 0;

	while (error_map[i].error_key_str != NULL) {
		const gchar *error_info = error_map[i].error_key_str;

		if (g_strrstr(error->message, error_info))
			return error_map[i].type;

		i++;
	}

	return ERROR_NONE;
}
int property_get_boolean(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				gboolean *value)
{
	GVariant *bool_v, *bool_vv;
	GError *error = NULL;

	bool_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (bool_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(bool_vv, "(v)", &bool_v);

	*value = g_variant_get_boolean(bool_v);

	g_variant_unref(bool_v);

	return 0;
}

char *property_get_string(GDBusProxy *proxy,
				const char *interface_name,
				const char *property)
{
	GVariant *string_v, *string_vv;
	char *string;
	GError *error = NULL;

	string_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (string_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(string_vv, "(v)", &string_v);

	string = g_variant_dup_string(string_v, NULL);

	g_variant_unref(string_v);

	return string;
}

int property_get_int16(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				gint16 *value)
{
	GVariant *int16_v, *int16_vv;
	GError *error = NULL;

	int16_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (int16_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(int16_vv, "(v)", &int16_v);

	*value = g_variant_get_int16(int16_v);

	g_variant_unref(int16_v);

	return 0;
}

int property_get_uint16(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint16 *value)
{
	GVariant *uint16_v, *uint16_vv;
	GError *error = NULL;

	uint16_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (uint16_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(uint16_vv, "(v)", &uint16_v);

	*value = g_variant_get_uint16(uint16_v);

	g_variant_unref(uint16_v);

	return 0;
}

int property_get_uint32(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint32 *u32)
{
	GVariant *u32_v, *u32_vv;
	GError *error = NULL;

	u32_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);
	if (u32_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(u32_vv, "(v)", &u32_v);

	*u32 = g_variant_get_uint32(u32_v);

	g_variant_unref(u32_v);

	return 0;
}

int property_get_uint64(GDBusProxy *proxy,
				const char *interface_name,
				const char *property,
				guint64 *u64)
{
	GVariant *u64_v, *u64_vv;
	GError *error = NULL;

	u64_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);
	if (u64_vv == NULL) {
		WARN("no cached property %s", property);
		return -1;
	}

	g_variant_get(u64_vv, "(v)", &u64_v);

	*u64 = g_variant_get_uint64(u64_v);

	g_variant_unref(u64_v);

	return 0;
}

char **property_get_string_list(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *strv_v, *strv_vv;
	char **strv;
	GError *error = NULL;

	strv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (strv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(strv_vv, "(v)", &strv_v);

	strv = g_variant_dup_strv(strv_v, NULL);

	return strv;
}

char **property_get_object_list(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *objv_v, *objv_vv;
	char **objv;
	GError *error = NULL;

	objv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (objv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(objv_vv, "(v)", &objv_v);

	objv = g_variant_dup_objv(objv_v, NULL);

	return objv;
}

GByteArray *property_get_bytestring(GDBusProxy *proxy,
					const char *interface_name,
					const char *property)
{
	GVariant *bytv_v, *bytv_vv;
	GByteArray *gb_array = NULL;
	GError *error = NULL;
	GVariantIter *byt_iter;
	guchar g_value;

	bytv_vv = g_dbus_proxy_call_sync(
			proxy, "Get",
			g_variant_new("(ss)", interface_name, property),
			0, -1, NULL, &error);

	if (bytv_vv == NULL) {
		WARN("no cached property %s", property);
		return NULL;
	}

	g_variant_get(bytv_vv, "(v)", &bytv_v);

	g_variant_get(bytv_v, "ay", &byt_iter);

	gb_array = g_byte_array_new();

	while (g_variant_iter_loop(byt_iter, "y", &g_value)) {
		g_byte_array_append(gb_array, &g_value,
					sizeof(unsigned char));
	}

	return gb_array;
}

void property_set_string(GDBusProxy *proxy,
					const char *interface_name,
					const char *property,
					const char *str)
{
	GError *error = NULL;
	GVariant *val = g_variant_new("s", str);
	GVariant *parameters = g_variant_new("(ssv)",
		interface_name, property, val);

	g_dbus_proxy_call_sync(
			proxy, "Set", parameters,
			0, -1, NULL, &error);
}

void property_set_uint64(GDBusProxy *proxy,
					const char *interface_name,
					const char *property,
					guint64 u64)
{
	GError *error = NULL;
	GVariant *val = g_variant_new("t", u64);
	GVariant *parameters = g_variant_new("(ssv)",
				interface_name, property, val);

	g_dbus_proxy_call_sync(
			proxy, "Set", parameters,
			0, -1, NULL, &error);
}

void convert_device_path_to_address(const gchar *device_path,
					gchar *device_address)
{
	gchar address[BT_ADDRESS_STRING_SIZE] = { 0 };
	gchar *dev_addr;

	if (device_path == NULL || device_address == NULL)
		return;

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		gchar *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL)
			*pos = ':';

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}

void simple_reply_callback(GObject *source_object, GAsyncResult *res,
							gpointer user_data)
{
	struct simple_reply_data *reply_data = user_data;
	enum bluez_error_type error_type = ERROR_NONE;
	GError *error = NULL;
	GVariant *ret;

	if (!reply_data || !reply_data->proxy)
		goto done;

	ret = g_dbus_proxy_call_finish(reply_data->proxy, res, &error);
	if (ret == NULL) {
		DBG("%s", error->message);
		error_type = get_error_type(error);

		g_error_free(error);
	} else
		g_variant_unref(ret);

	if (!reply_data)
		return;

	if (reply_data->reply_cb)
		reply_data->reply_cb(error_type, reply_data->user_data);

done:
	g_free(reply_data);
}

void device_path_to_address(const char *device_path, char *device_address)
{
	char address[BT_ADDRESS_STRING_SIZE] = { 0 };
	char *dev_addr = NULL;

	if (!device_path || !device_address)
		return;

	dev_addr = strstr(device_path, "dev_");
	if (dev_addr != NULL) {
		char *pos = NULL;
		dev_addr += 4;
		g_strlcpy(address, dev_addr, sizeof(address));

		while ((pos = strchr(address, '_')) != NULL)
			*pos = ':';

		g_strlcpy(device_address, address, BT_ADDRESS_STRING_SIZE);
	}
}

static int check_address(const char *device_address)
{
	DBG("");

	if (strlen(device_address) != 17)
		return -1;

	while (*device_address) {
		device_address += 2;

		if (*device_address == 0)
			break;

		if (*device_address++ != ':')
			return -1;
	}

	return 0;
}

unsigned char *convert_address_to_baddr(const char *address)
{
	int i, num;
	unsigned char *baddr = g_malloc0(6);

	DBG("address = %s, len = %d", address,
					(int)strlen(address));

	if (baddr == NULL)
		return NULL;

	if (check_address(address) != 0) {
		DBG("check_address != 0");
		return NULL;
	}

	num = 0;

	DBG("address = %s", address);

	for (i = 5; i >= 0; i--, address += 3) {
		baddr[num++] = strtol(address, NULL, 16);
		DBG("0x%2x", baddr[num-1]);
	}

	return baddr;
}

GDBusConnection *get_system_lib_dbus_connect(void)
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

unsigned int convert_appearance_to_type(unsigned int appearance)
{
	/*todo support it later*/
	return 0x00;
}

char **convert_uuid_to_profiles(char **uuids)
{
	guint length, index;
	gint num = 0;
	char **parts = NULL;
	unsigned int service;
	char **profiles;

	DBG("");

	length = g_strv_length(uuids);

	profiles = g_malloc0(sizeof(char *)*length + 1);

	if (!profiles)
		return NULL;

	for (index = 0; index < length; ++index) {
		parts = g_strsplit(uuids[index], "-", -1);
		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			continue;
		}

		service = g_ascii_strtoull(parts[0], NULL, 16);

		switch (service) {
		case  BLUETOOTH_SDP_UUID:
			profiles[num] = g_strdup("SDP");
			break;
		case  BLUETOOTH_RFCOMM_UUID:
			profiles[num] = g_strdup("RFCOMM");
			break;
		case  BLUETOOTH_TCS_UUID:
			profiles[num] = g_strdup("TCS-BIN");
			break;
		case  BLUETOOTH_ATT_UUID:
			profiles[num] = g_strdup("ATT");
			break;
		case  BLUETOOTH_OBEX_UUID:
			profiles[num] = g_strdup("OBEX");
			break;
		case  BLUETOOTH_BNEP_UUID:
			profiles[num] = g_strdup("BNEP");
			break;
		case  BLUETOOTH_UPNP_UUID:
			profiles[num] = g_strdup("UPNP");
			break;
		case  BLUETOOTH_HIDP_UUID:
			profiles[num] = g_strdup("HIDP");
			break;
		case  BLUETOOTH_HCCC_UUID:
			profiles[num] = g_strdup("Hardcopy Control Channel");
			break;
		case  BLUETOOTH_HCDC_UUID:
			profiles[num] = g_strdup("Hardcopy Data Channel");
			break;
		case  BLUETOOTH_HCN_UUID:
			profiles[num] = g_strdup("Hardcopy Notification");
			break;
		case  BLUETOOTH_AVCTP_UUID:
			profiles[num] = g_strdup("AVCTP");
			break;
		case  BLUETOOTH_AVDTP_UUID:
			profiles[num] = g_strdup("AVDTP");
			break;
		case  BLUETOOTH_CMTP_UUID:
			profiles[num] = g_strdup("CMTP");
			break;
		case  BLUETOOTH_MCAPC_UUID:
			profiles[num] = g_strdup("MCAP Control Channel");
			break;
		case  BLUETOOTH_MCAPD_UUID:
			profiles[num] = g_strdup("MCAP Data Channel");
			break;
		case  BLUETOOTH_L2CAP_UUID:
			profiles[num] = g_strdup("L2CAP");
			break;
		case  BLUETOOTH_SDSSC_UUID:
			profiles[num] =
				g_strdup(
				"Service Discovery Server Service Class");
			break;
		case  BLUETOOTH_BGDSC_UUID:
			profiles[num] =
				g_strdup(
				"Browse Group Descriptor Service Class");
			break;
		case  BLUETOOTH_PBR_UUID:
			profiles[num] = g_strdup("Public Browse Root");
			break;
		case  BLUETOOTH_SP_UUID:
			profiles[num] = g_strdup("Serial Port");
			break;
		case  BLUETOOTH_LAUP_UUID:
			profiles[num] = g_strdup("LAN Access Using PPP");
			break;
		case  BLUETOOTH_DN_UUID:
			profiles[num] = g_strdup("Dialup Networking");
			break;
		case  BLUETOOTH_IrMCS_UUID:
			profiles[num] = g_strdup("IrMC Sync");
			break;
		case  BLUETOOTH_OPP_UUID:
			profiles[num] = g_strdup("OBEX Object Push");
			break;
		case  BLUETOOTH_FTP_UUID:
			profiles[num] = g_strdup("OBEX File Transfer");
			break;
		case  BLUETOOTH_IRMCSC_UUID:
			profiles[num] = g_strdup("IrMC Sync Command");
			break;
		case  BLUETOOTH_HSP_UUID:
			profiles[num] = g_strdup("Headset");
			break;
		case  BLUETOOTH_CT_UUID:
			profiles[num] = g_strdup("Cordless Telephony");
			break;
		case  BLUETOOTH_ASOURCE_UUID:
			profiles[num] = g_strdup("Audio Source");
			break;
		case  BLUETOOTH_ASINK_UUID:
			profiles[num] = g_strdup("Audio Sink");
			break;
		case  BLUETOOTH_AVRCT_UUID:
			profiles[num] = g_strdup("A/V Remote Control Target");
			break;
		case  BLUETOOTH_AAD_UUID:
			profiles[num] = g_strdup("Advanced Audio Distribution");
			break;
		case  BLUETOOTH_AVRC_UUID:
			profiles[num] = g_strdup("A/V Remote Control");
			break;
		case  BLUETOOTH_AVRCC_UUID:
			profiles[num] =
				g_strdup("A/V Remote Control Controller");
			break;
		case  BLUETOOTH_INTERCOM_UUID:
			profiles[num] = g_strdup("Intercom");
			break;
		case  BLUETOOTH_FAX_UUID:
			profiles[num] = g_strdup("Fax");
			break;
		case  BLUETOOTH_HSPG_UUID:
			profiles[num] = g_strdup("Headset AG");
			break;
		case  BLUETOOTH_WAP_UUID:
			profiles[num] = g_strdup("WAP");
			break;
		case  BLUETOOTH_WAPC_UUID:
			profiles[num] = g_strdup("WAP Client");
			break;
		case  BLUETOOTH_PANU_UUID:
			profiles[num] = g_strdup("PANU");
			break;
		case  BLUETOOTH_NAP_UUID:
			profiles[num] = g_strdup("NAP");
			break;
		case  BLUETOOTH_GN_UUID:
			profiles[num] = g_strdup("GN");
			break;
		case  BLUETOOTH_DP_UUID:
			profiles[num] = g_strdup("Direct Printing");
			break;
		case  BLUETOOTH_RP_UUID:
			profiles[num] = g_strdup("Reference Printing");
			break;
		case  BLUETOOTH_BIP_UUID:
			profiles[num] = g_strdup("Basic Imaging Profile");
			break;
		case  BLUETOOTH_IR_UUID:
			profiles[num] = g_strdup("Imaging Responder");
			break;
		case  BLUETOOTH_IAA_UUID:
			profiles[num] = g_strdup("Imaging Automatic Archive");
			break;
		case  BLUETOOTH_IRO_UUID:
			profiles[num] = g_strdup("Imaging Referenced Objects");
			break;
		case  BLUETOOTH_HFP_UUID:
			profiles[num] = g_strdup("Handsfree");
			break;
		case  BLUETOOTH_HFPG_UUID:
			profiles[num] = g_strdup("Handsfree Audio Gateway");
			break;
		case  BLUETOOTH_DPROS_UUID:
			profiles[num] =
				g_strdup(
				"Direct Printing Refrence Objects Service");
			break;
		case  BLUETOOTH_RU_UUID:
			profiles[num] = g_strdup("Reflected UI");
			break;
		case  BLUETOOTH_BP_UUID:
			profiles[num] = g_strdup("Basic Printing");
			break;
		case  BLUETOOTH_PS_UUID:
			profiles[num] = g_strdup("Printing Status");
			break;
		case  BLUETOOTH_HIDS_UUID:
			profiles[num] =
				g_strdup("Human Interface Device Service");
			break;
		case  BLUETOOTH_HCR_UUID:
			profiles[num] = g_strdup("Hardcopy Cable Replacement");
			break;
		case  BLUETOOTH_HCRP_UUID:
			profiles[num] = g_strdup("HCR Print");
			break;
		case  BLUETOOTH_HCRS_UUID:
			profiles[num] = g_strdup("HCR Scan");
			break;
		case  BLUETOOTH_CIA_UUID:
			profiles[num] = g_strdup("Common ISDN Access");
			break;
		case  BLUETOOTH_SAP_UUID:
			profiles[num] = g_strdup("SIM Access");
			break;
		case  BLUETOOTH_PBAPC_UUID:
			profiles[num] = g_strdup("Phonebook Access Client");
			break;
		case  BLUETOOTH_PBAPS_UUID:
			profiles[num] = g_strdup("Phonebook Access Server");
			break;
		case  BLUETOOTH_PBAP_UUID:
			profiles[num] = g_strdup("Phonebook Access");
			break;
		case  BLUETOOTH_HSPHS_UUID:
			profiles[num] = g_strdup("Headset HS");
			break;
		case  BLUETOOTH_MAPS_UUID:
			profiles[num] = g_strdup("Message Access Server");
			break;
		case  BLUETOOTH_MNS_UUID:
			profiles[num] = g_strdup("Message Notification Server");
			break;
		case  BLUETOOTH_MAP_UUID:
			profiles[num] = g_strdup("Message Access Profile");
			break;
		case  BLUETOOTH_GNSS_UUID:
			profiles[num] = g_strdup("GNSS");
			break;
		case  BLUETOOTH_GNSSS_UUID:
			profiles[num] = g_strdup("GNSS Server");
			break;
		case  BLUETOOTH_PNPI_UUID:
			profiles[num] = g_strdup("PnP Information");
			break;
		case  BLUETOOTH_GENERICN_UUID:
			profiles[num] = g_strdup("Generic Networking");
			break;
		case  BLUETOOTH_GENERIFT_UUID:
			profiles[num] = g_strdup("Generic File Transfer");
			break;
		case  BLUETOOTH_GENERIAD_UUID:
			profiles[num] = g_strdup("Generic Audio");
			break;
		case  BLUETOOTH_GENERITP_UUID:
			profiles[num] = g_strdup("Generic Telephony");
			break;
		case  BLUETOOTH_UPNPS_UUID:
			profiles[num] = g_strdup("UPNP Service");
			break;
		case  BLUETOOTH_UPNPIPS_UUID:
			profiles[num] = g_strdup("UPNP IP Service");
			break;
		case  BLUETOOTH_UPNPIPPAN_UUID:
			profiles[num] = g_strdup("UPNP IP PAN");
			break;
		case  BLUETOOTH_UPNPIPLAP_UUID:
			profiles[num] = g_strdup("UPNP IP LAP");
			break;
		case  BLUETOOTH_UPNPIPL2CAP_UUID:
			profiles[num] = g_strdup("UPNP IP L2CAP");
			break;
		case  BLUETOOTH_VSOURCE_UUID:
			profiles[num] = g_strdup("Video Source");
			break;
		case  BLUETOOTH_VSINK_UUID:
			profiles[num] = g_strdup("Video Sink");
			break;
		case  BLUETOOTH_VDIST_UUID:
			profiles[num] = g_strdup("Video Distribution");
			break;
		case  BLUETOOTH_HDP_UUID:
			profiles[num] = g_strdup("HDP");
			break;
		case  BLUETOOTH_HDPSOURCE_UUID:
			profiles[num] = g_strdup("HDP Source");
			break;
		case  BLUETOOTH_HDPSINK_UUID:
			profiles[num] = g_strdup("HDP Sink");
			break;
		case  BLUETOOTH_GAP_UUID:
			profiles[num] = g_strdup("Generic Access Profile");
			break;
		case  BLUETOOTH_GATTP_UUID:
			profiles[num] = g_strdup("Generic Attribute Profile");
			break;
		case  BLUETOOTH_IAP_UUID:
			profiles[num] = g_strdup("Immediate Alert");
			break;
		case  BLUETOOTH_LLOSTP_UUID:
			profiles[num] = g_strdup("Link Loss");
			break;
		case  BLUETOOTH_TXP_UUID:
			profiles[num] = g_strdup("Tx Power");
			break;
		case  BLUETOOTH_CTSP_UUID:
			profiles[num] = g_strdup("Current Time Service");
			break;
		case  BLUETOOTH_RTUS_UUID:
			profiles[num] =
				g_strdup("Reference Time Update Service");
			break;
		case  BLUETOOTH_NDCS_UUID:
			profiles[num] = g_strdup("Next DST Change Service");
			break;
		case  BLUETOOTH_GLUCOSE_UUID:
			profiles[num] = g_strdup("Glucose");
			break;
		case  BLUETOOTH_HEALTHT_UUID:
			profiles[num] = g_strdup("Health Thermometer");
			break;
		case  BLUETOOTH_DEVICEI_UUID:
			profiles[num] = g_strdup("Device Information");
			break;
		case  BLUETOOTH_HEARTR_UUID:
			profiles[num] = g_strdup("Heart Rate");
			break;
		case  BLUETOOTH_PASS_UUID:
			profiles[num] = g_strdup("Phone Alert Status Service");
			break;
		case  BLUETOOTH_BSP_UUID:
			profiles[num] = g_strdup("Battery Service");
			break;
		case  BLUETOOTH_BLOODPP_UUID:
			profiles[num] = g_strdup("Blood Pressure");
			break;
		case  BLUETOOTH_ANS_UUID:
			profiles[num] = g_strdup("Alert Notification Service");
			break;
		case  BLUETOOTH_HID_UUID:
			profiles[num] = g_strdup("Human Interface Device");
			break;
		case  BLUETOOTH_SCANP_UUID:
			profiles[num] = g_strdup("Scan Parameters");
			break;
		case  BLUETOOTH_RSAC_UUID:
			profiles[num] = g_strdup("Running Speed and Cadence");
			break;
		case  BLUETOOTH_CSAC_UUID:
			profiles[num] = g_strdup("Cycling Speed and Cadence");
			break;
		case  BLUETOOTH_PRIMARYS_UUID:
			profiles[num] = g_strdup("Primary Service");
			break;
		case  BLUETOOTH_SECONDS_UUID:
			profiles[num] = g_strdup("Secondary Service");
			break;
		case  BLUETOOTH_INCLUDE_UUID:
			profiles[num] = g_strdup("Include");
			break;
		case  BLUETOOTH_CHARACTER_UUID:
			profiles[num] = g_strdup("Characteristic");
			break;
		case  BLUETOOTH_CHARACTEREP_UUID:
			profiles[num] =
				g_strdup("Characteristic Extended Properties");
			break;
		case  BLUETOOTH_CHARACTEREPUD_UUID:
			profiles[num] =
				g_strdup("Characteristic User Description");
			break;
		case  BLUETOOTH_CCHARACTEREPC_UUID:
			profiles[num] =
				g_strdup("Client Characteristic Configuration");
			break;
		case  BLUETOOTH_SCHARACTEREPC_UUID:
			profiles[num] =
				g_strdup("Server Characteristic Configuration");
			break;
		case  BLUETOOTH_CHARACTEREPF_UUID:
			profiles[num] = g_strdup("Characteristic Format");
			break;
		case  BLUETOOTH_CHARACTEREPAF_UUID:
			profiles[num] =
				g_strdup("Characteristic Aggregate Formate");
			break;
		case  BLUETOOTH_VALIDRANGE_UUID:
			profiles[num] = g_strdup("Valid Range");
			break;
		case  BLUETOOTH_EXTERNALRR_UUID:
			profiles[num] = g_strdup("External Report Reference");
			break;
		case  BLUETOOTH_REPORTR_UUID:
			profiles[num] = g_strdup("Report Reference");
			break;
		case  BLUETOOTH_DEVICENAME_UUID:
			profiles[num] = g_strdup("Device Name");
			break;
		case  BLUETOOTH_APPEARANCE_UUID:
			profiles[num] = g_strdup("Appearance");
			break;
		case  BLUETOOTH_PPF_UUID:
			profiles[num] = g_strdup("Peripheral Privacy Flag");
			break;
		case  BLUETOOTH_RECONNADDR_UUID:
			profiles[num] = g_strdup("Reconnection Address");
			break;
		case  BLUETOOTH_PPCP_UUID:
			profiles[num] =
				g_strdup(
				"Peripheral Preferred Connection Parameters");
			break;
		case  BLUETOOTH_SERVICEC_UUID:
			profiles[num] = g_strdup("Service Changed");
			break;
		case  BLUETOOTH_ALEVEL_UUID:
			profiles[num] = g_strdup("Alert Level");
			break;
		case  BLUETOOTH_TXPLEVEL_UUID:
			profiles[num] = g_strdup("Tx Power Level");
			break;
		case  BLUETOOTH_DATATIME_UUID:
			profiles[num] = g_strdup("Date Time");
			break;
		case  BLUETOOTH_DOW_UUID:
			profiles[num] = g_strdup("Day of Week");
			break;
		case  BLUETOOTH_DDT_UUID:
			profiles[num] = g_strdup("Day Date Time");
			break;
		case  BLUETOOTH_EXACTT256_UUID:
			profiles[num] = g_strdup("Exact Time 256");
			break;
		case  BLUETOOTH_DSTOFF_UUID:
			profiles[num] = g_strdup("DST Offset");
			break;
		case  BLUETOOTH_TIMEZ_UUID:
			profiles[num] = g_strdup("Time Zone");
			break;
		case  BLUETOOTH_LOCALTI_UUID:
			profiles[num] = g_strdup("Local Time Information");
			break;
		case  BLUETOOTH_TIMEWDST_UUID:
			profiles[num] = g_strdup("Time with DST");
			break;
		case  BLUETOOTH_TIMEACCURACY_UUID:
			profiles[num] = g_strdup("Time Accuracy");
			break;
		case  BLUETOOTH_TIMESOURCE_UUID:
			profiles[num] = g_strdup("Time Source");
			break;
		case  BLUETOOTH_REFERENCETI_UUID:
			profiles[num] = g_strdup("Reference Time Information");
			break;
		case  BLUETOOTH_TIMEUCP_UUID:
			profiles[num] = g_strdup("Time Update Control Point");
			break;
		case  BLUETOOTH_TIMEUS_UUID:
			profiles[num] = g_strdup("Time Update State");
			break;
		case  BLUETOOTH_GLUCOSEM_UUID:
			profiles[num] = g_strdup("Glucose Measurement");
			break;
		case  BLUETOOTH_BATTERYL_UUID:
			profiles[num] = g_strdup("Battery Level");
			break;
		case  BLUETOOTH_TEMPERATUREM_UUID:
			profiles[num] = g_strdup("Temperature Measurement");
			break;
		case  BLUETOOTH_TEMPERATURET_UUID:
			profiles[num] = g_strdup("Temperature Type");
			break;
		case  BLUETOOTH_INTERMEDIATET_UUID:
			profiles[num] = g_strdup("Intermediate Temperature");
			break;
		case  BLUETOOTH_MEASUREMENTI_UUID:
			profiles[num] = g_strdup("Measurement Interval");
			break;
		case  BLUETOOTH_BKIR_UUID:
			profiles[num] = g_strdup("Boot Keyboard Input Report");
			break;
		case  BLUETOOTH_SYSTEMID_UUID:
			profiles[num] = g_strdup("System ID");
			break;
		case  BLUETOOTH_MODELNS_UUID:
			profiles[num] = g_strdup("Model Number String");
			break;
		case  BLUETOOTH_SNS_UUID:
			profiles[num] = g_strdup("Serial Number String");
			break;
		case  BLUETOOTH_FIRMRS_UUID:
			profiles[num] = g_strdup("Firmware Revision String");
			break;
		case  BLUETOOTH_HARDRS_UUID:
			profiles[num] = g_strdup("Hardware Revision String");
			break;
		case  BLUETOOTH_SOFTRS_UUID:
			profiles[num] = g_strdup("Software Revision String");
			break;
		case  BLUETOOTH_MANUNS_UUID:
			profiles[num] = g_strdup("Manufacturer Name String");
			break;
		case  BLUETOOTH_IEEE11073_UUID:
			profiles[num] =
				g_strdup(
				"IEEE 11073-20601 Regulatory Cert. Data List");
			break;
		case  BLUETOOTH_CURRENTT_UUID:
			profiles[num] = g_strdup("Current Time");
			break;
		case  BLUETOOTH_SCANR_UUID:
			profiles[num] = g_strdup("Scan Refresh");
			break;
		case  BLUETOOTH_BKOR_UUID:
			profiles[num] = g_strdup("Boot Keyboard Output Report");
			break;
		case  BLUETOOTH_BMIR_UUID:
			profiles[num] = g_strdup("Boot Mouse Input Report");
			break;
		case  BLUETOOTH_GMC_UUID:
			profiles[num] = g_strdup("Glucose Measurement Context");
			break;
		case  BLUETOOTH_BLOODPM_UUID:
			profiles[num] = g_strdup("Blood Pressure Measurement");
			break;
		case  BLUETOOTH_INTERMEDIATECP_UUID:
			profiles[num] = g_strdup("Intermediate Cuff Pressure");
			break;
		case  BLUETOOTH_HEARTRM_UUID:
			profiles[num] = g_strdup("Heart Rate Measurement");
			break;
		case  BLUETOOTH_BODYSL_UUID:
			profiles[num] = g_strdup("Body Sensor Location");
			break;
		case  BLUETOOTH_HEARTRCP_UUID:
			profiles[num] = g_strdup("Heart Rate Control Point");
			break;
		case  BLUETOOTH_ALERTS_UUID:
			profiles[num] = g_strdup("Alert Status");
			break;
		case  BLUETOOTH_RINGERCP_UUID:
			profiles[num] = g_strdup("Ringer Control Point");
			break;
		case  BLUETOOTH_RINGERS_UUID:
			profiles[num] = g_strdup("Ringer Setting");
			break;
		case  BLUETOOTH_ALERTCIBM_UUID:
			profiles[num] = g_strdup("Alert Category ID Bit Mask");
			break;
		case  BLUETOOTH_ALERTCI_UUID:
			profiles[num] = g_strdup("Alert Category ID");
			break;
		case  BLUETOOTH_ALERTNCP_UUID:
			profiles[num] =
				g_strdup("Alert Notification Control Point");
			break;
		case  BLUETOOTH_UNREADAS_UUID:
			profiles[num] = g_strdup("Unread Alert Status");
			break;
		case  BLUETOOTH_NEWALERT_UUID:
			profiles[num] = g_strdup("New Alert");
			break;
		case  BLUETOOTH_SNAC_UUID:
			profiles[num] =
				g_strdup("Supported New Alert Category");
			break;
		case  BLUETOOTH_SUAC_UUID:
			profiles[num] =
				g_strdup("Supported Unread Alert Category");
			break;
		case  BLUETOOTH_BLOODPF_UUID:
			profiles[num] = g_strdup("Blood Pressure Feature");
			break;
		case  BLUETOOTH_HIDINFO_UUID:
			profiles[num] = g_strdup("HID Information");
			break;
		case  BLUETOOTH_REPORTMAP_UUID:
			profiles[num] = g_strdup("Report Map");
			break;
		case  BLUETOOTH_HIDCP_UUID:
			profiles[num] = g_strdup("HID Control Point");
			break;
		case  BLUETOOTH_REPORT_UUID:
			profiles[num] = g_strdup("Report");
			break;
		case  BLUETOOTH_PROTOCALM_UUID:
			profiles[num] = g_strdup("Protocol Mode");
			break;
		case  BLUETOOTH_SCANIW_UUID:
			profiles[num] = g_strdup("Scan Interval Window");
			break;
		case  BLUETOOTH_PNPID_UUID:
			profiles[num] = g_strdup("PnP ID");
			break;
		case  BLUETOOTH_GLUCOSEF_UUID:
			profiles[num] = g_strdup("Glucose Feature");
			break;
		case  BLUETOOTH_RECORDACP_UUID:
			profiles[num] = g_strdup("Record Access Control Point");
			break;
		case  BLUETOOTH_RSCM_UUID:
			profiles[num] = g_strdup("RSC Measurement");
			break;
		case  BLUETOOTH_RSMF_UUID:
			profiles[num] = g_strdup("RSC Feature");
			break;
		case  BLUETOOTH_SCCP_UUID:
			profiles[num] = g_strdup("SC Control Point");
			break;
		case  BLUETOOTH_CSCM_UUID:
			profiles[num] = g_strdup("CSC Measurement");
			break;
		case  BLUETOOTH_CSCF_UUID:
			profiles[num] = g_strdup("CSC Feature");
			break;
		case  BLUETOOTH_SENSORL_UUID:
			profiles[num] = g_strdup("Sensor Location");
			break;
		default:
			num--;
			break;
		}
		num++;
	}

	return profiles;
}

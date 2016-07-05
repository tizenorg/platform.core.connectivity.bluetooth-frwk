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

#include <string.h>
#include <glib.h>
#include <dlog.h>
#include <gio/gio.h>
#include <cynara-client.h>
#include <cynara-creds-gdbus.h>

#include "bluetooth-api.h"
#include "bt-request-handler.h"
#include "bt-service-common.h"
#include "bt-service-util.h"

#include "bt-service-core-adapter.h"
#include "bt-service-core-device.h"

/* For maintaining Application Sync API call requests */
GSList *invocation_list = NULL;

static GDBusConnection *bt_service_conn;
static guint owner_id = 0;
cynara *p_cynara;
cynara_configuration *conf;

static const gchar bt_service_introspection_xml[] =
"<node name='/org/projectx/bt_service'>"
"	<interface name='org.projectx.bt'>"
"		<method name='service_request'>"
			/* Input Parameters */
"			<arg type='i' name='service_type' direction='in' />"
"			<arg type='i' name='service_function' direction='in' />"
"			<arg type='i' name='request_type' direction='in' />"
"			<arg type='ay' name='input_param1' direction='in' />"
"			<arg type='ay' name='input_param2' direction='in' />"
"			<arg type='ay' name='input_param3' direction='in' />"
"			<arg type='ay' name='input_param4' direction='in' />"
"			<arg type='ay' name='input_param5' direction='in' />"
			/* Return Parameters */
"			<arg type='i' name='output_param1' direction='out' />"
"			<arg type='v' name='output_param2' direction='out' />"
"		</method>"
"	</interface>"
"</node>";

GDBusNodeInfo *node_info = NULL;

static void __bt_service_method(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data);

int __bt_bluez_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GArray **out_param1);
int __bt_obexd_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GVariant *in_param5,
		GArray **out_param1);
int __bt_agent_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GArray **out_param1);
int __bt_core_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1);

gboolean __bt_service_check_privilege(int function_name,
					int service_type,
					const char *unique_name);

/* Function definitions*/
GSList *_bt_get_invocation_list(void)
{
	return invocation_list;
}

void _bt_free_info_from_invocation_list(invocation_info_t *req_info)
{
	GSList *l;
	invocation_info_t *info;

	for (l = invocation_list; l != NULL; l = g_slist_next(l)) {
		info = l->data;
		if (info == NULL)
			continue;

		/* No two same sync requests from same application can exist */
		if ((strcasecmp(info->sender, req_info->sender) == 0) &&
				req_info->service_function == info->service_function) {

			invocation_list = g_slist_remove(invocation_list, req_info);
			g_free(req_info);
			break;
		}
	}

}

static void __bt_service_get_parameters(GVariant *in_param,
		void *value, int size)
{
	void *buf = NULL;
	buf = (void *)g_variant_get_data(in_param);
	memcpy(value, buf, size);
}

static gboolean __bt_is_sync_function(int service_function)
{
	/*TODO: Keep adding sync methods with expect replies from bluetooth service */
	if (service_function == BT_GET_LOCAL_ADDRESS
			|| service_function == BT_GET_LOCAL_NAME
			|| service_function == BT_GET_LOCAL_VERSION
			|| service_function == BT_GET_BONDED_DEVICES
			|| service_function == BT_GET_BONDED_DEVICE
			|| service_function == BT_IS_SERVICE_USED)
		return TRUE;
	else
		return FALSE;
}

void _bt_save_invocation_context(GDBusMethodInvocation *invocation, int result,
		char *sender, int service_function,
		gpointer invocation_data)
{
	BT_DBG("Saving the invocation context: service_function [%d]", service_function);
	invocation_info_t *info;
	info = g_malloc0(sizeof(invocation_info_t));
	info->context = invocation;
	info->result = result;
	info->sender = sender;
	info->service_function = service_function;
	info->user_data = invocation_data;
	invocation_list = g_slist_append(invocation_list, info);

}

static void __bt_service_method(GDBusConnection *connection,
		const gchar *sender,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *method_name,
		GVariant *parameters,
		GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	FN_START;
	BT_DBG("Method[%s] Object Path[%s] Interface Name[%s]",
			method_name, object_path, interface_name);

	if (g_strcmp0(method_name, "service_request") == 0) {
		int service_type;
		int service_function;
		int request_type;
		GVariant *param1 = NULL;
		GVariant *param2 = NULL;
		GVariant *param3 = NULL;
		GVariant *param4 = NULL;
		GVariant *param5 = NULL;
		GArray *out_param1 = NULL;
		GVariant *out_var = NULL;
		int result = 0;
		int request_id = -1;
		const char *sender = NULL;

		g_variant_get(parameters, "(iii@ay@ay@ay@ay@ay)", &service_type,
				&service_function, &request_type,
				&param1, &param2, &param3, &param4, &param5);

		out_param1 = g_array_new(FALSE, FALSE, sizeof(gchar));

		sender = g_dbus_method_invocation_get_sender(invocation);

		if (service_type == BT_CORE_SERVICE) {
			BT_DBG("No need to check privilege from bt-core");
		} else if (__bt_service_check_privilege(service_function,
					service_type, (const char *)sender) == FALSE) {
			BT_ERR("Client don't have the privilege to excute this function");
			result = BLUETOOTH_ERROR_PERMISSION_DEINED;
			goto fail;
		}

		if (request_type == BT_ASYNC_REQ
				|| service_function == BT_OBEX_SERVER_ACCEPT_CONNECTION) {
			/* Set the timer */
			request_id = _bt_assign_request_id();
			BT_DBG("Request ID: %d", request_id);

			if (request_id < 0) {
				BT_ERR("Fail to assign the request id");
				result = BLUETOOTH_ERROR_INTERNAL;

				goto fail;
			}
		}

		BT_DBG("SERVICE TYPE [%d] SERVICE FUNC [%d]",
				service_type, service_function);
		switch (service_type) {
		case BT_BLUEZ_SERVICE:
			result = __bt_bluez_request(service_function,
					request_type, request_id,
					invocation, param1, param2,
					param3, param4, &out_param1);
			break;
		case BT_OBEX_SERVICE:
			result = __bt_obexd_request(service_function,
					request_type, request_id,
					invocation, param1,
					param2, param3,
					param4, param5, &out_param1);
			break;
		case BT_AGENT_SERVICE:
			result = __bt_agent_request(service_function,
					request_type, request_id,
					invocation, param1,
					param2, param3,
					param4, &out_param1);
			break;
		case BT_CORE_SERVICE:
			result = __bt_core_request(service_function,
					request_type, request_id,
					invocation, param1);
			break;
		case BT_CHECK_PRIVILEGE:
			result = BLUETOOTH_ERROR_NONE;
			break;
		default:
			BT_ERR("Unknown service type");
			result = BLUETOOTH_ERROR_INTERNAL;
			goto fail;
		}

		if (result != BLUETOOTH_ERROR_NONE) {
			goto fail;
		}

		if ((request_type == BT_ASYNC_REQ ||
			service_function == BT_OBEX_SERVER_ACCEPT_CONNECTION) &&
			service_function != BT_OPP_PUSH_FILES) {
			BT_DBG("INSERT INTO REQ LIST");
			_bt_insert_request_list(request_id, service_function,
						NULL, invocation);
		} else {
			/* Return result */
			if (service_type == BT_CHECK_PRIVILEGE ||
					service_function != BT_OPP_PUSH_FILES) {
				if (!__bt_is_sync_function(service_function)) {
					out_var = g_variant_new_from_data((const GVariantType *)"ay",
							out_param1->data, out_param1->len,
							TRUE, NULL, NULL);

					GVariant *temp = g_variant_new("(iv)", result, out_var);
					g_dbus_method_invocation_return_value(invocation, temp);
				} else {
					/*
					 * API expects return value from Bluetooth stack, so just save
					 * the invocation and invoke it when we get response from stack.
					 */
					BT_INFO("Invocation context will be saved in service_function");
				}

				g_array_free(out_param1, TRUE);
				out_param1 = NULL;
			}
		}

		g_variant_unref(param1);
		g_variant_unref(param2);
		g_variant_unref(param3);
		g_variant_unref(param4);
		g_variant_unref(param5);
//		g_free(sender);
		FN_END;
		return;
fail:
		BT_ERR_C("Request is failed [%s] [%x]",
				_bt_convert_error_to_string(result), result);

		out_var = g_variant_new_from_data((const GVariantType *)"ay",
				out_param1->data, out_param1->len,
				TRUE, NULL, NULL);

		GVariant *temp = g_variant_new("(iv)", result, out_var);
		g_dbus_method_invocation_return_value(invocation, temp);

		g_array_free(out_param1, TRUE);
		out_param1 = NULL;

		if (request_type == BT_ASYNC_REQ)
			_bt_delete_request_id(request_id);

		g_variant_unref(param1);
		g_variant_unref(param2);
		g_variant_unref(param3);
		g_variant_unref(param4);
		g_variant_unref(param5);
//		g_free(sender);
	}

	FN_END;
	return;
}


static const GDBusInterfaceVTable method_table = {
	__bt_service_method,
	NULL,
	NULL,
};

int __bt_bluez_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GArray **out_param1)
{
	int result = BLUETOOTH_ERROR_NONE;
	char *sender = NULL;

	switch (function_name) {
	case BT_ENABLE_ADAPTER: {
		result = _bt_enable_adapter();
		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			BT_DBG("_bt_enable_adapter scheduled successfully! save invocation context");
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_DISABLE_ADAPTER: {
		result = _bt_disable_adapter();
		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			BT_DBG("_bt_disable_adapter scheduled successfully! save invocation context");
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_START_DISCOVERY: {
		result = _bt_start_discovery();
		break;
	}
	case BT_CANCEL_DISCOVERY:
		result = _bt_cancel_discovery();
		break;
	case BT_IS_DISCOVERYING: {
		gboolean discovering = FALSE;
		discovering = _bt_is_discovering();
		g_array_append_vals(*out_param1,
				&discovering, sizeof(gboolean));
		break;
	}
	case BT_GET_LOCAL_ADDRESS: {
		result = _bt_get_local_address();

		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_GET_LOCAL_VERSION: {
		result = _bt_get_local_version();

		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_GET_LOCAL_NAME: {
		result = _bt_get_local_name();

		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_SET_LOCAL_NAME: {
		bluetooth_device_name_t local_name = { {0} };
		__bt_service_get_parameters(in_param1,
				&local_name, sizeof(bluetooth_device_name_t));
		result = _bt_set_local_name(local_name.name);
		break;
	}
	case BT_GET_DISCOVERABLE_MODE: {
		int discoverable_mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		result = _bt_get_discoverable_mode(&discoverable_mode);
		g_array_append_vals(*out_param1, &discoverable_mode, sizeof(int));
		break;
	}
	case BT_GET_DISCOVERABLE_TIME: {
		int timeout = 0;

		result = _bt_get_timeout_value(&timeout);
		g_array_append_vals(*out_param1, &timeout, sizeof(int));
		break;
	}
	case BT_SET_DISCOVERABLE_MODE: {
		int mode = BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE;
		int time = 0;

		__bt_service_get_parameters(in_param1, &mode, sizeof(int));
		__bt_service_get_parameters(in_param2, &time, sizeof(int));

		result = _bt_set_discoverable_mode(mode, time);
		break;
	}
	case BT_IS_CONNECTABLE: {
		gboolean is_connectable = FALSE;

		is_connectable = _bt_is_connectable();
		g_array_append_vals(*out_param1, &is_connectable, sizeof(gboolean));
		break;
	}
	case BT_SET_CONNECTABLE: {
		gboolean is_connectable;

		__bt_service_get_parameters(in_param1,
				&is_connectable, sizeof(gboolean));
		result = _bt_set_connectable(is_connectable);
		break;
	}
	case BT_IS_SERVICE_USED: {
		char *uuid = NULL;

		uuid = (char *)g_variant_get_data(in_param1);
		BT_INFO("UUID to be searched [%s]", uuid);
		result = _bt_is_service_used();

		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, (gpointer)uuid);
		}
		break;
	}
	case BT_GET_BONDED_DEVICES: {
		result = _bt_adapter_get_bonded_devices();
		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, NULL);
		}
		break;
	}
	case BT_GET_BONDED_DEVICE: {
		bluetooth_device_address_t address = { {0} };

		__bt_service_get_parameters(in_param1,
				&address, sizeof(bluetooth_device_address_t));

		result = _bt_device_get_bonded_device_info(&address);
		/* Save invocation */
		if (result == BLUETOOTH_ERROR_NONE) {
			char *addr = g_malloc0(sizeof(char) * BT_ADDRESS_STRING_SIZE);
			if (!addr) {
				result = BLUETOOTH_ERROR_MEMORY_ALLOCATION;
				break;
			}

			_bt_convert_addr_type_to_string(addr, address.addr);
			sender = (char*)g_dbus_method_invocation_get_sender(context);
			_bt_save_invocation_context(context, result, sender,
					function_name, addr);
		}
		break;
	}
	case BT_SET_ALIAS: {
		bluetooth_device_address_t address = { {0} };
		const char *local_name;

		__bt_service_get_parameters(in_param1,
				&address, sizeof(bluetooth_device_address_t));
		local_name = (const char *)g_variant_get_data(in_param2);

		result = _bt_set_alias(&address, local_name);
		break;
	}
	case BT_BOND_DEVICE:{
		    bluetooth_device_address_t address = { {0} };

		    __bt_service_get_parameters(in_param1,
					    &address, sizeof(bluetooth_device_address_t));
		    result = _bt_bond_device(&address, BLUETOOTH_DEV_CONN_DEFAULT, out_param1);

		    /* Save invocation */
		    if (result == BLUETOOTH_ERROR_NONE) {
			    char * addr = g_malloc0(BT_ADDRESS_STRING_SIZE);
			    _bt_convert_addr_type_to_string(addr, address.addr);
			    BT_DBG("_bt_bond_device scheduled successfully! save invocation context");
			    sender = (char*)g_dbus_method_invocation_get_sender(context);
			    _bt_save_invocation_context(context, result, sender,
					    function_name, (gpointer)addr);
		    }
		    break;
	}
	case BT_UNBOND_DEVICE: {
		       bluetooth_device_address_t address = { {0} };

		       __bt_service_get_parameters(in_param1,
				       &address, sizeof(bluetooth_device_address_t));
		       result = _bt_unbond_device(&address, out_param1);

		       /* Save invocation */
		       if (result == BLUETOOTH_ERROR_NONE) {
			       char * addr = g_malloc0(BT_ADDRESS_STRING_SIZE);
			       _bt_convert_addr_type_to_string(addr, address.addr);
			       BT_DBG("_bt_unbond_device scheduled successfully! save invocation context");
			       sender = (char*)g_dbus_method_invocation_get_sender(context);
			       _bt_save_invocation_context(context, result, sender,
					       function_name, (gpointer)addr);
		       }
		       break;
	}
	default:
		BT_INFO("UnSupported function [%d]", function_name);
		result = BLUETOOTH_ERROR_NOT_SUPPORT;
		break;
	}

	return result;
}

int __bt_obexd_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GVariant *in_param5,
		GArray **out_param1)
{
	BT_DBG("+");

	int result = BLUETOOTH_ERROR_NONE;

	BT_DBG("function_name : %x", function_name);

	switch (function_name) {
		/*TODO*/
	}

	FN_END;

	return result;
}

int __bt_agent_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1,
		GVariant *in_param2,
		GVariant *in_param3,
		GVariant *in_param4,
		GArray **out_param1)
{
	BT_DBG("+");

	int result = BLUETOOTH_ERROR_NONE;

	switch (function_name) {
		/*TODO*/
	}

	return result;
}

int __bt_core_request(int function_name,
		int request_type,
		int request_id,
		GDBusMethodInvocation *context,
		GVariant *in_param1)
{
	BT_DBG("+");

	int result = BLUETOOTH_ERROR_NONE;

	switch (function_name) {
		/*TODO*/
	}

	return result;
}

gboolean __bt_service_check_privilege(int function_name,
					int service_type,
					const char *unique_name)
{
	int ret_val;
	gboolean result = TRUE;
	char *client_creds = NULL;
	char *user_creds = NULL;
	char *client_session = "";
	enum cynara_client_creds client_creds_method = CLIENT_METHOD_SMACK;
	enum cynara_user_creds user_creds_method = USER_METHOD_UID;
	char err_msg[256] = {0, };

	retv_if(unique_name == NULL, FALSE);

	BT_DBG("unique_name: %s", unique_name);

	retv_if(bt_service_conn == NULL, FALSE);

	ret_val = cynara_creds_get_default_client_method(&client_creds_method);
	if (ret_val != CYNARA_API_SUCCESS) {
		cynara_strerror(ret_val, err_msg, sizeof(err_msg));
		BT_ERR("Fail to get default client method: %s", err_msg);
		return FALSE;
	}

	ret_val = cynara_creds_get_default_user_method(&user_creds_method);
	if (ret_val != CYNARA_API_SUCCESS) {
		cynara_strerror(ret_val, err_msg, sizeof(err_msg));
		BT_ERR("Fail to get default user method: %s", err_msg);
		return FALSE;
	}

	ret_val = cynara_creds_gdbus_get_client(bt_service_conn, unique_name, client_creds_method, &client_creds);
	if (ret_val != CYNARA_API_SUCCESS) {
		cynara_strerror(ret_val, err_msg, sizeof(err_msg));
		BT_ERR("Fail to get client credential: %s", err_msg);
		return FALSE;
	}

	BT_DBG("client_creds: %s", client_creds);

	ret_val = cynara_creds_gdbus_get_user(bt_service_conn, unique_name, user_creds_method, &user_creds);
	if (ret_val != CYNARA_API_SUCCESS) {
		cynara_strerror(ret_val, err_msg, sizeof(err_msg));
		BT_ERR("Fail to get user credential: %s", err_msg);
		if (client_creds)
			free(client_creds);
		return FALSE;
	}

	BT_DBG("user_creds: %s", user_creds);

	switch (function_name) {
	case BT_SET_LOCAL_NAME:
	case BT_START_DISCOVERY:
	case BT_START_CUSTOM_DISCOVERY:
	case BT_CANCEL_DISCOVERY:
	case BT_OOB_ADD_REMOTE_DATA:
	case BT_OOB_REMOVE_REMOTE_DATA:
	case BT_SET_ADVERTISING:
	case BT_SET_CUSTOM_ADVERTISING:
	case BT_SET_ADVERTISING_PARAMETERS:
	case BT_START_LE_DISCOVERY:
	case BT_STOP_LE_DISCOVERY:

	case BT_BOND_DEVICE:
	case BT_CANCEL_BONDING:
	case BT_UNBOND_DEVICE:
	case BT_SET_ALIAS:
	case BT_SET_AUTHORIZATION:
	case BT_UNSET_AUTHORIZATION:
	case BT_SEARCH_SERVICE:

	case BT_RFCOMM_CLIENT_CONNECT:
	case BT_RFCOMM_CLIENT_CANCEL_CONNECT:
	case BT_RFCOMM_SOCKET_DISCONNECT:
	case BT_RFCOMM_SOCKET_WRITE:
	case BT_RFCOMM_CREATE_SOCKET:
	case BT_RFCOMM_REMOVE_SOCKET:

	case BT_OPP_PUSH_FILES:
	case BT_OPP_CANCEL_PUSH:

	case BT_OBEX_SERVER_ACCEPT_CONNECTION:
	case BT_OBEX_SERVER_REJECT_CONNECTION:
	case BT_OBEX_SERVER_ACCEPT_FILE:
	case BT_OBEX_SERVER_REJECT_FILE:
	case BT_OBEX_SERVER_SET_PATH:
	case BT_OBEX_SERVER_SET_ROOT:
	case BT_OBEX_SERVER_CANCEL_TRANSFER:
	case BT_OBEX_SERVER_CANCEL_ALL_TRANSFERS:

	case BT_AUDIO_CONNECT:
	case BT_AUDIO_DISCONNECT:
	case BT_AG_CONNECT:
	case BT_AG_DISCONNECT:
	case BT_AV_CONNECT:
	case BT_AV_DISCONNECT:
	case BT_AV_SOURCE_CONNECT:
	case BT_AV_SOURCE_DISCONNECT:
	case BT_AVRCP_CONTROL_CONNECT:
	case BT_AVRCP_CONTROL_DISCONNECT:
	case BT_AVRCP_HANDLE_CONTROL:
	case BT_AVRCP_SET_TRACK_INFO:
	case BT_AVRCP_SET_PROPERTY:
	case BT_AVRCP_SET_PROPERTIES:
	case BT_AVRCP_CONTROL_SET_PROPERTY:

	case BT_HF_CONNECT:
	case BT_HF_DISCONNECT:

	case BT_HID_CONNECT:
	case BT_HID_DISCONNECT:

	case BT_HID_DEVICE_ACTIVATE:
	case BT_HID_DEVICE_DEACTIVATE:
	case BT_HID_DEVICE_CONNECT:
	case BT_HID_DEVICE_DISCONNECT:
	case BT_HID_DEVICE_SEND_MOUSE_EVENT:
	case BT_HID_DEVICE_SEND_KEY_EVENT:
	case BT_HID_DEVICE_SEND_REPLY_TO_REPORT:

	case BT_CONNECT_LE:
	case BT_DISCONNECT_LE:

	case BT_SET_ADVERTISING_DATA:
	case BT_SET_SCAN_RESPONSE_DATA:

	case BT_HDP_CONNECT:
	case BT_HDP_DISCONNECT:
	case BT_HDP_SEND_DATA:
	case BT_HDP_REGISTER_SINK_APP:
	case BT_HDP_UNREGISTER_SINK_APP:

	case BT_DPM_SET_ALLOW_BT_MODE:
	case BT_DPM_GET_ALLOW_BT_MODE:
	case BT_DPM_SET_DEVICE_RESTRITION:
	case BT_DPM_GET_DEVICE_RESTRITION:
	case BT_DPM_SET_UUID_RESTRITION:
	case BT_DPM_GET_UUID_RESTRITION:
	case BT_DPM_ADD_DEVICES_BLACKLIST:
	case BT_DPM_ADD_DEVICES_WHITELIST:
	case BT_DPM_ADD_UUIDS_BLACKLIST:
	case BT_DPM_ADD_UUIDS_WHITELIST:
	case BT_DPM_CLEAR_DEVICES_BLACKLIST:
	case BT_DPM_CLEAR_DEVICES_WHITELIST:
	case BT_DPM_CLEAR_UUIDS_BLACKLIST:
	case BT_DPM_CLEAR_UUIDS_WHITELIST:
	case BT_DPM_REMOVE_DEVICE_BLACKLIST:
	case BT_DPM_REMOVE_DEVICE_WHITELIST:
	case BT_DPM_REMOVE_UUID_BLACKLIST:
	case BT_DPM_REMOVE_UUID_WHITELIST:
	case BT_DPM_GET_DEVICES_BLACKLIST:
	case BT_DPM_GET_DEVICES_WHITELIST:
	case BT_DPM_GET_UUIDS_BLACKLIST:
	case BT_DPM_GET_UUIDS_WHITELIST:
	case BT_DPM_SET_ALLOW_OUTGOING_CALL:
	case BT_DPM_GET_ALLOW_OUTGOING_CALL:
	case BT_DPM_SET_PAIRING_STATE:
	case BT_DPM_GET_PAIRING_STATE:
	case BT_DPM_SET_PROFILE_STATE:
	case BT_DPM_GET_PROFILE_STATE:
	case BT_DPM_SET_DESKROP_CONNECTIVITY_STATE:
	case BT_DPM_GET_DESKROP_CONNECTIVITY_STATE:
	case BT_DPM_SET_DISCOVERABLE_STATE:
	case BT_DPM_GET_DISCOVERABLE_STATE:
	case BT_DPM_SET_LIMITED_DISCOVERABLE_STATE:
	case BT_DPM_GET_LIMITED_DISCOVERABLE_STATE:
	case BT_DPM_SET_DATA_TRANSFER_STATE:
	case BT_DPM_GET_DATA_TRANSFER_STATE:

	case BT_NETWORK_ACTIVATE:
	case BT_NETWORK_DEACTIVATE:
	case BT_NETWORK_CONNECT:
	case BT_NETWORK_DISCONNECT:
	case BT_NETWORK_SERVER_DISCONNECT:

	case BT_GATT_GET_PRIMARY_SERVICES:
	case BT_GATT_DISCOVER_CHARACTERISTICS:
	case BT_GATT_SET_PROPERTY_REQUEST:
	case BT_GATT_READ_CHARACTERISTIC:
	case BT_GATT_DISCOVER_CHARACTERISTICS_DESCRIPTOR:
	case BT_GATT_REGISTER_APPLICATION:
	case BT_GATT_REGISTER_SERVICE:
	case BT_GATT_SEND_RESPONSE:
	case BT_PBAP_CONNECT:
	case BT_PBAP_DISCONNECT:
	case BT_PBAP_GET_PHONEBOOK_SIZE:
	case BT_PBAP_GET_PHONEBOOK:
	case BT_PBAP_GET_LIST:
	case BT_PBAP_PULL_VCARD:
	case BT_PBAP_PHONEBOOK_SEARCH:

		ret_val = cynara_check(p_cynara, client_creds, client_session, user_creds,
				BT_PRIVILEGE_PUBLIC);

		if (ret_val != CYNARA_API_ACCESS_ALLOWED) {
			BT_ERR("Fail to access: %s", BT_PRIVILEGE_PUBLIC);
			result = FALSE;
		}

		/* Need to check mediastorage privilege */
		if (function_name == BT_PBAP_GET_PHONEBOOK ||
				function_name == BT_PBAP_PULL_VCARD) {
			ret_val = cynara_check(p_cynara, client_creds, client_session, user_creds,
					MEDIASTORAGE_PRIVILEGE);

			if (ret_val != CYNARA_API_ACCESS_ALLOWED) {
				BT_ERR("Fail to access: %s", MEDIASTORAGE_PRIVILEGE);
				result = FALSE;
			}
		}
		break;

	case BT_ENABLE_ADAPTER:
	case BT_DISABLE_ADAPTER:
	case BT_RESET_ADAPTER:
	case BT_RECOVER_ADAPTER:
	case BT_ENABLE_ADAPTER_LE:
	case BT_DISABLE_ADAPTER_LE:
	case BT_SET_CONNECTABLE:
	case BT_SET_DISCOVERABLE_MODE:
	case BT_ADD_WHITE_LIST:
	case BT_REMOVE_WHITE_LIST:
	case BT_CLEAR_WHITE_LIST:
	case BT_SET_MANUFACTURER_DATA:
	case BT_SET_SCAN_PARAMETERS:

	case BT_CANCEL_SEARCH_SERVICE:
	case BT_ENABLE_RSSI:

	case BT_RFCOMM_ACCEPT_CONNECTION:
	case BT_RFCOMM_REJECT_CONNECTION:
	case BT_RFCOMM_LISTEN:

	case BT_AVRCP_CONTROL_GET_PROPERTY:
	case BT_AVRCP_GET_TRACK_INFO:

	case BT_SET_CONTENT_PROTECT:
	case BT_BOND_DEVICE_BY_TYPE:
	case BT_SET_LE_PRIVACY:
	case BT_LE_CONN_UPDATE:
	case BT_LE_READ_MAXIMUM_DATA_LENGTH:
	case BT_LE_WRITE_HOST_SUGGESTED_DATA_LENGTH:
	case BT_LE_READ_HOST_SUGGESTED_DATA_LENGTH:
	case BT_LE_SET_DATA_LENGTH:

	case BT_LE_IPSP_INIT:
	case BT_LE_IPSP_DEINIT:
	case BT_LE_IPSP_CONNECT:
	case BT_LE_IPSP_DISCONNECT:
		ret_val = cynara_check(p_cynara, client_creds, client_session, user_creds,
				BT_PRIVILEGE_PLATFORM);

		if (ret_val != CYNARA_API_ACCESS_ALLOWED) {
			BT_ERR("Fail to access: %s", BT_PRIVILEGE_PLATFORM);
			result = FALSE;
		}
		break;

	case BT_CHECK_ADAPTER:
	case BT_GET_RSSI:

	case BT_GET_LOCAL_NAME:
	case BT_GET_LOCAL_ADDRESS:
	case BT_GET_LOCAL_VERSION:
	case BT_IS_SERVICE_USED:
	case BT_GET_DISCOVERABLE_MODE:
	case BT_GET_DISCOVERABLE_TIME:
	case BT_IS_DISCOVERYING:
	case BT_IS_LE_DISCOVERYING:
	case BT_IS_CONNECTABLE:
	case BT_GET_BONDED_DEVICES:
	case BT_GET_BONDED_DEVICE:
	case BT_IS_DEVICE_CONNECTED:
	case BT_GET_SPEAKER_GAIN:
	case BT_SET_SPEAKER_GAIN:
	case BT_OOB_READ_LOCAL_DATA:
	case BT_RFCOMM_CLIENT_IS_CONNECTED:
	case BT_RFCOMM_IS_UUID_AVAILABLE:
	case BT_GET_ADVERTISING_DATA:
	case BT_GET_SCAN_RESPONSE_DATA:
	case BT_IS_ADVERTISING:

	case BT_OBEX_SERVER_ALLOCATE:
	case BT_OBEX_SERVER_DEALLOCATE:
		/* Non-privilege control */
		break;
	default:
		BT_ERR("Unknown function!");
		result = FALSE;
		break;
	}

	if (client_creds)
		free(client_creds);

	if (user_creds)
		free(user_creds);

	return result;
}

GDBusNodeInfo *__bt_service_create_method_node_info
					(const gchar *introspection_data)
{
	GError *err = NULL;
	GDBusNodeInfo *node_info = NULL;

	if (introspection_data == NULL) {
		BT_ERR("Introspection XML not present");
		return NULL;
	}

	node_info = g_dbus_node_info_new_for_xml(introspection_data, &err);

	if (err) {
		BT_ERR("Unable to create node: %s", err->message);
		g_clear_error(&err);
	}
	return node_info;
}

int __bt_service_register_object(GDBusConnection *conn,
		GDBusNodeInfo *node_info, gboolean reg)
{
	static guint service_id = 0;
	GError *error = NULL;

	if (reg) {
		if (node_info == NULL)
			return -1;

		service_id = g_dbus_connection_register_object(conn,
				BT_SERVICE_PATH,
				node_info->interfaces[0],
				&method_table,
				NULL, NULL, &error);
		if (service_id == 0)
			return -1;
	} else {
		if (service_id > 0) {
			g_dbus_connection_unregister_object(conn,
					service_id);
			service_id = 0;
		}
	}

	return 0;
}

int _bt_service_register(void)
{
	GDBusConnection *conn;
	GError *err = NULL;
	int result;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	retv_if(conn == NULL, BLUETOOTH_ERROR_INTERNAL);

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
				BT_SERVICE_NAME,
				G_BUS_NAME_OWNER_FLAGS_NONE,
				NULL, NULL, NULL,
				NULL, NULL);
	BT_DBG("owner_id is [%d]", owner_id);
	if (owner_id == 0)
		goto fail;

	node_info = __bt_service_create_method_node_info(
			bt_service_introspection_xml);

	if (node_info == NULL)
		goto fail;

	result = __bt_service_register_object(conn, node_info, TRUE);
	g_dbus_node_info_unref(node_info);
	node_info = NULL;

	if (result != BLUETOOTH_ERROR_NONE)
		goto fail;

	bt_service_conn = conn;

	return BLUETOOTH_ERROR_NONE;

fail:
	if (bt_service_conn) {
		g_object_unref(bt_service_conn);
		bt_service_conn = NULL;
	}

	return BLUETOOTH_ERROR_INTERNAL;
}

void _bt_service_unregister(void)
{
	if (bt_service_conn) {
		__bt_service_register_object(bt_service_conn, NULL, FALSE);
		if (bt_service_conn) {
			g_object_unref(bt_service_conn);
			bt_service_conn = NULL;
		}
		if (node_info) {
			g_dbus_node_info_unref(node_info);
			node_info = NULL;
		}
		if (owner_id > 0) {
			g_bus_unown_name(owner_id);
			owner_id = 0;
		}
	}
}

int _bt_service_cynara_init(void)
{
	int result;
	char err_msg[256] = {0, };

	retv_if(p_cynara != NULL, BLUETOOTH_ERROR_ALREADY_INITIALIZED);

	result = cynara_initialize(&p_cynara, conf);

	if (result != CYNARA_API_SUCCESS) {
		cynara_strerror(result, err_msg, sizeof(err_msg));
		BT_ERR("Fail to initialize cynara: [%s]", err_msg);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

void _bt_service_cynara_deinit(void)
{
	int result;
	char err_msg[256] = {0, };

	ret_if(p_cynara == NULL);

	result = cynara_finish(p_cynara);

	if (result != CYNARA_API_SUCCESS) {
		cynara_strerror(result, err_msg, sizeof(err_msg));
		BT_ERR("Fail to finish cynara: [%s]", err_msg);
		return;
	}

	p_cynara = NULL;
	conf = NULL;
}

void _bt_service_method_return(GDBusMethodInvocation *invocation,
		GArray *out_param, int result)
{
	GVariant *out_var;
	BT_DBG("+");
	out_var = g_variant_new_from_data((const GVariantType *)"ay",
			out_param->data, out_param->len, TRUE, NULL, NULL);

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(iv)", result, out_var));
	BT_DBG("-");
}

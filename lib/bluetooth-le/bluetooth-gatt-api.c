/*
 * Bluetooth-frwk low energy
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hocheol Seo <hocheol.seo@samsung.com>
 *	    Girishashok Joshi <girish.joshi@samsung.com>
 *	    Chanyeol Park <chanyeol.park@samsung.com>
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

#include "bluetooth-api-common.h"
#include "bluetooth-api.h"

#define BLUEZ_CHAR_INTERFACE "org.bluez.Characteristic"

#define GATT_OBJECT_PATH  "/org/bluez/gatt_attrib"

typedef struct {
	GObject parent;
} BluetoothGattService;

typedef struct {
	GObjectClass parent;
} BluetoothGattServiceClass;

GType bluetooth_gatt_service_get_type(void);

#define BLUETOOTH_GATT_TYPE_SERVICE (bluetooth_gatt_service_get_type())

#define BLUETOOTH_GATT_SERVICE(object)	\
		(G_TYPE_CHECK_INSTANCE_CAST((object), \
		BLUETOOTH_GATT_TYPE_SERVICE, BluetoothGattService))

#define BLUETOOTH_GATT_SERVICE_CLASS(klass)	\
		(G_TYPE_CHECK_CLASS_CAST((klass), \
		BLUETOOTH_GATT_TYPE_SERVICE, BluetoothGattServiceClass))

#define BLUETOOTH_GATT_IS_SERVICE(object)	\
		(G_TYPE_CHECK_INSTANCE_TYPE((object), BLUETOOTH_GATT_TYPE_SERVICE))

#define BLUETOOTH_GATT_IS_SERVICE_CLASS(klass)	\
		(G_TYPE_CHECK_CLASS_TYPE((klass), BLUETOOTH_GATT_TYPE_SERVICE))

#define BLUETOOTH_GATT_SERVICE_GET_CLASS(obj)	\
		(G_TYPE_INSTANCE_GET_CLASS((obj), \
		BLUETOOTH_GATT_TYPE_SERVICE, BluetoothGattServiceClass))

G_DEFINE_TYPE(BluetoothGattService, bluetooth_gatt_service, G_TYPE_OBJECT)

static gboolean bluetooth_gatt_value_changed(BluetoothGattService *agent,
					gchar *obj_path,
					gpointer byte_array,
					DBusGMethodInvocation *context);

#include "bluetooth-gatt-glue.h"

static void bluetooth_gatt_service_init(BluetoothGattService *obj)
{
	g_assert(obj != NULL);
}

static void bluetooth_gatt_service_finalize(GObject *obj)
{
	G_OBJECT_CLASS(bluetooth_gatt_service_parent_class)->finalize(obj);
}

static void bluetooth_gatt_service_class_init(BluetoothGattServiceClass *klass)
{
	GObjectClass *object_class = (GObjectClass *)klass;

	g_assert(klass != NULL);

	object_class->finalize = bluetooth_gatt_service_finalize;

	dbus_g_object_type_install_info(BLUETOOTH_GATT_TYPE_SERVICE,
					&dbus_glib_bluetooth_gatt_object_info);
}

static gboolean bluetooth_gatt_value_changed(BluetoothGattService *agent,
					gchar *obj_path,
					gpointer byte_array,
					DBusGMethodInvocation *context)
{
	DBG("+ \n");
	bt_gatt_char_value_t char_val;

	char_val.char_handle = obj_path;
	char_val.char_value = byte_array;

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_GATT_CHAR_VAL_CHANGED,
			BLUETOOTH_ERROR_NONE, &char_val);

	DBG("- \n");

	return TRUE;
}

static void __add_value_changed_method(DBusGConnection *conn)
{
	static gboolean method_added = FALSE;
	BluetoothGattService *bluetooth_gatt_obj = NULL;

	if (method_added) {
		DBG("Method already added. \n");
		return;
	}

	method_added = TRUE;

	bluetooth_gatt_obj = g_object_new(BLUETOOTH_GATT_TYPE_SERVICE, NULL);

	dbus_g_connection_register_g_object(conn, GATT_OBJECT_PATH,
			G_OBJECT(bluetooth_gatt_obj));

	return;
}

static char **__get_string_array_from_gptr_array(GPtrArray *gp)
{
	gchar *gp_path = NULL;
	char **path = NULL;
	int i;

	path = g_malloc0(gp->len * sizeof(char *));

	for (i = 0; i < gp->len; i++) {
		gp_path = g_ptr_array_index(gp, i);
		path[i] = g_strdup(gp_path);
		DBG("path[%d] : [%s]", i, path[i]);
	}
	return path;
}

static void __bluetooth_internal_get_char_cb(DBusGProxy *proxy,
					DBusGProxyCall *call,
					gpointer user_data)
{
	GError *error = NULL;
	GPtrArray *gp_array = NULL;
	bt_gatt_discovered_char_t svc_char = { 0, };

	svc_char.service_handle = user_data;

	if (!dbus_g_proxy_end_call(proxy, call, &error,
		dbus_g_type_get_collection("GPtrArray", DBUS_TYPE_G_OBJECT_PATH),
		&gp_array, G_TYPE_INVALID)) {
		ERR("Error : %s \n", error->message);
		g_error_free(error);
		_bluetooth_internal_event_cb(BLUETOOTH_EVENT_GATT_SVC_CHAR_DISCOVERED,
			BLUETOOTH_ERROR_INTERNAL, &svc_char);
		g_free(svc_char.service_handle);
		g_object_unref(proxy);
		return;
	}

	if (NULL != gp_array) {
		svc_char.handle_info.count = gp_array->len;
		svc_char.handle_info.handle = __get_string_array_from_gptr_array(gp_array);
	}

	_bluetooth_internal_event_cb(BLUETOOTH_EVENT_GATT_SVC_CHAR_DISCOVERED,
			BLUETOOTH_ERROR_NONE, &svc_char);

	g_ptr_array_free(gp_array, TRUE);
	g_free(svc_char.service_handle);
	g_free(svc_char.handle_info.handle);
	g_object_unref(proxy);
	return;
}

BT_EXPORT_API int bluetooth_gatt_free_primary_services(bt_gatt_handle_info_t *prim_svc)
{
	DBG("+\n");
	if (prim_svc == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	g_strfreev(prim_svc->handle);

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_free_service_property(bt_gatt_service_property_t *svc_pty)
{
	DBG("+\n");
	if (svc_pty == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	g_free(svc_pty->uuid);
	g_strfreev(svc_pty->handle_info.handle);

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_free_char_property(bt_gatt_char_property_t *char_pty)
{
	DBG("+\n");
	if (char_pty == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	g_free(char_pty->uuid);
	g_free(char_pty->name);
	g_free(char_pty->description);
	g_free(char_pty->val);

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_get_primary_services(const bluetooth_device_address_t *address,
								bt_gatt_handle_info_t *prim_svc)
{
	DBG("+\n");
	bt_info_t *bt_internal_info = NULL;
	char device_address[BT_ADDRESS_STRING_SIZE] = { 0 };
	const char *device_path = NULL;
	GError *error = NULL;
	DBusGProxy *device_proxy = NULL;
	GHashTable *hash = NULL;
	GValue *value = NULL;
	GPtrArray *gp_array  = NULL;

	if (address == NULL || prim_svc == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	_bluetooth_internal_addr_type_to_addr_string(device_address, address);
	DBG("bluetooth address [%s]\n", device_address);

	if (!bt_internal_info->adapter_proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(bt_internal_info->adapter_proxy, "FindDevice", &error,
		G_TYPE_STRING, device_address, G_TYPE_INVALID,
		DBUS_TYPE_G_OBJECT_PATH, &device_path, G_TYPE_INVALID);
	if (error) {
		ERR("FindDevice Call Error %s[%s]", error->message, device_address);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	if (!device_path)
		return BLUETOOTH_ERROR_INTERNAL;

	device_proxy = _bluetooth_internal_find_device_by_path(device_path);
	if (!device_proxy)
		return BLUETOOTH_ERROR_INTERNAL;

	dbus_g_proxy_call(device_proxy, "GetProperties", &error, G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);
	if (error) {
		ERR("GetProperties Call Error %s[%s]", error->message, device_address);
		g_error_free(error);
		g_object_unref(device_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_object_unref(device_proxy);

	if (!hash)
		return BLUETOOTH_ERROR_INTERNAL;

	value = g_hash_table_lookup(hash, "Services");
	if (!value)
		return BLUETOOTH_ERROR_INTERNAL;

	gp_array = g_value_get_boxed(value);
	if (!gp_array)
		return BLUETOOTH_ERROR_INTERNAL;

	prim_svc->count = gp_array->len;
	prim_svc->handle = __get_string_array_from_gptr_array(gp_array);
	g_ptr_array_free(gp_array, TRUE);

	DBG("-\n");
	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_discover_service_characteristics(const char *service_handle)
{
	DBusGProxy *service_proxy = NULL;
	bt_info_t *bt_internal_info = NULL;
	char *handle;

	if (service_handle == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	service_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
						BLUEZ_SERVICE_NAME, service_handle,
						BLUEZ_CHAR_INTERFACE);
	if (service_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	handle = g_strdup(service_handle);
	DBG("Requested characteristic handle:%s \n ", handle);

	if (!dbus_g_proxy_begin_call(service_proxy, "DiscoverCharacteristics",
			(DBusGProxyCallNotify)__bluetooth_internal_get_char_cb,
			handle, NULL, G_TYPE_INVALID)) {
		g_free(handle);
		g_object_unref(service_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_get_service_property(const char *service_handle,
						bt_gatt_service_property_t *service)
{
	DBusGProxy *service_proxy = NULL;
	bt_info_t *bt_internal_info = NULL;
	GHashTable *hash = NULL;
	GError *error = NULL;
	GValue *value = NULL;
	GPtrArray *gp_array  = NULL ;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	service_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
						BLUEZ_SERVICE_NAME, service_handle,
						BLUEZ_CHAR_INTERFACE);
	if (service_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(service_proxy, "GetProperties", &error, G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);
	if (error != NULL) {
		ERR("GetProperties Call Error %s\n", error->message);
		g_error_free(error);
		g_object_unref(service_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	g_object_unref(service_proxy);

	if (!hash)
		return BLUETOOTH_ERROR_INTERNAL;

	value = g_hash_table_lookup(hash, "UUID");
	service->uuid = value ? g_value_dup_string(value) : NULL;
	if (service->uuid) {
		DBG("svc_pty.uuid = [%s] \n", service->uuid);
	}

	value = g_hash_table_lookup(hash, "Characteristics");
	gp_array = value ? g_value_get_boxed(value) : NULL;
	if (NULL != gp_array) {
		service->handle_info.count = gp_array->len;
		service->handle_info.handle = __get_string_array_from_gptr_array(gp_array);
		g_ptr_array_free(gp_array, TRUE);
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_watch_characteristics(const char *service_handle)
{
	DBusGProxy *watch_proxy = NULL;
	bt_info_t *bt_internal_info = NULL;
	GError *error = NULL;

	if (NULL == service_handle)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	DBG("Entered service handle:%s \n ", service_handle);

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	watch_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
				BLUEZ_SERVICE_NAME, service_handle,
				BLUEZ_CHAR_INTERFACE);
	if (watch_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	__add_value_changed_method(bt_internal_info->conn);

	dbus_g_proxy_call(watch_proxy, "RegisterCharacteristicsWatcher", &error,
				DBUS_TYPE_G_OBJECT_PATH, GATT_OBJECT_PATH,
				G_TYPE_INVALID, G_TYPE_INVALID);
	if (error) {
		ERR("Method call  Fail: %s", error->message);
		g_error_free(error);
		g_object_unref(watch_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_object_unref(watch_proxy);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_unwatch_characteristics(const char *service_handle)
{
	DBusGProxy *watch_proxy = NULL;
	bt_info_t *bt_internal_info = NULL;
	GError *error = NULL;

	if (NULL == service_handle)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	DBG("Entered service handle:%s \n ", service_handle);

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	watch_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
				BLUEZ_SERVICE_NAME, service_handle,
				BLUEZ_CHAR_INTERFACE);
	if (watch_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(watch_proxy, "UnregisterCharacteristicsWatcher", &error,
				DBUS_TYPE_G_OBJECT_PATH, GATT_OBJECT_PATH,
				G_TYPE_INVALID, G_TYPE_INVALID);
	if (error) {
		ERR("Method call  Fail: %s", error->message);
		g_error_free(error);
		g_object_unref(watch_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	g_object_unref(watch_proxy);

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_get_characteristics_property(const char *char_handle,
						bt_gatt_char_property_t *characteristic)
{
	bt_info_t *bt_internal_info = NULL;
	DBusGProxy *characteristic_proxy = NULL;
	GHashTable *hash = NULL;
	GError *error = NULL;
	GValue *value = NULL;
	GByteArray *gb_array = NULL;

	if (char_handle == NULL || characteristic == NULL)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	characteristic_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
							BLUEZ_SERVICE_NAME, char_handle,
							BLUEZ_CHAR_INTERFACE);
	if (characteristic_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	dbus_g_proxy_call(characteristic_proxy, "GetProperties", &error, G_TYPE_INVALID,
				dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				&hash, G_TYPE_INVALID);
	if (error != NULL) {
		ERR("GetProperties Call Error %s\n", error->message);
		g_error_free(error);
		g_object_unref(characteristic_proxy);
		return BLUETOOTH_ERROR_INTERNAL;
	}
	g_object_unref(characteristic_proxy);

	if (!hash)
		return BLUETOOTH_ERROR_INTERNAL;

	value = g_hash_table_lookup(hash, "UUID");
	characteristic->uuid = value ? g_value_dup_string(value) : NULL;
	if (characteristic->uuid) {
		DBG("characteristic->uuid = [%s] \n", characteristic->uuid);
	}

	value = g_hash_table_lookup(hash, "Name");
	characteristic->name = value ? g_value_dup_string(value) : NULL;
	if (characteristic->name) {
		DBG("characteristic->name = [%s] \n", characteristic->name);
	}

	value = g_hash_table_lookup(hash, "Description");
	characteristic->description = value ? g_value_dup_string(value) : NULL;
	if (characteristic->description) {
		DBG("characteristic->description = [%s] \n", characteristic->description);
	}

	value = g_hash_table_lookup(hash, "Value");

	gb_array = value ? g_value_get_boxed(value) : NULL;
	if (gb_array) {
		if (gb_array->len) {
			DBG("gb_array->len  = %d \n", gb_array->len);
			characteristic->val_len = gb_array->len;

			characteristic->val = g_malloc0(gb_array->len * sizeof(unsigned char));
			memcpy(characteristic->val, gb_array->data, gb_array->len);
		} else {
			characteristic->val = NULL;
			characteristic->val_len = 0;
		}

		g_byte_array_free(gb_array, TRUE);
	} else {
		characteristic->val = NULL;
		characteristic->val_len = 0;
	}

	return BLUETOOTH_ERROR_NONE;
}

BT_EXPORT_API int bluetooth_gatt_set_characteristics_value(const char *char_handle,
						const guint8 *value, int length)
{
	bt_info_t *bt_internal_info = NULL;
	DBusGProxy *characteristic_proxy = NULL;
	GValue *val;
	GByteArray *gbarray;
	GError *error = NULL;

	if (char_handle == NULL || value == NULL || length == 0)
		return BLUETOOTH_ERROR_INVALID_PARAM;

	DBG("Requested characteristic handle:%s \n ", char_handle);

	_bluetooth_internal_session_init();

	if (_bluetooth_internal_is_adapter_enabled() == FALSE)
		return BLUETOOTH_ERROR_DEVICE_NOT_ENABLED;

	bt_internal_info = _bluetooth_internal_get_information();

	characteristic_proxy = dbus_g_proxy_new_for_name(bt_internal_info->conn,
							BLUEZ_SERVICE_NAME, char_handle,
							BLUEZ_CHAR_INTERFACE);
	if (characteristic_proxy == NULL) {
		ERR("ERROR: Can't make dbus proxy");
		return BLUETOOTH_ERROR_INTERNAL;
	}

	gbarray = g_byte_array_new();
	g_byte_array_append(gbarray, (guint8 *)value, length);

	val = g_new0(GValue, 1);
	g_value_init(val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_take_boxed(val, gbarray);

	dbus_g_proxy_call(characteristic_proxy, "SetProperty",
		&error, G_TYPE_STRING, "Value",
		G_TYPE_VALUE, val, G_TYPE_INVALID, G_TYPE_INVALID);

	g_object_unref(characteristic_proxy);
	g_free(val);

	if (error) {
		ERR("Set value Fail: %s", error->message);
		g_error_free(error);
		return BLUETOOTH_ERROR_INTERNAL;
	}

	return BLUETOOTH_ERROR_NONE;
}

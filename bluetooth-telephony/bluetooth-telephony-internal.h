/*
 * bluetooth-telephony
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 * 		GirishAshok Joshi <girish.joshi@samsung.com>
 *		DoHyun Pyun <dh79.pyun@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BLUETOOTH_TELEPHONY_INTERNAL_H_
#define _BLUETOOTH_TELEPHONY_INTERNAL_H_

#ifdef __cplusplus
extern "C"{
#endif /*__cplusplus*/

#define BLUETOOTH_TELEPHONY_METHOD (bluetooth_telephony_method_get_type())
#define BLUETOOTH_TELEPHONY_METHOD_GET_OBJECT(obj) \
		(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethod))

#define BLUETOOTH_TELEPHONY_METHOD_IS_OBJECT(obj) \
		(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		BLUETOOTH_TELEPHONY_METHOD))

#define BLUETOOTH_TELEPHONY_METHOD_CLASS(class) \
		(G_TYPE_CHECK_CLASS_CAST((class), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodClass))

#define BLUETOOTH_TELEPHONY_METHOD_GET_AGENT_CLASS(obj) \
		(G_TYPE_INSTANCE_GET_CLASS((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodClass))

#define BLUETOOTH_TELEPHONY_METHOD_IS_AGENT_CLASS(class) \
		(G_TYPE_CHECK_CLASS_TYPE((class), BLUETOOTH_TELEPHONY_METHOD))

#define BLUETOOTH_TELEPHONY_METHOD_AGENT_GET_PRIVATE(obj) \
		(G_TYPE_INSTANCE_GET_PRIVATE((obj), \
		BLUETOOTH_TELEPHONY_METHOD, BluetoothTelephonyMethodPrivate))

typedef struct _BluetoothTelephonyMethod BluetoothTelephonyMethod;
typedef struct _BluetoothTelephonyMethodClass BluetoothTelephonyMethodClass;

struct _BluetoothTelephonyMethod {
	GObject parent;
};

struct _BluetoothTelephonyMethodClass {
	GObjectClass parent_class;
};

BluetoothTelephonyMethod *bluetooth_telephony_method_new(void);
GType bluetooth_telephony_method_get_type(void);

G_DEFINE_TYPE(BluetoothTelephonyMethod, bluetooth_telephony_method, G_TYPE_OBJECT)


static gboolean bluetooth_telephony_method_answer(BluetoothTelephonyMethod *object,
				guint callid,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_release(
				BluetoothTelephonyMethod *object, guint callid,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_reject(BluetoothTelephonyMethod  *object,
				guint callid, DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_threeway(
				BluetoothTelephonyMethod *object, guint value,
				DBusGMethodInvocation *context);

static gboolean bluetooth_telephony_method_send_dtmf(
				BluetoothTelephonyMethod *object,
				gchar *dtmf, DBusGMethodInvocation *context);

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*_BLUETOOTH_TELEPHONY_INTERNAL_H_*/

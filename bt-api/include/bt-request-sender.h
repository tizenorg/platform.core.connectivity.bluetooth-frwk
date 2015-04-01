/*
 * bluetooth-frwk
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#ifndef _BT_REQUEST_SENDER_H_
#define _BT_REQUEST_SENDER_H_

#include <sys/types.h>
#include <glib.h>
#include <dbus/dbus-glib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int service_function;
	DBusGProxy *proxy;
	DBusGProxyCall *proxy_call;
	void *cb;
	void *user_data;
} bt_req_info_t;

void _bt_deinit_proxys(void);

int _bt_send_request(int service_type, int service_function,
			GArray *in_param1, GArray *in_param2,
			GArray *in_param3, GArray *in_param4,
			GArray **out_param1);


int _bt_send_request_async(int service_type, int service_function,
			GArray *in_param1, GArray *in_param2,
			GArray *in_param3, GArray *in_param4,
			void *callback, void *user_data);


#ifdef __cplusplus
}
#endif

#endif /* _BT_REQUEST_SENDER_H_ */

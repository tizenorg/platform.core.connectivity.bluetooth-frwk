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

#ifndef _BT_REQUEST_SENDER_H_
#define _BT_REQUEST_SENDER_H_

#include <sys/types.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int service_function;
	GDBusProxy *proxy;
	void *cb;
	void *user_data;
} bt_req_info_t;

void _bt_gdbus_deinit_proxys(void);

int _bt_sync_send_request(int service_type, int service_function,
			GArray *in_param1, GArray *in_param2,
			GArray *in_param3, GArray *in_param4,
			GArray **out_param1);

#define _bt_send_request(a, b, format ...) ( \
	{ \
	BT_INFO_C("Sync Request => type=%s, fn=%s(0x%x)", #a, #b, b); \
	_bt_sync_send_request(a, b, format); \
	} \
	)

int _bt_async_send_request(int service_type, int service_function,
			GArray *in_param1, GArray *in_param2,
			GArray *in_param3, GArray *in_param4,
			void *callback, void *user_data);

#define _bt_send_request_async(a, b, format ...) ( \
	{ \
	BT_INFO_C("Async Request => type=%s, fn=%s(0x%x)", #a, #b, b); \
	_bt_async_send_request(a, b, format); \
	} \
	)

#ifdef __cplusplus
}
#endif

#endif /* _BT_REQUEST_SENDER_H_ */

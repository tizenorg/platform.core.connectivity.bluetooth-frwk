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

#ifndef _BLUETOOTH_OPC_API_H_
#define _BLUETOOTH_OPC_API_H_


#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define OBEX_CLIENT_SERVICE "org.openobex.client"
#define OBEX_CLIENT_INTERFACE "org.openobex.Client"
#define OBEX_CLIENT_AGENT_PATH "/org/bluez/obex_client_agent/%d/%d"
#define BT_BD_ADDR_MAX_LEN 18
#define BT_OPC_AGENT_ERROR (__bt_opc_error_quark())

typedef enum {
	BT_OBEX_AGENT_ERROR_REJECT,
	BT_OBEX_AGENT_ERROR_CANCEL,
	BT_OBEX_AGENT_ERROR_TIMEOUT,
} bt_opc_agent_error_t;

struct obexd_transfer_hierarchy {
	char *name;
	char *file_name;
	gint64 size;
};


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _BLUETOOTH_OPC_API_H_ */


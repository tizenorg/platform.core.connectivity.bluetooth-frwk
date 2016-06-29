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


#ifndef _BT_REQUEST_HANDLER_H_
#define _BT_REQUEST_HANDLER_H_

#include <sys/types.h>
#include <glib.h>
#include <glib-object.h>

#include "bt-internal-types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BT_SERVICE_NAME "org.projectx.bt"
#define BT_SERVICE_PATH "/org/projectx/bt_service"

/* Invocation information structure for API's
+   expecting replies from bluetooth service */
typedef struct {
        char * sender;
        int service_function;
        GDBusMethodInvocation *context;
        int result;
        gpointer user_data;
} invocation_info_t;

GSList *_bt_get_invocation_list(void);

void _bt_save_invocation_context(GDBusMethodInvocation *invocation, int result,
                char *sender, int service_function,
                gpointer invocation_data);

void _bt_free_info_from_invocation_list(invocation_info_t *req_info);

int _bt_service_register(void);

void _bt_service_unregister(void);

int _bt_service_cynara_init(void);

void _bt_service_cynara_deinit(void);

void _bt_service_method_return(GDBusMethodInvocation *invocation,
		GArray *out_param, int result);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_REQUEST_HANDLER_H_*/


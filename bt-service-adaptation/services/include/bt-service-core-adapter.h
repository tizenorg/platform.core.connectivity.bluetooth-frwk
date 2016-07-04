/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
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


#ifndef _BT_SERVICE_CORE_ADAPTER_H_
#define _BT_SERVICE_CORE_ADAPTER_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
        ADAPTER_DISCOVERY_STOPPED,
        ADAPTER_DISCOVERY_STARTED,
        ADAPTER_DISCOVERY_STARTING,
        ADAPTER_DISCOVERY_STOPPING,
} bt_adapter_discovery_state_t;

typedef enum {
	BT_DEACTIVATED,
	BT_ACTIVATED,
	BT_ACTIVATING,
	BT_DEACTIVATING,
} bt_status_t;

int _bt_enable_adapter(void);

int _bt_disable_adapter(void);

int _bt_start_discovery(void);

int _bt_cancel_discovery(void);

gboolean _bt_is_discovering(void);

int _bt_stack_init(void);

int _bt_get_local_address(void);

int _bt_get_local_version(void);

int _bt_get_local_name(void);

int _bt_set_local_name(char *local_name);

int _bt_get_discoverable_mode(int *mode);

gboolean _bt_is_connectable(void);

int _bt_is_service_used(void);

int _bt_set_connectable(gboolean connectable);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_CORE_ADAPTER_H_*/


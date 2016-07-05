/*
 * BLUETOOTH HAL
 *
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

#ifndef __BT_HAL_AGENT_H__
#define __BT_HAL_AGENT_H__

#include <stdint.h>
#include <glib.h>
#include <unistd.h>
#include <dlog.h>
#include <stdio.h>

void* _bt_hal_create_agent(const char *path, gboolean adapter);

void _bt_hal_destroy_agent(void *agent);

gboolean _bt_hal_agent_is_canceled(void);

void _bt_hal_agent_set_canceled(gboolean value);

int _bt_hal_agent_reply_cancellation(void);

void* _bt_hal_get_adapter_agent(void);

void _bt_hal_initialize_adapter_agent(void);

void _bt_hal_destroy_adapter_agent(void);

#endif //__BT_HAL_AGENT__

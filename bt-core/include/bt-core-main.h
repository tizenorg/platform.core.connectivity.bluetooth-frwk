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

#ifndef _BT_CORE_MAIN_H_
#define _BT_CORE_MAIN_H_

#include <sys/types.h>
#include "bt-internal-types.h"

#ifdef __cplusplus
extern "C" {
#endif

void _bt_core_terminate(void);
gboolean _bt_check_terminating_condition(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_CORE_MAIN_H_*/


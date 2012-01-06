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

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <pthread.h>

#include <bluetooth-api.h>
#include <tet_api.h>

static void startup();

static void cleanup();


void (*tet_startup) () = startup;
void (*tet_cleanup) () = cleanup;

 void utc_bluetooth_enable_adapter_1(void);

 void utc_bluetooth_enable_adapter_2(void);

 struct tet_testlist tet_testlist[] =	{
				{ utc_bluetooth_enable_adapter_1,1},
				{ utc_bluetooth_enable_adapter_2,2},
				{NULL,0}
			};

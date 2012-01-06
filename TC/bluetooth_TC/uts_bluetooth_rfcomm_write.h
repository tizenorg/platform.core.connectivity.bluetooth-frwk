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

 void uts_bluetooth_rfcomm_write_1(void);

 void uts_bluetooth_rfcomm_write_2(void);

  void uts_bluetooth_rfcomm_write_3(void);

 struct tet_testlist tet_testlist[] =	{
				{ uts_bluetooth_rfcomm_write_1,1},
				{ uts_bluetooth_rfcomm_write_2,2},
				{ uts_bluetooth_rfcomm_write_3,3},
				{NULL,0}
			};


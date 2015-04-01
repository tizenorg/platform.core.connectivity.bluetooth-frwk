/*
 * bluetooth-frwk
 *
 * Copyright (c) 2013 Intel Corporation.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <bundle.h>
#include <notification.h>
#include "bt-service-common.h"

#define BT_ICON 	DATA_DIR_ICON"/icons/default/bt-icon.png"
#define BT_SUCCESS 	0
#define BT_FAILED 	1

int notification_launch(bundle *user_data);

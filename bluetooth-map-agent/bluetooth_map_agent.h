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

#ifndef __DEF_BT_PB_AGENT_H_
#define __DEF_BT_PB_AGENT_H_

#include <unistd.h>
#include <dlog.h>

#include <stdio.h>

#include <dbus/dbus-glib.h>

#define BT_MAP_AGENT_ERROR (__bt_map_agent_error_quark())

typedef enum {
	BT_MAP_AGENT_ERROR_INTERNAL,
	BT_MAP_AGENT_ERROR_CANCEL,
} bt_map_agent_error_t;

#define BT_MAP_SERVICE_OBJECT_PATH "/org/bluez/map_agent"
#define BT_MAP_SERVICE_NAME "org.bluez.map_agent"
#define BT_MAP_SERVICE_INTERFACE "org.bluez.MapAgent"

#define BT_MAP_AGENT	"BT_MAP_AGENT"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_MAP_AGENT,\
				"%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_MAP_AGENT,\
				"%s():%d "fmt, __func__, __LINE__, ##args)

#endif /* __DEF_BT_AGENT_H_ */

/*
 *   bluetooth-media-control
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:	Hocheol Seo <hocheol.seo@samsung.com>
 *		Girishashok Joshi <girish.joshi@samsung.com>
 *		Chanyeol Park <chanyeol.park@samsung.com>
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BT_MP_CONTROL_INTERNAL_H_
#define _BT_MP_CONTROL_INTERNAL_H_

#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <glib.h>
#include <dlog.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

#ifndef BT_EXPORT_API
#define BT_EXPORT_API __attribute__((visibility("default")))
#endif

#define BT_MEDIA_CONTROL "BT_MEDIA_CONTROL"
#define DBG(fmt, args...) SLOG(LOG_DEBUG, BT_MEDIA_CONTROL, "%s():%d "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) SLOG(LOG_ERROR, BT_MEDIA_CONTROL, "%s():%d "fmt, __func__, __LINE__, ##args)

/* defines*/
#define MEDIA_OBJECT_PATH_LENGTH	50

#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*_BT_MP_CONTROL_INTERNAL_H_*/

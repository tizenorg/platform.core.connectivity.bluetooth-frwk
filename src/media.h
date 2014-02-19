/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*               http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#ifndef __BLUETOOTH_MEDIA__
#define __BLUETOOTH_MEDIA__

#include <gio/gio.h>

#include "bluez.h"

G_BEGIN_DECLS

#define TYPE_MEDIA_SKELETON (media_skeleton_get_type())

#define MEDIA_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST((o), \
				TYPE_MEDIA_SKELETON, MediaSkeleton))

#define MEDIA_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((K), \
				TYPE_MEDIA_SKELETON, MediaSkeletonClass))

#define MEDIA_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS((o), \
				TYPE_MEDIA_SKELETON, MediaSkeletonClass))

#define IS_MEDIA_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), \
						TYPE_MEDIA_SKELETON))

#define IS_MEIDA_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((K), \
						TYPE_MEDIA_SKELETON))

typedef struct _MediaSkeleton MediaSkeleton;
typedef struct _MediaSkeletonClass MediaSkeletonClass;

struct _MediaSkeleton
{
	GDBusInterfaceSkeleton parent_instance;
};

struct _MediaSkeletonClass
{
	GDBusInterfaceSkeletonClass parent_class;
};

GType media_skeleton_get_type(void) G_GNUC_CONST;

MediaSkeleton *bt_service_media_new(void);

void bt_service_media_init(GDBusObjectSkeleton *object,
					GDBusConnection *connection,
					bluez_adapter_t *adapter);

void bt_service_media_deinit(void);

G_END_DECLS

#endif

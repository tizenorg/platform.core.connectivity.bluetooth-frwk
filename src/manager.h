/*
* Bluetooth-Frwk-NG
*
* Copyright (c) 2013-2014 Intel Corporation.
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

#ifndef __COMMS_MANAGER__
#define __COMMS_MANAGER__

#include <gio/gio.h>
#include "common.h"

#define COMMS_TYPE_MANAGER_SKELETON (comms_manager_skeleton_get_type())

#define COMMS_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST((o),\
					COMMS_TYPE_MANAGER_SKELETON,\
						CommsManagerSkeleton))

#define COMMS_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k),\
					COMMS_TYPE_MANAGER_SKELETON,\
						CommsManagerSkeletonClass))

#define COMMS_MANAGER_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS((o),\
						COMMS_TYPE_MANAGER_SKELETON,\
						CommsManagerSkeletonClass))

#define IS_COMMS_MANAGER_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE((o),\
						COMMS_TYPE_MANAGER_SKELETON))

#define IS_COMMS_MANAGER_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((k),\
						COMMS_TYPE_MANAGER_SKELETON))

typedef struct _CommsManagerSkeleton CommsManagerSkeleton;
typedef struct _CommsManagerSkeletonClass CommsManagerSkeletonClass;
typedef struct _CommsManagerSkeletonPrivate CommsManagerSkeletonPrivate;

struct _CommsManagerSkeleton
{
	GDBusInterfaceSkeleton parent_instance;
	CommsManagerSkeletonPrivate *priv;
};

struct _CommsManagerSkeletonClass
{
	GDBusInterfaceSkeletonClass parent_class;
};

GType comms_manager_skeleton_get_type(void) G_GNUC_CONST;

CommsManagerSkeleton *comms_service_manager_new(
				GDBusObjectManagerServer *server);

#endif

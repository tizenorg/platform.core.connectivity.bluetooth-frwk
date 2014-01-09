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

#ifndef __BLUETOOTH_OPP__
#define __BLUETOOTH_OPP__

#include <gio/gio.h>
#include "common.h"

#define TYPE_OPP_SKELETON (opp_skeleton_get_type())

#define OPP_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST((o), TYPE_OPP_SKELETON,\
								OppSkeleton))

#define OPP_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), TYPE_OPP_SKELETON,\
							OppSkeletonClass))

#define OPP_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS((o),\
						TYPE_OPP_SKELETON,\
						OppSkeletonClass))

#define IS_OPP_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), TYPE_OPP_SKELETON))

#define IS_OPP_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((k),\
						TYPE_OPP_SKELETON))

typedef struct _OppSkeleton OppSkeleton;
typedef struct _OppSkeletonClass OppSkeletonClass;

struct _OppSkeleton
{
	GDBusInterfaceSkeleton parent_instance;
};

struct _OppSkeletonClass
{
	GDBusInterfaceSkeletonClass parent_class;
};

GType opp_skeleton_get_type (void) G_GNUC_CONST;

OppSkeleton *bt_service_opp_new(void);

void bt_service_opp_init(GDBusObjectSkeleton *object,
				GDBusConnection *connection);

void bt_service_opp_deinit(void);

#endif

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

#ifndef __BLUETOOTH_PAIRING__
#define __BLUETOOTH_PAIRING__

#include <gio/gio.h>

#include "bluez.h"

G_BEGIN_DECLS

#define TYPE_PAIRING_SKELETON (pairing_skeleton_get_type())

#define PAIRING_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST((o), \
				TYPE_PAIRING_SKELETON, PairingSkeleton))

#define PAIRING_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((K), \
				TYPE_PAIRING_SKELETON, PairingSkeletonClass))

#define PAIRING_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS((o), \
				TYPE_PAIRING_SKELETON, PairingSkeletonClass))

#define IS_PAIRING_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), \
						TYPE_PAIRING_SKELETON))

#define IS_PAIRING_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE((K), \
						TYPE_PAIRING_SKELETON))

typedef struct _PairingSkeleton PairingSkeleton;
typedef struct _PairingSkeletonClass PairingSkeletonClass;

struct _PairingSkeleton
{
	GDBusInterfaceSkeleton parent_instance;
};

struct _PairingSkeletonClass
{
	GDBusInterfaceSkeletonClass parent_class;
};

GType pairing_skeleton_get_type(void) G_GNUC_CONST;

PairingSkeleton *bt_service_pairing_new(void);

void bt_service_pairing_init(GDBusObjectSkeleton *object,
					GDBusConnection *connection,
					bluez_adapter_t *adapter);

void bt_service_pairing_deinit(void);

G_END_DECLS

#endif
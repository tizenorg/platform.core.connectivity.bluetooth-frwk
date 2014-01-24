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

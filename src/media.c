#include "common.h"
#include "gdbus.h"
#include "comms_error.h"
#include "bluez.h"
#include "media.h"
#include "vertical.h"

#define BLUETOOTH_OBJECT "/org/tizen/comms/bluetooth"

static const GDBusMethodInfo *_media_method_info_pointers[] =
{
	GDBUS_METHOD("MediaPlayerChangeProperty",
				GDBUS_ARGS(_ARG("type", "u"),
				_ARG("value", "u")), NULL),
	GDBUS_METHOD("MediaPlayerChangeProperties",
				GDBUS_ARGS(_ARG("properties", "a{sv}")),
				NULL),
	GDBUS_METHOD("MediaPlayerChangeTrack",
				GDBUS_ARGS(_ARG("Track", "a{sv}")),
				NULL),
	NULL
};

static const GDBusInterfaceInfo _media_interface_info =
{
	-1,
	"org.tizen.comms.mediaplayer",
	(GDBusMethodInfo **) &_media_method_info_pointers,
	NULL,
	NULL,
	NULL
};

G_DEFINE_TYPE(MediaSkeleton, media_skeleton,
			G_TYPE_DBUS_INTERFACE_SKELETON);

static GDBusInterfaceInfo *media_skeleton_dbus_interface_get_info(
				GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceInfo *) &_media_interface_info;
}

static GDBusObjectSkeleton *bt_object_skeleton;
static bluez_adapter_t *default_adapter;
static MediaSkeleton *bt_media;

static void bt_media_register_dbus_interface(MediaSkeleton *skeleton,
					GDBusConnection *connection)
{
	GDBusInterfaceSkeleton *media_interface;

	DBG("");

	media_interface = G_DBUS_INTERFACE_SKELETON(skeleton);

	g_dbus_object_skeleton_add_interface(bt_object_skeleton,
						media_interface);
}

static void bt_media_unregister_dbus_interface()
{
	GDBusInterfaceSkeleton *media_interface;

	media_interface = G_DBUS_INTERFACE_SKELETON(bt_media);

	g_dbus_object_skeleton_remove_interface(bt_object_skeleton,
						media_interface);
}

static void media_skeleton_handle_method_call(GDBusConnection *connection,
					const gchar *sender,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *method_name,
					GVariant *parameters,
					GDBusMethodInvocation *invocation,
					gpointer user_data)
{
	DBG("method: %s", method_name);

	if (default_adapter == NULL){
		DBG("no adapter");
		return;
	}
}

static const GDBusInterfaceVTable media_skeleton_vtable =
{
	media_skeleton_handle_method_call,
	NULL,
	NULL
};

static GDBusInterfaceVTable *media_skeleton_dbus_interface_get_vtable(
					GDBusInterfaceSkeleton *skeleton)
{
	return (GDBusInterfaceVTable *) &media_skeleton_vtable;
}

static void media_skeleton_object_finalize(GObject *object)
{
	DBG("Finalize");

	G_OBJECT_CLASS(media_skeleton_parent_class)->finalize(object);
}

static void media_skeleton_init(MediaSkeleton *skeleton)
{
	DBG("Instance Init");
}

static GVariant *media_skeleton_dbus_interface_get_properties(
				GDBusInterfaceSkeleton *_skeleton)
{
	GVariantBuilder builder;

	DBG("");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	return g_variant_builder_end (&builder);
}

static void media_skeleton_class_init(MediaSkeletonClass *klass)
{
	GObjectClass *gobject_class;
	GDBusInterfaceSkeletonClass *gdbus_skeleton_class;

	DBG("Class Init");

	gobject_class = G_OBJECT_CLASS(klass);
	gobject_class->finalize = media_skeleton_object_finalize;

	gdbus_skeleton_class = G_DBUS_INTERFACE_SKELETON_CLASS(klass);
	gdbus_skeleton_class->get_info =
				media_skeleton_dbus_interface_get_info;
	gdbus_skeleton_class->get_vtable =
				media_skeleton_dbus_interface_get_vtable;
	gdbus_skeleton_class->get_properties =
				media_skeleton_dbus_interface_get_properties;
}

MediaSkeleton *bt_service_media_new(void)
{
	return (MediaSkeleton *)g_object_new(TYPE_MEDIA_SKELETON, NULL);
}

void bt_service_media_init(GDBusObjectSkeleton *gdbus_object_skeleton,
						GDBusConnection *connection,
						bluez_adapter_t *adapter)
{
	DBG("");
}

void bt_service_media_deinit(void)
{
	DBG("");
}

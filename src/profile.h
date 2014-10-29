#ifndef __COMMS_PROFILE__
#define __COMMS_PROFILE__

#include <gio/gio.h>

struct comms_bluetooth_profile_desc {
	const char *profile_name;
	const char *description;
	int (*init)(GDBusObjectSkeleton *skeleton,
			GDBusConnection *connection);
	void (*deinit)(void);
};

#define COMMS_BLUETOOTH_PROFILE_DEFINE(name, description, init, deinit) \
	struct comms_bluetooth_profile_desc comms_bluetooth_profile_desc = { \
		#name, description, init, deinit \
	};

/* Add other profiles */
enum profile_type {
	OPP_PROFILE,
	HFP_PROFILE,
	MAX_PROFILE
};

int profile_init(enum profile_type type, GDBusObjectSkeleton *skeleton,
					GDBusConnection *connection);

#endif

#include <dlfcn.h>

#include "common.h"
#include "profile.h"

struct comms_bluetooth_profile {
	void *handle;
	struct comms_bluetooth_profile_desc *desc;
};

static GList *profiles;

static enum profile_type profile_name_to_type(const char *profile_name)
{
	if (g_strcmp0(profile_name, "opp") == 0)
		return OPP_PROFILE;
	else if (g_strcmp0(profile_name, "hfp") == 0)
		return HFP_PROFILE;
	else
		return -1;
}

static struct comms_bluetooth_profile *find_profile(enum profile_type type)
{
	struct comms_bluetooth_profile *profile;
	enum profile_type cur_type;
	GList *list, *next;

	for (list = g_list_first(profiles); list; list = next) {
		next = g_list_next(list);

		profile = list->data;

		if (profile->desc == NULL)
			continue;

		cur_type = profile_name_to_type(profile->desc->profile_name);
		if (cur_type == type)
			return profile;
	}

	return NULL;
}

static int add_profile(void *handle, struct comms_bluetooth_profile_desc *desc)
{
	struct comms_bluetooth_profile *profile;

	if (desc->init == NULL)
		return -1;

	profile = g_try_new0(struct comms_bluetooth_profile, 1);
	if (profile == NULL)
		return -1;

	profile->handle = handle;
	profile->desc = desc;

	profiles = g_list_append(profiles, profile);

	return 0;
}

static struct comms_bluetooth_profile_desc *load_profile_module(
						enum profile_type type)
{
	struct comms_bluetooth_profile_desc *desc;
	char *file_name = NULL;
	void *handle;

	/* TODO: How to decide the shared library name */
	if (type == OPP_PROFILE)
		file_name = g_build_filename(PROFILEDIR,
					"opp-profile.so", NULL);
	else if(type == HFP_PROFILE)
		file_name = g_build_filename(PROFILEDIR,
					"hfp-profile.so", NULL);

	handle = dlopen(file_name, RTLD_NOW);

	g_free(file_name);

	if (handle == NULL) {
		ERROR("Load profile error %s", dlerror());

		return NULL;
	}

	desc = dlsym(handle, "comms_bluetooth_profile_desc");
	if (desc == NULL) {
		ERROR("Load symbol error %s", dlerror());
		dlclose(handle);

		return NULL;
	}

	add_profile(handle, desc);

	return desc;
}

int profile_init(enum profile_type type, GDBusObjectSkeleton *skeleton,
					GDBusConnection *connection)
{
	struct comms_bluetooth_profile_desc *desc;
	struct comms_bluetooth_profile *profile;

	if (type < 0 || type >= MAX_PROFILE) {
		ERROR("Invalid profile type");
		return -1;
	}

	/* If we find the profile, it must be initialized */
	profile = find_profile(type);
	if (profile != NULL)
		return 0;

	desc = load_profile_module(type);
	if (desc == NULL)
		return -1;

	return desc->init(skeleton, connection);
}

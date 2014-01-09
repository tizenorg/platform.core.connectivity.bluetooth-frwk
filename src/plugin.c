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

#include <dlfcn.h>
#include <glib.h>

#include "version.h"
#include "plugin.h"

static GList *plugins;

struct comms_service_plugin {
	void *handle;
	struct comms_service_plugin_desc *desc;
};

static int add_plugin(void *handle, struct comms_service_plugin_desc *desc)
{
	struct comms_service_plugin *plugin;

	if (desc->init == NULL)
		return -1;

	if (!g_str_equal(desc->version, COMMS_SERVICE_VERSION)) {
		ERROR("Invalid version %s for %s", desc->version,
							desc->description);
		return -1;
	}

	plugin = g_try_new0(struct comms_service_plugin, 1);
	if (plugin == NULL)
		return -1;

	plugin->handle = handle;
	plugin->desc = desc;

	plugins = g_list_append(plugins, plugin);

	return 0;
}

int comms_service_plugin_init(void)
{
	GList *list;
	GDir *dir;
	const gchar *file;
	gchar *filename;

	DBG("");

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (dir == NULL) {
		DBG("%s doesn't exit", PLUGINDIR);
		return 0;
	}

	while ((file = g_dir_read_name(dir)) != NULL) {
		void *handle;
		struct comms_service_plugin_desc *desc;

		if (g_str_has_prefix(file, "lib"))
			continue;

		if (!g_str_has_suffix(file, ".so"))
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		handle = dlopen(filename, RTLD_NOW);
		if (handle == NULL) {
			ERROR("Load %s error: %s", filename, dlerror());
			g_free(filename);
				continue;
		}

		g_free(filename);

		desc = dlsym(handle, "comms_service_plugin_desc");
		if (desc == NULL) {
			ERROR("Load symbol error: %s", dlerror());
			dlclose(handle);
			continue;
		}

		if (add_plugin(handle, desc))
			dlclose(handle);
	}

	g_dir_close(dir);

	for (list = plugins; list; list = list->next) {
		struct comms_service_plugin *plugin = list->data;

		if (plugin->desc->init() < 0)
			continue;
	}

	return 0;
}

void comms_service_plugin_cleanup(void)
{
	GList *list;

	DBG("");

	for (list = plugins; list; list = list->next) {
		struct comms_service_plugin *plugin = list->data;

		plugin->desc->exit();

		if (plugin->handle != NULL)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_list_free(plugins);
}

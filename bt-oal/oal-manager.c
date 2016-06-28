/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd.
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

#include <stdio.h>
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <dlfcn.h>

#include <bluetooth.h>

#include "oal-internal.h"
#include "oal-event.h"
#include <oal-hardware.h>

#define BT_HAL_LIB_NAME			"libbluetooth.default.so"
#define HAL_LIBRARY_PATH 		"/usr/lib"
#define LIB_PATH_SIZE 			50
#define LIB_NAME_SIZE 			50

static const hw_module_t* module = NULL;
static const bt_interface_t *blued_api = NULL;

static gboolean unload_libs(gpointer data);
static bluetooth_device_t* load_hal_lib(void);
static const bt_interface_t * get_stack_interface(bluetooth_device_t* bt_device);
static int load(const char *libname, const struct hw_module_t **module);
static int unload(const struct hw_module_t *module);

oal_status_t oal_mgr_init_internal(void)
{
	bluetooth_device_t* bt_device;

	bt_device = load_hal_lib();

	if (bt_device == NULL) {
		BT_ERR("HAL Library loading failed");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	blued_api = get_stack_interface(bt_device);

	if (blued_api == NULL) {
		BT_ERR("Stack Interface failed");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	return adapter_mgr_init(blued_api);
}

oal_status_t oal_bt_init(oal_event_callback cb)
{
	API_TRACE("Version: %s", OAL_VERSION_STR);
	_bt_event_dispatcher_init(cb);
	return OAL_STATUS_PENDING;
}

void oal_bt_deinit(void)
{
	BT_INFO("+");
	blued_api->cleanup();
	blued_api = NULL;
	unload_libs(NULL);
	BT_INFO("-");
}

void oal_mgr_cleanup(void)
{
	/*TODO Unsupported */
}

void oal_mgr_stack_reload(void)
{
	/*TODO Unsupported */
}

gboolean oal_lib_init(gpointer data)
{
	oal_status_t ret;
	BT_INFO("Going to check Chip Attachment...");

	if (hw_is_module_ready() == OAL_STATUS_SUCCESS) {
		if(hw_get_chip_type() == BT_CHIP_TYPE_UNKNOWN) {
			BT_DBG("Chip Type Unknown, starting timer...");
		} else {
			ret = oal_mgr_init_internal();
			if(OAL_STATUS_SUCCESS == ret)
				send_event(OAL_EVENT_OAL_INITIALISED_SUCCESS, NULL);
			else
				send_event(OAL_EVENT_OAL_INITIALISED_FAILED, NULL);
		}
	} else {
		BT_DBG("Chip Not Yet Ready, try again...");
		return FALSE;
	}
	return TRUE;
}

static gboolean unload_libs(gpointer data)
{
	unload((hw_module_t const*)module);
	module = NULL;
	return FALSE;
}

static bluetooth_device_t* load_hal_lib(void)
{
	int err = 0;
	hw_device_t* device;
	bluetooth_device_t* bt_device = NULL;

	BT_DBG("Loading HAL lib");
	if (module == NULL) {
		switch(hw_get_chip_type()) {
			case BT_CHIP_TYPE_PLATFORM:
				BT_INFO("Tizen Platform BT chip: Tizen Platform HAL library will be loaded");
				err = load(BT_HAL_LIB_NAME, (const hw_module_t **)&module);
				break;
			default:
				BT_WARN("Chip type Unknown, So no Library Load");
				err = -EINVAL;
				break;
		}
	} else
		BT_WARN("Lib already loaded");

	if (err == 0) {
		err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
		if (err == 0) {
			bt_device = (bluetooth_device_t *)device;
			BT_INFO("HAL Library loaded successfullly");
		}
	}

	if (err != 0)
		BT_INFO("%d", err);
	return bt_device;
}

static const bt_interface_t * get_stack_interface(bluetooth_device_t* bt_device)
{
	const bt_interface_t *blued_api = NULL;
	/* Get the Bluetooth interface */
	blued_api = bt_device->get_bluetooth_interface();

	return blued_api;
}

static int load(const char *libname, const struct hw_module_t **module)
{
	int status = -ENOENT;
	char libpath[LIB_PATH_SIZE];
	void *handle;
	struct hw_module_t *hmi;

	OAL_CHECK_PARAMETER(libname, return);

	snprintf(libpath, sizeof(libpath), "%s/%s", HAL_LIBRARY_PATH, libname);
	BT_INFO("Loading Library: %s", libpath);

	/*
	 * load the symbols resolving undefined symbols before
	 * dlopen returns. Since RTLD_GLOBAL is not or'd in with
	 * RTLD_NOW the external symbols will not be global
	 */

	prctl(666, "[bt-service] Load Lib S", strlen("[bt-service] Load Lib S"));

	handle = dlopen(libpath, RTLD_NOW);
	if (handle == NULL) {
		char const *err_str = dlerror();
		BT_ERR("load: module=%s\n%s", libpath, err_str?err_str:"unknown");
		status = -EINVAL;
		goto done;
	}

	prctl(666, "[bt-service] Load Lib E", strlen("[bt-service] Load Lib E"));

	/* Get the address of the struct hal_module_info. */
	const char *sym = HAL_MODULE_INFO_SYM_AS_STR;
	hmi = (struct hw_module_t *)dlsym(handle, sym);
	if (hmi == NULL) {
		BT_ERR("load: couldn't find symbol %s", sym);
		status = -EINVAL;
		goto done;
	}

	/* Check that the id matches */
	if (strcmp(BT_HARDWARE_MODULE_ID, hmi->id) != 0) {
		BT_ERR("load: id=%s != hmi->id=%s", BT_HARDWARE_MODULE_ID, hmi->id);
		status = -EINVAL;
		goto done;
	}

	hmi->dso = handle;
	status = 0;

done:
	if (status != 0) {
		hmi = NULL;
		if (handle != NULL) {
			dlclose(handle);
			handle = NULL;
		}
	} else {
		BT_DBG("loaded HAL id=%s libpath=%s hmi=%p handle=%p",
				BT_HARDWARE_MODULE_ID, libpath, hmi, handle);
	}
	*module = hmi;
	return status;
}

static int unload(const struct hw_module_t *module)
{
	int ret = 1;

	if(module)
		ret = dlclose(module->dso);

	if(ret != 0)
	{
		BT_ERR("dlclose failed:%d", ret);
	}
	BT_WARN("Issues with dl: %s\n", dlerror());
	return ret;
}

void oal_set_debug_mode(gboolean mode)
{
	/*TODO Unsupported */
}

gboolean oal_get_debug_mode(void)
{
	/*TODO Unsupported */
        return FALSE;
}


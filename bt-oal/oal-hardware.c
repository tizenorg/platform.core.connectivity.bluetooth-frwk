/*
 * Open Adaptation Layer (OAL)
 *
 * Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <tzplatform_config.h>

#include "oal-hardware.h"
#include "oal-manager.h"
#include "oal-internal.h"

#define MAX_LINE_SIZE                   256
#define MAX_STRING_SIZE                 128

static bt_chip_type_t try_get_chip_type(void);

static bt_chip_type_t bt_chip_type = BT_CHIP_TYPE_PLATFORM;

const unsigned int nBTVidPidArry[][3] = {               /**< list of BT dongle's vid, pid */
	/* { Vendor ID, Product ID, Chip Vendor } */
	{0x0000, 0x0001, BT_CHIP_TYPE_PLATFORM},	/* Tizen Platform BT Chip */
};

static const char *str_chip_type[] = {
        FOREACH_TYPE(GENERATE_TYPE_STRING)
};

int hw_is_chip_connected()
{
	/* Currently not supported, return TRUE as default */
	return TRUE;
}

bt_chip_type_t hw_get_chip_type(void)
{
	bt_chip_type_t type;

	type = ((bt_chip_type != BT_CHIP_TYPE_UNKNOWN) ? bt_chip_type : try_get_chip_type());

	API_TRACE("Type: %s", str_chip_type[type]);
	return type;
}

oal_status_t hw_chip_firmware_update(void)
{
	return OAL_STATUS_NOT_SUPPORT;
}

oal_status_t hw_is_module_ready(void)
{
	/* For Tizen Platform, set HW module ready to TRUE by default */
	return OAL_STATUS_SUCCESS;
}

oal_status_t hw_is_fwupgrade_required(gboolean *is_required)
{
	return OAL_STATUS_NOT_SUPPORT;
}

static bt_chip_type_t try_get_chip_type(void)
{
	return bt_chip_type;
}


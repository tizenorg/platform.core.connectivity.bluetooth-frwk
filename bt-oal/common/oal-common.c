/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
*
* Contact: Anupam Roy <anupam.r@samsung.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*			   http://www.apache.org/licenses/LICENSE-2.0
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
#include <dlog.h>
#include <string.h>
#include <vconf.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bluetooth.h>
#include "oal-internal.h"
#include "oal-common.h"

#define BT_UUID_STRING_SIZE 37
#define BT_UUID_LENGTH_MAX 16

oal_status_t convert_to_oal_status(bt_status_t status) {
	oal_status_t ret = OAL_STATUS_INTERNAL_ERROR;

	switch(status) {
	case BT_STATUS_SUCCESS:
	case BT_STATUS_DONE:
		ret = OAL_STATUS_SUCCESS;
		break;
	case BT_STATUS_NOT_READY:
		ret = OAL_STATUS_NOT_READY;
		break;
	case BT_STATUS_BUSY:
		ret = OAL_STATUS_BUSY;
		break;
	case BT_STATUS_PARM_INVALID:
		ret = OAL_STATUS_INVALID_PARAM;
		break;
	case BT_STATUS_RMT_DEV_DOWN:
		ret = OAL_STATUS_RMT_DEVICE_DOWN;
		break;
	case BT_STATUS_AUTH_FAILURE:
		ret = OAL_STATUS_AUTH_FAILED;
		break;
	case BT_STATUS_UNSUPPORTED:
		ret = OAL_STATUS_NOT_SUPPORT;
		break;
	case BT_STATUS_UNHANDLED:
	case BT_STATUS_FAIL:
	case BT_STATUS_NOMEM:
	default:
		ret = OAL_STATUS_INTERNAL_ERROR;
		break;
	}
	return ret;
}

static const char * status_str[] = {
    "BT_STATUS_SUCCESS",
    "BT_STATUS_FAIL",
    "BT_STATUS_NOT_READY",
    "BT_STATUS_NOMEM",
    "BT_STATUS_BUSY",
    "BT_STATUS_DONE",
    "BT_STATUS_UNSUPPORTED",
    "BT_STATUS_PARM_INVALID",
    "BT_STATUS_UNHANDLED",
    "BT_STATUS_AUTH_FAILURE",
    "BT_STATUS_RMT_DEV_DOWN"
};

const char * status2string(bt_status_t status) {
	if(status >= BT_STATUS_SUCCESS && status <= BT_STATUS_RMT_DEV_DOWN)
		return status_str[status];
	else {
		BT_ERR("Invalid BT status from stack");
		return "BT_STATUS_UNKNOWN";
	}
}


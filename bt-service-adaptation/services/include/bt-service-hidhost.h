/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Atul Kumar Rai <a.rai@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __BT_SERVICE_HIDHOST_H__
#define __BT_SERVICE_HIDHOST_H__

#include <glib.h>
#include <sys/types.h>
#include "bluetooth-api.h"

#ifdef __cplusplus
extern "C" {
#endif

	int _bt_hidhost_initialize(void);
	void _bt_hidhost_deinitialize(void);
	int _bt_hid_connect(bluetooth_device_address_t *device_address);
	int _bt_hid_disconnect(bluetooth_device_address_t *device_address);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __BT_SERVICE_HIDHOST_H__ */

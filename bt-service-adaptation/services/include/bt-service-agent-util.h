/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
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


#ifndef _BT_SERVICE_AGENT_UTIL_H_
#define _BT_SERVICE_AGENT_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

gboolean _bt_agent_is_auto_response(unsigned int dev_class,
                                const gchar *address, const gchar *name);

int _bt_agent_generate_passkey(char *passkey, int size);

gboolean _bt_agent_is_device_blacklist(const char *address,
                                                        const char *name);

void _bt_agent_release_memory(void);

gboolean _bt_agent_is_hid_keyboard(unsigned int dev_class);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_AGENT_UTIL_H_*/

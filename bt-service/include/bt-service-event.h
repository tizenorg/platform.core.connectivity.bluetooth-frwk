/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
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


#ifndef _BT_SERVICE_EVENT_H_
#define _BT_SERVICE_EVENT_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int _bt_send_event(int event_type, int event, int type, ...);

int _bt_init_service_event_sender(void);
void _bt_deinit_service_event_sender(void);

int _bt_init_service_event_receiver(void);
void _bt_deinit_service_event_receiver(void);

int _bt_opp_client_event_init(void);
void _bt_opp_client_event_deinit(void);

void _bt_get_temp_remote_devinfo(void);

void _bt_stop_discovery_timeout(void);

int _bt_send_hf_local_term_event(char *address);
int _bt_init_hf_local_term_event_sender(void);
void _bt_deinit_hf_local_term_event_sender(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_BT_SERVICE_EVENT_H_*/


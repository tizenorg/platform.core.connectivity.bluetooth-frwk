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

#ifndef _BT_SERVICE_EVENT_RECEIVER_H_
#define _BT_SERVICE_EVENT_RECEIVER_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*_bt_service_event_handler_callback) (int event_type, gpointer event_data);

typedef enum {
	BT_ADAPTER_MODULE,
	BT_DEVICE_MODULE,
	BT_HID_MODULE,
} bt_service_module_t;

void _bt_service_oal_event_receiver(int event_type, gpointer event_data, gsize len);
void _bt_service_register_event_handler_callback(
	bt_service_module_t module, _bt_service_event_handler_callback cb);
void _bt_service_unregister_event_handler_callback(bt_service_module_t module);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _BT_SERVICE_EVENT_RECEIVER_H_ */

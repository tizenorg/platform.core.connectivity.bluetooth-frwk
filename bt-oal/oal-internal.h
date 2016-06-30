/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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

#ifndef _OAL_INTERNAL_H_
#define _OAL_INTERNAL_H_

#include <glib.h>
#include <sys/types.h>
#include <dlog.h>
#include <bluetooth.h>

#include <oal-event.h>
#include "oal-manager.h"
#include "oal-utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OAL_VERSION_STR "Samsung OAL Version v0.1"

#define PR_TASK_PERF_USER_TRACE 666
#define BT_ADDRESS_STRING_SIZE 18
#define BT_UUID_STRING_MAX 50

#undef LOG_TAG
#define LOG_TAG "BT_OAL"

#define BT_DBG(fmt, args...) \
        LOGD(fmt, ##args)
#define BT_ERR(fmt, args...) \
        LOGE(RED(fmt), ##args);
#define BT_INFO(fmt, args...) \
		LOGI(fmt, ##args)
#define BT_VBS(fmt, args...) \
		{SLOGI(fmt, ##args);LOGI(fmt, ##args);}
#define BT_WARN(fmt, args...) \
		LOGW(YELLOW(fmt), ##args)
#define NO_SUPP_CHK(status, fmt, args...) do {\
			if(status == BT_STATUS_UNSUPPORTED)	\
				BT_WARN(fmt, ##args);			\
			else								\
				BT_ERR(fmt, ##args);			\
			} while(0)


#define API_TRACE(fmt, args...) {LOG_(LOG_ID_SYSTEM, DLOG_INFO, "OAL_API", GREEN(fmt), ##args); \
			LOG_(LOG_ID_MAIN, DLOG_INFO, LOG_TAG, GREEN("[OAL_API]"fmt), ##args);}

#define send_event_trace(e, d, l, a, fmt, args...) do {\
									bdstr_t bdstr;\
									send_event_no_trace(e, d, l); \
									LOG_(LOG_ID_SYSTEM, DLOG_INFO, "OAL_EVENT", GREEN(fmt" [%s] %s"), ##args, bdt_bd2str(a, &bdstr), str_event[event]); \
									LOG_(LOG_ID_MAIN, DLOG_INFO, LOG_TAG, GREEN("[OAL_EVENT]"fmt" [%s] %s"), ##args, bdt_bd2str(a, &bdstr), str_event[event]);\
									} while(0)


#define ret_if(expr) \
	do { \
		if (expr) { \
			BT_ERR("(%s) return", #expr); \
			return; \
		} \
	} while (0)

#define retv_if(expr, val) \
	do { \
		if (expr) { \
			BT_ERR("(%s) return", #expr); \
			return (val); \
		} \
	} while (0)

#define OAL_CHECK_PARAMETER(arg, func) \
	do { \
		if (arg == NULL) \
		{ \
			BT_ERR("INVALID PARAMETER"); \
			func OAL_STATUS_INVALID_PARAM; \
		} \
	} while (0)

#define CHECK_OAL_INITIALIZED() \
	do { \
		if (blued_api == NULL) { \
			BT_ERR("OAL Not Initialized"); \
			return OAL_STATUS_NOT_READY; \
		} \
	} while (0)

#define BT_ADDRESS_STRING_SIZE 18

typedef struct {
	int len;
	uint8_t * adv_data;
} ble_adv_data_t;

/* Adapter manager */
void oal_mgr_cleanup(void);
void oal_mgr_stack_reload(void);

oal_status_t adapter_mgr_init(const bt_interface_t * stack_if);

/* Event Manager */
/* Use this when Address is to be printed */
void send_event_bda_trace(oal_event_t event, gpointer event_data, gsize len, bt_address_t *address);

/* Use this when no address printing is required */
#define _bt_dispatch_event send_event
void send_event(oal_event_t event, gpointer event_data, gsize len);
void _bt_event_dispatcher_init(oal_event_callback cb);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_HARDWARE_H_*/


/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _BT_HAL_LOG_H_
#define _BT_HAL_LOG_H_

#undef LOG_TAG
#define LOG_TAG "BLUETOOTH_HAL"

#ifdef FUNCTION_TRACE
#define FN_START BT_DBG("[ENTER FUNC]")
#define FN_END BT_DBG("[EXIT FUNC]")
#else
#define FN_START
#define FN_END
#endif

#define LOG_COLOR_RESET    "\033[0m"
#define LOG_COLOR_RED      "\033[31m"
#define LOG_COLOR_YELLOW   "\033[33m"
#define LOG_COLOR_GREEN         "\033[32m"
#define LOG_COLOR_BLUE          "\033[36m"
#define LOG_COLOR_PURPLE   "\033[35m"

#define DBG(fmt, args...) \
        SLOGD(fmt, ##args)
#define INFO(fmt, args...) \
        SLOGI(fmt, ##args)
#define ERR(fmt, args...) \
        SLOGE(fmt, ##args)

#define INFO_C(fmt, arg...) \
        SLOGI_IF(TRUE,  LOG_COLOR_GREEN" "fmt" "LOG_COLOR_RESET, ##arg)
#define ERR_C(fmt, arg...) \
        SLOGI_IF(TRUE,  LOG_COLOR_RED" "fmt" "LOG_COLOR_RESET, ##arg)

#define DBG_SECURE(fmt, args...) SECURE_SLOGD(fmt, ##args)
#define ERR_SECURE(fmt, args...) SECURE_SLOGE(fmt, ##args)

#endif //_BT_HAL_LOG_H_

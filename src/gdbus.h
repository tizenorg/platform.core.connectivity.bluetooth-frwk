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

#ifndef __COMMS_COMMON_H__
#define __COMMS_COMMON_H__

#include <gio/gio.h>

#define _ARG(name, signature) \
	&(const GDBusArgInfo) {-1, name, signature, NULL}
#define GDBUS_ARGS(args...) \
	(GDBusArgInfo **) &(const GDBusArgInfo *[]) {args, NULL}
#define GDBUS_METHOD(name, args_in, args_out) \
	&(const GDBusMethodInfo) {-1, name, args_in, args_out, NULL}
#define GDBUS_PROPERTY(name, signature, flag) \
	&(const GDBusPropertyInfo) {-1, name, signature, flag, NULL}

#endif

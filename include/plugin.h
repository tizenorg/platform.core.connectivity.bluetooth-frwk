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

#include "version.h"
#include "common.h"

#ifndef __COMMS_SERVICE_PLUGIN_H__
#define __COMMS_SERVICE_PLUGIN_H__

#ifdef __cplusplus
extern "C" {
#endif

struct comms_service_plugin_desc {
	const char *name;
	const char *description;
	const char *version;
	int (*init) (void);
	void (*exit) (void);
};

#define COMMS_SERVICE_PLUGIN_DEFINE(name, description, version, init, exit) \
		struct comms_service_plugin_desc comms_service_plugin_desc = { \
			#name, description, version, init, exit \
		};

#ifdef __cplusplus
}
#endif

#endif /* __COMMS_SERVICE_PLUGIN_H */

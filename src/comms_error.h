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

#ifndef __COMMS_ERROR_H__
#define __COMSS_ERROR_H__

#include <gio/gio.h>

#define ERROR_INTERFACE "org.tizen.comms.Error"

static inline void comms_error_invalid_args(GDBusMethodInvocation *invocation)
{
	
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
}

static inline void comms_error_busy(GDBusMethodInvocation *invocation)
{
	
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".InPropgress",
				"Invalid arguments in method call");
}

static inline void comms_error_already_done(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AlreadyDone",
				"Already Done");
}

static inline void comms_error_already_exists(GDBusMethodInvocation *invocation)
{
	
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AlreadyExists",
				"Already Exists");
}

static inline void comms_error_not_supported(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NotSupported",
				"Operation is not supported");
}

static inline void comms_error_not_connected(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NotConnected",
				"Not Connected");
}

static inline void comms_error_already_connected(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AlreadyConnected",
				"Already Connected");
}

static inline void comms_error_in_progress(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".InProgress",
				"In Progress");
}

static inline void comms_error_not_available(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NotAvailable",
				"Operation currently not available");
}

static inline void comms_error_does_not_exist(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".DoesNotExist",
				"Does Not Exist");
}

static inline void comms_error_not_authorized(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NotAuthorized",
				"Operation Not Authorized");
}

static inline void comms_error_no_such_adapter(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NoSuchAdapter",
				"No such adapter");
}

static inline void comms_error_agent_not_available(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".AgentNotAvailable",
				"Agent Not Available");
}

static inline void comms_error_not_ready(GDBusMethodInvocation *invocation)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".NotReady",
				"Resource Not Ready");
}

static inline void comms_error_failed(GDBusMethodInvocation *invocation,
						const gchar *str)
{
	g_dbus_method_invocation_return_dbus_error(invocation,
				ERROR_INTERFACE ".Failed",
				str);
}

#endif

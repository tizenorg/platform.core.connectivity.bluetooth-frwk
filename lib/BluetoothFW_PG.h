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

/**
 *
 * @ingroup   SLP_PG
 * @defgroup   BLUETOOTH BluetoothFW
@{
<h1 class="pg">Introduction</h1>
	<h2 class="pg">Purpose of this document</h2>
The purpose of this document is to describe how applications can use Bluetooth APIs for handling or working with Bluetooth. This document gives programming guidelines to application engineers.

	<h2 class="pg">Scope</h2>
The scope of this document is limited to Bluetooth API usage

	<h2 class="pg">Abbreviations</h2>
<table>
	<tr>		<td>API</td>		<td>Application Programming Interface</td></tr>
	<tr>		<td>SDK</td>		<td>Software Development Kit</td></tr>
	<tr>		<td>RFCOMM</td>		<td>Radio Frequency Communication</td></tr>
	<tr>		<td>L2CAP</td>		<td>Logical Link Control and adaptation Protocol</td></tr>
	<tr>		<td>LM</td>		<td>Link Manager</td></tr>
</table>

<h1>Bluetooth Framework Architecture</h1>
	<h2 class="pg">Architecture overview</h2>
@image html bluetooth_image001.png

<h1>Bluetooth Framework Features</h1>
The Bluetooth API exposes a high level interface that is used by applications.

Bluetooth API currently provides 3 kinds of APIs.
@n GAP APIs: These APIs are used to perform operations related to the local device such as set device name, set visibility mode etc. It also exposes APIs to perform basic Bluetooth related operations like device search
@n SDP APIs: These APIs are used to search service list supported by a specific device. A record in the service list gives a description of a service supported by the device. Specific records having a service ID assigned by Bluetooth SIG give a exact information of predefined service roles.
@n RFCOMM APIs: In order to establish a serial connection between two Bluetooth devices, this SDK provides simple RFCOMM APIs. After receiving FD from SDK, developer can use regular system functions like read() write() poll() select() etc to send or receive data.

Bluetooth can be shared among several applications, and the Bluetooth framework will supervise some of the important functionalities like pairing, configuration, and authorization. These functions will be confirmed by the user with use of a Bluetooth agent daemon.

<h1>Using Bluetooth API</h1>
You can use Bluetooth API to communication with other Bluetooth enabled device (mobile phone, PC etc) over RFCOMM interface. This SDK provides supporting Device management functions to find the device you want to connect with. You can refer to the following use cases as examples for writing your own Bluetooth based application.

	<h2 class="pg">Listening for events</h2>
In general, Bluetooth API provided to you is asynchronous in nature. Hence it becomes mandatory for Application to listen for the events which may be sent by Bluetooth API as per the data received. An application developer can call bluetooth_register_callback() function to register a callback function of bluetooth_cb_func_ptr type. This registered function will receive events of bluetooth_event_type_t type along with any any data.

	<h2 class="pg">Managing Adapter</h2>
Bluetooth Adaptor represents the Bluetooth Chip present in your device. The bluetooth_enable_adapter() API can be used to activate Bluetooth. This API sends a request to Bluetooth chip for activation. This will also initialize Bluetooth adaptor. Upon completion of the procedure, it will send BLUETOOTH_EVENT_ENABLED event. Bluetooth adapter should be disabled to switch off Bluetooth chip (and thereby saving power). bluetooth_disable_adapter() function will do that job for you. After switching off Bluetooth, BLUETOOTH_EVENT_DISABLED will be sent by SDK to application for confirmation.

	<h2 class="pg">Getting local device information</h2>
Every Bluetooth device has a unique 48 bit address assigned to it. You can read your Bluetooth device's address by using bluetooth_get_local_address() API. It is a synchronous function call. In its output parameter, you can receive bluetooth_device_address_t type of pointer which will contain Bluetooth address. Since its inconvenient for user to remember the address, Bluetooth provides a method to have a friendly name for each device. You can get or set the device name by bluetooth_get_local_name() and bluetooth_set_local_name() respectively. If you set the name, BLUETOOTH_EVENT_LOCAL_NAME_CHANGED event will be sent to application to inform result of requested operation. As per Bluetooth standard, maximum length of device name can be BLUETOOTH_DEVICE_NAME_MAX_LENGTH or 248 bytes. It should be in UTF-8 format.

In order to be discoverable to other devices, your Bluetooth device should respond to inquiry scan requests. You can retrieve the mode of your device by calling bluetooth_get_discoverable_mode() API. It is a synchronous API which will give you current mode in bluetooth_discoverable_mode_t format. You can choose from the four different modes: connectable only (non discoverable), general discoverable, time limited discoverable (discoverable for limited time duration) and limited discoverable.

	<h2 class="pg">Searching for peer Bluetooth device</h2>
You can search for peer Bluetooth devices using the bluetooth_start_discovery() API. It is an asynchronous function call. You can receive the BLUETOOTH_EVENT_DISCOVERY_STARTED event when any discovery session is successfully started from the target, even if your application does not request discovery. After the opened discovery session is closed, you will get the BLUETOOTH_EVENT_DISCOVERY_FINISHED event. During the discovery session, you can get several BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND events and BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED events. The former event gives information of a device without its name and the latter event includes a friendly name for the device, and is delivered after the former event. The latter event can be delivered more than once for a device.
@n Since only one discovery session is permitted at a time, a discovery request will return failure if there is a session already open.

	<h2 class="pg">Serial communication in wireless way</h2>
There are two roles in serial communication. One is server role which is waiting a connection from another device. The other role is client role which initiates a connection. For serial communication between your application in two targets.
@n At first you should open server in one device. It can be done with bluetooth_rfcomm_create_socket() API and bluetooth_rfcomm_listen_and_accept() API. You can get a server socket file descriptor with the first API and can start waiting with the second API.
@n At next, client device can connect with a waiting server with bluetooth_rfcomm_remote_connect() API. When a client is successfully connected with a server, you will receive the device node path for serial connection. With opening this path you can communicate with server device by reading and writing it.
@n You should match UUID string with a server. You can use a UUID predefined by Bluetooth SIG if you want to use a specific Bluetooth profile role. Otherwise you should use your own UUID with 128bits hexa value formatted as like "#######-####-####-####-############" Format of Bluetooth SIG predefined UUID is "000####-0000-1000-8000-00805F9B34FB"

	<h2 class="pg">Tips & Tricks</h2>
You can connect with PC having Bluetooth adapter with Serial Port emulation Profile. For this, you should use SPP UUID string, "0001101-0000-1000-8000-00805F9B34FB" If the serial connection is established, you can use a serial port in PC side for communicating with your application in a device.

<h1>API descriptions</h1>
	<h2 class="pg">Defines</h2>
		<h3 class="pg">General</h3>
<table>
	<tr>		<td>Macro Name</td>
		<td>Value</td>
		<td>Description</td></tr>
	<tr>		<td>BLUETOOTH_ADDRESS_LENGTH</td>
		<td>6</td>
		<td>Bluetooth address is represented as 48 bits. This is defined in Bluetooth Core Specification document. This macro represents Bluetooth address length in bytes</td></tr>
	<tr>		<td>BLUETOOTH_DEVICE_NAME_LENGTH_MAX</td>
		<td>248</td>
		<td>The Bluetooth device name can be up to 248 bytes maximum according to "Link Manager Protocol". It shall be encoded according to UTF-8</td></tr>
</table>

		<h3 class="pg">Error codes</h3>
<table>
	<tr>		<td>Macro Name</td>
		<td>Value</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_BASE</td>
		<td>0</td>
		<td>Error code base</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NONE</td>
		<td>BLUETOOTH_ERROR_BASE</td>
		<td>No error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_CANCEL</td>
		<td>BLUETOOTH_ERROR_BASE - 0x01</td>
		<td>Cancelled</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_INVALID_CALLBACK</td>
		<td>BLUETOOTH_ERROR_BASE - 0x02</td>
		<td>Callback error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_INVALID_PARAM</td>
		<td>BLUETOOTH_ERROR_BASE - 0x03</td>
		<td>invalid parameter</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_INVALID_DATA</td>
		<td>BLUETOOTH_ERROR_BASE - 0x04</td>
		<td>invalid data error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_MEMORY_ALLOCATION</td>
		<td>BLUETOOTH_ERROR_BASE - 0x05</td>
		<td>Memory allocation error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_OUT_OF_MEMORY</td>
		<td>BLUETOOTH_ERROR_BASE - 0x06</td>
		<td>out of memory error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_TIMEOUT</td>
		<td>BLUETOOTH_ERROR_BASE - 0x07</td>
		<td>timeout error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NO_RESOURCES</td>
		<td>BLUETOOTH_ERROR_BASE - 0x08</td>
		<td>No resource error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_INTERNAL</td>
		<td>BLUETOOTH_ERROR_BASE - 0x09</td>
		<td>internal error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NOT_SUPPORT</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0A</td>
		<td>Not supported error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_DEVICE_NOT_ENABLED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0B</td>
		<td>Operation is failed because of not enabled BT Adapter</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_DEVICE_ALREADY_ENABLED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0C</td>
		<td>Enabling is failed because of already enabled BT Adapter</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_DEVICE_BUSY</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0D</td>
		<td>Operation is failed because of other on going operation</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_ACCESS_DENIED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0E</td>
		<td>access denied error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_MAX_CLIENT</td>
		<td>BLUETOOTH_ERROR_BASE - 0x0F</td>
		<td>max client error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NOT_FOUND</td>
		<td>BLUETOOTH_ERROR_BASE - 0x10</td>
		<td>not found error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_SERVICE_SEARCH_ERROR</td>
		<td>BLUETOOTH_ERROR_BASE - 0x11</td>
		<td>service search fail</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_PARING_FAILED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x12</td>
		<td>pairing failed error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NOT_PAIRED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x13</td>
		<td>Not paired error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_SERVICE_NOT_FOUND</td>
		<td>BLUETOOTH_ERROR_BASE - 0x14</td>
		<td>no service error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NOT_CONNECTED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x15</td>
		<td>no connection error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_ALREADY_CONNECT</td>
		<td>BLUETOOTH_ERROR_BASE - 0x16</td>
		<td>already connected error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_CONNECTION_BUSY</td>
		<td>BLUETOOTH_ERROR_BASE - 0x17</td>
		<td>connection busy error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_CONNECTION_ERROR</td>
		<td>BLUETOOTH_ERROR_BASE - 0x18</td>
		<td>connection error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_MAX_CONNECTION</td>
		<td>BLUETOOTH_ERROR_BASE - 0x19</td>
		<td>max connection error</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_NOT_IN_OPERATION</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1A</td>
		<td>Not in operation</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_CANCEL_BY_USER</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1B</td>
		<td>cancelled by user</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_REGISTRATION_FAILED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1C</td>
		<td>registration failed</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_IN_PROGRESS</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1D</td>
		<td>operation is in progress </td></tr>

	<tr>		<td>BLUETOOTH_ERROR_AUTHENTICATION_FAILED</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1E</td>
		<td>authentication failed</td></tr>

	<tr>		<td>BLUETOOTH_ERROR_HOST_DOWN</td>
		<td>BLUETOOTH_ERROR_BASE - 0x1F</td>
		<td>Remote host is down</td></tr>


</table>

	<h2 class="pg">Enums</h2>
		<h3 class="pg">bluetooth_adapter_state_t</h2>
Adapter state
<table>
	<tr><td colspan="2">bluetooth_adapter_state_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_ADAPTER_DISABLED</td>
		<td>Bluetooth adapter is disabled</td></tr>

	<tr>		<td>BLUETOOTH_ADAPTER_ENABLED</td>
		<td>Bluetooth adapter is enabled</td></tr>

	<tr>		<td>BLUETOOTH_ADAPTER_CHANGING_ENABLE</td>
		<td>Bluetooth adapter is currently enabling</td></tr>

	<tr>		<td>BLUETOOTH_ADAPTER_CHANGING_DISABLE</td>
		<td>Bluetooth adapter is currently disabling</td></tr>
</table>

		<h3 class="pg">bluetooth_discoverable_mode_t</h3>
Discoverable mode
<table>
	<tr><td colspan="2">bluetooth_discoverable_mode_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_DISCOVERABLE_MODE_CONNECTABLE</td>
		<td>Non discoverable mode, other device cannot search the device</td></tr>

	<tr>		<td>BLUETOOTH_DISCOVERABLE_MODE_GENERAL_DISCOVERABLE</td>
		<td>Discoverable mode, other device can search the device</td></tr>

	<tr>		<td>BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE</td>
		<td>Discoverable mode with time limit, After specific timeout it is changed to non discoverable mode</td></tr>
</table>

		<h3 class="pg">bluetooth_event_type_t</h3>
Bluetooth event type
<table>
	<tr><td colspan="2">bluetooth_event_type_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_NONE</td>
		<td>No event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_ENABLED</td>
		<td>Bluetooth adapter enabled broadcasting event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_DISABLED</td>
		<td>Bluetooth adapter disabled broadcasting event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_LOCAL_NAME_CHANGED</td>
		<td>Local friendly name changed broadcasting event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_REQUESTED</td>
		<td>When setting  local discoverable mode to BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE, this event comes to set timeout for bluetooth_get_discoverable_mode() API.</td></tr>
@n Only the API caller receive this event.
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED</td>
		<td>Bluetooth discoverable mode changed, parameter is pointer to changed mode</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_DISCOVERY_OPTION_REQUESTED</td>
		<td>(Not supported)</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_DISCOVERY_STARTED</td>
		<td>Discovery session started broadcasting event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_DISCOVERY_FINISHED</td>
		<td>Discovery session finished broadcasting event</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND</td>
		<td>During discovery session, found device is reported with this event.</td></tr>
@n Only the API caller receives this event.

	<tr>		<td>BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED</td>
		<td>During discovery session, friendly name information of found device is reported with this event.</td></tr>
@n Only the API caller receives this event.

	<tr>		<td>BLUETOOTH_EVENT_BONDING_FINISHED</td>
		<td>Newly bonded device is reported with this event. This is broadcasting event.</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED</td>
		<td>If bonded device is locally removed, this event reported. This is broadcasting event. Removing is not sent to a unbonded peer device because it means removing locally stored key for the device.</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_BONDED_DEVICE_FOUND</td>
		<td>Bonded device is reported with this event if you uses bluetooth_get_bonded_device_list() API. Only the API caller receives this event.</td></tr>
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_REMOTE_DEVICE_READ</td>
		<td>Information directly getting from peer device is reported with this event if you uses bluetooth_get_remote_device() API.</td></tr>
@n Only the API caller receives this event.
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_DEVICE_AUTHORIZED</td>
		<td>This event reports the result of bluetooth_authorize_device() API.</td></tr>
@n Only the API caller receives this event.
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_DEVICE_UNAUTHORIZED</td>
		<td>This event reports the result of bluetooth_authorize_device() API.</td></tr>
@n Only the API caller receives this event.
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_SERVICE_SEARCHED</td>
		<td>This event reports the result of bluetooth_search_service() API.</td></tr>
@n Only the API caller receives this event.

	<tr>		<td>BLUETOOTH_EVENT_SERVICE_SEARCH_CANCELLED</td>
		<td>During searching service, bluetooth_cancel_service_search() API is called, this event indicated the cancellation of searching without BLUETOOTH_EVENT_SERVICE_SEARCHED event.</td></tr>
@n Only the API caller receives this event.
@n (Not supported yet)

	<tr>		<td>BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED</td>
		<td>This event is occured if RFCOMM data recieves from remote device.</td></tr>

	<tr>		<td>BLUETOOTH_EVENT_RFCOMM_CONNECTED</td>
		<td>If RFCOMM socket is connected, this event reported </td></tr>

	<tr>		<td>BLUETOOTH_EVENT_RFCOMM_DISCONNECTED</td>
		<td>If RFCOMM socket is disconnected, this event reported </td></tr>

	<tr>		<td>BLUETOOTH_EVENT_MAX</td>
		<td>Max value</td></tr>
</table>

		<h3 class="pg">bluetooth_device_service_class_t</h3>
Service class part of class of device returned from device discovery, all service which supported found devi	ce is masked. Each type is defined by Bluetooth SIG.
<table>
	<tr><td colspan="2">bluetooth_device_service_class_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_LIMITED_DISCOVERABLE_MODE</td>
		<td>device in limited discoverable mode</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_POSITIONING</td>
		<td>Positioning service</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_NETWORKING</td>
		<td>Networking service</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_RENDERING</td>
		<td>Printing, Speaker</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_CAPTURING</td>
		<td>Capturing (Scanner, Microphone)</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_OBJECT_TRANSFER</td>
		<td>Object Transfer service</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_AUDIO</td>
		<td>Audio service</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_TELEPHONY</td>
		<td>Telephony service</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_SERVICE_CLASS_INFORMATION</td>
		<td>WEB-server, WAP-server</td></tr>

</table>

		<h3 class="pg">bluetooth_device_major_class_t</h3>
Major device class (part of Class of Device)
<table>
	<tr><td colspan="2">bluetooth_device_service_class_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_MISC</td>
		<td>Miscellaneous major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER</td>
		<td>Computer major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE</td>
		<td>Phone major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT</td>
		<td>LAN major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO</td>
		<td>AUDIO major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL</td>
		<td>Peripheral major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING</td>
		<td>Imaging major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE</td>
		<td>Wearable major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_TOY</td>
		<td>Toy major device class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH</td>
		<td>Health major device class</td></tr>

</table>

		<h3 class="pg">bluetooth_device_minor_class_t</h3>
Minor device class (part of Class of Device)
<table>
	<tr><td colspan="2">bluetooth_device_service_class_t</td></tr>

	<tr>		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_UNCLASSIFIED</td>
		<td>Not classified class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_DESKTOP_WORKSTATION</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, Desktop PC</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_SERVER_CLASS_COMPUTER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, Desktop Server</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_LAPTOP</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, Laptop</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HANDHELD_PC_OR_PDA</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, PDA</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PALM_SIZED_PC_OR_PDA</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, Desktop PDA</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_WEARABLE_COMPUTER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_COMPUTER, wearable computer</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CELLULAR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE, cellular phone</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CORDLESS</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE, cordless phone</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_SMART_PHONE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE, Cellular phone, smart phone</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_WIRED_MODEM_OR_VOICE_GATEWAY</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE, voice gateway</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_COMMON_ISDN_ACCESS</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PHONE, ISDN</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_FULLY_AVAILABLE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_1_TO_17_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_17_TO_33_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_33_TO_50_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_50_to_67_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_67_TO_83_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_83_TO_99_PERCENT_UTILIZED</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_NO_SERVICE_AVAILABLE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_LAN_ACCESS_POINT, indicating network performance</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HEADSET_PROFILE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Headset minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HANDSFREE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Handsfree minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_MICROPHONE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Microphone minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_LOUD_SPEAKER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Loud Speaker minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HEADPHONES</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Headphones minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PORTABLE_AUDIO</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Portable Audio minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CAR_AUDIO</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Car Audio minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_SET_TOP_BOX</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Set top box minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HIFI_AUDIO_DEVICE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Hifi audio device minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VCR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, VCR minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VIDEO_CAMERA</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Video Camera minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CAM_CORDER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Camcorder minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VIDEO_MONITOR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Video Monitor minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VIDEO_DISPLAY_AND_LOUD_SPEAKER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Video Display and Loud Speaker minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VIDEO_CONFERENCING</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Video Conferencing minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_GAMING_OR_TOY</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_AUDIO, Gaming or toy minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_KEY_BOARD</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Key board minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_POINTING_DEVICE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Pointing Device minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_COMBO_KEYBOARD_OR_POINTING_DEVICE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Combo Keyboard or pointing device  minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_JOYSTICK</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, JoyStick minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_GAME_PAD</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Game Pad minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_REMOTE_CONTROL</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Remote Control minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_SENSING_DEVICE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Sensing Device minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_DIGITIZER_TABLET</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Digitizer minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CARD_READER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Card Reader minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_DIGITAL_PEN</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Digital pen minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HANDHELD_SCANNER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Handheld scanner minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HANDHELD_GESTURAL_INPUT_DEVICE
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_PERIPHERAL, Handheld gestural input device minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_DISPLAY</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING, Display minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CAMERA</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING, Camera minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_SCANNER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING, Scanner minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PRINTER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_IMAGING, Printer minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_WRIST_WATCH</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE, Wrist watch minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PAGER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE, Pager minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_JACKET</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE, Jacket minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HELMET</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE, Helmet minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_GLASSES</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_WEARABLE, Glasses minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_ROBOT</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_TOY, Robot minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_VEHICLE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_TOY, Vehicle minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_DOLL_OR_ACTION</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_TOY, Doll or Action minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_CONTROLLER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_TOY, Controller minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_GAME</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_TOY, Game minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_BLOOD_PRESSURE_MONITOR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Blood Pressure minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_THERMOMETER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Thermometer minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_WEIGHING_SCALE</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Weighing Scale minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_GLUCOSE_METER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Glucose minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PULSE_OXIMETER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Pulse Oximeter minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_HEART_OR_PULSE_RATE_MONITOR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Heart or pulse rate monitor minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_MEDICAL_DATA_DISPLAY</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Medical minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_MEDICAL_STEP_COUNTER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Step counter minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_BODY_COMPOSITION_ANALYZER</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Body composition analyzer minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_PEAK_FLOW_MONITOR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Peak flow monitor minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_MEDICATION_MONITOR</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Medication monitor minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_KNEE_PROSTHESIS</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Knee prosthesis minor class</td></tr>

	<tr>		<td>BLUETOOTH_DEVICE_MINOR_CLASS_ANKLE_PROSTHESIS</td>
		<td>Detailed class for BLUETOOTH_DEVICE_MAJOR_CLASS_HEALTH, Ankle prosthesis minor class</td></tr>
</table>

	<h2 class="pg">Structures</h2>
		<h3 class="pg">bluetooth_device_address_t</h3>
This is Bluetooth device address type, fixed to 6 bytes ##:##:##:##:##:##
<table>
	<tr><td colspan="3">bluetooth_device_service_class_t</td></tr>

	<tr>		<td>Type</td>
		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>unsigned char [BLUETOOTH_ADDRESS_LENGTH]</td>
		<td>addr</td>
		<td>Address of Bluetooth device</td></tr>
</table>

		<h3 class="pg">bluetooth_device_name_t</h3>
This is Bluetooth device name type, maximum size of Bluetooth device name is 248 bytes
<table>
	<tr><td colspan="3">bluetooth_device_service_class_t</td></tr>

	<tr>		<td>Type</td>
		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>char [BLUETOOTH_DEVICE_NAME_LENGTH_MAX]</td>
		<td>name</td>
		<td>Name of Bluetooth device</td></tr>
</table>

		<h3 class="pg">bluetooth_device_class_t</h3>
Structure to hold the device class information
<table>
	<tr><td colspan="3">bluetooth_device_class_t</td></tr>

	<tr>		<td>Type</td>
		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>bluetooth_device_major_class_t</td>
		<td>major_class;</td>
		<td>major device class</td></tr>

	<tr>		<td>bluetooth_device_minor_class_t</td>
		<td>minor_class</td>
		<td>minor device class</td></tr>

	<tr>		<td>bluetooth_device_service_class_t</td>
		<td>service_class</td>
		<td>service device class</td></tr>
</table>

		<h3 class="pg">bluetooth_device_info_t</h3>
Structure to hold the device information
<table>
	<tr><td colspan="3">bluetooth_device_info_t</td></tr>

	<tr>		<td>Type</td>
		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>bluetooth_device_address_t</td>
		<td>device_address</td>
		<td>Device address</td></tr>

	<tr>		<td>bluetooth_device_name_t</td>
		<td>device_name</td>
		<td>Device name</td></tr>

	<tr>		<td>bluetooth_device_class_t</td>
		<td>device_class</td>
		<td>Device class</td></tr>

	<tr>		<td>unsigned int</td>
		<td>service_list_array</td>
		<td>Service list array</td></tr>

	<tr>		<td>int</td>
		<td>service_index</td>
		<td>Service list number</td></tr>

	<tr>		<td>int</td>
		<td>rssi</td>
		<td>Received signal strength indicator</td></tr>

	<tr>		<td>gboolean</td>
		<td>paired</td>
		<td>Paired status</td></tr>

	<tr>		<td>gboolean</td>
		<td>connected</td>
		<td>Connected status</td></tr>

	<tr>		<td>gboolean</td>
		<td>trust</td>
		<td>Authorized status</td></tr>
</table>

		<h3 class="pg">bluetooth_event_param_t</h3>
Structure to hold event information
<table>
	<tr><td colspan="3">bluetooth_device_info_t</td></tr>

	<tr>		<td>Type</td>
		<td>Name</td>
		<td>Description</td></tr>

	<tr>		<td>int</td>
		<td>event</td>
		<td>Event type</td></tr>

	<tr>		<td>int</td>
		<td>result</td>
		<td>Success or error value</td></tr>

	<tr>		<td>void *</td>
		<td>param_data</td>
		<td>Parameter data pointer</td></tr>

	<tr>		<td>void *</td>
		<td>user_data</td>
		<td>User data pointer</td></tr>
</table>

	<h2 class="pg">Call back functions</h2>
		<h3 class="pg">bluetooth_cb_func_ptr</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">Void(* bluetooth_cb_func_ptr)(int event, bluetooth_event_param_t* event_param, void *user_data)</td></tr>

	<tr><td rowspan="3">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>event</td>
		<td>int</td>
		<td>Event type</td></tr>

	<tr>		<td>event_param</td>
		<td>bluetooth_event_param_t*</td>
		<td>Event data</td></tr>

	<tr>		<td>user_data</td>
		<td>void *</td>
		<td>User data</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td>

	<tr>		<td>Returns</td>
<td colspan="3">Void*</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This call back function will be used to pass asynchronous events to application</td></tr>
</table>

	<h2 class="pg">Functions</h2>
		<h3 class="pg">bluetooth_register_callback</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_register_callback(bluetooth_cb_func_ptr callback_ptr, void *user_data)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>callback_ptr</td>
		<td>bluetooth_cb_func_ptr</td>
		<td>a pointer to callback function</td></tr>

	<tr>		<td>user_data</td>
		<td>void *</td>
		<td>a pointer to user data</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function will register the callback function, to handle events received from Bluetooth framework. </td></tr>

	<tr><td colspan="4">This is a synchronous call. No event is returned after this function call</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param, void *user_data)
{
	GMainLoop *main_loop = (GMainLoop*) user_data;

	switch(event)
	{
		// Code for each event
		default:
			g_main_loop_quit(main_loop);
			break;
	}
}

int main()
{
	GMainLoop *main_loop = NULL;
	int ret = 0;
	g_type_init();
	main_loop = g_main_loop_new(NULL, FALSE);
	ret = bluetooth_register_callback(bt_event_callback, (void*)main_loop);
	if (ret >= BLUETOOTH_ERROR_NONE)
	{
		// bluetooth_register_callback returned Success
	}
	else
	{
		// bluetooth_register_callback returned failiure
	}
	g_main_loop_run(main_loop);
}
@endcode
</table>

- Sequence flow
@image html bluetooth_image002.png

		<h3 class="pg">bluetooth_enable_adapter</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_enable_adapter(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function initializes Bluetooth protocol stack for use. This function is typically called at startup or when Bluetooth services are required. This function must be called before calling any other API of Bluetooth operations.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n If the call is success then the application will receive BLUETOOTH_EVENT_ENABLED event through registered callback function.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_ENABLED:
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				// Successfully Enabled
			}
			else
			{
				// Failed
			}
			break;
	}
}

...

int ret = 0;
ret = bluetooth_enable_adapter();
@endcode
</table>

 - Sequence flow
@image html bluetooth_image003.png

		<h3 class="pg">bluetooth_disable_adapter</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_disable_adapter(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function disables Bluetooth protocol stack and hardware. This function should be called when Bluetooth is no longer used.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n If this call is successful then the application will receive BLUETOOTH_EVENT_DISABLED event through registered callback function.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
        	case BLUETOOTH_EVENT_DISABLED:
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				// Successfully disabled
			}
			else
			{
				// Failed
			}
			break;
	}
}

...

int ret = 0;
ret = bluetooth_disable_adapter();
@endcode
</table>

- Sequence flow
@image html bluetooth_image004.png

		<h3 class="pg">bluetooth_check_adapter</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_check_adapter(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">bluetooth_adapter_state_t - Adapter state
@n or
@n Negative value (Error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function checks whether the Bluetooth adapter is enabled or not.</td></tr>

	<tr><td colspan="4">This function is a synchronous call.</td></tr>

@code

bluetooth_device_address_t local_address={0,};
int ret = 0;

ret = bluetooth_get_local_address(&local_address);
@endcode
</table>


- Sequence flow
@image html bluetooth_image005.png

		<h3 class="pg">bluetooth_get_local_address</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_get_local_address(bluetooth_device_address_t* local_address)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>local_address</td>
		<td>bluetooth_device_address_t *</td>
		<td>Device address of local Bluetooth adapter</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on Success, Negative value (Error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function is used to get the device address of the local Bluetooth adapter.</td></tr>

	<tr><td colspan="4">This function is a synchronous call.</td></tr>

@code
bluetooth_device_name_t local_name={0,}
int ret = 0;
ret = bluetooth_get_local_name (&local_name);
@endcode
</table>

- Sequence flow
@image html bluetooth_image006.png

		<h3 class="pg">bluetooth_get_local_name</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_get_local_name(bluetooth_device_name_t* local_name)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>local_name</td>
		<td>bluetooth_device_name_t*</td>
		<td>Local device name</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value (error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function is used to get the local device name.</td></tr>

	<tr><td colspan="4">This function is a synchronous call.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_LOCAL_NAME_CHANGED :
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				// Successfully local name changed
			}
			else
			{
				// Failed
			}
			break;
	}
}

bluetooth_device_name_t local_name={0,}
int ret = 0;
ret = bluetooth_set_local_name (&local_name);
@endcode
</table>

- Sequence flow
@image html bluetooth_image007.png

		<h3 class="pg">bluetooth_set_local_name</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_set_local_name(const bluetooth_device_name_t* local_name)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>local_name</td>
		<td>const bluetooth_device_name_t*</td>
		<td>Local device name</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value (error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function is used to set the local device name.</td></tr>

	<tr><td colspan="4">This function is an synchronous call.

 @code
 bluetooth_discoverable_mode_t discoverable_mode_ptr;
 int ret = 0;
 ret = bluetooth_get_discoverable_mode (&discoverable_mode_ptr);
 @endcode
</table>

- Sequence flow
@image html bluetooth_image008.png

		<h3 class="pg">bluetooth_get_discoverable_mode</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_get_discoverable_mode(bluetooth_discoverable_mode_t* discoverable_mode_ptr)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>discoverable_mode_ptr</td>
		<td>bluetooth_discoverable_mode_t*</td>
		<td>current bluetooth discoverable mode</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value (error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function is used to get the discoverable mode (Visibility option)</td></tr>

	<tr><td colspan="4">This function is a synchronous call.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_DISCOVERABLE_MODE_CHANGED :
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				// Successfully local name changed
			}
			else
			{
				// Failed
			}
			break;
	}
}

bluetooth_discoverable_mode_t mode;
int ret = 0;
mode= BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
ret = bluetooth_set_discoverable_mode (mode, 180);
@endcode
</table>

- Sequence flow
@image html bluetooth_image009.png

		<h3 class="pg">bluetooth_set_discoverable_mode</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_set_discoverable_mode(bluetooth_discoverable_mode_t discoverable_mode, int timeout)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>discoverable_mode</td>
		<td>bluetooth_discoverable_mode_t</td>
		<td>Local device name</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value (error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function is used to set the discoverable mode (Visibility option).</td></tr>

	<tr><td colspan="4">If new discoverable mode is time limited discoverable mode then application will receive BLUETOOTH_EVENT_DISCOVERABLE_TIMEOUT_REQUESTED event through registered callback function. Application can use default timeout, 180 seconds, by ignoring this event.
@n This function is an synchronous call.

@code

bluetooth_discoverable_mode_t mode;
int ret = 0;
mode= BLUETOOTH_DISCOVERABLE_MODE_TIME_LIMITED_DISCOVERABLE;
ret = bluetooth_set_discoverable_mode (mode, 180);
@endcode
</table>

- Sequence flow
@image html bluetooth_image010.png

		<h3 class="pg">bluetooth_start_discovery</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_start_discovery(unsigned short max_response, unsigned short discovery_duration, unsigned int classOfDeviceMask)</td></tr>

	<tr><td rowspan="4">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>max_response</td>
		<td>unsigned short</td>
		<td>the maximum response of the number of founded devices</td></tr>

	<tr>		<td>Discovery_duration</td>
		<td>unsigned short</td>
		<td>Bluetooth discovery duration</td></tr>

	<tr>		<td>ClassOfDeviceMask</td>
		<td>unsigned int</td>
		<td>Classes of the device mask which user wants</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value (error code) if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function searches for peer Bluetooth devices. It first performs an inquiry; for each device found from the inquiry it gets the remote name of the device.
@n To decide searching options like device type, maximum duration, filtering option, application will receive BLUETOOTH_EVENT_DISCOVERY_OPTION_REQUESTED event through registered callback function. Application can use ignore this event for just using default options, all devices, 30 seconds duration, no filter, general discover option.
@n The device discovery can be cancelled by calling bluetooth_stop_discovery().</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n If the call is success then the application will receive BLUETOOTH_EVENT_DISCOVERY_STARTED event through registered callback function.
@n The discovery is responded by BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND event for each device it finds and BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED event for each device name it finds. The completion or cancellation of the discovery is indicated by BLUETOOTH_EVENT_DISCOVERY_FINISHED event.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND:
		{
			bluetooth_device_info_t *device_info = NULL;
			printf("BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND, result [0x%04x]", param->result);
			device_info  = (bluetooth_device_info_t *)param->param_data;
			memcpy(&searched_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			printf("dev [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", \
				device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
				device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5]);
			break;
		}
                   case BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED:
		{
			bluetooth_device_info_t *device_info = NULL;
			printf("BLUETOOTH_EVENT_REMOTE_DEVICE_NAME_UPDATED, result [0x%04x]", param->result);
			device_info  = (bluetooth_device_info_t *)param->param_data;
			memcpy(&searched_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			printf("dev [%s] [%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X]", device_info->device_name.name, \
				device_info->device_address.addr[0], device_info->device_address.addr[1], device_info->device_address.addr[2], \
				device_info->device_address.addr[3], device_info->device_address.addr[4], device_info->device_address.addr[5]);
			break;
		}

		case BLUETOOTH_EVENT_DISCOVERY_FINISHED:
			printf("BLUETOOTH_EVENT_DISCOVERY_FINISHED, result [0x%04x]", param->result);
			break;
	}
}

unsigned short max_response;
unsigned short discovery_duration;
unsigned classOfDeviceMask;
int ret = 0;

max_response =0;
discovery_duration =0;
classOfDeviceMask =0;

ret = bluetooth_start_discovery(max_response,discovery_duration,classOfDeviceMask);
@endcode
</table>

- Sequence flow
@image html bluetooth_image011.png

		<h3 class="pg">bluetooth_cancel_discovery</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_cancel_discovery (void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">This function returns true on success or false on failure</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function stops the ongoing device discovery operation.
@n * with an error code BLUETOOTH_ERROR_CANCEL</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n If the call is successful in canceling discovery then the application will receive BLUETOOTH_EVENT_DISCOVERY_FINISHED event through registered callback function.</td></tr>

@code
void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
		case BLUETOOTH_EVENT_DISCOVERY_FINISHED:
			TC_PRT("BLUETOOTH_EVENT_DISCOVERY_FINISHED, result[0x%04x]", param->result);
			break;
	}
}

..

int ret = 0;

ret = bluetooth_cancel_discovery();
@endcode
</table>

- Sequence flow
@image html bluetooth_image012.png

		<h3 class="pg">bluetooth_is_discovering</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_is_discovering(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 if there is no device discovery, 1 if there is a device discovery, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function checks whether the device discovery is started or not.</td></tr>

	<tr><td colspan="4">This function is a synchronous call.</td></tr>

@code
int ret = 0;
ret = bluetooth_is_discovering ();
@endcode
</table>

- Sequence flow
@image html bluetooth_image013.png

		<h3 class="pg">bluetooth_bond_device</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_bond_device(const bluetooth_device_address_t *device_address)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>device_address</td>
		<td>bluetooth_device_address_t *</td>
		<td>This indicates an address of the device with which the pairing should be initiated</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">This function returns true on success or false on failure</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function initiates a bonding procedure with a peer device. The bonding procedure enables authentication and optionally encryption on the Bluetooth link.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n Response will be received through BLUETOOTH_EVENT_BONDING_FINISHED event.</td></tr>

@code
bluetooth_device_address_t searched_device = {{0}};
bluetooth_device_address_t bonded_device = {{0}};

void bt_event_callback(int event, bluetooth_event_param_t* param)
{
 	switch(event)
        {
		case BLUETOOTH_EVENT_REMOTE_DEVICE_FOUND:
		{
			bluetooth_device_info_t *device_info = NULL;
			device_info  = (bluetooth_device_info_t *)param->param_data;
			memset(&searched_device, 0x00, sizeof(bluetooth_device_address_t));
			memcpy(&searched_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			break;
		}

        	case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				device_info  = (bluetooth_device_info_t *)param->param_data;
				memset(&bonded_device, 0x00, sizeof(bluetooth_device_address_t));
				memcpy(&bonded_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			}
			else
			{
				//bonding failed
			}
			break;
		}
	}
}

...

int ret = 0;

// After running bluetooth_start_discovery API, call this API if you are in testing.
// Because we try to bond to the lastest searched device for testing in under code.
if (searched_device.addr[0] || searched_device.addr[1] || searched_device.addr[2] \
	|| searched_device.addr[3] || searched_device.addr[4] || searched_device.addr[5])
{
	ret = bluetooth_bond_device(&searched_device);
}
@endcode
</table>

- Sequence flow
@image html bluetooth_image014.png

		<h3 class="pg">bluetooth_cancel_bonding</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_cancel_bonding(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This API is called to cancel the on-going bonding procedure.</td></tr>

	<tr><td colspan="4">This function is an synchronous call.
@code
...

int ret = 0;

ret = bluetooth_cancel_bonding();
@endcode
</table>

- Sequence flow
@image html bluetooth_image015.png

		<h3 class="pg">bluetooth_unbond_device</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_unbond_device(const bluetooth_device_address_t *device_address)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>device_address</td>
		<td>const bluetooth_device_address_t *</td>
		<td>This indicates an address of the device to remove bonding</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">This function returns true on success or false on failure</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function removes the bonded device from the bonded list.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n The request to remove the specified device from the bonded list is responded by BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED event</td></tr>

@code
bluetooth_device_address_t bonded_device = {{0}};

void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
        	case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				device_info  = (bluetooth_device_info_t *)param->param_data;
				memset(&bonded_device, 0x00, sizeof(bluetooth_device_address_t));
				memcpy(&bonded_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			}
			else
			{
				//bonding failed
			}
			break;
		}

		case BLUETOOTH_EVENT_BONDED_DEVICE_REMOVED:
		{
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				//Unbound scuccess
			}
			else
				//unbound failure
		}
	}
}


...

int ret = 0;

// After running bluetooth_bond_device API, call this API if you are in testing.
// Because we try to unbond to the lastest bonded device for testing in under code.

ret = bluetooth_unbond_device(bonded_device);
@endcode
</table>

- Sequence flow
@image html bluetooth_image016.png

		<h3 class="pg">bluetooth_get_bonded_device_list </h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_get_bonded_device_list(GPtrArray **dev_list)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">This function returns true on success or false on failure</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function gets a list of all the bonded(paired) devices.</td></tr>

	<tr><td colspan="4">This function is an synchronous call.
@n Information for bonded devices can be obtained when result code is BLUETOOTH_ERROR_NONE. If not, there is no valid information in the dev_list.
 * The len field in the dev_list represents the number of bonded devices. The data structure for bonded device information is bluetooth_paired_device_info_t.

 @code
void bt_get_bonded_devices(void)
{
...
	int i;
	GPtrArray *devinfo = NULL;
	bluetooth_paired_device_info_t *ptr;

	// allocate the g_pointer_array
	devinfo = g_ptr_array_new();

	ret = bluetooth_get_bonded_device_list(&devinfo);
	if (ret != BLUETOOTH_ERROR_NONE)
	{
		printf("bluetooth_get_bonded_device_list failed with [%d]",ret);
	}
	else
	{
		printf("g pointer arrary count : [%d]", devinfo->len);
		for(i=0; i<devinfo->len;i++)
		{
			ptr = g_ptr_array_index(devinfo, i);
			if(ptr != NULL)
			{
				printf("Name [%s]\n", ptr->device_name.name);
				printf("Major Class [%d]\n", ptr->device_class.major_class);
				printf("Minor Class [%d]\n", ptr->device_class.minor_class);
				printf("Service Class [%d]\n", ptr->device_class.service_class);
				printf("%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n", ptr->device_address.addr[0], ptr->device_address.addr[1], ptr->device_address.addr[2], ptr->device_address.addr[3], ptr->device_address.addr[4], ptr->device_address.addr[5]);

				// handle
				...
			}
		}
	}
	// free g_pointer_array
	g_ptr_array_free(devinfo, TRUE);
}

@endcode
</table>

- Sequence flow
@image html bluetooth_image017.png

		<h3 class="pg">bluetooth_get_remote_device (Not supported yet)</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_get_remote_device(const bluetooth_device_address_t *device_address)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>device_address</td>
		<td>const bluetooth_device_address_t *</td>
		<td>This indicates an address of the remote device</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function gets specific remote device.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n This API is responded by BLUETOOTH_EVENT_REMOTE_DEVICE_READ event.</td></tr>

@code
int ret = 0;
ret = bluetooth_get_remote_device(&remote_address);
@endcode
</table>

- Sequence flow
@image html bluetooth_image018.png

		<h3 class="pg">bluetooth_authorize_device</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_authorize_device(const bluetooth_device_address_t *device_address, gboolean authorized)</td></tr>

	<tr><td rowspan="3">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>device_address</td>
		<td>const bluetooth_device_address_t *</td>
		<td>This indicates an address of the device to authorize</td></tr>

	<tr>		<td>authorized</td>
		<td>gboolean</td>
		<td>TRUE: authorized FALSE:unauthorized</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function authorizes a bonded device to be able to connect without user confirmation.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n Response will be received through BLUETOOTH_EVENT_DEVICE_AUTHORIZED event.</td></tr>

@code
bluetooth_device_address_t bonded_device = {{0}};

void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
        	case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				device_info  = (bluetooth_device_info_t *)param->param_data;
				memset(&bonded_device, 0x00, sizeof(bluetooth_device_address_t));
				memcpy(&bonded_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			}
			else
			{
				//bonding failed
			}
			break;
		}

		case BLUETOOTH_EVENT_DEVICE_AUTHORIZED :
		{
			if (param->result == BLUETOOTH_ERROR_NONE)
			{
				//Device authorized
			}
			//device authorization failed failure
		}
	}
}

...

int ret = 0;
gboolean authorized;

authorized =TRUE;

ret = bluetooth_authorize_device(&bonded_device,authorized);
@endcode
</table>

- Sequence flow
@image html bluetooth_image019.png

		<h3 class="pg">bluetooth_search_service</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_search_service(const bluetooth_device_address_t *device_address)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>device_address</td>
		<td>const bluetooth_device_address_t *</td>
		<td>This indicates an address of the device whose services need to be found</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This API call initiates the search for the services supported by the specified device.</td></tr>

	<tr><td colspan="4">This function is an asynchronous call.
@n The service search request is responded by BLUETOOTH_EVENT_SERVICE_SEARCHED event</td></tr>

@code
bluetooth_device_address_t bonded_device = {{0}};

void bt_event_callback(int event, bluetooth_event_param_t* param)
{
	switch(event)
	{
        	case BLUETOOTH_EVENT_BONDING_FINISHED:
		{
			TC_PRT("BLUETOOTH_EVENT_BONDING_FINISHED, result [0x%04x]", param->result);
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bluetooth_device_info_t *device_info = NULL;
				device_info  = (bluetooth_device_info_t *)param->param_data;
				memset(&bonded_device, 0x00, sizeof(bluetooth_device_address_t));
				memcpy(&bonded_device, &device_info->device_address, sizeof(bluetooth_device_address_t));
			}
			else
			{
				//bonding failed
			}
			break;
		}

		case BLUETOOTH_EVENT_SERVICE_SEARCHED:
		{
			int i = 0;
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bt_sdp_info_t * bt_sdp_info=param->param_data;

				for(i=0; i<bt_sdp_info->service_index; i++)
					printf("[%#x]\n", bt_sdp_info->service_list_array[i]);
			}
			else
			{
				// service searched fail
			}
		}
	}
}

...

int ret = 0;
ret = bluetooth_search_service(&bonded_device);
@endcode
</table>

- Sequence flow
@image html bluetooth_image020.png

		<h3 class="pg">bluetooth_cancel_service_search</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_cancel_service_search(void)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">0 on success, negative value if failed</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function cancels the ongoing service search operation</td></tr>

	<tr><td colspan="4">This function is an synchronous call.

@code
...

int ret = 0;
ret = bluetooth_cancel_service_search();
@endcode
</table>

- Sequence flow
@image html bluetooth_image021.png

		<h3 class="pg">bluetooth_rfcomm_create_socket</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_create_socket(const char *uuid)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>uuid</td>
		<td>const char*</td>
		<td>UUID (128 bits)</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">socket FD</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function register rfcomm socket with the given UUID</td></tr>

	<tr><td colspan="4">This is a synchronous operation</td></tr>
 @code

  int fd = 0;
  const char * rfcomm_test_uuid="00001101-0000-1000-8000-00805F9B34FB";
  fd  = bluetooth_rfcomm_create_socket(rfcomm_test_uuid);

 @endcode
</table>

- Sequence flow
@image html bluetooth_image022.png

		<h3 class="pg">bluetooth_rfcomm_listen_and_accept</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_listen_and_accept(int socket_fd, int max_pending_connection)</td></tr>

	<tr><td rowspan="3">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>socket_fd</td>
		<td>int</td>
		<td>Server socket FD</td></tr>

	<tr>		<td>max_pending_connection</td>
		<td>int</td>
		<td>Max pending connection.</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">success or not</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function make rfcomm socket listen with socket. When ever a remote device gets connected, BLUETOOTH_EVENT_RFCOMM_CONNECTED event will get generated. This API is not a blocking call.
 Once the connection is sucessfull, BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED event will get generated when there is some incoming data.</td></tr>

	<tr><td colspan="4">This is a synchronous operation</td></tr>
  @code

 void bt_event_callback(int event, bluetooth_event_param_t* param)
 {
       Switch(event)
       {
           case BLUETOOTH_EVENT_RFCOMM_CONNECTED:
           {
                if (param->result == BLUETOOTH_ERROR_NONE)
	         {
                    bluetooth_rfcomm_connection_t *con_ind =
                      (bluetooth_rfcomm_connection_t *)param->param_data;

                    if(con_ind->device_role == RFCOMM_ROLE_SERVER)
                    {
                        //A client has been connected to the sever
                        printf("\nClient fd = %d", conn_ind->socket_fd;
                    }
                    else
                    {

                    }
                }
            }
       }
 }

 int ret = 0;
 int max_connect = 1;
 const char * spp_uuid ="00001101-0000-1000-8000-00805F9B34FB";
 int socket_fd = bluetooth_rfcomm_create_socket(spp_uuid);
 ret = bluetooth_rfcomm_listen_and_accept(socket_fd, max_connect);

 @endcode
</table>

- Sequence flow
@image html bluetooth_image024.png


		<h3 class="pg">bluetooth_rfcomm_remove_socket</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_remove_socket(int socket_fd, const char *uuid)</td></tr>

	<tr><td rowspan="3">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

 	<tr>		<td>socket_fd</td>
		<td>int</td>
		<td>Server socket FD</td></tr>

	<tr>		<td>uuid</td>
		<td>const char*</td>
		<td>UUID (128 bits)</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">success or not</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">This function deregister rfcomm socket with the given socket descriptor and UUID. If a client connection exists, then BLUETOOTH_EVENT_RFCOMM_DISCONNECTED event will get generated to indicate that the client connection has been terminated.</td></tr>

	<tr><td colspan="4">This is a synchronous operation</td></tr>
 @code
 void bt_event_callback(int event, bluetooth_event_param_t* param)
 {
       Switch(event)
       {
           case BLUETOOTH_EVENT_RFCOMM_DISCONNECTED:
           {
                if (param->result == BLUETOOTH_ERROR_NONE)
	         {
                            //A connection exists and it got disconnect
                }
            }
       }
 }


 ...

 int ret = 0;
 int fd = 0;
 const char * spp_uuid ="00001101-0000-1000-8000-00805F9B34FB";
 fd  = bluetooth_rfcomm_create_socket(spp_uuid);
 ret = bluetooth_rfcomm_listen_and_accept(fd, 1);
 ....
 ret = bluetooth_rfcomm_remove_socket(fd, spp_uuid);

 @endcode
</table>

- Sequence flow
@image html bluetooth_image023.png

		<h3 class="pg">bluetooth_rfcomm_connect</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_connect(const bluetooth_device_address_t  *remote_bt_address, const char * remote_uuid)</td></tr>

	<tr><td rowspan="3">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>remote_bt_address</td>
		<td>const bluetooth_device_address_t  *</td>
		<td>Remote device?™s Bluetooth address</td></tr>

	<tr>		<td>remot_uuid</td>
		<td>const char*</td>
		<td>remote uuid</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">success or not</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">Connect to a specific RFCOMM based service on a remote device. It is advisible to do a service search before connecting. When ever the connection is successful, BLUETOOTH_EVENT_RFCOMM_CONNECTED event will gets generated.
 Once the connection is sucessfull, BLUETOOTH_EVENT_RFCOMM_DATA_RECEIVED event will get generated when there is some incoming data.</td></tr>

	<tr><td colspan="4">This is Asynchronous operation</td></tr>
  @code

 void bt_event_callback(int event, bluetooth_event_param_t* param)
 {
	switch(event)
	{
		case BLUETOOTH_EVENT_SERVICE_SEARCHED:
		{
			if (param->result >= BLUETOOTH_ERROR_NONE)
			{
				bt_sdp_info_t * bt_sdp_info=param->param_data;

				printf("Dev add = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
					bt_sdp_info->device_addr.addr[0], bt_sdp_info->device_addr.addr[1], bt_sdp_info->device_addr.addr[2], \
					bt_sdp_info->device_addr.addr[3], bt_sdp_info->device_addr.addr[4], bt_sdp_info->device_addr.addr[5]);

					printf("Supported service list:\n");
					for(i=0; i<bt_sdp_info->service_index; i++)
						printf("[%#x]\n", bt_sdp_info->service_list_array[i]);

				//Alternate method
				//ret = bluetooth_rfcomm_connect(bt_sdp_info->device_addr, rfcomm_test_uuid);
			}
			break;
		}
		case BLUETOOTH_EVENT_RFCOMM_CONNECTED:
		{
			bluetooth_rfcomm_connection_t *conn_ind = (bluetooth_rfcomm_connection_t *)param->param_data;

			printf("\nConnected from FD %d, Role = %s",  conn_ind->socket_fd,
								(conn_ind->device_role == RFCOMM_ROLE_SERVER)? "SERVER":"CLIENT");
		}
	}
 }

  bluetooth_device_address_t remote_address = {{0},};
  const char * spp_uuid ="00001101-0000-1000-8000-00805F9B34FB";
  remote_address.addr[0] = 0x0; remote_address.addr[1] = 0x0A; remote_address.addr[2] = 0x3A;
  remote_address.addr[3]= 0x54; remote_address.addr[4] = 0x19;  remote_address.addr[5]= 0x36;
  ret = bluetooth_search_service(&remote_address);
 if (ret < 0)
  	printf("Seach failed, Reason = %d", ret);
  else
	 printf("Search Success, Ret = %d", ret);

  ret = bluetooth_rfcomm_connect(&remote_address, spp_uuid);
  if (ret < 0)
  	printf("Connection failed, Reason = %d", ret);
  else
	 printf("Connection Success, Ret = %d", ret);

  @endcode
</table>

- Sequence flow
@image html bluetooth_image025.png

		<h3 class="pg">bluetooth_rfcomm_disconnect</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_disconnect(int socket_fd)</td></tr>

	<tr><td rowspan="2">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>socket_fd</td>
		<td>int</td>
		<td>Client socket FD</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">success or not</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">Disconnect a specific(remote address)  RFCOMM connection</td></tr>

	<tr><td colspan="4">This is a synchronous operation</td></tr>
 @code

  ret = bluetooth_rfcomm_disconnect(g_ret_fd);
  if (ret < 0)
  	printf("Disconnection failed");
  else
  	printf("Disconnection Success");

 @endcode
</table>

- Sequence flow
@image html bluetooth_image026.png

		<h3 class="pg">bluetooth_rfcomm_write</h3>
<table>
	<tr>		<td>Function Prototype</td>
<td colspan="3">int bluetooth_rfcomm_write(int fd, const char *buf, int length)</td></tr>

	<tr><td rowspan="4">Input Parameters</td>
		<td>Variable Name</td>
		<td>Data Type</td>
		<td>Description</td></tr>

	<tr>		<td>fd</td>
		<td>int</td>
		<td>Socket descriptor</td></tr>

	<tr>		<td>buf</td>
		<td>const char*</td>
		<td>Buffer data to send</td></tr>

	<tr>		<td>length</td>
		<td>int</td>
		<td>Length of the buffer</td></tr>

	<tr>		<td>Output Parameters</td>
		<td>n/a</td>
		<td>n/a</td>
		<td>n/a</td></tr>

	<tr>		<td>Returns</td>
<td colspan="3">success or not</td></tr>

	<tr>		<td>Function Description</td>
<td colspan="3">Send the data to the remote device. This API used by both the client and the sever to send the data.</td></tr>

	<tr><td colspan="4">This is a synchronous operation</td></tr>
 @code

 int ret = 0;
 char *buff = "abcdefghijklmnopqrstuvwxyz";
 int len = 26;
 ret = bluetooth_rfcomm_write(fd, buff, len);


 @endcode
</table>

- Sequence flow
@image html bluetooth_image027.png

*/
/**
@}
*/

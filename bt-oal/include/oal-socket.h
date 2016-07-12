/*
* Open Adaptation Layer (OAL)
*
* Copyright (c) 2014-2015 Samsung Electronics Co., Ltd.
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


#ifndef _OAL_SOCKET_HOST_H_
#define _OAL_SOCKET_HOST_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	OAL_SOCK_RFCOMM,
	OAL_SOCK_SCO,
	OAL_SOCK_L2CAP
} oal_sock_type_t;

/**
 * @fn oal_status_t socket_enable(void);
 * @brief Enables the rfcomm profile
 *
 * This API will register the callback function, when any response/data are received from
 * bluetooth RFCOMM remote device. @n
 * this registered callback function will be get called with fd of remote device, data buffer and its length.
 * This function is a synchronous call.
 *
 * @param[in]   data_cb      A pointer to the callback function
 * @return      BLUETOOTH_ERROR_NONE - Success
 * @remark      None
 * @see         None
 * */
oal_status_t socket_enable(void);

/**
 * @fn oal_status_t socket_disable(void);
 * @brief Disables the rfcomm profile
 *
 * This API will disable RFCOMM profile. Before disabling it's better to ensure
 * all the connections are closed
 * This function is a synchronous call.
 *
 * @return      BLUETOOTH_ERROR_NONE - Success
 * @remark      None
 * @see         socket_disconnect
 * */
oal_status_t socket_disable(void);

/**
 * @fn int  socket_connect(oal_sock_type_t sock_type, bt_address_t* bd, oal_uuid_t* p_uuid, int channel);
 * @brief Creates outgoing client
 *
 * This API connects to the remote RFCOMM server. It takes either server UUID or Channel
 * along with the bluetooth MAC address of Server.
 * It returns the Outgoing Client FD. Two events are associated with this API:
 *	1. OAL_EVENT_OUTGOING_CONNECTED: When Outgoing Client connects
 *	succefully to remote Server.
 *	2. OAL_EVENT_SOCKET_DISCONNECTED: When Outgoing Client fails to
 *	connect/Outgoing client hung up.
 * The FD received can be used to send data using interface socket_write. Data
 * coming from remote interface comes through the callback registered at time of
 * socket_init
 * This function is a asynchronous call.
 *
 * @param[in]   sock_type  Bluetooth socket type to be connected
 * @param[in]   p_uuid     UUID of the remote RFCOMM SERVER
 * @param[in]   channel    channel
 * @param[in]   bd         Bluetooth Mac address of RFCOMM server
 * @return      Outgoing client FD --- Success
 * @see         socket_disconnect
 */
int socket_connect(oal_sock_type_t sock_type, oal_uuid_t* p_uuid, int channel, bt_address_t* bd);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /*_OAL_SOCKET_HOST_H_*/

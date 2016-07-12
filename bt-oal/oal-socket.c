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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>
#include <dlog.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

#include <oal-event.h>
#include <oal-manager.h>
#include "oal-internal.h"

#include "bluetooth.h"
#include "bt_sock.h"
#include "oal-socket.h"
#include "oal-utils.h"

#define CHECK_OAL_SOCKET_ENABLED() \
	do { \
		if (socket_api == NULL) { \
			BT_ERR("Socket is not Initialized"); \
			return OAL_STATUS_NOT_READY; \
		} \
	} while (0)

/* Definitions */
#define MAX_RETRY 5
#define SOCK_SHORT_LEN 2
#define SOCK_INT_LEN 4
#define SOCK_CONNECT_INFO_LEN 16
#define SOCK_BD_ADDR_LEN 6

typedef struct {
	int fd;
	int sock_type;
	bt_address_t address;
	guint control_id;
	GIOChannel *control_io;
} oal_client_info_t;

/*
 * Global variables
 */
static const btsock_interface_t* socket_api = NULL;

static int getInt(char *buf, int len)
{
	int val = 0;

	if(len != SOCK_INT_LEN)
		return -1;
	val = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	return val;
}

static int getShort(char *buf, int len)
{
	int val = 0;

	if(len != SOCK_SHORT_LEN)
		return -1;
	val = buf[0] | (buf[1] << 8);
	return val;
}

static int getBdaddr(char *buf, int len, bt_bdaddr_t *bd)
{
	int val = 0;

	if(len != SOCK_BD_ADDR_LEN)
		return -1;
	bd->address[0] = buf[0];
	bd->address[1] = buf[1];
	bd->address[2] = buf[2];
	bd->address[3] = buf[3];
	bd->address[4] = buf[4];
	bd->address[5] = buf[5];
	BT_DBG("Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			bd->address[0], bd->address[1], bd->address[2],
			bd->address[3], bd->address[4], bd->address[5]);
	return val;
}
static void remove_io_channel(guint gid, GIOChannel *gch)
{
	if(gch != NULL)
		g_io_channel_shutdown(gch, TRUE, NULL);
	if(gid > 0)
		g_source_remove(gid);
}

static int socket_process_cmsg(struct msghdr *pMsg, int * data_fd)
{
	struct cmsghdr *cmsgptr = NULL;

	for (cmsgptr = CMSG_FIRSTHDR(pMsg);
			cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(pMsg, cmsgptr)) {

		if (cmsgptr->cmsg_level != SOL_SOCKET) {
			continue;
		}

		if (cmsgptr->cmsg_type == SCM_RIGHTS) {
			int *pDescriptors = (int *)CMSG_DATA(cmsgptr);
			int count = ((cmsgptr->cmsg_len - CMSG_LEN(0)) / sizeof(int));

			if (count < 0) {
				BT_ERR("ERROR Invalid count of descriptors");
				continue;
			}

			BT_DBG("Server, socket fd for connection: %d", pDescriptors[0]);
			*data_fd = pDescriptors[0];
		}
	}

	return 0;
}

static int socket_read(int fd, char *buf, size_t len, int *data_fd)
{
	int ret;
	struct msghdr msg;
	struct iovec iv;
	struct cmsghdr cmsgbuf[2*sizeof(struct cmsghdr) + 0x100];
	int retryCount = 0;
	int flags = 0;

	fd_set  toselect_fd;
	struct timeval wait;

	BT_INFO("socket_read, fd = %d", fd);

	retv_if(fd < 0, -1);

	memset(&msg, 0, sizeof(msg));
	memset(&iv, 0, sizeof(iv));

	iv.iov_base = buf;
	iv.iov_len = len;

	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		BT_ERR("Not able to change socket nonblocking");
		return -2;
	}

	FD_ZERO(&toselect_fd);
	FD_SET(fd, &toselect_fd);
	wait.tv_sec = 1;
	wait.tv_usec = 0;

	ret = select(fd + 1, &toselect_fd, NULL, NULL, &wait);
	if (ret < 0) {
		fcntl(fd, F_SETFL, flags );
		BT_ERR("Time out on selecy = %d", ret);
		return -1;
	}

repeat:
	retryCount ++;
	ret = recvmsg(fd, &msg, 0); //MSG_NOSIGNAL);
	BT_DBG("socket_read, recvmsg ret = %d", ret);
	if(ret < 0 && errno == EINTR) {
		if (retryCount < MAX_RETRY) {
			goto repeat;
		} else {
			fcntl(fd, F_SETFL, flags );
			return -2;
		}
	}

	if (ret < 0 && errno == EPIPE) {
		// Treat this as an end of stream
		fcntl(fd, F_SETFL, flags );
		BT_ERR("EOS errno: %d", errno);
		return 0;
	}

	if (ret < 0) {
		fcntl(fd, F_SETFL, flags );
		BT_ERR("Ret errno: %d", errno);
		return -1;
	}

	/* FD_ISSET need not be checked */
	fcntl(fd, F_SETFL, flags );
	if ((msg.msg_flags & (MSG_CTRUNC | MSG_OOB | MSG_ERRQUEUE)) != 0) {
		// To us, any of the above flags are a fatal error
		BT_ERR("MSG Flags errno: %d", errno);
		return -2;
	}

	if (ret >= 0 && data_fd) {
		BT_INFO("Connection received");
		socket_process_cmsg(&msg, data_fd);
	}

	return ret;
}

static int sock_wait_for_channel(int sock_fd)
{
	int readlen = -1;
	char buf[SOCK_INT_LEN];

	readlen = socket_read(sock_fd, buf, SOCK_INT_LEN, NULL);
	return getInt(buf, readlen);
}

static int sock_wait_for_connect_signal(int sock_fd,
		int *data_fd, bt_bdaddr_t *bd_addr)
{
	int readlen = -1;
	char buf[SOCK_CONNECT_INFO_LEN];
	int size = -1, channel = -1, status = -1;
	int len = 0;

	readlen = socket_read(sock_fd, buf, SOCK_CONNECT_INFO_LEN, data_fd);
	BT_DBG("Socket Read len: %d", readlen);
	if(readlen == 0) {
		BT_WARN("Listen stopped");
		return -1; /* This essentially means that the listen is stopped */
	}

	if(readlen != SOCK_CONNECT_INFO_LEN) {
		BT_ERR("Read length is not same as socket info length");
		return -2;
	}

	size = getShort(&buf[len], SOCK_SHORT_LEN);
	len += SOCK_SHORT_LEN;
	if(size != SOCK_CONNECT_INFO_LEN)
		return -3;

	getBdaddr(&buf[len], SOCK_BD_ADDR_LEN, bd_addr);len += SOCK_BD_ADDR_LEN;
	channel = getInt(&buf[len], SOCK_INT_LEN); len += SOCK_INT_LEN;
	status = getInt(&buf[len], SOCK_INT_LEN);

	BT_INFO("BTSOCK CONNECTION ESTABLISHED REMOTE Channel:%d, Status:%d",
			channel, status);
	return 0;
}

static int sock_wait_for_connection_setup(oal_client_info_t *p_oal_client_info)
{
	int channel = -1;
	int ret = -1;

	/* First, wait for channel number */
	channel = sock_wait_for_channel(p_oal_client_info->fd);
	if(channel < 0) {
		BT_ERR("ERROR, incorrect channel= %d", channel);
		return OAL_STATUS_INTERNAL_ERROR;
	}

	BT_INFO("client channel= %d", channel);

	/* Now, wait for connection signal */
	ret = sock_wait_for_connect_signal(p_oal_client_info->fd,
			NULL, (bt_bdaddr_t *)&p_oal_client_info->address);
	if (0 > ret) {
		BT_ERR("ERROR, sock_wait_for_connect_signal failed");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	return OAL_STATUS_SUCCESS;
}

/*
 * This function will be called only once as connection setup is done here
 * and then data will be received directly in application context using fd
 * passed in socket connection event.
 */
static gboolean sockclient_thread(GIOChannel *gio, GIOCondition cond, gpointer data)
{
	event_socket_client_conn_t *client_info_ev;
	oal_client_info_t *p_oal_client_info = (oal_client_info_t *)data;

	retv_if(p_oal_client_info == NULL, FALSE);
	retv_if(p_oal_client_info->fd < 0, FALSE);

	BT_DBG("Client fd= %d", p_oal_client_info->fd);

	/* This memory will be freed by event dispatcher */
	client_info_ev = g_new0(event_socket_client_conn_t, 1);
	client_info_ev->fd = p_oal_client_info->fd;
	client_info_ev->sock_type = p_oal_client_info->sock_type;
	memcpy(&client_info_ev->address, &p_oal_client_info->address, sizeof(bt_address_t));

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		BT_INFO("Client disconnected-0x%X (fd = %d)",
				cond, p_oal_client_info->fd);
		goto failed;
	}

	if (OAL_STATUS_SUCCESS == sock_wait_for_connection_setup(p_oal_client_info)) {
		BT_INFO("connection setup success");
		send_event_bda_trace(OAL_EVENT_SOCKET_OUTGOING_CONNECTED, client_info_ev,
				sizeof(event_socket_client_conn_t), &p_oal_client_info->address);
		goto done;
	}

	BT_ERR("ERROR, incorrect connection setup");

failed:
	remove_io_channel(p_oal_client_info->control_id, p_oal_client_info->control_io);
	send_event_bda_trace(OAL_EVENT_SOCKET_DISCONNECTED, client_info_ev,
			sizeof(event_socket_client_conn_t), &p_oal_client_info->address);
done:
	g_free(p_oal_client_info);
	return FALSE;
}

int socket_connect(oal_sock_type_t sock_type, oal_uuid_t *p_uuid, int channel, bt_address_t* bd)
{
	oal_client_info_t *p_oal_client_info = NULL;
	int sock_fd = -1;
	bdstr_t bdstr;

	API_TRACE("Socket connect: %s", bdt_bd2str(bd, &bdstr));

	CHECK_OAL_SOCKET_ENABLED();

	p_oal_client_info = g_new0(oal_client_info_t, 1);

	switch (sock_type) {
	case OAL_SOCK_RFCOMM:
		if(channel < 0 )
			socket_api->connect((const bt_bdaddr_t *)bd,
				BTSOCK_RFCOMM, p_uuid->uuid, 0, &sock_fd, 0);
		else
			socket_api->connect((const bt_bdaddr_t *)bd,
				BTSOCK_RFCOMM, NULL, channel, &sock_fd, 0);
		break;
	default:
		BT_ERR("Socket type: %d not supported");
	}

	if(sock_fd < 0) {
		BT_ERR("Bluetooth socket connect failed");
		return sock_fd;
	}

	BT_INFO("Bluetooth client socket created, sock_fd=%d", sock_fd);

	p_oal_client_info->fd = sock_fd;
	p_oal_client_info->sock_type = sock_type;
	memcpy(&p_oal_client_info->address, bd, sizeof(bt_address_t));
	p_oal_client_info->control_io = g_io_channel_unix_new(p_oal_client_info->fd);
	p_oal_client_info->control_id = g_io_add_watch(p_oal_client_info->control_io,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			sockclient_thread, p_oal_client_info);
	g_io_channel_set_close_on_unref(p_oal_client_info->control_io, FALSE);
	g_io_channel_unref(p_oal_client_info->control_io);

	BT_DBG("Client watch added");
	return sock_fd;
}

oal_status_t socket_enable()
{
	const bt_interface_t *blued_api;

	API_TRACE("Socket Init");

	blued_api = adapter_get_stack_interface();
	if(blued_api == NULL) {
		BT_ERR("Stack is not initialized");
		return OAL_STATUS_NOT_READY;
	}

	if(socket_api != NULL) {
		BT_WARN("Socket Interface is already initialized...");
		return OAL_STATUS_ALREADY_DONE;
	}

	socket_api = (const btsock_interface_t*)blued_api->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!socket_api){
		BT_ERR("OAL Socket failed to initialize");
		return OAL_STATUS_INTERNAL_ERROR;
	}

	BT_DBG("Socket successfully initiated");
	return OAL_STATUS_SUCCESS ;
}

oal_status_t socket_disable(void)
{

	API_TRACE("Socket Deinit");

	CHECK_OAL_SOCKET_ENABLED();
	socket_api = NULL;
	return OAL_STATUS_SUCCESS;
}

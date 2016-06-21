/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <glib.h>

#include "bluetooth-api.h"
#include "bt-internal-types.h"

#include "bt-service-common.h"
#include "bt-service-event.h"
#include "bt-service-event-manager.h"

#define MAX_DEVICES 100

struct uuid_def {
	char *uuid;
};

static struct uuid_def hid_uuids[] = {
	{ "00001124-0000-1000-8000-00805f9b34fb"	},
	{ "00001200-0000-1000-8000-00805f9b34fb"	},
};

static struct uuid_def tizen_mobile_uuids[] = {
	{ "00001800-0000-1000-8000-00805f9b34fb" },
	{ "00001801-0000-1000-8000-00805f9b34fb" },
	{ "0000110c-0000-1000-8000-00805f9b34fb" },
	{ "0000110a-0000-1000-8000-00805f9b34fb" },
	{ "00001132-0000-1000-8000-00805f9b34fb" },
	{ "00001133-0000-1000-8000-00805f9b34fb" },
	{ "0000112f-0000-1000-8000-00805f9b34fb" },
	{ "00001105-0000-1000-8000-00805f9b34fb" },
	{ "0000111f-0000-1000-8000-00805f9b34fb" },
	{ "00001112-0000-1000-8000-00805f9b34fb" },
};

static struct uuid_def mobile_uuids[] = {
	{ "00001105-0000-1000-8000-00805f9b34fb" },
	{ "0000110a-0000-1000-8000-00805f9b34fb" },
	{ "0000110c-0000-1000-8000-00805f9b34fb" },
	{ "00001112-0000-1000-8000-00805f9b34fb" },
	{ "00001115-0000-1000-8000-00805f9b34fb" },
	{ "00001116-0000-1000-8000-00805f9b34fb" },
	{ "0000111f-0000-1000-8000-00805f9b34fb" },
	{ "0000112d-0000-1000-8000-00805f9b34fb" },
	{ "0000112f-0000-1000-8000-00805f9b34fb" },
	{ "00001132-0000-1000-8000-00805f9b34fb" },
	{ "00001200-0000-1000-8000-00805f9b34fb" },
	{ "00001800-0000-1000-8000-00805f9b34fb" },
	{ "00001801-0000-1000-8000-00805f9b34fb" },
};

static struct uuid_def a2dp_only_uuids[] = {
	{ "0000110b-0000-1000-8000-00805f9b34fb" },
	{ "0000110c-0000-1000-8000-00805f9b34fb" },
	{ "0000110d-0000-1000-8000-00805f9b34fb" },
	{ "0000110e-0000-1000-8000-00805f9b34fb" },
};

static struct uuid_def headset_uuids[] = {
	{ "0000111e-0000-1000-8000-00805f9b34fb" },
	{ "00001108-0000-1000-8000-00805f9b34fb" },
	{ "0000110d-0000-1000-8000-00805f9b34fb" },
	{ "0000110b-0000-1000-8000-00805f9b34fb" },
	{ "0000110e-0000-1000-8000-00805f9b34fb" },
};

struct bt_sample_dev_info_t {
	int rssi;
	int class;
	char *address;
	char *name;
	struct uuid_def *uuids;
	unsigned int uuid_count;
	gboolean paired;
	bluetooth_connected_link_t connected;
	gboolean trust;
	char *manufacturer_data;
	int manufacturer_data_len;
	guchar addr_type;
};

static struct bt_sample_dev_info_t sample_devices[] = {
	{ -69, 2360344, "00:1B:66:01:23:1C", "Sennheiser P", a2dp_only_uuids, sizeof(a2dp_only_uuids) / sizeof(a2dp_only_uuids[0]), FALSE, 0x00, FALSE, NULL, 0, BDADDR_BREDR},
	{ -70, 5898764, "A8:7C:01:EF:3C:73", "Galaxy S6 edge", mobile_uuids, sizeof(mobile_uuids) / sizeof(mobile_uuids[0]), FALSE, 0x00, FALSE, NULL, 0, BDADDR_BREDR},
	{ -58, 2360324, "50:C9:71:56:30:5A", "Jabra SUPREME a4.18.0", headset_uuids, sizeof(headset_uuids) / sizeof(headset_uuids[0]), FALSE, 0x00, FALSE, NULL, 0, BDADDR_BREDR},
	{ -75, 5767692, "AC:5A:14:24:B9:33", "Tizen 3.0 Mobile", tizen_mobile_uuids, sizeof(tizen_mobile_uuids) / sizeof(tizen_mobile_uuids[0]), FALSE, 0x00, FALSE, NULL, 0, BDADDR_BREDR},
	{ -60, 9600, "34:15:9E:D4:83:B3", "Apple Wireless Mouse", hid_uuids, sizeof(hid_uuids) / sizeof(hid_uuids[0]), FALSE, 0x00, FALSE, NULL, 0, BDADDR_BREDR},
};

typedef struct {
	int event_id;
	guint timer_id;
} bt_timer_info_t;

static GSList *timer_list = NULL;
static int sample_device_num = sizeof(sample_devices) / sizeof(sample_devices[0]);

void _bt_create_event_timer(int event_id, int interval, void *event_cb, void *user_data)
{
	bt_timer_info_t *event_info = NULL;

	BT_DBG("+");

	event_info = g_malloc0(sizeof(bt_timer_info_t));
	/* Fix : NULL_RETURNS */
	ret_if(event_info == NULL);

	_bt_delete_event_timer(event_id);

	event_info->event_id = event_id;

	/* Assign a timer id  */
	event_info->timer_id = g_timeout_add(interval, (GSourceFunc)event_cb, (gpointer)user_data);

	BT_DBG("Create event timer. event id: %d, timer id: %d", event_id, event_info->timer_id);

	timer_list = g_slist_append(timer_list, event_info);

	BT_DBG("-");
}

void _bt_delete_event_timer(int event_id)
{
	GSList *l;

	BT_DBG("+");

	BT_DBG("Remove event timer. event id: %d", event_id);

	for (l = timer_list; l != NULL; l = g_slist_next(l)) {
		bt_timer_info_t *info = l->data;
		if (info == NULL)
			continue;

		if (info->event_id == event_id) {
			BT_DBG("Found the event id");
			/* Remove the previous timer */
			g_source_remove(info->timer_id);
			timer_list = g_slist_remove(timer_list, info);
			g_free(info);
			break;
		}
	}

	BT_DBG("-");
}

void _bt_delete_all_event_timer(void)
{
	GSList *l;

	BT_DBG("+");

	for (l = timer_list; l != NULL; l = g_slist_next(l)) {
		bt_timer_info_t *info = l->data;
		if (info == NULL)
			continue;

		g_source_remove(info->timer_id);
		timer_list = g_slist_remove(timer_list, info);
		g_free(info);
	}

	g_slist_free(timer_list);
	timer_list = NULL;

	BT_DBG("-");
}

int _bt_get_sample_device_number(void)
{
	return sample_device_num;
}

bt_remote_dev_info_t *_bt_get_sample_device(int index)
{
	bt_remote_dev_info_t *dev_info;

	dev_info = g_malloc0(sizeof(bt_remote_dev_info_t));
	retv_if(dev_info == NULL, NULL);

	dev_info->rssi = sample_devices[index].rssi;
	dev_info->class = sample_devices[index].class;
	dev_info->paired = sample_devices[index].paired;
	dev_info->connected = sample_devices[index].connected;
	dev_info->trust = sample_devices[index].trust;
	dev_info->addr_type = sample_devices[index].addr_type;

	dev_info->name = g_strdup(sample_devices[index].name);
	dev_info->address = g_strdup(sample_devices[index].address);

	dev_info->uuid_count = sample_devices[index].uuid_count;

	if (dev_info->uuid_count > 0) {
		int i;
		dev_info->uuids = g_malloc0(sizeof(char *) * dev_info->uuid_count);

		for (i = 0; i < dev_info->uuid_count; i++) {
			BT_DBG("uuid[%d]: %s", i, sample_devices[index].uuids[i]);
			dev_info->uuids[i] = g_strdup(sample_devices[index].uuids[i].uuid);
		}
	}

	dev_info->manufacturer_data_len = sample_devices[index].manufacturer_data_len;

	if (dev_info->manufacturer_data_len > 0) {
		dev_info->manufacturer_data = g_malloc0(dev_info->manufacturer_data_len);
		if (dev_info->manufacturer_data)
			memcpy(dev_info->manufacturer_data, sample_devices[index].manufacturer_data,
					dev_info->manufacturer_data_len);
	}

	return dev_info;
}


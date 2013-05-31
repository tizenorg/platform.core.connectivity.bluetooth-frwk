#include <stdlib.h>
#include <glib.h>
#include <glib-object.h>
#include "common.h"
#include "bluez.h"

#define MOUSE "00_1F_20_24_9B_9E"
#define MY_IPHONE "F0_DC_E2_7F_41_3D"

GMainLoop *loop;

bluez_adapter_t *adapter;
bluez_device_t *device;

gboolean idle_work(gpointer user_data)
{
	static uint times = 0;

	times++;

	device = bluez_adapter_get_device(adapter, MY_IPHONE);
	if (device) {
		DBG("Pair device %p", device);
		bluez_adapter_remove_device(adapter, device);
		bluez_device_pair(device);
	}

	return FALSE;
}

int main(int argc, char **argv)
{
	g_type_init();

	loop = g_main_loop_new(NULL, FALSE);

	bluez_lib_init();

	adapter = bluez_adapter_get_adapter("hci0");
	if (adapter != NULL) {

		bluez_adapter_set_powered(adapter, 1);

		bluez_adapter_start_discovery(adapter); 

		g_timeout_add(2000, idle_work, NULL);

	} else
		DBG("Can't get adapter");

	g_main_loop_run(loop);

	bluez_lib_deinit();

	g_printerr("Successfully completed %s\n", argv[0]);

	return 0;
}

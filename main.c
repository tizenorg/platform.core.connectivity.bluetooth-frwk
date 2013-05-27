#include <stdlib.h>
#include <glib.h>
#include <glib-object.h>
#include "common.h"
GMainLoop *loop;

void *adapter;

int main(int argc, char **argv)
{
	int ret;

	g_type_init();

	loop = g_main_loop_new(NULL, FALSE);

	bluez_lib_init();

	adapter = bluez_adapter_get_adapter("hci0");
	if (adapter != NULL) {
		bluez_adapter_set_powered(adapter, 0);
//		bluez_adapter_start_discovery(adapter);
	}

	g_main_loop_run(loop);

	bluez_lib_deinit();

	g_printerr("Successfully completed %s\n", argv[0]);

	return 0;
}

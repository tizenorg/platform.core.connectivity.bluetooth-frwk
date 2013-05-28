#include <stdlib.h>
#include <glib.h>
#include <glib-object.h>
#include "common.h"
GMainLoop *loop;

void *adapter;

gboolean idle_work(gpointer user_data)
{

	static uint times = 0;

	gboolean powered;

	times++;

	if (!bluez_adapter_get_property_powered(adapter, &powered)) {
		DBG("adapter hci0 state %d", powered);

		bluez_adapter_set_powered(adapter, !powered);
	} else
		ERROR("get adapter hci0 state error");

	if (times > 10) {
		bluez_lib_deinit();
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char **argv)
{
	int ret;
	gboolean powered;

	g_type_init();

	loop = g_main_loop_new(NULL, FALSE);

	bluez_lib_init();
	adapter = bluez_adapter_get_adapter("hci0");
	if (adapter != NULL) {

		bluez_adapter_set_powered(adapter, 1);

		idle_work(NULL);

		g_timeout_add(2000, idle_work, NULL);

	}

	g_main_loop_run(loop);

	bluez_lib_deinit();

	g_printerr("Successfully completed %s\n", argv[0]);

	return 0;
}

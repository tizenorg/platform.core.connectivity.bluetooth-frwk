#include <stdlib.h>
#include <glib.h>
#include <glib-object.h>
#include "common.h"
#include "bluez.h"

GMainLoop *loop;

bluez_adapter_t *adapter;

static void adapter_alias_cb (bluez_adapter_t *adapter, const gchar **alias, gpointer user_data)
{
	DBG("adapter 0x%p changed to %s", adapter, *alias);
}

static void adapter_powered_cb (bluez_adapter_t *adapter,
					gboolean powered,
					gpointer user_data)
{
	DBG("adapter 0x%p changed to %d", adapter, powered);
}

gboolean idle_work(gpointer user_data)
{

	static uint times = 0;
	const gchar *alias;
	gboolean powered;

	times++;

	if (!bluez_adapter_get_property_powered(adapter, &powered)) {
		DBG("adapter hci0 state %d", powered);

		bluez_adapter_set_powered(adapter, !powered);
	} else
		ERROR("get adapter hci0 state error");



	if (!bluez_adapter_get_property_alias(adapter, &alias)) {
		gchar *new_alias = g_strdup(alias);

		DBG("adapter alias %s", alias);

		new_alias[0] = new_alias[0] - 1;

		bluez_adapter_set_alias(adapter, new_alias);
	}

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
		bluez_adapter_set_alias_changed_cb(adapter,
						adapter_alias_cb, NULL);
//		bluez_adapter_set_powered_changed_cb(adapter,
//						adapter_powered_cb, NULL);
		bluez_adapter_set_powered(adapter, 1);

		idle_work(NULL);

		g_timeout_add(2000, idle_work, NULL);

	}

	g_main_loop_run(loop);

	bluez_lib_deinit();

	g_printerr("Successfully completed %s\n", argv[0]);

	return 0;
}

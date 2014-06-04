
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "bluetooth.h"

void onnamechanged(char* name, void* userdata)
{
       DBG( ": onnamechanged with name %s!!!", name);
}

int main (int argc, char* argv[])
{
	if (argc < 1) {
		DBG("Failed : it needs at least an argument !!!");
	}

	char* name;
	bt_initialize();
	sleep(4);
	bt_adapter_state_e state = BT_ADAPTER_DISABLED;
	bt_adapter_get_state(&state);
	sleep(3);
	DBG("state = %d", state);


       if(bt_adapter_set_name_changed_cb(onnamechanged, NULL) != BT_ERROR_NONE) {
        	DBG( "bt_adapter_set_name_changed_cb() failed");
       }
       DBG( ": onnamechanged callback registered.");
	sleep(3);
	bt_adapter_set_name(argv[0]);
	sleep(3);
	bt_adapter_get_name(&name);
	DBG ("get name returns : %s ",name);
	sleep(4);
	return EXIT_SUCCESS;

}

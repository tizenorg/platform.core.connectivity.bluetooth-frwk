PKG_CONFIG_PATH=/usr/lib/pkgconfig
export PKG_CONFIG_PATH
CC ?= gcc

###################################################
# add your TestCase List Here
#
# e.g.,
# TC1 = utc_frameworkName_apiName_func
# TC2 = utc_ApplicationLib_recurGetDayOfWeek_func
TARGETS = uts_bluetooth_register_callback \
uts_bluetooth_check_adapter \
uts_bluetooth_enable_adapter \
uts_bluetooth_authorize_device \
uts_bluetooth_start_discovery \
uts_bluetooth_cancel_discovery \
uts_bluetooth_bond_device \
uts_bluetooth_search_service \
uts_bluetooth_cancel_service_search \
uts_bluetooth_get_bonded_device_list \
uts_bluetooth_unbond_device \
uts_bluetooth_cancel_bonding \
uts_bluetooth_get_discoverable_mode \
uts_bluetooth_get_local_address \
uts_bluetooth_get_local_name \
uts_bluetooth_get_remote_device \
uts_bluetooth_set_discoverable_mode \
uts_bluetooth_set_local_name \
uts_bluetooth_is_discovering \
uts_bluetooth_rfcomm_create_socket \
uts_bluetooth_rfcomm_remove_socket \
uts_bluetooth_rfcomm_listen \
uts_bluetooth_rfcomm_connect \
uts_bluetooth_rfcomm_disconnect \
uts_bluetooth_rfcomm_write \
uts_bluetooth_disable_adapter
	
###################################################
# add your Package Config Info Here
#
# e.g.,
# PKGS=calendar
PKGS=bluetooth-api glib-2.0

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

###################################################
# Modify here 
# depending on the Test Case you want to build
# 
# e.g.,
# TCLIST = $(TC1) $(TC2)


all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGETS)
	rm -f tet_captured
	rm -f tet_lock
	rm -f *~

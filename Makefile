CFLAGS := `pkg-config --cflags  dbus-1 glib-2.0 gio-2.0 gthread-2.0`
LDFLAGS := `pkg-config --libs dbus-1 glib-2.0 gio-2.0 gthread-2.0`

bluez-lib-test: main.o bluez-lib.o
	$(CC) $^ -o $@ $(LDFLAGS)

bluez-lib.o: bluez-lib.c
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

#bt-call-engine-glue.h: bt_call_engine.xml
#	dbus-binding-tool --prefix=bt_call_engine --mode=glib-server --output=bt-call-engine-glue.h bt_call_engine.xml

clean:
	rm *.o bluez-lib-test

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(bt-service C)

SET(SRCS
marshal.c
bt-service-main.c
bt-service-event-sender.c
bt-service-event-receiver.c
bt-service-common.c
bt-service-util.c
bt-service-adapter.c
bt-service-device.c
bt-service-hid.c
bt-service-network.c
bt-service-audio.c
bt-service-oob.c
bt-service-obex-agent.c
bt-service-opp-client.c
bt-service-obex-server.c
bt-service-rfcomm-client.c
bt-service-rfcomm-server.c
bt-service-avrcp.c
bt-request-handler.c
bt-service-agent.c
bt-service-gap-agent.c
)

IF(LIBNOTIFY_SUPPORT)
LIST(APPEND SRCS
bt-popup.c
)
ENDIF(LIBNOTIFY_SUPPORT)

IF(LIBNOTIFICATION_SUPPORT)
LIST(APPEND SRCS
bt-service-agent-notification.c
)
ENDIF(LIBNOTIFICATION_SUPPORT)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)

IF(LIBNOTIFY_SUPPORT)
	pkg_check_modules(service_pkgs REQUIRED vconf aul vconf dbus-glib-1 capi-network-tethering libprivilege-control status alarm-service notification security-server libnotify gdk-pixbuf-2.0 gtk+-3.0)
ELSE(LIBNOTIFY_SUPPORT)
	pkg_check_modules(service_pkgs REQUIRED vconf aul vconf syspopup-caller dbus-glib-1 capi-network-tethering libprivilege-control status alarm-service notification security-server)
ENDIF(LIBNOTIFY_SUPPORT)

FOREACH(flag ${service_pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag} -Wall")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")
SET(APP_SYSCONFDIR /opt/var/lib/bluetooth)

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DTARGET")
	MESSAGE("add -DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

FIND_PROGRAM(MARSHALTOOL NAMES glib-genmarshal)
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${CMAKE_CURRENT_SOURCE_DIR}/marshal.list --header > ${CMAKE_CURRENT_SOURCE_DIR}/include/marshal.h")
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${CMAKE_CURRENT_SOURCE_DIR}/marshal.list --body > ${CMAKE_CURRENT_SOURCE_DIR}/marshal.c")

FIND_PROGRAM(DBUS_BINDING_TOOL NAMES dbus-binding-tool)
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=bt ${CMAKE_CURRENT_SOURCE_DIR}/bt-request-service.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/include/bt-service-method.h")
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=bt_obex_agent ${CMAKE_CURRENT_SOURCE_DIR}/bt-service-obex-agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/include/bt-obex-agent-method.h")
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=gap_agent ${CMAKE_CURRENT_SOURCE_DIR}/bt-service-gap-agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/include/bt-gap-agent-method.h")
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=bt_media_agent ${CMAKE_CURRENT_SOURCE_DIR}/bt-service-media-agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/include/bt-media-agent-method.h")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DVENDOR=\"${APP_VENDOR}\"")
ADD_DEFINITIONS("-DAPPNAME=\"${APP_NAME}\"")
ADD_DEFINITIONS("-DAPP_DIR=\"${APP_DIR}\"")
ADD_DEFINITIONS("-DAPP_LOCALEDIR=\"${APP_LOCALEDIR}\"")
ADD_DEFINITIONS("-DAPP_SYSCONFDIR=\"${APP_SYSCONFDIR}\"")

IF(LIBNOTIFY_SUPPORT OR LIBNOTIFICATION_SUPPORT)
	ADD_DEFINITIONS("-DDATA_DIR_ICON=\"${SHARE_INSTALL_PREFIX}\"")
	MESSAGE("Icon used for notification is : ${SHARE_INSTALL_PREFIX}/icons/default/bt-icon.png")
ENDIF(LIBNOTIFY_SUPPORT OR LIBNOTIFICATION_SUPPORT)

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})

# to permit usage of bluetooth_cancel_bonding in bt-popup.c. This build bluetooth-api first.
IF(LIBNOTIFY_SUPPORT)
	ADD_DEPENDENCIES(${PROJECT_NAME} bluetooth-api)
	TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${service_pkgs_LDFLAGS} bluetooth-api)
ELSE(LIBNOTIFY_SUPPORT)
	TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${service_pkgs_LDFLAGS})
ENDIF(LIBNOTIFY_SUPPORT)


IF(NOT MULTI_USER_SUPPORT)
	INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.projectx.bt.service DESTINATION share/dbus-1/system-services)
ENDIF(NOT MULTI_USER_SUPPORT)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/auto-pair-blacklist DESTINATION /opt/var/lib/bluetooth)

# install booting script
IF(NOT MULTI_USER_SUPPORT)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service DESTINATION /etc/rc.d/init.d)
ENDIF(NOT MULTI_USER_SUPPORT)

IF(MULTI_USER_SUPPORT)
	install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service_user.conf DESTINATION /etc/dbus-1/system.d)
ELSE(MULTI_USER_SUPPORT)
	install (FILES ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service.conf DESTINATION /etc/dbus-1/system.d)
ENDIF(MULTI_USER_SUPPORT)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})


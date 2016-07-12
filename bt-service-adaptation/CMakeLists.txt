CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(bt-service C)

#Include Source files for bluetooth service common files only
SET(SRCS
marshal.c
./services/bt-service-main.c
./services/bt-service-common.c
./services/bt-service-event-sender.c
./services/bt-service-util.c
./services/bt-request-handler.c
./services/adapter/bt-service-core-adapter.c
./services/device/bt-service-core-device.c
./services/bt-service-event-receiver.c
./services/bt-service-dpm.c
./services/bt-service-agent-util.c
./services/hid/bt-service-hidhost.c
./services/socket/bt-service-socket.c
)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
        SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/services/include)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../bt-oal/include)
LINK_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../bt-oal)

SET(PKG_MODULES
        vconf
        aul
        vconf
        syspopup-caller
        dbus-glib-1
        dbus-1
        gio-2.0
        alarm-service
        capi-content-mime-type
        capi-network-connection
        pkgmgr
        cynara-client
        cynara-creds-gdbus
        eventsystem
        storage
)

IF("$ENV{CFLAGS}" MATCHES "-DTIZEN_NETWORK_TETHERING_ENABLE")
SET(PKG_MODULES ${PKG_MODULES}
        capi-network-tethering
)
ENDIF()

INCLUDE(FindPkgConfig)
pkg_check_modules(service_pkgs REQUIRED ${PKG_MODULES})

FOREACH(flag ${service_pkgs_CFLAGS})
        SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag} -Wall")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall")
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

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DVENDOR=\"${APP_VENDOR}\"")
ADD_DEFINITIONS("-DAPPNAME=\"${APP_NAME}\"")
ADD_DEFINITIONS("-DAPP_DIR=\"${APP_DIR}\"")
ADD_DEFINITIONS("-DAPP_LOCALEDIR=\"${APP_LOCALEDIR}\"")
ADD_DEFINITIONS("-DAPP_SYSCONFDIR=\"${APP_SYSCONFDIR}\"")
ADD_DEFINITIONS("-DHPS_FEATURE")
ADD_DEFINITIONS("-DTIZEN_DPM_ENABLE")

IF(LIBNOTIFY_SUPPORT OR LIBNOTIFICATION_SUPPORT)
        ADD_DEFINITIONS("-DDATA_DIR_ICON=\"${SHARE_INSTALL_PREFIX}\"")
        MESSAGE("Icon used for notification is : ${SHARE_INSTALL_PREFIX}/icons/default/bt-icon.png")
ENDIF(LIBNOTIFY_SUPPORT OR LIBNOTIFICATION_SUPPORT)

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${service_pkgs_LDFLAGS} -lbt-oal)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.projectx.bt.service DESTINATION share/dbus-1/system-services)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/auto-pair-blacklist DESTINATION /opt/var/lib/bluetooth/)

# install booting script
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service.conf.in ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service.conf)

IF (TIZEN_WEARABLE)
        INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/wearable/stack_info DESTINATION /usr/etc/bluetooth/)
ELSE ()
        INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mobile/stack_info DESTINATION /usr/etc/bluetooth/)
ENDIF (TIZEN_WEARABLE)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-service.conf DESTINATION /etc/dbus-1/system.d)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} -ldl)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})

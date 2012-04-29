CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(bluetooth-agent C)

SET(SRCS bluetooth-agent.c bluetooth-agent-cb.c marshal.c sc_core_agent.c)
SET(APP_VENDOR samsung)
SET(APP_NAME bluetooth-agent)
SET(APP_DIR /usr/bin)
SET(APP_LOCALEDIR /usr/share/locale)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED vconf aul syspopup-caller contacts-service dbus-glib-1 msg-service email-service)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

FIND_PROGRAM(UNAME NAMES uname)
EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DTARGET")
	MESSAGE("add -DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

FIND_PROGRAM(MARSHALTOOL NAMES glib-genmarshal)
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${CMAKE_CURRENT_SOURCE_DIR}/marshal.list --header > ${CMAKE_CURRENT_SOURCE_DIR}/marshal.h")
EXEC_PROGRAM("${MARSHALTOOL}" ARGS "--prefix=marshal ${CMAKE_CURRENT_SOURCE_DIR}/marshal.list --body > ${CMAKE_CURRENT_SOURCE_DIR}/marshal.c")

FIND_PROGRAM(DBUS_BINDING_TOOL NAMES dbus-binding-tool)
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=sc_core_agent ${CMAKE_CURRENT_SOURCE_DIR}/sc_core_agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/sc_core_agent_glue.h")
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=bluetooth_obex_agent ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_obex_agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_obex_agent_glue.h")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DVENDOR=\"${APP_VENDOR}\"")
ADD_DEFINITIONS("-DAPPNAME=\"${APP_NAME}\"")
ADD_DEFINITIONS("-DAPP_DIR=\"${APP_DIR}\"")
ADD_DEFINITIONS("-DAPP_LOCALEDIR=\"${APP_LOCALEDIR}\"")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/org.bluez.frwk_agent.service DESTINATION share/dbus-1/services)

# install booting script
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth-frwk-agent DESTINATION /etc/rc.d/init.d)

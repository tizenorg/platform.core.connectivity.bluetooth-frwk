CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(bluetooth-api C)

SET(SRCS bluetooth-api-common.c marshal.c bluetooth-gap-api.c bluetooth-sdp-api.c bluetooth-rfcomm-api.c bluetooth-network-api.c bluetooth-hdp-api.c obex-agent.c bluetooth-opc-api.c 
bluetooth-obex-server-api.c bluetooth-hid-api.c)
SET(HEADERS bluetooth-api.h bluetooth-hid-api.h)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.0)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

INCLUDE(FindPkgConfig)
pkg_check_modules(packages REQUIRED dlog dbus-glib-1 gobject-2.0 gmodule-2.0 vconf 
libxml-2.0 mdm syspopup-caller)

FOREACH(flag ${packages_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g ")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

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
EXEC_PROGRAM("${DBUS_BINDING_TOOL}" ARGS "--prefix=obex_agent ${CMAKE_CURRENT_SOURCE_DIR}/obex-agent.xml --mode=glib-server --output=${CMAKE_CURRENT_SOURCE_DIR}/obex-agent-glue.h")

#SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${SRCS})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES VERSION ${VERSION})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${packages_LDFLAGS})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.pc.in ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc DESTINATION lib/pkgconfig)

FOREACH(hfile ${HEADERS})
	INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${hfile} DESTINATION include/bluetooth-api)
ENDFOREACH(hfile)


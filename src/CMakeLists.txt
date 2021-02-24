cmake_minimum_required(VERSION 2.6)
PROJECT(babeld-utils)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-unknown-warning-option -Wno-format-truncation)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES main.c)

SET(LIBS
        ubox ubus json-c blobmsg_json owipcalc)

ADD_EXECUTABLE(babeld-utils ${SOURCES})

TARGET_LINK_LIBRARIES(babeld-utils ${LIBS})

INSTALL(TARGETS babeld-utils
        RUNTIME DESTINATION /usr/sbin/)

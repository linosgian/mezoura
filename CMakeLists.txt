cmake_minimum_required(VERSION 3.10)

PROJECT(mezoura C)

ADD_DEFINITIONS(-Os -Wall -Wno-unknown-warning-option -Wno-array-bounds -Wno-format-truncation -Werror --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

find_library(bpf NAMES bpf)
ADD_EXECUTABLE(mezoura mezoura.c loader.c interface.c prometheus.c)
TARGET_LINK_LIBRARIES(mezoura uci ${bpf} ubox)

INSTALL(TARGETS mezoura
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

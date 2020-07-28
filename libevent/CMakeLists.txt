cmake_minimum_required(VERSION 2.8)

message (STATUS "lib src dir = ${PROJECT_SOURCE_DIR}")
message (STATUS "lib bin dir = ${PROJECT_BINARY_DIR}")

set(LIBRARY_OUTPUT_PATH "${PROJECT_BINARY_DIR}/lib")
aux_source_directory(${PROJECT_SOURCE_DIR}/libevent LIBEVENT_SRC)

add_library(event STATIC ${LIBEVENT_SRC})
# set_target_properties (event_static PROPERTIES OUTPUT_NAME "event")

install (TARGETS event DESTINATION lib)
# install (FILES ${PROJECT_SOURCE_DIR}/libevent/event.h DESTINATION include)

cmake_minimum_required(VERSION 2.8)
project (router_config_learning_tool)

message (STATUS "src dir = ${PROJECT_SOURCE_DIR}")
message (STATUS "bin dir = ${PROJECT_BINARY_DIR}")
# message (STATUS "cmake dir = ${CMAKE_INCLUDE_PATH}, ${CMAKE_LIBRARY_PATH}")

add_subdirectory ("libevent")


## src dir
set(EXECUTABLE_OUTPUT_PATH "${PROJECT_BINARY_DIR}/bin")
add_compile_options(-Wall -Wno-pointer-sign)
aux_source_directory(${PROJECT_SOURCE_DIR}/src MAIN_SRC)
include_directories("${PROJECT_SOURCE_DIR}/src")
include_directories("${PROJECT_SOURCE_DIR}/libevent")
message (STATUS "MAIN_SRC = ${MAIN_SRC}")


# find_library(EVENT_LIB_NAME event HINTS ${PROJECT_BINARY_DIR}/lib)
# message (STATUS "EVENT_LIB_NAME = ${EVENT_LIB_NAME}")
set(EVENT_LIB_NAME "event")
link_directories("${PROJECT_BINARY_DIR}/lib")

add_executable(router_config_learning_tool ${MAIN_SRC})
install (TARGETS router_config_learning_tool DESTINATION bin)

target_link_libraries(router_config_learning_tool ${EVENT_LIB_NAME})




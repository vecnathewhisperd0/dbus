cmake_minimum_required(VERSION 3.0)

if(COMMAND cmake_policy)
    cmake_policy(SET CMP0074 NEW)
endif()

project(DBus1test)
find_package(DBus1 CONFIG)

if(NOT DBus1_VERSION OR NOT CHECK_VERSION OR NOT DBus1_VERSION VERSION_EQUAL CHECK_VERSION)
    message(FATAL_ERROR "version mismatch actual '${DBus1_VERSION}' expected '${CHECK_VERSION}'")
endif()

add_executable(mytest test.c)
target_link_libraries(mytest dbus-1)
install(TARGETS mytest DESTINATION bin)

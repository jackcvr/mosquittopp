cmake_minimum_required(VERSION 3.18)

project(MosquittoppTest CXX)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(LIBMOSQUITTO_VERSION "2.0.11")

function(add_exe name src std)
    add_executable(${name} ${src})
    target_compile_features(${name} PRIVATE cxx_std_${std})
    target_compile_options(${name} PRIVATE -Os -pedantic -Wall -Wextra -U_LIBCPP_ENABLE_CXX17_REMOVED_UNEXPECTED_FUNCTIONS)
endfunction()

include(cmake/CPM.cmake)

# C++ wrapper
CPMAddPackage(
    NAME mosquittopp
    SOURCE_DIR ..
)

# cJSON fix for libmosquitto
find_package(PkgConfig REQUIRED)
pkg_check_modules(libcjson REQUIRED libcjson)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/include/cjson")
file(COPY "/usr/include/cjson/cJSON.h" DESTINATION "${CMAKE_BINARY_DIR}/include/cjson")
include_directories("${CMAKE_BINARY_DIR}/include")

# TODO: install cjson via CPM for debian image

# libmosquitto (static)
CPMAddPackage(
    NAME libmosquitto
    GITHUB_REPOSITORY eclipse-mosquitto/mosquitto
    VERSION 2.1.2
    OPTIONS
        "WITH_LIB_CPP OFF"
        "WITH_CLIENTS OFF"
        "WITH_BROKER OFF"
        "WITH_APPS OFF"
        "WITH_PLUGINS OFF"
        "WITH_DOCS OFF"
        "WITH_WEBSOCKETS OFF"
        "WITH_CTRL_SHELL OFF"
        "WITH_TESTS OFF"
        "WITH_LTO OFF"
        "WITH_TLS OFF"
        "OPENSSL_USE_STATIC_LIBS ON"
        "WITH_BUNDLED_DEPS ON"
        "WITH_STATIC_LIBRARIES ON"
        "WITH_SHARED_LIBRARIES ON"
        "WITH_PIC ON"
        "CJSON_LIBRARY /usr/lib/libcjson.a"  # alpine hardcoded path
)
if(libmosquitto_ADDED)
    target_include_directories(libmosquitto_static PRIVATE
        "${libmosquitto_SOURCE_DIR}/deps"
        "${libmosquitto_SOURCE_DIR}/libcommon"
    )
    include_directories("${libmosquitto_SOURCE_DIR}/include")
    target_compile_definitions(libmosquitto_common PRIVATE HAVE_GETRANDOM=1)
    target_compile_options(libmosquitto_common PRIVATE
        "$<$<COMPILE_LANGUAGE:C>:-include>"
        "$<$<COMPILE_LANGUAGE:C>:sys/random.h>"
    )
endif()
add_exe(main_static main.cpp 23)
target_link_libraries(main_static PRIVATE mosquittopp libmosquitto_static)
target_link_options(main_static PRIVATE -static)


# libmosquitto (dynamic pre-installed)
find_package(PkgConfig REQUIRED)
pkg_check_modules(libmosquitto REQUIRED IMPORTED_TARGET libmosquitto>=${LIBMOSQUITTO_VERSION})
add_exe(main_dynamic main.cpp 23)
target_link_libraries(main_dynamic PRIVATE mosquittopp PkgConfig::libmosquitto)

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

# cJSON (static)
set(CMAKE_C_STANDARD 99 CACHE STRING "" FORCE)
CPMAddPackage(
    NAME cjson
    GITHUB_REPOSITORY DaveGamble/cJSON
    VERSION 1.7.19
    OPTIONS
        "BUILD_SHARED_AND_STATIC_LIBS ON"
        "ENABLE_CJSON_TEST OFF"
)
if(cjson_ADDED)
    file(MAKE_DIRECTORY "${cjson_SOURCE_DIR}/cjson")
    file(COPY "${cjson_SOURCE_DIR}/cJSON.h" DESTINATION "${cjson_SOURCE_DIR}/cjson")
    include_directories("${cjson_SOURCE_DIR}")
    set(CJSON_DIR "${cjson_BINARY_DIR}" CACHE PATH "" FORCE)
    add_library(cJSON STATIC IMPORTED GLOBAL)
    set_target_properties(cJSON PROPERTIES
        IMPORTED_LOCATION "${cjson_BINARY_DIR}/libcjson.a"
        INTERFACE_INCLUDE_DIRECTORIES "${cjson_SOURCE_DIR}"
    )
endif()

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
        "WITH_BUNDLED_DEPS ON"
        "WITH_STATIC_LIBRARIES ON"
        "WITH_PIC ON"
)
if(libmosquitto_ADDED)
    add_dependencies(libmosquitto_static cjson)
    if(TARGET libmosquitto)
        add_dependencies(libmosquitto cjson)
    endif()
    target_compile_definitions(libmosquitto_common PRIVATE HAVE_GETRANDOM=1)
    target_compile_options(libmosquitto_common PRIVATE
        "$<$<COMPILE_LANGUAGE:C>:-include>"
        "$<$<COMPILE_LANGUAGE:C>:sys/random.h>"
    )
    target_include_directories(libmosquitto_static PRIVATE "${libmosquitto_SOURCE_DIR}/deps")
    target_include_directories(libmosquitto_static INTERFACE "${libmosquitto_SOURCE_DIR}/include")
endif()
add_exe(main_static main.cpp 23)
target_link_libraries(main_static PRIVATE mosquittopp libmosquitto_static)
target_link_options(main_static PRIVATE -static)


# libmosquitto (dynamic pre-installed)
find_package(PkgConfig REQUIRED)
pkg_check_modules(libmosquitto REQUIRED IMPORTED_TARGET libmosquitto>=${LIBMOSQUITTO_VERSION})
add_exe(main_dynamic main.cpp 23)
target_link_libraries(main_dynamic PRIVATE mosquittopp PkgConfig::libmosquitto)

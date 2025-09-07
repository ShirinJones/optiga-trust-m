cmake_minimum_required(VERSION 3.16)

set(MBEDTLS_USER_CONFIG_FILE "${CMAKE_SOURCE_DIR}/main/mbedtls_user_config.h" CACHE INTERNAL "mbedtls user config file")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(optiga_ecdh_demo)
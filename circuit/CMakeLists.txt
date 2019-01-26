cmake_minimum_required(VERSION 3.8)
project(ethsnarks-hashpreimage)
add_subdirectory(../ethsnarks ../.build/ethsnarks EXCLUDE_FROM_ALL)

find_package(OpenSSL REQUIRED)

add_library(x_hashpreimage SHARED hashpreimage.cpp)
target_link_libraries(x_hashpreimage ethsnarks_common OpenSSL::Crypto)
set_property(TARGET x_hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(x_hashpreimage_cli hashpreimage_cli.cpp)
target_link_libraries(x_hashpreimage_cli ethsnarks_common OpenSSL::Crypto)

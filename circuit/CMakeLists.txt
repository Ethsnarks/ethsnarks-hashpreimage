cmake_minimum_required(VERSION 3.8)
project(ethsnarks-hashpreimage)
add_subdirectory(../ethsnarks ../.build/ethsnarks EXCLUDE_FROM_ALL)

find_package(OpenSSL REQUIRED)

add_library(hashpreimage SHARED hashpreimage.cpp)
target_link_libraries(hashpreimage ethsnarks_common OpenSSL::Crypto)
set_property(TARGET hashpreimage PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(hashpreimage_cli hashpreimage_cli.cpp)
target_link_libraries(hashpreimage_cli ethsnarks_common OpenSSL::Crypto)

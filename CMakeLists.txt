cmake_minimum_required(VERSION 3.16)
project(Pinata VERSION 3.2 LANGUAGES C ASM)

if(NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "Setting CMAKE_BUILD_TYPE to MinSizeRel")
    set(CMAKE_BUILD_TYPE MinSizeRel)
endif()

add_subdirectory(src)

cmake_minimum_required(VERSION 3.21)
project(spacefssimc C)

set(CMAKE_C_STANDARD 23)

add_executable(spacefssimc main.c SpaceFS/spacefs_basic.c SpaceFS/Internal/spacefs_internal_api.c)


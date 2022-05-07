cmake_minimum_required(VERSION 3.00)
project(spacefssimc C)

set(CMAKE_C_STANDARD 11)

add_executable(spacefssimc main.c SpaceFS/spacefs_basic.c SpaceFS/Internal/spacefs_internal_api.c SpaceFS/Internal/CRC/src/crc32.c)


/**
 *  Copyright (C) 2021  Tobias Egger
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SPACEFSSIMC_SPACEFS_BASE_HEADER_H
#define SPACEFSSIMC_SPACEFS_BASE_HEADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint32_t spacefs_address_t;
typedef int fp_t;
typedef uint32_t mode_t;

#define BURST_SIZE 128
/* Additional Security Measure */
#define MAX_OP_LEN 10000000

typedef enum {
    SPACEFS_ERROR = 0,
    SPACEFS_OK,
    SPACEFS_FILE_TOO_SMALL,
    SPACEFS_EOF,
    SPACEFS_MISMATCH,
    SPACEFS_MATCH,
    SPACEFS_CHECKSUM,
    SPACEFS_FILE_EXISTS,
    SPACEFS_FILE_NOT_FOUND,
    SPACEFS_INVALID_HANDLE,
    SPACEFS_INVALID_HANDLE_MEMBER,
    SPACEFS_INVALID_NAME,
    SPACEFS_HARDWARE_FAULT,
    SPACEFS_BLOCK_FOUND,
    SPACEFS_NO_SPACE_LEFT,
    SPACEFS_INVALID_PARAMETER,
    SPACEFS_INVALID_OPERATION,
    SPACEFS_FS_ERROR
} spacefs_status_t;

/**
 * index, 8bit
 * begin, 32bit
 * end, 32bit
 * size, 32bit
 * nr-blocks, 32 bit,
 *  * str, n-bit
 */

typedef struct {
    uint8_t index;
    uint32_t begin;
    uint32_t end;
    uint32_t size;
    uint32_t nr_blocks;
    uint32_t filename_length;
    uint32_t checksum;
} file_block_t;

typedef struct {
    uint8_t max_filename_length;
    uint8_t max_file_number;
    uint16_t block_size;
    uint32_t block_count;
    uint32_t device_size;
    uint32_t checksum;
} discovery_block_t;

typedef struct {
    uint32_t next;
    uint32_t prev;
} block_t;

typedef struct {
    void *low_level_handle;

    spacefs_status_t (*read)(void *low_level_handle, uint32_t address, uint8_t *data, uint32_t length, size_t drive_nr);

    spacefs_status_t
    (*write)(void *low_level_handle, uint32_t address, uint8_t *data, uint32_t length, size_t drive_nr);

    uint8_t max_filename_length;
    uint8_t max_file_number;

    uint16_t block_size;
    uint32_t block_count;

    uint32_t device_size;
} spacefs_handle_t;

typedef struct {
    fp_t fp;
    mode_t mode;
    uint32_t offset_read;
    uint32_t offset_write;
    spacefs_handle_t *handle;
    size_t drive_nr;
} fd_t;

#endif //SPACEFSSIMC_SPACEFS_BASE_HEADER_H

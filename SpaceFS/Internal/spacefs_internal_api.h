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

#ifndef SPACEFS_INTERNAL_API_H
#define SPACEFS_INTERNAL_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint32_t spacefs_address_t;

#define BURST_SIZE 128

#define RETURN_PN_ERROR(code) \
    if (code != SPACEFS_OK) { \
        return code;           \
    }
typedef enum {
    SPACEFS_ERROR = 0,
    SPACEFS_OK,
    SPACEFS_EOF,
    SPACEFS_MISMATCH,
    SPACEFS_MATCH,
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

typedef struct __attribute__((packed)) {
    uint8_t index;
    uint32_t begin;
    uint32_t end;
    uint32_t size;
    uint32_t nr_blocks;
    uint32_t filename_length;
} file_block_t;

typedef struct __attribute__((packed)) {
    uint8_t max_filename_length;
    uint8_t max_file_number;
    uint16_t block_size;
    uint32_t block_count;
    uint32_t device_size;
} discovery_block_t;

typedef struct __attribute__((packed)) {
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

/**
 * Wrapper for the low level write callback
 * @param handle The spacefs handle that contains the low level write callback
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param data The data to write
 * @param length The length of the data to write
 * @param drive_nr The drive number to write to
 * @return error codes
 */
spacefs_status_t spacefs_api_write(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                                   size_t drive_nr);

/**
 * Wrapper for the low level read callback
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param data The data to write
 * @param length The length of the data to read
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_read(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length, size_t drive_nr);

/**
 * Reads from memory and checks if the memory matches given data
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param expected_data The data we compare with the read data
 * @param length The length of the data to read/compare
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_read_checked(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *expected_data,
                         uint32_t length, size_t drive_nr);

/**
 * Writes to the spacefs device and checks if the written data is correct
 * @param handle The spacefs handle that contains the low level read and write callbacks
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param data The data to write
 * @param length The length of the data to read
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_write_checked(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                          size_t drive_nr);


/**
 * Memsets the memory
 * @param handle The spacefs handle that contains the low level read and write callbacks
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param length The length of the data to write
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t spacefs_api_memset(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t data, uint32_t length,
                                    size_t drive_nr);

/**
 * Checks if the handle is valid
 * @param handle
 * @return error codes
 */
spacefs_status_t spacefs_api_check_handle(spacefs_handle_t *handle);

/**
 * Gets the IDX of the next block
 * @param handle The handle
 * @param file_area Start Address of the file area
 * @param block_area Start Address of the block area
 * @param current_block The current block
 * @param next_block Returns the next block
 * @param front_first current->next(true) or current->previous(false)?
 * @param drive_nr The drive nr
 * @return error codes
 */
spacefs_status_t
spacefs_api_get_next_block(spacefs_handle_t *handle, spacefs_address_t file_area, spacefs_address_t block_area,
                           size_t current_block, size_t *next_block, bool front_first, size_t drive_nr);


/**
 * Get the Address of the fp
 * @param handle The handle
 * @param file_area_begin The file area start address
 * @param idx The idx of the file
 * @return the address calculated
 */
spacefs_address_t
spacefs_api_get_file_address(spacefs_handle_t *handle, const spacefs_address_t *file_area_begin, size_t idx);

/**
 * Get the Address of the block
 * @param handle The handle
 * @param block_area_begin The block area start address
 * @param idx The idx of the block
 * @return the address calculated
 */
spacefs_address_t
spacefs_api_get_block_address(spacefs_handle_t *handle, const spacefs_address_t *block_area_begin, size_t idx);

#endif //SPACEFS_INTERNAL_API_H

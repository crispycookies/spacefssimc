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

#include "spacefs_base_header.h"

#define RETURN_CUSTOM_ERROR(code, expected) \
    if ((code) != (expected)) { \
        return code;           \
    }

#define RETURN_PN_ERROR(code) RETURN_CUSTOM_ERROR(code, SPACEFS_OK)

typedef struct {
    spacefs_address_t file_area_begin;
    spacefs_address_t file_idx_address;
    spacefs_address_t fat_address;
    spacefs_address_t block_area_begin_address;
} spacefs_tuple_t;

typedef enum {
    backup = 0,
    left = 1,
    right = 2
} spacefs_drive_idx_t;

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


spacefs_address_t spacefs_api_get_file_area_begin(spacefs_address_t start);

spacefs_address_t spacefs_api_get_block_area_begin(spacefs_handle_t *handle, spacefs_address_t fat_begin_address);

/**
 * Gets the address of the fat
 * @param handle
 * @param file_area_begin
 * @return
 */
spacefs_address_t
spacefs_api_get_fat_address(spacefs_handle_t *handle, const spacefs_address_t *file_area_begin);

spacefs_tuple_t spacefs_api_get_address_tuple(fd_t *fd);

/**
 * Calculates the maximum size to be written into one block
 * @param size The desired size to be written
 * @param fd FD containing the information
 * @return The maximum size that is allowed to be written
 */
size_t spacefs_api_limit_operation_to_block_size(size_t size, fd_t *fd);

/**
 * Calculates to total number of blocks required for a operation
 * @param size Size to work with
 * @param fd Filedescriptor
 * @return Number of blocks to required
 */
size_t spacefs_api_get_block_count(size_t size, fd_t *fd);

/**
 * Reads from memory and calculates a crc32 checksum
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param data The data we read
 * @param length The length of the data to read/compare
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_read_crc(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                     size_t drive_nr, uint32_t *checksum);

/**
 * Reads from memory and calculates a crc32 checksum
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param length The length of the data to read/compare
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_read_crc_throwaway_data(spacefs_handle_t *handle, spacefs_address_t *address, uint32_t length,
                                    size_t drive_nr, uint32_t *checksum);


/**
 * Writes to the spacefs device and checks if the written data is correct
 * @param handle The spacefs handle that contains the low level read and write callbacks
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param data The data to write
 * @param length The length of the data to read
 * @param checksum Checksum
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_write_checked_crc(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                              uint32_t *checksum,
                              size_t drive_nr);

/**
 * Returns the index of the other eeprom in the eeprom tuple (when xor=enabled)
 * @param drive_nr Index of the current eeprom
 * @return index of the other eeprom to write to
 */
size_t spacefs_api_get_other_drive(size_t drive_nr);

/**
 * Is the drive specified the right writing (non-backup) drive
 * @param drive_nr Specified drive
 * @return true if it is the right one
 */
bool spacefs_api_is_right_drive(size_t drive_nr);

/**
 * Is the drive specified the left writing (non-backup) drive
 * @param drive_nr Specified drive
 * @return true if it is the left one
 */
bool spacefs_api_is_left_drive(size_t drive_nr);

/**
 * Is the drive specified the backup drive
 * @param drive_nr Specified drive
 * @return true if it is the backup drive
 */
bool spacefs_api_is_backup_drive(size_t drive_nr);

/**
 * Gets the number of the backup drive belonging to drive_nr
 * @param drive_nr The drive to get the backup drive for
 * @return idx of the backup drive
 */
size_t spacefs_api_get_backup_drive(size_t drive_nr);
/**
 * Calculates a^b
 * @param[in,out] a
 * @param b
 * @param size The size of a and b, a and b must be the same size
 */
void spacefs_api_xor(uint8_t *a, const uint8_t *b, size_t size);

#endif //SPACEFS_INTERNAL_API_H

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

#include "spacefs_internal_api.h"
#include "CRC/include/checksum.h"

#include <memory.h>

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
                                   size_t drive_nr) {
    spacefs_status_t rc = handle->write(handle->low_level_handle, *address, data, length, drive_nr);
    (*address) += length;
    return rc;
}

/**
 * Wrapper for the low level read callback
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param data The data to write
 * @param length The length of the data to read
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t spacefs_api_read(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                                  size_t drive_nr) {
    spacefs_status_t rc = handle->read(handle->low_level_handle, *address, data, length, drive_nr);
    uint8_t arr[64];
    if (length == 64) {
        memcpy(arr, data, length);
    }
    (*address) += length;
    return rc;
}

static spacefs_status_t
sfs_helper_checked_read(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *expected_data, uint8_t *rx,
                        uint32_t length, size_t drive_nr) {
    spacefs_status_t rc;

    rc = spacefs_api_read(handle, address, rx, length, drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }
    if (memcmp(rx, expected_data, length) != 0) {
        return SPACEFS_MISMATCH;
    }

    return SPACEFS_MATCH;
}

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
spacefs_api_read_checked(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *expected_data, uint32_t length,
                         size_t drive_nr) {
    uint8_t rechecked[BURST_SIZE];
    memset(rechecked, 0, BURST_SIZE);

    spacefs_address_t tmp = *address;
    tmp += length;

    spacefs_status_t rc = SPACEFS_MATCH;
    uint32_t count = length / sizeof rechecked;
    uint32_t mod = length % sizeof rechecked;

    for (size_t i = 0; i < count; i++) {
        rc = sfs_helper_checked_read(handle, address, &expected_data[i * sizeof rechecked], rechecked, sizeof rechecked,
                                     drive_nr);
        if (rc != SPACEFS_MATCH) {
            (*address) = tmp;
            return rc;
        }
    }
    if (mod != 0) {
        rc = sfs_helper_checked_read(handle, address, &expected_data[count * sizeof rechecked], rechecked, mod,
                                     drive_nr);
    }
    (*address) = tmp;

    return rc;
}

static spacefs_status_t
sfs_helper_checked_write(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *rx, uint8_t *tx,
                         uint32_t length, size_t drive_nr) {
    spacefs_status_t rc;

    spacefs_address_t read_address = *address;

    rc = spacefs_api_write(handle, address, tx, length, drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }
    rc = sfs_helper_checked_read(handle, &read_address, tx, rx, length, drive_nr);

    if (rc == SPACEFS_MATCH) {
        rc = SPACEFS_OK;
    }
    return rc;
}

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
                          size_t drive_nr) {
    uint8_t rechecked[BURST_SIZE];
    memset(rechecked, 0, BURST_SIZE);

    spacefs_address_t tmp = *address;
    tmp += length;

    spacefs_status_t rc = SPACEFS_ERROR;
    uint32_t count = length / sizeof rechecked;
    uint32_t mod = length % sizeof rechecked;

    for (size_t i = 0; i < count; i++) {
        rc = sfs_helper_checked_write(handle, address, rechecked, &data[i * sizeof rechecked], sizeof rechecked,
                                      drive_nr);
        if (rc != SPACEFS_OK) {
            (*address) = tmp;
            return rc;
        }
    }
    if (mod != 0) {
        rc = sfs_helper_checked_write(handle, address, rechecked, &data[count * sizeof rechecked], mod, drive_nr);
    }
    (*address) = tmp;
    return rc;
}

/**
 * Memsets the memory
 * @param handle The spacefs handle that contains the low level read and write callbacks
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param length The length of the data to write
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t spacefs_api_memset(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t data, uint32_t length,
                                    size_t drive_nr) {
    uint8_t zero_data[BURST_SIZE];
    memset(zero_data, data, BURST_SIZE);

    spacefs_address_t tmp = *address;
    tmp += length;

    spacefs_status_t rc = SPACEFS_ERROR;
    uint32_t count = length / sizeof zero_data;
    uint32_t mod = length % sizeof zero_data;

    for (size_t i = 0; i < count; i++) {
        rc = spacefs_api_write_checked(handle, address, zero_data, sizeof zero_data, drive_nr);
        if (rc != SPACEFS_OK) {
            (*address) = tmp;
            return rc;
        }
    }
    if (mod != 0) {
        rc = spacefs_api_write_checked(handle, address, zero_data, mod, drive_nr);
    }
    (*address) = tmp;
    return rc;
}

/**
 * Checks if the handle is valid
 * @param handle
 * @return error codes
 */
spacefs_status_t spacefs_api_check_handle(spacefs_handle_t *handle) {
    if (handle == NULL) {
        return SPACEFS_INVALID_HANDLE;
    }
    if (handle->read == NULL) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    if (handle->write == NULL) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    if (handle->max_filename_length == 0) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    if (handle->max_file_number == 0) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    if (handle->block_size == 0) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    if (handle->block_count == 0) {
        return SPACEFS_INVALID_HANDLE_MEMBER;
    }
    return SPACEFS_OK;
}

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
                           size_t current_block, size_t *next_block, bool front_first, size_t drive_nr) {
    spacefs_status_t rc;
    spacefs_address_t address;
    if (current_block < handle->max_file_number) {
        // check the file area
        file_block_t ft;
        address = spacefs_api_get_file_address(handle, &file_area, current_block);
        rc = spacefs_api_read(handle, &address, (uint8_t *) &ft, sizeof ft, drive_nr);
        if (front_first) {
            (*next_block) = ft.begin;
        } else {
            (*next_block) = ft.end;
        }
    } else {
        // check the block area
        block_t bt;
        address = spacefs_api_get_block_address(handle, &block_area, current_block);
        rc = spacefs_api_read(handle, &address, (uint8_t *) &bt, sizeof bt, drive_nr);
        if (front_first) {
            (*next_block) = bt.next;
        } else {
            (*next_block) = bt.prev;
        }
    }
    return rc;
}

/**
 * Get the Address of the fp
 * @param handle The handle
 * @param file_area_begin The file are start address
 * @param idx The idx of the file
 * @return the address calculated
 */
spacefs_address_t
spacefs_api_get_file_address(spacefs_handle_t *handle, const spacefs_address_t *file_area_begin, size_t idx) {
    spacefs_address_t file_address = (*file_area_begin) + idx * (handle->max_filename_length + sizeof(file_block_t));
    return file_address;
}

/**
 * Get the Address of the block
 * @param handle The handle
 * @param block_area_begin The block area start address
 * @param idx The idx of the block
 * @return the address calculated
 */
spacefs_address_t
spacefs_api_get_block_address(spacefs_handle_t *handle, const spacefs_address_t *block_area_begin, size_t idx) {
    spacefs_address_t real_idx = idx - handle->max_file_number;
    spacefs_address_t offset = handle->block_size + sizeof(block_t);
    spacefs_address_t file_address = (*block_area_begin) + real_idx * offset;

    return file_address;
}

spacefs_address_t
spacefs_api_get_fat_address(spacefs_handle_t *handle, const spacefs_address_t *file_area_begin) {
    return spacefs_api_get_file_address(handle, file_area_begin, handle->max_file_number);
}

spacefs_address_t spacefs_api_get_file_area_begin(spacefs_address_t start) {
    return start + sizeof(discovery_block_t);
}

spacefs_address_t spacefs_api_get_block_area_begin(spacefs_handle_t *handle, spacefs_address_t fat_begin_address) {
    spacefs_address_t fat_add = handle->block_count / 8;
    if (handle->block_count % 8) {
        fat_add++;
    }
    return fat_add + fat_begin_address;
}

spacefs_tuple_t spacefs_api_get_address_tuple(fd_t *fd, spacefs_address_t start_address) {
    spacefs_tuple_t tuple;
    tuple.file_area_begin = spacefs_api_get_file_area_begin(0);
    tuple.fat_address = spacefs_api_get_fat_address(fd->handle, &tuple.file_area_begin);
    tuple.block_area_begin_address = spacefs_api_get_block_area_begin(fd->handle, tuple.fat_address);
    tuple.file_idx_address = spacefs_api_get_file_address(fd->handle, &tuple.file_area_begin, fd->fp);

    return tuple;
}

/**
 * Calculates the maximum size to be written into one block
 * @param size The desired size to be written
 * @param fd FD containing the information
 * @return The maximum size that is allowed to be written
 */
size_t spacefs_api_limit_operation_to_block_size(size_t size, fd_t *fd) {
    if (size <= fd->handle->block_size) {
        return size;
    } else {
        return fd->handle->block_size;
    }
}

/**
 * Calculates to total number of blocks required for a operation
 * @param size Size to work with
 * @param offset Potential offset_read supplied
 * @param fd Filedescriptor
 * @return Number of blocks to required
 */
size_t spacefs_api_get_block_count(size_t size, fd_t *fd) {
    size += fd->offset_read;
    size_t blocks = size / fd->handle->block_size;
    if (size % fd->handle->block_size) {
        blocks++;
    }
    return blocks;
}

/**
 * Writes to the spacefs device and checks if the written data is correct. Also calculates a checksum.
 * @param handle The spacefs handle that contains the low level read and write callbacks
 * @param address The address to write to. Keep in mind that this address is incremented to point to the next address not written
 * @param data The data to write
 * @param length The length of the data to read
 * @param drive_nr The drive number to read from
 * @param checksum The checksum
 * @return error codes
 */
spacefs_status_t
spacefs_api_write_chsum(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length,
                        size_t drive_nr, uint32_t *checksum) {
    spacefs_status_t rc = spacefs_api_write_checked(handle, address, data, length, drive_nr);
    RETURN_PN_ERROR(rc);
    (*checksum) = append_crc_32(*checksum, data, length);
}

/**
 * Wrapper for the low level read callback
 * @param handle The spacefs handle that contains the low level read callback
 * @param address The address to read from. Keep in mind that this address is incremented to point to the next address not read
 * @param length The length of the data to read
 * @param drive_nr The drive number to read from
 * @return error codes
 */
spacefs_status_t
spacefs_api_read_chsum(spacefs_handle_t *handle, spacefs_address_t *address, uint32_t length, size_t drive_nr,
                       uint32_t *checksum) {
    uint8_t rechecked[BURST_SIZE];
    memset(rechecked, 0, BURST_SIZE);

    spacefs_address_t tmp = *address;
    tmp += length;

    spacefs_status_t rc = SPACEFS_MATCH;
    uint32_t count = length / sizeof rechecked;
    uint32_t mod = length % sizeof rechecked;

    for (size_t i = 0; i < count; i++) {
        rc = spacefs_api_read(handle, address, rechecked, sizeof rechecked,
                                     drive_nr);
        if (rc != SPACEFS_MATCH) {
            (*address) = tmp;
            return rc;
        }

        (*checksum) = append_crc_32(*checksum, rechecked, sizeof rechecked);
    }
    if (mod != 0) {
        rc = spacefs_api_read(handle, address, rechecked, mod,
                                     drive_nr);
        (*checksum) = append_crc_32(*checksum, rechecked, sizeof mod);
    }
    (*address) = tmp;

    return rc;
}
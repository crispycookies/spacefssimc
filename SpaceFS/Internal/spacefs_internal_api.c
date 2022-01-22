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
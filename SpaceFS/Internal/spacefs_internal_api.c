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
 *
 * @deprecated Please use spacefs_api_write_checked instead
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

    if (handle->readback_enable) {
        rc = sfs_helper_checked_read(handle, &read_address, tx, rx, length, drive_nr);
    }

    if (rc == SPACEFS_MATCH) {
        rc = SPACEFS_OK;
    }
    return rc;
}

/**
 * Writes to the spacefs device and checks if the written data is correct (if desired)
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
    // TODO here
    spacefs_address_t other_eeprom = *address;
    spacefs_address_t backup_eeprom = *address;
    size_t backup_nr = spacefs_api_get_backup_drive(drive_nr);
    size_t other_nr = spacefs_api_get_other_drive(drive_nr);

    uint8_t rechecked[BURST_SIZE];
    uint8_t rechecked_backup[BURST_SIZE];
    memset(rechecked, 0, BURST_SIZE);
    memset(rechecked_backup, 0, BURST_SIZE);


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
        // TODO drive nr
        rc = spacefs_api_read(handle, &other_eeprom, rechecked, sizeof rechecked, other_nr);
        RETURN_PN_ERROR(rc);

        spacefs_api_xor(rechecked, &data[i * sizeof rechecked], sizeof rechecked);

        rc = sfs_helper_checked_write(handle, &backup_eeprom, rechecked_backup, rechecked, sizeof rechecked, backup_nr);
        RETURN_PN_ERROR(rc);
    }
    if (mod != 0) {
        rc = sfs_helper_checked_write(handle, address, rechecked, &data[count * sizeof rechecked], mod, drive_nr);
        if (rc != SPACEFS_OK) {
            (*address) = tmp;
            return rc;
        }
        // TODO drive nr
        rc = spacefs_api_read(handle, &other_eeprom, rechecked, mod, other_nr);
        RETURN_PN_ERROR(rc);

        spacefs_api_xor(rechecked, &data[count * sizeof rechecked], mod);

        rc = sfs_helper_checked_write(handle, &backup_eeprom, rechecked_backup, rechecked, mod, backup_nr);
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
spacefs_status_t spacefs_api_get_next_block(spacefs_handle_t *handle, spacefs_address_t file_area, spacefs_address_t block_area, size_t current_block, size_t *next_block, bool front_first, size_t drive_nr){
    spacefs_status_t rc;
    spacefs_address_t address;
    if (current_block < handle->max_file_number) {
        // check the file area
        file_block_t ft;
        address = spacefs_api_get_file_address(handle, &file_area, current_block);
        rc = spacefs_api_read(handle, &address, (uint8_t*)&ft, sizeof ft, drive_nr);
        if (front_first)  {
            (*next_block) = ft.begin;
        } else {
            (*next_block) = ft.end;
        }
    } else {
        // check the block area
        block_t bt;
        address = spacefs_api_get_block_address(handle, &block_area, current_block);
        rc = spacefs_api_read(handle, &address, (uint8_t*)&bt, sizeof bt, drive_nr);
        if (front_first)  {
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
                     size_t drive_nr, uint32_t *checksum) {
    spacefs_status_t rc = spacefs_api_read(handle, address, data, length, drive_nr);
    (*checksum) = append_crc_32(*checksum, data, length);
    return rc;
}

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
                                    size_t drive_nr, uint32_t *checksum) {
    uint8_t rechecked[BURST_SIZE];
    memset(rechecked, 0, BURST_SIZE);

    spacefs_address_t tmp = *address;
    tmp += length;

    spacefs_status_t rc = SPACEFS_MATCH;
    uint32_t count = length / sizeof rechecked;
    uint32_t mod = length % sizeof rechecked;

    for (size_t i = 0; i < count; i++) {
        rc = spacefs_api_read_crc(handle, address, rechecked, sizeof rechecked,
                                     drive_nr, checksum);
        if (rc != SPACEFS_OK) {
            (*address) = tmp;
            return rc;
        }
    }
    if (mod != 0) {
        rc = spacefs_api_read_crc(handle, address, rechecked, mod, drive_nr, checksum);
    }
    (*address) = tmp;

    return rc;
}

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
spacefs_api_write_checked_crc(spacefs_handle_t *handle, spacefs_address_t *address, uint8_t *data, uint32_t length, uint32_t *checksum,
                          size_t drive_nr) {
    spacefs_status_t rc = spacefs_api_write_checked(handle, address, data, length, drive_nr);
    (*checksum) = append_crc_32(*checksum, data, length);
    return rc;
}

static bool spacefs_api_is_drive(size_t drive_nr, spacefs_drive_idx_t type)
{
    return drive_nr % 3 == (size_t)type;
}

/**
 * Is the drive specified the right writing (non-backup) drive
 * @param drive_nr Specified drive
 * @return true if it is the right one
 */
bool spacefs_api_is_right_drive(size_t drive_nr) {
    return spacefs_api_is_drive(drive_nr, right);
}

/**
 * Is the drive specified the left writing (non-backup) drive
 * @param drive_nr Specified drive
 * @return true if it is the left one
 */
bool spacefs_api_is_left_drive(size_t drive_nr) {
    return spacefs_api_is_drive(drive_nr, left);
}

/**
 * Is the drive specified the backup drive
 * @param drive_nr Specified drive
 * @return true if it is the backup drive
 */
bool spacefs_api_is_backup_drive(size_t drive_nr) {
    return spacefs_api_is_drive(drive_nr, backup);
}

/**
 * Returns the index of the other eeprom in the eeprom tuple (when xor=enabled)
 * @param drive_nr Index of the current eeprom
 * @return index of the other eeprom to write to
 */
size_t spacefs_api_get_other_drive(size_t drive_nr) {
    if(spacefs_api_is_backup_drive(drive_nr)) {
        return -1;
    }
    if (spacefs_api_is_left_drive(drive_nr)){
        return drive_nr + 1;
    }
    /* implicitly the right drive */
    return drive_nr - 1;
}

/**
 * Gets the number of the backup drive belonging to drive_nr
 * @param drive_nr The drive to get the backup drive for
 * @return idx of the backup drive
 */
size_t spacefs_api_get_backup_drive(size_t drive_nr) {
    if(spacefs_api_is_backup_drive(drive_nr)) {
        return drive_nr;
    }
    if (spacefs_api_is_left_drive(drive_nr)){
        return drive_nr + 2;
    }
    /* implicitly the right drive */
    return drive_nr + 1;
}

/**
 * Calculates a^b
 * @param[in,out] a
 * @param b
 */
void spacefs_api_xor(uint8_t *a, const uint8_t *b, size_t size) {
    for (int i = 0; i < size; i++) {
        a[i] ^= b[i];
    }
}

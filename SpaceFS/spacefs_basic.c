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

#include <stdbool.h>
#include <string.h>
#include <memory.h>
#include "spacefs_basic.h"

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

static spacefs_status_t sfs_write_discovery_block(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address) {
    discovery_block_t discovery_block;

    discovery_block.max_filename_length = handle->max_filename_length;
    discovery_block.max_file_number = handle->max_file_number;
    discovery_block.block_size = handle->block_size;
    discovery_block.block_count = handle->block_count;
    discovery_block.device_size = handle->device_size;

    return spacefs_api_write_checked(handle, address, (uint8_t *) &discovery_block, sizeof(discovery_block_t),
                                     drive_nr);
}

static spacefs_status_t
sfs_write_file_block(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address, size_t idx,
                     size_t filename_length) {
    file_block_t file_block;
    memset(&file_block, 0, sizeof(file_block_t));
    file_block.filename_length = filename_length;
    file_block.index = idx;

    return spacefs_api_write_checked(handle, address, (uint8_t *) &file_block, sizeof(file_block_t), drive_nr);
}

static spacefs_status_t sfs_write_filename(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address,
                                           const char *filename, size_t filename_length) {
    if (filename_length == 0) {
        return spacefs_api_memset(handle, address, 0x00, handle->max_filename_length, drive_nr);
    } else {
        spacefs_address_t address_tmp = *address;

        spacefs_status_t rc = spacefs_api_memset(handle, address, 0x00, handle->max_filename_length, drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        return spacefs_api_write_checked(handle, &address_tmp, (uint8_t *) filename, filename_length, drive_nr);
    }
}

static spacefs_status_t
sfs_write_file_table_entry(spacefs_handle_t *handle, size_t drive_nr, uint8_t index, const char *filename,
                           uint32_t filesize,
                           uint32_t *address) {
    spacefs_status_t rc = sfs_write_file_block(handle, drive_nr, address, index, filesize);
    if (rc != SPACEFS_OK) {
        (*address) = (*address) + handle->max_filename_length;
        return rc;
    }

    return sfs_write_filename(handle, drive_nr, address, filename, filesize);
}

/**
 *
 * @param handle
 * @param drive_nr
 * @return
 */
static spacefs_status_t sfs_write_file_table(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address) {
    spacefs_status_t rc = SPACEFS_ERROR;
    for (uint32_t i = 0; i < handle->max_file_number; i++) {
        rc = sfs_write_file_table_entry(handle, drive_nr, i, NULL, 0,
                                        address);
        if (rc != SPACEFS_OK) {
            return rc;
        }
    }
    return rc;
}

static spacefs_status_t sfs_write_fat(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address) {
    return spacefs_api_memset(handle, address, 0x00, handle->block_count / 8 + 1, drive_nr);
}

static spacefs_status_t sfs_initialize_blocks(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address) {
    return spacefs_api_memset(handle, address, 0x00, handle->block_count * handle->block_size, drive_nr);
}

static spacefs_status_t
sfs_find_filename(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, char *filename,
                  size_t filelen, fp_t *index) {
    spacefs_status_t rc;
    spacefs_address_t tmp_address = *address;
    file_block_t rechecked;

    (*address) = (*address) + (sizeof(file_block_t) + handle->max_filename_length) * handle->max_file_number;

    for (fp_t i = 0; i < handle->max_file_number; i++) {
        rechecked.index = i;
        rc = spacefs_api_read(handle, &tmp_address, (uint8_t *) &rechecked, sizeof(file_block_t), drive_nr);

        if (rc == SPACEFS_OK) {
            if (rechecked.filename_length == filelen) {
                rc = spacefs_api_read_checked(handle, &tmp_address, (uint8_t *) filename, filelen, drive_nr);
                if (rc == SPACEFS_MATCH) {
                    (*index) = i;
                    return rc;
                }
            }
        } else {
            tmp_address += filelen;
        }
    }

    return SPACEFS_MISMATCH;
}

static spacefs_status_t
sfs_set_filename(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, char *filename,
                 size_t filelen, size_t index) {
    (*address) = (*address) + (sizeof(file_block_t) + handle->max_filename_length) * index;
    return sfs_write_file_table_entry(handle, drive_nr, index, filename, filelen, address);
}

static fd_t sfs_open(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, char *filename,
                     size_t filelen, fp_t index, mode_t mode, bool exists) {
    if (!exists && sfs_set_filename(handle, drive_nr, address, filename, filelen, index) != SPACEFS_OK) {
        return INVALID_FP;
    }

    fd_t fd;
    fd.fp = index;
    fd.mode = mode;
    fd.offset = 0;
    fd.handle = handle;
    fd.drive_nr = drive_nr;
    return fd;
}

/**
 * Formats the filesystem for a given drive
 * @param handle The handle that contains the low-level callbacks(read, write) and some settings(block size, number of blocks)
 * @param drive_nr The physical drive number
 * @return error code
 */
spacefs_status_t spacefs_basic_format(spacefs_handle_t *handle, size_t drive_nr) {
    spacefs_address_t address = 0;
    spacefs_status_t rc = spacefs_api_check_handle(handle);

    if (rc != SPACEFS_OK) {
        return rc;
    }

    rc = sfs_write_discovery_block(handle, drive_nr, &address);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    rc = sfs_write_file_table(handle, drive_nr, &address);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    rc = sfs_write_fat(handle, drive_nr, &address);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    return sfs_initialize_blocks(handle, drive_nr, &address);
    //return SPACEFS_OK;
}

/**
 * Opens a file on a given drive
 * @param handle The handle that contains the low-level callbacks(read, write) and some settings(block size, number of blocks)
 * @param drive_nr The physical drive number
 * @param filename Filename to open
 * @param mode Mode to open the file with
 * @return A handle to the opened file
 */
fd_t spacefs_fopen(spacefs_handle_t *handle, size_t drive_nr, char *filename, mode_t mode) {
    if (spacefs_api_check_handle(handle) != SPACEFS_OK) {
        return INVALID_FP;
    }
    if (filename == NULL) {
        return INVALID_FP;
    }
    if (strlen(filename) == 0) {
        return INVALID_FP;
    }
    if (strlen(filename) >= handle->max_filename_length) {
        return INVALID_FP;
    }

    if (!(mode & O_RDONLY) && !(mode & O_WRONLY) && !(mode & O_RDWR)) {
        return INVALID_FP;
    }

    spacefs_address_t address = sizeof(discovery_block_t);
    spacefs_address_t tmp_address = address;
    fp_t idx = 0;

    if (sfs_find_filename(handle, drive_nr, &tmp_address, filename, strlen(filename), &idx) == SPACEFS_MATCH) {
        return sfs_open(handle, drive_nr, &address, filename, strlen(filename), idx, mode, true);
    } else {
        tmp_address = address;
        if (sfs_find_filename(handle, drive_nr, &tmp_address, 0, 0, &idx) == SPACEFS_MISMATCH) {
            // ERROR! No Name Slot left!
            return INVALID_FP;
        } else {
            return sfs_open(handle, drive_nr, &address, filename, strlen(filename), idx, mode, false);
        }
    }
}

static size_t get_block_in_byte(uint8_t byte) {
    for (size_t i = 0; i < 8; i++) {
        if (!(byte & (1 << i))) {
            return i;
        }
    }
    return 0;
}

static spacefs_status_t
sfs_set_unused_block(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, size_t *block_nr) {
    spacefs_status_t rc;
    size_t fat_entries = handle->block_count / 8;
    if (handle->block_count % 8 != 0) {
        fat_entries++;
    }

    for (size_t i = 0; i < fat_entries; i++) {
        uint8_t fat_entry = 0xFF;
        spacefs_address_t tmp_address = *address;
        rc = spacefs_api_read(handle, address, &fat_entry, 1, drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }

        // Found an empty slot in the FAT-entry
        if (fat_entry != 0xFF) {
            size_t fat_idx = get_block_in_byte(fat_entry);
            (*block_nr) = i * 8 + fat_idx + handle->max_file_number;
            fat_entry |= (1<<fat_idx);
            rc = spacefs_api_write_checked(handle, &tmp_address, &fat_entry, 1, drive_nr);
            if (rc != SPACEFS_OK) {
                return rc;
            } else {
                return SPACEFS_BLOCK_FOUND;
            }
        }
    }
    return SPACEFS_NO_SPACE_LEFT;
}

spacefs_status_t
sfs_unset_used_block(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, size_t block_nr) {
    if (block_nr >= handle->block_count) {
        return SPACEFS_ERROR;
    }
    spacefs_address_t fat_entry_address = (*address) + block_nr / 8;
    spacefs_address_t fat_entry_address_wb = fat_entry_address;

    uint8_t fat_entry_shift = block_nr % 8;
    uint8_t fat_entry = 0xFF;

    spacefs_status_t rc = spacefs_api_read(handle, &fat_entry_address, &fat_entry, 1, drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    fat_entry &= ~(1 << fat_entry_shift);
    rc = spacefs_api_write(handle, &fat_entry_address_wb, &fat_entry, 1, drive_nr);

    return rc;
}

static spacefs_address_t
sfs_get_block_address(spacefs_handle_t *handle, const spacefs_address_t *block_area_begin, size_t idx) {
    spacefs_address_t file_address = (*block_area_begin) + (idx - handle->max_file_number) * (handle->block_size + sizeof(block_t));
    return file_address;
}

static spacefs_address_t
sfs_get_file_idx_address(spacefs_handle_t *handle, const spacefs_address_t *file_area_begin, size_t idx) {
    spacefs_address_t file_address = (*file_area_begin) + idx * (handle->max_filename_length + sizeof(file_block_t));
    return file_address;
}

/**
 * Link double linked list
 * @param handle
 * @param drive_nr
 * @param address
 * @param previous_block
 * @param own_block
 * @param next_block
 * @return
 */
static spacefs_status_t
sfs_link_list_items(spacefs_handle_t *handle, size_t drive_nr,
                    spacefs_address_t *block_area_begin,
                    spacefs_address_t *file_area_begin,
                    size_t previous_block,
                    size_t own_block, size_t next_block) {
    spacefs_status_t rc;

    spacefs_address_t block_prev;
    spacefs_address_t block_next;
    spacefs_address_t block_own = sfs_get_block_address(handle, block_area_begin, own_block);

    spacefs_address_t block_prev_write;
    spacefs_address_t block_next_write;
    spacefs_address_t block_own_write = block_own;

    // Link previous block
    if (previous_block < handle->max_file_number) {
        file_block_t previous_block_data;
        block_prev = sfs_get_file_idx_address(handle, file_area_begin, previous_block);
        block_prev_write = block_prev;
        rc = spacefs_api_read(handle, &block_prev, (uint8_t *) &previous_block_data, sizeof(file_block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        previous_block_data.begin = own_block;
        rc = spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &previous_block_data,
                                       sizeof(file_block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
    }
    else {
        block_t block_prev_read;
        block_prev = sfs_get_block_address(handle, block_area_begin, previous_block);
        block_prev_write = block_prev;
        rc = spacefs_api_read(handle, &block_prev, (uint8_t *) &block_prev_read, sizeof(block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        block_prev_read.next = own_block;
        rc = spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &block_prev_read, sizeof(block_t),
                                       drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
    }

    // Link current block
    block_t block_own_read;
    rc = spacefs_api_read(handle, &block_own, (uint8_t *) &block_own_read, sizeof(block_t), drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }
    block_own_read.prev = previous_block;
    block_own_read.next = next_block;
    rc = spacefs_api_write_checked(handle, &block_own_write, (uint8_t *) &block_own_read, sizeof(block_t), drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    // Link next block
    if (previous_block < handle->max_file_number) {
        file_block_t next_block_data;
        block_next = sfs_get_file_idx_address(handle, file_area_begin, next_block);
        block_next_write = block_next;
        rc = spacefs_api_read(handle, &block_next, (uint8_t *) &next_block_data, sizeof(file_block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        next_block_data.begin = own_block;
        rc = spacefs_api_write_checked(handle, &block_next_write, (uint8_t *) &next_block_data,
                                       sizeof(file_block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
    }
    else {
        block_t block_next_read;
        block_next = sfs_get_block_address(handle, block_area_begin, next_block);
        block_next_write = block_next;
        rc = spacefs_api_read(handle, &block_prev, (uint8_t *) &block_next_read, sizeof(block_t), drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        block_next_read.next = own_block;
        rc = spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &block_next_read, sizeof(block_t),
                                       drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
    }
    return SPACEFS_OK;
}

spacefs_address_t get_block_area_begin(spacefs_handle_t *handle, spacefs_address_t fat_begin_address) {
    spacefs_address_t fat_add = handle->block_count/8;
    if (handle->block_count % 8) {
        fat_add++;
    }
    return fat_add + fat_begin_address;
}
spacefs_address_t get_file_area_begin(spacefs_address_t start) {
    return start + sizeof(discovery_block_t);
}

/**
 * Writes data to a file
 * @param fd The handle to the file
 * @param data The data to write
 * @param size The length of the data
 * @return error code
 */
spacefs_status_t spacefs_fwrite(fd_t fd, uint8_t *data, size_t size) {
    spacefs_status_t rc = spacefs_api_check_handle(fd.handle);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    spacefs_address_t file_area_begin = get_file_area_begin(0);
    spacefs_address_t fat_address = (file_area_begin + (fd.handle->max_file_number * sizeof(file_block_t)));
    spacefs_address_t block_area_begin = get_block_area_begin(fd.handle, fat_address);

    size_t block_count_to_use = size / (fd.handle->block_size);
    if (size % (fd.handle->block_size) != 0) {
        block_count_to_use++;
    }

    size_t previous_block = fd.fp;
    size_t next_block = fd.fp;
    size_t offset = 0;
    size_t len;
    if (size <= fd.handle->block_size) {
        size = 0;
        len = size;
    } else {
        len = fd.handle->block_size;
    }

    for (int i = 0; i < block_count_to_use; i++) {
        size_t own_block;
        spacefs_address_t tmp_block_area = block_area_begin;
        spacefs_address_t tmp_fat_address = fat_address;
        spacefs_address_t block_address;
        rc = sfs_set_unused_block(fd.handle,  fd.drive_nr,&tmp_fat_address, &own_block);
        if (rc != SPACEFS_BLOCK_FOUND) {
            return rc;
        }

        rc = sfs_link_list_items(fd.handle, fd.drive_nr, &tmp_block_area, &file_area_begin, previous_block, own_block, next_block);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        previous_block = own_block;
        block_address = sfs_get_block_address(fd.handle, &tmp_block_area, own_block) + sizeof(block_t);

        rc = spacefs_api_write_checked(fd.handle,  &block_address, &data[offset], len, fd.drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }

        offset += len;
        if (size <= fd.handle->block_size) {
            size = 0;
            len = size;
        } else {
            size -= len;
            len = fd.handle->block_size;
        }
    }

    return rc;
}

/**
 * Get size of file starting from seek
 * @param fd file descriptor
 * @return remaining size of file
 */
size_t spacefs_ftell(fd_t fd) {
    // TODO
    return 0;
}

/**
 * Reads data from a file
 * @param fd The handle to the file
 * @param data The data to read
 * @param size The length of the data
 * @return error code
 */
spacefs_status_t spacefs_fread(fd_t fd, uint8_t *data, size_t size) {
    spacefs_status_t rc = spacefs_api_check_handle(fd.handle);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    // read first block to get first block
    spacefs_address_t file_start_address = get_file_area_begin(0);
    spacefs_address_t file_idx_address = sfs_get_file_idx_address(fd.handle, &file_start_address, fd.fp);
    spacefs_address_t fat_address = (file_start_address + (fd.handle->max_file_number * sizeof(file_block_t)));
    spacefs_address_t block_area_begin_address = get_block_area_begin(fd.handle, fat_address);

    file_block_t fb;
    rc = spacefs_api_read(fd.handle, &file_idx_address, (uint8_t*)&fb, sizeof fb, fd.drive_nr);
    if (rc != SPACEFS_OK) {
        return rc;
    }

    size_t next_block = fb.begin;
    size_t offset = 0;
    size_t length;
    size_t blocks_to_read;

    if (size <= fb.size) {
        size = fb.size;
    }

    blocks_to_read = size / fd.handle->block_size;
    if (size & fd.handle->block_size) {
        blocks_to_read++;
    }

    if (size <= fd.handle->block_size) {
        length = size;
    } else {
        length = fd.handle->block_size;
    }

    for (int i = 0; i < blocks_to_read; i++) {
        block_t bt;
        spacefs_address_t block_addr = sfs_get_block_address(fd.handle, &block_area_begin_address, next_block);
        rc = spacefs_api_read(fd.handle, &block_addr, (uint8_t*)&bt, sizeof bt, fd.fp);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        rc = spacefs_api_read(fd.handle, &block_addr, &data[offset], length, fd.drive_nr);
        if (rc != SPACEFS_OK) {
            return rc;
        }
        next_block = bt.next;
        size -= length;
        offset += length;

        if (size <= fd.handle->block_size) {
            length = size;
        } else {
            length = fd.handle->block_size;
        }
    }

    return rc;
}

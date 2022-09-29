/**
 *  Copyright (C) 2021  Tobias Egger, Steven Trinkenschuh
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
#include "Internal/CRC/include/checksum.h"
#include "spacefs_basic.h"

static spacefs_status_t spacefs_read_ringbuffer_internal(fd_t *fd, uint8_t *data, size_t size);

static spacefs_status_t spacefs_write_ringbuffer_internal(fd_t *fd, uint8_t *data, size_t size);

static void sfs_calculate_discovery_block_crc(discovery_block_t *discovery_block) {
    uint32_t checksum = crc_32((unsigned char *) (&discovery_block->max_filename_length),
                               sizeof(discovery_block->max_filename_length));

    /* I am not proud of this spaghetti code here and everywhere in this FS */
    /* but I prefer this explicit approach over casting discovery_block_t and subtracting */
    /* sizeof(discovery_block.checksum) */
    checksum = append_crc_32(checksum, (unsigned char *) (&discovery_block->max_file_number),
                             sizeof(discovery_block->max_file_number));
    checksum = append_crc_32(checksum, (unsigned char *) (&discovery_block->block_size),
                             sizeof(discovery_block->block_size));
    checksum = append_crc_32(checksum, (unsigned char *) (&discovery_block->block_count),
                             sizeof(discovery_block->block_count));
    checksum = append_crc_32(checksum, (unsigned char *) (&discovery_block->device_size),
                             sizeof(discovery_block->device_size));

    discovery_block->checksum = checksum;
}

static spacefs_status_t sfs_write_discovery_block(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address) {
    discovery_block_t discovery_block;
    uint32_t checksum;

    discovery_block.max_filename_length = handle->max_filename_length;
    discovery_block.max_file_number = handle->max_file_number;
    discovery_block.block_size = handle->block_size;
    discovery_block.block_count = handle->block_count;
    discovery_block.device_size = handle->device_size;

    sfs_calculate_discovery_block_crc(&discovery_block);

    return spacefs_api_write_checked(handle, address, (uint8_t *) &discovery_block, sizeof(discovery_block_t),
                                     drive_nr);
}

static uint32_t sfs_calculate_crc_fileblock_no_file(file_block_t *file_block) {
    uint32_t checksum = crc_32((unsigned char *) (&file_block->size),
                               sizeof(file_block->size));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->index),
                             sizeof(file_block->index));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->begin),
                             sizeof(file_block->begin));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->end),
                             sizeof(file_block->end));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->size),
                             sizeof(file_block->size));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->nr_blocks),
                             sizeof(file_block->nr_blocks));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->filename_length),
                             sizeof(file_block->filename_length));
    checksum = append_crc_32(checksum, (unsigned char *) (&file_block->name_checksum),
                             sizeof(file_block->name_checksum));
    return checksum;
}

static uint32_t sfs_calculate_crc_fileblock(file_block_t *file_block, const char *filename) {
    uint32_t checksum = sfs_calculate_crc_fileblock_no_file(file_block);
    checksum = append_crc_32(checksum, (unsigned char *) filename, file_block->filename_length);

    return checksum;
}

static spacefs_status_t
sfs_write_file_block(spacefs_handle_t *handle, size_t drive_nr, uint32_t *address, size_t idx, const char *filename,
                     size_t filename_length, uint32_t filename_checksum) {
    file_block_t file_block;
    memset(&file_block, 0, sizeof(file_block_t));
    file_block.filename_length = filename_length;
    file_block.index = idx;
    file_block.name_checksum = filename_checksum;

    file_block.checksum = sfs_calculate_crc_fileblock(&file_block, filename);

    return spacefs_api_write_checked(handle, address, (uint8_t *) &file_block, sizeof(file_block_t), drive_nr);
}

static spacefs_status_t
sfs_write_filename(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, const char *filename,
                   size_t filename_length, uint32_t *crc) {
    if (filename_length == 0) {
        return spacefs_api_memset(handle, address, 0x00, handle->max_filename_length, drive_nr);
    } else {
        spacefs_address_t address_tmp = *address;

        spacefs_status_t rc = spacefs_api_memset(handle, address, 0x00, handle->max_filename_length, drive_nr);
        RETURN_PN_ERROR(rc)
        return spacefs_api_write_checked_crc(handle, &address_tmp, (uint8_t *) filename, filename_length, crc, drive_nr);
    }
}

static spacefs_status_t
sfs_write_file_table_entry(spacefs_handle_t *handle, size_t drive_nr, uint8_t index, const char *filename,
                           uint32_t filesize,
                           uint32_t *address) {
    uint32_t crc = 0;
    uint32_t address_after_fileblock = (*address) + sizeof(file_block_t);

    spacefs_status_t rc = sfs_write_filename(handle, drive_nr, &address_after_fileblock, filename, filesize, &crc);
    RETURN_PN_ERROR(rc)

    rc = sfs_write_file_block(handle, drive_nr, address, index, filename, filesize, crc);
    address += address_after_fileblock;
    return rc;
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
        RETURN_PN_ERROR(rc)
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
    fd.offset_read = 0;
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

    RETURN_PN_ERROR(rc)

    rc = sfs_write_discovery_block(handle, drive_nr, &address);
    RETURN_PN_ERROR(rc)

    rc = sfs_write_file_table(handle, drive_nr, &address);
    RETURN_PN_ERROR(rc)

    rc = sfs_write_fat(handle, drive_nr, &address);
    RETURN_PN_ERROR(rc)

    return sfs_initialize_blocks(handle, drive_nr, &address);
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

    if (!(mode & O_READ) && !(mode & O_WRITE) && !(mode & O_RDWR)) {
        return INVALID_FP;
    }

    spacefs_address_t address = sizeof(discovery_block_t);
    spacefs_address_t tmp_address = address;
    fp_t idx = 0;

    if (sfs_find_filename(handle, drive_nr, &tmp_address, filename, strlen(filename), &idx) == SPACEFS_MATCH) {
        return sfs_open(handle, drive_nr, &address, filename, strlen(filename), idx, mode, true);
    } else {
        if (!(mode & O_CREAT)) {
            return INVALID_FP;
        }
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

static spacefs_status_t sfs_check_block_table(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t address, size_t *fat_entries) {
    uint32_t crc_calc = 0;
    uint32_t crc_read = 0;
    spacefs_status_t rc;
    (*fat_entries) = handle->block_count / 8;
    if (handle->block_count % 8 != 0) {
        (*fat_entries)++;
    }

    /* base address + fat-entries = crc address */
    rc = spacefs_api_read_crc_throwaway_data(handle, &address, *fat_entries, drive_nr, &crc_calc);
    RETURN_PN_ERROR(rc)

    rc = spacefs_api_read(handle, &address, (uint8_t*)&crc_read, sizeof crc_read, drive_nr);
    RETURN_PN_ERROR(rc)

    if (crc_read != crc_calc) {
        return SPACEFS_CHECKSUM;
    }
    return rc;
}

static spacefs_status_t
sfs_set_unused_block(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, size_t *block_nr) {
    spacefs_address_t address_crc = *address;
    spacefs_status_t rc;
    uint32_t crc_calc = 0;
    size_t fat_entries;

    rc = sfs_check_block_table(handle, drive_nr, *address, &fat_entries);
    RETURN_PN_ERROR(rc)

    /* reset address */
    *address = address_crc;

    for (size_t i = 0; i < fat_entries; i++) {
        uint8_t fat_entry = 0xFF;
        spacefs_address_t tmp_address = *address;
        rc = spacefs_api_read(handle, address, &fat_entry, 1, drive_nr);
        RETURN_PN_ERROR(rc)

        // Found an empty slot in the FAT-entry
        if (fat_entry != 0xFF) {
            size_t fat_idx = get_block_in_byte(fat_entry);
            (*block_nr) = i * 8 + fat_idx + handle->max_file_number;
            fat_entry |= (1 << fat_idx);
            rc = spacefs_api_write_checked(handle, &tmp_address, &fat_entry, 1, drive_nr);
            RETURN_PN_ERROR(rc)

            rc = spacefs_api_read_crc_throwaway_data(handle, &address_crc, fat_entries, drive_nr, &crc_calc);
            RETURN_PN_ERROR(rc)

            rc = spacefs_api_write_checked(handle, &address_crc, (uint8_t*)&crc_calc, sizeof crc_calc, drive_nr);
            RETURN_PN_ERROR(rc)

            return SPACEFS_BLOCK_FOUND;
        }
    }
    return SPACEFS_NO_SPACE_LEFT;
}

spacefs_status_t
sfs_unset_used_block(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *address, size_t block_nr) {
    if (block_nr >= handle->block_count) {
        return SPACEFS_ERROR;
    }
    uint32_t crc_read = 0;
    spacefs_address_t address_crc = *address;
    spacefs_address_t fat_entry_address = (*address) + block_nr / 8;
    spacefs_address_t fat_entry_address_wb = fat_entry_address;

    uint8_t fat_entry_shift = block_nr % 8;
    uint8_t fat_entry = 0xFF;
    size_t fat_entries = 0;

    /* check if the checksum was valid before writing to FS */
    spacefs_status_t rc = sfs_check_block_table(handle, drive_nr, *address, &fat_entries);
    RETURN_PN_ERROR(rc)

    /* reset address */
    *address = address_crc;

    rc = spacefs_api_read(handle, &fat_entry_address, &fat_entry, 1, drive_nr);
    RETURN_PN_ERROR(rc)

    fat_entry &= ~(1 << fat_entry_shift);
    rc = spacefs_api_write_checked(handle, &fat_entry_address_wb, &fat_entry, 1, drive_nr);

    rc = spacefs_api_read_crc_throwaway_data(handle, &address_crc, fat_entries, drive_nr, &crc_read);
    RETURN_PN_ERROR(rc);

    *address = address_crc;

    return spacefs_api_write_checked(handle, address, (uint8_t*)&crc_read, 1, drive_nr);
}

static spacefs_address_t
sfs_get_block_address(spacefs_handle_t *handle, const spacefs_address_t *block_area_begin, size_t idx) {
    spacefs_address_t real_idx = idx - handle->max_file_number;
    spacefs_address_t offset = handle->block_size + sizeof(block_t);
    spacefs_address_t file_address = (*block_area_begin) + real_idx * offset;

    return file_address;
}

static uint32_t sfs_calculate_crc_block(block_t *fb) {
    uint32_t crc = crc_32((unsigned char *) (&fb->prev), sizeof(fb->prev));
    crc = append_crc_32(crc, (unsigned char *) (&fb->next), sizeof(fb->next));
    crc = append_crc_32(crc, (unsigned char *) (&fb->data_checksum), sizeof(fb->data_checksum));
    return crc;
}

static spacefs_status_t
sfs_link_block(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *block_area_begin, uint32_t block_to_add_to,
               uint32_t block_to_write_to) {
    block_t block_prev_read;
    uint32_t checksum;
    spacefs_address_t block_prev = spacefs_api_get_block_address(handle, block_area_begin, block_to_write_to);
    spacefs_address_t block_prev_write = block_prev;
    spacefs_status_t rc = spacefs_api_read(handle, &block_prev, (uint8_t *) &block_prev_read, sizeof(block_t),
                                           drive_nr);
    RETURN_PN_ERROR(rc)

    block_prev_read.next = block_to_add_to;

    checksum = sfs_calculate_crc_block(&block_prev_read);
    block_prev_read.checksum = checksum;

    return spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &block_prev_read, sizeof(block_t),
                                   drive_nr);
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
sfs_link_list_items(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t *block_area_begin,
                    spacefs_address_t *file_area_begin, size_t previous_block, size_t own_block, size_t next_block,
                    uint32_t data_checksum) {
    spacefs_status_t rc;

    spacefs_address_t block_prev;
    spacefs_address_t block_next;
    spacefs_address_t block_own = spacefs_api_get_block_address(handle, block_area_begin, own_block);

    spacefs_address_t block_prev_write;
    spacefs_address_t block_next_write;
    spacefs_address_t block_own_write = block_own;

    // Link previous block
    if (previous_block < handle->max_file_number) {
        file_block_t previous_block_data;
        uint32_t checksum = 0;
        block_prev = spacefs_api_get_file_address(handle, file_area_begin, previous_block);
        block_prev_write = block_prev;
        rc = spacefs_api_read_crc(handle, &block_prev, (uint8_t *) &previous_block_data, sizeof(file_block_t), drive_nr,
                                  &checksum);
        RETURN_PN_ERROR(rc)

        // read filename
        if (previous_block_data.filename_length >= handle->max_filename_length ||
            previous_block_data.filename_length >= handle->device_size ||
            previous_block_data.filename_length >= MAX_OP_LEN) {
            return SPACEFS_CHECKSUM;
        }
        previous_block_data.begin = own_block;
        checksum = append_crc_32(checksum, (uint8_t *) &own_block, sizeof own_block);

        rc = spacefs_api_read_crc_throwaway_data(handle, &block_prev, previous_block_data.filename_length, drive_nr,
                                                 &checksum);
        RETURN_PN_ERROR(rc)

        previous_block_data.checksum = checksum;
        rc = spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &previous_block_data,
                                       sizeof(file_block_t), drive_nr);
        RETURN_PN_ERROR(rc)
    } else {
        rc = sfs_link_block(handle, drive_nr, block_area_begin, own_block, previous_block);
        RETURN_PN_ERROR(rc)
    }
    uint32_t crc;

    // Link current block
    block_t block_own_read;
    rc = spacefs_api_read(handle, &block_own, (uint8_t *) &block_own_read, sizeof(block_t), drive_nr);
    RETURN_PN_ERROR(rc)

    block_own_read.prev = previous_block;
    block_own_read.next = next_block;
    block_own_read.data_checksum = data_checksum;

    /* Calculate Checksum */
    crc = sfs_calculate_crc_block(&block_own_read);
    block_own_read.checksum = crc;

    rc = spacefs_api_write_checked(handle, &block_own_write, (uint8_t *) &block_own_read, sizeof(block_t), drive_nr);
    RETURN_PN_ERROR(rc)

    // Link next block
    if (next_block < handle->max_file_number) {
        file_block_t next_block_data;
        uint32_t checksum = 0;
        block_next = spacefs_api_get_file_address(handle, file_area_begin, next_block);
        block_next_write = block_next;
        rc = spacefs_api_read_crc(handle, &block_next, (uint8_t *) &next_block_data, sizeof(file_block_t), drive_nr,
                                  &checksum);
        RETURN_PN_ERROR(rc)

        // read filename
        if (next_block_data.filename_length >= handle->max_filename_length ||
            next_block_data.filename_length >= handle->device_size ||
            next_block_data.filename_length >= MAX_OP_LEN) {
            return SPACEFS_CHECKSUM;
        }

        next_block_data.end = own_block;
        checksum = append_crc_32(checksum, (uint8_t *) &own_block, sizeof own_block);

        rc = spacefs_api_read_crc_throwaway_data(handle, &block_prev, next_block_data.filename_length, drive_nr,
                                                 &checksum);
        RETURN_PN_ERROR(rc)

        next_block_data.checksum = checksum;
        rc = spacefs_api_write_checked(handle, &block_next_write, (uint8_t *) &next_block_data,
                                       sizeof(file_block_t), drive_nr);
        RETURN_PN_ERROR(rc)
    } else {
        block_t block_next_read;
        block_next = spacefs_api_get_block_address(handle, block_area_begin, next_block);
        block_next_write = block_next;
        rc = spacefs_api_read(handle, &block_prev, (uint8_t *) &block_next_read, sizeof(block_t), drive_nr);
        RETURN_PN_ERROR(rc)

        block_next_read.prev = own_block;
        rc = spacefs_api_write_checked(handle, &block_prev_write, (uint8_t *) &block_next_read, sizeof(block_t),
                                       drive_nr);
        RETURN_PN_ERROR(rc)
    }
    return SPACEFS_OK;
}

/**
 * Adds/Sets the size of the file
 * @param handle The spacefs handle
 * @param drive_nr The drive nr
 * @param fb_address The address of the file block
 * @param size The size to add/set
 * @param absolute If true, we set the size to size, else we add size
 * @return error code
 */
static spacefs_status_t
sfs_update_size(spacefs_handle_t *handle, size_t drive_nr, spacefs_address_t fb_address, int size, bool absolute,
                uint32_t checksum, bool noupdate) {
    file_block_t fb;
    uint32_t _checksum = checksum;
    spacefs_address_t write_address = fb_address;
    spacefs_status_t rc = spacefs_api_read(handle, &fb_address, (uint8_t *) &fb, sizeof(file_block_t), drive_nr);
    RETURN_PN_ERROR(rc)

    if (!noupdate) {
        if (absolute) {
            if (size < 0) {
                return SPACEFS_INVALID_PARAMETER;
            }
            fb.size = size;
        } else {
            if (fb.size + size < 0) {
                return SPACEFS_INVALID_PARAMETER;
            }
            fb.size += size;
        }
    }

    if (fb.filename_length >= handle->max_filename_length ||
        fb.filename_length >= handle->device_size ||
        fb.filename_length >= MAX_OP_LEN) {
        return SPACEFS_CHECKSUM;
    }

    _checksum = sfs_calculate_crc_fileblock_no_file(&fb);
    rc = spacefs_api_read_crc_throwaway_data(handle, &fb_address, fb.filename_length, drive_nr, &_checksum);
    RETURN_PN_ERROR(rc);

    return spacefs_api_write_checked(handle, &write_address, (uint8_t *) &fb, sizeof(file_block_t), drive_nr);
}

/**
 * Writes data to a file
 * @param fd The handle to the file
 * @param data The data to write
 * @param size The length of the data
 * @return error code
 */
static spacefs_status_t spacefs_fwrite_internal(fd_t fd, uint8_t *data, size_t size) {
    spacefs_tuple_t addresses = spacefs_api_get_address_tuple(&fd, 0);

    size_t block_count_to_use = (size + fd.offset_read) / (fd.handle->block_size);
    if ((size + fd.offset_read) % (fd.handle->block_size) != 0) {
        block_count_to_use++;
    }

    size_t previous_block = fd.fp;
    size_t next_block = fd.fp;
    size_t bytes_written = 0;
    size_t bytes_skipped_or_written = 0;
    size_t len;

    size_t next_ = next_block;
    size_t previous_file_size;

    // In case we append a file we need to know how many bytes were overwritten and how many were appended...
    spacefs_status_t rc = spacefs_ftell(fd, &previous_file_size);
    RETURN_PN_ERROR(rc)

    for (int i = 0; i < block_count_to_use; i++) {
        size_t own_block;
        spacefs_address_t tmp_block_area = addresses.block_area_begin_address;
        spacefs_address_t tmp_fat_address = addresses.fat_address;
        spacefs_address_t block_address;

        rc = spacefs_api_get_next_block(fd.handle, addresses.file_area_begin, addresses.block_area_begin_address, next_,
                                        &next_, true,
                                        fd.drive_nr);
        RETURN_PN_ERROR(rc)

        if (next_ < fd.handle->max_file_number) {
            uint32_t checksum = 0;
            len = spacefs_api_limit_operation_to_block_size(size, &fd);

            /*
             * Only required when writing a new block
             */
            rc = sfs_set_unused_block(fd.handle, fd.drive_nr, &tmp_fat_address, &own_block);
            RETURN_CUSTOM_ERROR(rc, SPACEFS_BLOCK_FOUND);


            block_address = sfs_get_block_address(fd.handle, &tmp_block_area, own_block) + sizeof(block_t);

            rc = spacefs_api_write_checked_crc(fd.handle, &block_address, &data[bytes_written], len, &checksum,
                                               fd.drive_nr);
            RETURN_PN_ERROR(rc)

            /*
             * Only required when writing a new block
             */
            rc = sfs_link_list_items(fd.handle, fd.drive_nr, &tmp_block_area, &addresses.file_area_begin,
                                     previous_block,
                                     own_block,
                                     next_block, checksum);
            RETURN_PN_ERROR(rc)
            previous_block = own_block;

            rc = sfs_update_size(fd.handle, fd.drive_nr, addresses.file_idx_address, (int) len, false, checksum, false);
            RETURN_PN_ERROR(rc)

            bytes_written += len;
            if (size <= fd.handle->block_size) {
                size = 0;
                len = size;
            } else {
                size -= len;
                len = spacefs_api_limit_operation_to_block_size(size, &fd);
            }
            bytes_skipped_or_written += len;
            next_ = own_block;
        } else {
            uint32_t checksum = 0;
            if (bytes_skipped_or_written + fd.handle->block_size > fd.offset_read) {
                /* We need to write now */
                int byte_index = (int) fd.offset_read - (int) bytes_skipped_or_written;
                if (byte_index > 0 && size != 0) {
                    size_t bytes_to_write = fd.handle->block_size - byte_index;

                    if (bytes_to_write > fd.handle->block_size) {
                        bytes_to_write = fd.handle->block_size;
                    }
                    if (bytes_to_write > size) {
                        bytes_to_write = size;
                    }
                    block_address = sfs_get_block_address(fd.handle, &tmp_block_area, next_) + sizeof(block_t);
                    block_address += byte_index;

                    if (!byte_index) {
                        spacefs_address_t buffer = block_address;
                        rc = spacefs_api_read_crc_throwaway_data(fd.handle, &buffer, byte_index, fd.drive_nr,
                                                                 &checksum);
                        RETURN_PN_ERROR(rc);
                    }

                    rc = spacefs_api_write_checked_crc(fd.handle, &block_address, &data[bytes_written], bytes_to_write,
                                                       &checksum, fd.drive_nr);
                    RETURN_PN_ERROR(rc)

                    size_t written = bytes_to_write + byte_index;
                    if (written < fd.handle->block_size) {
                        size_t remaining = fd.handle->block_size - written;
                        rc = spacefs_api_read_crc_throwaway_data(fd.handle, &block_address, remaining, fd.drive_nr,
                                                                 &checksum);
                    }

                    bytes_written += bytes_to_write;
                    size -= bytes_to_write;
                    bytes_skipped_or_written += fd.handle->block_size;

                    size_t current_size = byte_index + bytes_to_write + (i * fd.handle->block_size);
                    rc = sfs_update_size(fd.handle, fd.drive_nr, addresses.file_idx_address, (int) (current_size),
                                         true, checksum, (current_size > previous_file_size));
                    RETURN_PN_ERROR(rc)
                }
            } else {
                bytes_skipped_or_written += fd.handle->block_size;
            }
            previous_block = next_;
        }
    }

    return rc;
}

spacefs_status_t spacefs_fwrite(fd_t *fd, uint8_t *data, size_t size) {
    spacefs_status_t rc = spacefs_api_check_handle(fd->handle);
    RETURN_PN_ERROR(rc)

    if (!(fd->mode & O_WRITE)) {
        return SPACEFS_INVALID_OPERATION;
    }

    if ((fd->mode & O_RING) == O_RING) {
        return spacefs_write_ringbuffer_internal(fd, data, size);
    } else {
        return spacefs_fwrite_internal(*fd, data, size);
    }
}

static bool spacefs_check_crc(mode_t mode) {
    return mode & O_IGNORE_CRC;
}

/**
 * Reads data from a file
 * @param fd The handle to the file
 * @param data The data to read
 * @param size The length of the data
 * @return error code
 */
static spacefs_status_t spacefs_fread_internal(fd_t fd, uint8_t *data, size_t size) {
    spacefs_tuple_t addresses = spacefs_api_get_address_tuple(&fd, 0);

    file_block_t fb;
    spacefs_status_t rc = spacefs_api_read(fd.handle, &addresses.file_idx_address, (uint8_t *) &fb, sizeof fb,
                                           fd.drive_nr);
    RETURN_PN_ERROR(rc)

    size_t next_block = fb.begin;
    size_t offset = 0;
    size_t length;
    size_t blocks_to_read;
    size_t bytes_read = 0;
    bool check_crc = spacefs_check_crc(fd.mode);
    bool crc_error = false;

    if (size + fd.offset_read > fb.size) {
        return SPACEFS_EOF;
    }

    blocks_to_read = spacefs_api_get_block_count(size, &fd);
    length = spacefs_api_limit_operation_to_block_size(size, &fd);

    for (int i = 0; i < blocks_to_read; i++) {
        block_t bt;
        uint32_t checksum;
        uint32_t data_checksum = 0;
        spacefs_address_t block_addr = spacefs_api_get_block_address(fd.handle, &addresses.block_area_begin_address,
                                                                     next_block);
        rc = spacefs_api_read(fd.handle, &block_addr, (uint8_t *) &bt, sizeof bt, fd.fp);
        RETURN_PN_ERROR(rc)

        checksum = sfs_calculate_crc_block(&bt);
        if (bt.checksum != checksum) {
            crc_error = true;
            if (check_crc) {
                return SPACEFS_CHECKSUM;
            }
        }

        if (bytes_read + length >= fd.offset_read) {
            size_t byte_offset = fd.offset_read - bytes_read;
            if (fd.offset_read < bytes_read) {
                byte_offset = 0;
            }
            size_t bytes_to_read = fd.handle->block_size - byte_offset;
            if (bytes_to_read > length) {
                bytes_to_read = length;
            }

            if (byte_offset != 0) {
                rc = spacefs_api_read_crc_throwaway_data(fd.handle, &block_addr, byte_offset, fd.drive_nr,
                                                         &data_checksum);
                RETURN_CUSTOM_ERROR(rc, SPACEFS_MATCH)
            }

            rc = spacefs_api_read_crc(fd.handle, &block_addr, &data[offset], bytes_to_read, fd.drive_nr,
                                      &data_checksum);
            RETURN_PN_ERROR(rc)

            if ((bytes_to_read + byte_offset) < fd.handle->block_size) {
                size_t remaining_bytes = fd.handle->block_size - (bytes_to_read + byte_offset);
                rc = spacefs_api_read_crc_throwaway_data(fd.handle, &block_addr, remaining_bytes, fd.drive_nr,
                                                         &data_checksum);
                RETURN_CUSTOM_ERROR(rc, SPACEFS_MATCH)
            }

            if (data_checksum != bt.data_checksum) {
                crc_error = true;
                if (check_crc) {
                    return SPACEFS_CHECKSUM;
                }
            }

            offset += bytes_to_read;
        }

        next_block = bt.next;
        size -= length;
        bytes_read += length;

        length = spacefs_api_limit_operation_to_block_size(size, &fd);
    }
    if (crc_error && rc == SPACEFS_OK) {
        return SPACEFS_OP_FINISHED_CHECKSUM_ERR;
    }
    return rc;
}

spacefs_status_t spacefs_fread(fd_t *fd, uint8_t *data, size_t size) {
    spacefs_status_t rc = spacefs_api_check_handle(fd->handle);
    RETURN_PN_ERROR(rc)

    if (!(fd->mode & O_READ)) {
        return SPACEFS_INVALID_OPERATION;
    }

    if (fd->mode & O_RING) {
        return spacefs_read_ringbuffer_internal(fd, data, size);
    } else {
        return spacefs_fread_internal(*fd, data, size);
    }
}

/**
 * Get size of file starting from begin
 * @param fd file descriptor
 * @param fd returns the size of the file
 * @return error code
 */
spacefs_status_t spacefs_ftell(fd_t fd, size_t *size) {
    spacefs_status_t rc = spacefs_api_check_handle(fd.handle);
    RETURN_PN_ERROR(rc)

    if (size == NULL) {
        return SPACEFS_INVALID_PARAMETER;
    }

    fp_t idx = fd.fp;
    spacefs_address_t file_table_address = spacefs_api_get_file_area_begin(0);
    spacefs_address_t file_idx_address = spacefs_api_get_file_address(fd.handle, &file_table_address, idx);

    file_block_t fb;
    rc = spacefs_api_read(fd.handle, &file_idx_address, (uint8_t *) &fb, sizeof fb, fd.drive_nr);
    RETURN_PN_ERROR(rc)

    (*size) = fb.size;
    return rc;
}

spacefs_status_t spacefs_fseek(fd_t *fd, size_t position, seek_type_t read_or_write) {
    if (fd == NULL) {
        return SPACEFS_INVALID_PARAMETER;
    }
    size_t size;
    spacefs_status_t rc = spacefs_ftell(*fd, &size);
    RETURN_PN_ERROR(rc)

    if (position == SPACEFS_SEEK_END) {
        if (read_or_write & READ) {
            fd->offset_read = size;
        }
        if (read_or_write & WRITE) {
            fd->offset_write = size;
        }
    } else if (position <= size) {
        if (read_or_write & READ) {
            fd->offset_read = position;
        }
        if (read_or_write & WRITE) {
            fd->offset_write = position;
        }
    } else {
        return SPACEFS_FILE_TOO_SMALL;
    }

    return SPACEFS_OK;
}

spacefs_status_t spacefs_create_ringbuffer(fd_t fd, size_t size, char *filename) {
    spacefs_status_t rc = spacefs_api_check_handle(fd.handle);
    RETURN_PN_ERROR(rc)

    fd.mode |= O_RING;

    uint8_t buffer[BURST_SIZE];
    memset(buffer, 0, sizeof buffer);

    size_t chunks_to_write = size / (sizeof buffer);
    if (size % (sizeof buffer)) {
        chunks_to_write++;
    }

    for (size_t i = 0; i < chunks_to_write; i++) {
        size_t data_to_write = sizeof buffer;
        if (size < sizeof buffer) {
            data_to_write = size;
        }

        rc = spacefs_fwrite_internal(fd, buffer, data_to_write);
        RETURN_PN_ERROR(rc)

        size -= data_to_write;
    }

    return SPACEFS_NO_SPACE_LEFT;
}

spacefs_status_t spacefs_read_ringbuffer_internal(fd_t *fd, uint8_t *data, size_t size) {
    size_t max_size;
    spacefs_status_t rc = spacefs_ftell(*fd, &max_size);
    RETURN_PN_ERROR(rc)

    if (size > max_size) {
        return SPACEFS_FILE_TOO_SMALL;
    }

    if (fd->offset_read + size <= max_size) {
        rc = spacefs_fread_internal(*fd, data, size);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, fd->offset_read + size, READ);
        RETURN_PN_ERROR(rc)
    } else {
        size_t len_of_first_chunk = max_size - fd->offset_read;
        size -= len_of_first_chunk;

        rc = spacefs_fread_internal(*fd, &data[0], len_of_first_chunk);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, 0, READ);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fread_internal(*fd, &data[len_of_first_chunk], size);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, size, READ);
        RETURN_PN_ERROR(rc)
    }
    return SPACEFS_OK;
}

spacefs_status_t spacefs_write_ringbuffer_internal(fd_t *fd, uint8_t *data, size_t size) {
    size_t max_size;
    spacefs_status_t rc = spacefs_ftell(*fd, &max_size);
    RETURN_PN_ERROR(rc)

    if (size > max_size) {
        return SPACEFS_FILE_TOO_SMALL;
    }

    if (fd->offset_read + size <= max_size) {
        rc = spacefs_fwrite_internal(*fd, data, size);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, fd->offset_read + size, WRITE);
        RETURN_PN_ERROR(rc)
    } else {
        size_t len_of_first_chunk = max_size - fd->offset_read;
        size -= len_of_first_chunk;

        rc = spacefs_fwrite_internal(*fd, &data[0], len_of_first_chunk);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, 0, WRITE);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fwrite_internal(*fd, &data[len_of_first_chunk], size);
        RETURN_PN_ERROR(rc)

        rc = spacefs_fseek(fd, size, WRITE);
        RETURN_PN_ERROR(rc)
    }
    return SPACEFS_OK;
}

/**
 * @brief Verify the filesystem integrity
 * @param fd file descriptor
 */
spacefs_status_t spacefs_verify_integrity(spacefs_handle_t *handle, size_t drive_nr) {
    discovery_block_t dt;
    spacefs_address_t address = 0;
    uint32_t crc = 0;
    spacefs_status_t rc = spacefs_api_check_handle(handle);
    RETURN_PN_ERROR(rc)

    rc = spacefs_api_read(handle, &address, (uint8_t *) &dt, sizeof(dt), drive_nr);
    RETURN_PN_ERROR(rc);

    crc = dt.checksum;

    sfs_calculate_discovery_block_crc(&dt);

    return crc == dt.checksum ? SPACEFS_OK : SPACEFS_CHECKSUM;
}

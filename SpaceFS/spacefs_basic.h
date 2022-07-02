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

#ifndef SPACEFS_BASIC_H
#define SPACEFS_BASIC_H

#ifdef __cplusplus
extern "C" {
#endif


#include "Internal/spacefs_internal_api.h"

typedef enum {
    READ = 1,
    WRITE = 2
} seek_type_t;

#define SPACEFS_SEEK_BEGIN 0
#define SPACEFS_SEEK_END -1

static const fd_t INVALID_FP = {-1, 0, 0, 0, NULL, 0};

#define O_READ   0x0001
#define O_WRITE  (O_READ << 1)
#define O_RDWR   (O_READ | O_WRITE)
#define O_CREAT  (O_RDWR << 1)
#define O_RING   (O_CREAT << 1)
#define O_IGNORE_CRC (O_RING << 1)

/**
 * Formats the filesystem for a given drive
 * @param handle The handle that contains the low-level callbacks(read, write) and some settings(block size, number of blocks)
 * @param drive_nr The physical drive number
 * @return error code
 */
spacefs_status_t spacefs_basic_format(spacefs_handle_t *handle, size_t drive_nr);

/**
 * Opens a file on a given drive
 * @param handle The handle that contains the low-level callbacks(read, write) and some settings(block size, number of blocks)
 * @param drive_nr The physical drive number
 * @param filename Filename to open
 * @param mode Mode to open the file with
 * @return A handle to the opened file
 */
fd_t spacefs_fopen(spacefs_handle_t *handle, size_t drive_nr, char *filename, mode_t mode);

/**
 * Writes data to a file
 * @param fd The handle to the file
 * @param data The data to write
 * @param size The length of the data
 * @return error code
 */
spacefs_status_t spacefs_fwrite(fd_t* fd, uint8_t *data, size_t size);

/**
 * Reads data from a file
 * @param fd The handle to the file
 * @param data The data to read
 * @param size The length of the data
 * @return error code
 */
spacefs_status_t spacefs_fread(fd_t* fd, uint8_t *data, size_t size);

/**
 * Get size of file starting from begin
 * @param fd file descriptor
 * @param fd returns the size of the file
 * @return error code
 */
spacefs_status_t spacefs_ftell(fd_t fd, size_t *size);

/**
 * Seeks to a specific position
 * @param fd The filedescriptor
 * @param position The position to seek to
 * @param read_or_write
 * @return error code
 */
spacefs_status_t spacefs_fseek(fd_t *fd, size_t position, seek_type_t read_or_write);

/**
 * Creates a ringbuffer WIP
 * @param fd
 * @param size
 * @param filename
 * @return
 */
spacefs_status_t spacefs_create_ringbuffer(fd_t fd, size_t size, char *filename);

#ifdef __cplusplus
}
#endif

#endif //SPACEFS_BASIC_H

#include <stdio.h>
#include <stdint-gcc.h>
#include <string.h>
#include <stdbool.h>
#include "SpaceFS/Internal/spacefs_internal_api.h"
#include "SpaceFS/spacefs_basic.h"

void create_eeprom_mock(const char *name, const size_t size_in_bytes, const uint8_t init_val) {
    FILE *f = fopen(name, "wb");
    if (f == NULL) {
        printf("Error opening file!\n");
        return;
    }
    for (size_t i = 0; i < size_in_bytes; i++) {
        fputc(init_val, f);
    }
    fclose(f);
}

void cleanup_eeprom_mock(const char* name) {

}


spacefs_status_t
spacefs_read(void *low_level_handle, uint32_t address, uint8_t *data, uint32_t length, size_t drive_nr) {
    char *eeprom_mock_name = (char *) low_level_handle;
    FILE* f = fopen(eeprom_mock_name, "rb");
    if (f == NULL) {
        printf("Error opening file!\n");
        return SPACEFS_ERROR;
    }
    fseek(f, address, SEEK_SET);
    fread(data, 1, length, f);
    fclose(f);
    return SPACEFS_OK;
}

spacefs_status_t
spacefs_write(void *low_level_handle, uint32_t address, uint8_t *data, uint32_t length, size_t drive_nr) {
    char *eeprom_mock_name = (char *) low_level_handle;
    FILE* f = fopen(eeprom_mock_name, "rb+");
    if (f == NULL) {
        printf("Error opening file!\n");
        return SPACEFS_ERROR;
    }
    fseek(f, address, SEEK_SET);
    for (size_t i = 0; i < length; i++) {
        fputc(data[i], f);
    }
    fclose(f);
    return SPACEFS_OK;
}


int main() {
    create_eeprom_mock("test.bin", 128*64*8, 'A');

    spacefs_handle_t handle;
    handle.read = spacefs_read;
    handle.write = spacefs_write;
    handle.low_level_handle = "test.bin";
    handle.max_file_number = 2;
    handle.max_filename_length = 10;
    handle.block_count = 128;
    handle.block_size = 64;

    if (spacefs_basic_format(&handle, 0) != SPACEFS_OK) {
        printf("Error formatting!\n");
        return 1;
    }
    fd_t fd = spacefs_fopen(&handle, 0, "test.txt", O_CREAT | O_RDWR);
    if (fd.fp == -1) {
        printf("Error opening file!\n");
        return 1;
    }

    fd_t fd2 = spacefs_fopen(&handle, 0, "test2.txt", O_CREAT | O_RDWR);
    if (fd2.fp == -1) {
        printf("Error opening file!\n");
        return 1;
    }

    uint8_t buffer[200];
    uint8_t read_buffer[200];
    memset(buffer, 'X', sizeof buffer);
    memset(read_buffer, 0, sizeof read_buffer);

    spacefs_status_t write = spacefs_fwrite(fd, buffer, sizeof buffer);
    if (write != SPACEFS_OK) {
        while(true);
    }

    spacefs_status_t read = spacefs_fread(fd, read_buffer, sizeof read_buffer);
    if (read != SPACEFS_OK) {
        while(true);
    }
    
    return 0;
}

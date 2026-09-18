/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

#ifndef NVOL_STORAGE_H
#define NVOL_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keys.h" // SALT_LEN, KEY_LEN

// Non-volatile storage interface for keys and configuration.

// Create the storage directory if needed. use_bin_format picks raw .bin vs
// human-readable .txt.
signed char nvol_storage_init(const char *base_path_ptr, bool use_bin_format);

void nvol_storage_cleanup(void);

signed char nvol_storage_read(const char *path_ptr, uint8_t *data_ptr, size_t max_len,
                              size_t *actual_len_ptr);
signed char nvol_storage_write(const char *path_ptr, const uint8_t *data_ptr, size_t len);
signed char nvol_storage_write_u8(const char *path_ptr, uint8_t value);
signed char nvol_storage_read_u8(const char *path_ptr, uint8_t *value_ptr);
signed char nvol_storage_write_u16(const char *path_ptr, uint16_t value);
signed char nvol_storage_read_u16(const char *path_ptr, uint16_t *value_ptr);
signed char nvol_storage_write_u32(const char *path_ptr, uint32_t value);
signed char nvol_storage_read_u32(const char *path_ptr, uint32_t *value_ptr);
signed char nvol_storage_write_u64(const char *path_ptr, uint64_t value);
signed char nvol_storage_read_u64(const char *path_ptr, uint64_t *value_ptr);
signed char nvol_storage_write_key_id(const char *path_ptr, uint32_t key_id);
signed char nvol_storage_read_key_id(const char *path_ptr, uint32_t *key_id_ptr);
signed char nvol_storage_write_varlen(const char *path_ptr,
                                      const uint8_t *data_ptr, size_t len);
signed char nvol_storage_read_varlen(const char *path_ptr, uint8_t *data_ptr,
                                     size_t max_len, size_t *actual_len_ptr);

// Allocating variant of read_varlen; caller must free *data_ptr.
signed char nvol_storage_read_varlen_alloc(const char *path_ptr, uint8_t **data_ptr,
                                           size_t *len_ptr);

signed char nvol_storage_write_key(const char *path_ptr, const uint8_t key_ptr[32]);
signed char nvol_storage_read_key(const char *path_ptr, uint8_t key_ptr[32]);
signed char nvol_storage_write_salt(const char *path_ptr,
                                    const uint8_t salt_ptr[SALT_LEN]);
signed char nvol_storage_read_salt(const char *path_ptr, uint8_t salt_ptr[SALT_LEN]);
signed char nvol_storage_delete(const char *path_ptr);
bool nvol_storage_exists(const char *path_ptr);
void nvol_storage_list_keys(void);

// Load key hex value from provisioning file (-k debug path).
uint8_t *retrieve_dict_from_file(const char *filename_ptr, const char *key_ptr,
                                 size_t *out_len_ptr);

#endif // NVOL_STORAGE_H
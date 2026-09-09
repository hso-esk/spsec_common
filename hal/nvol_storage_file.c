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

#include "nvol_storage_adapter.h"
#include "platform_nvol_storage.h"

static signed char file_storage_init(const char *base_path_ptr, bool use_bin_format) {
  return platform_nvol_storage_init(base_path_ptr, use_bin_format);
}

static void file_storage_cleanup(void) {
  platform_nvol_storage_cleanup();
}

static signed char file_storage_read(const char *path_ptr, uint8_t *data_ptr, size_t max_len,
                                     size_t *actual_len_ptr) {
  return platform_nvol_storage_read(path_ptr, data_ptr, max_len, actual_len_ptr);
}

static signed char file_storage_write(const char *path_ptr, const uint8_t *data_ptr,
                                      size_t len) {
  return platform_nvol_storage_write(path_ptr, data_ptr, len);
}

static signed char file_storage_write_u8(const char *path_ptr, uint8_t value) {
  return platform_nvol_storage_write_u8(path_ptr, value);
}

static signed char file_storage_read_u8(const char *path_ptr, uint8_t *value_ptr) {
  return platform_nvol_storage_read_u8(path_ptr, value_ptr);
}

static signed char file_storage_write_u32(const char *path_ptr, uint32_t value) {
  return platform_nvol_storage_write_u32(path_ptr, value);
}

static signed char file_storage_read_u32(const char *path_ptr, uint32_t *value_ptr) {
  return platform_nvol_storage_read_u32(path_ptr, value_ptr);
}

static signed char file_storage_write_u64(const char *path_ptr, uint64_t value) {
  return platform_nvol_storage_write_u64(path_ptr, value);
}

static signed char file_storage_read_u64(const char *path_ptr, uint64_t *value_ptr) {
  return platform_nvol_storage_read_u64(path_ptr, value_ptr);
}

static signed char file_storage_write_u16(const char *path_ptr, uint16_t value) {
  return platform_nvol_storage_write_u16(path_ptr, value);
}

static signed char file_storage_read_u16(const char *path_ptr, uint16_t *value_ptr) {
  return platform_nvol_storage_read_u16(path_ptr, value_ptr);
}

static signed char file_storage_write_key_id(const char *path_ptr, uint32_t key_id) {
  return platform_nvol_storage_write_key_id(path_ptr, key_id);
}

static signed char file_storage_read_key_id(const char *path_ptr, uint32_t *key_id_ptr) {
  return platform_nvol_storage_read_key_id(path_ptr, key_id_ptr);
}

static signed char file_storage_read_varlen(const char *path_ptr, uint8_t *data_ptr,
                                            size_t max_len, size_t *actual_len_ptr) {
  return platform_nvol_storage_read_varlen(path_ptr, data_ptr, max_len, actual_len_ptr);
}

static signed char file_storage_read_varlen_alloc(const char *path_ptr, uint8_t **data_ptr,
                                                  size_t *len_ptr) {
  return platform_nvol_storage_read_varlen_alloc(path_ptr, data_ptr, len_ptr);
}

static signed char file_storage_write_varlen(const char *path_ptr,
                                             const uint8_t *data_ptr, size_t len) {
  return platform_nvol_storage_write_varlen(path_ptr, data_ptr, len);
}

static signed char file_storage_write_key(const char *path_ptr, const uint8_t key_ptr[32]) {
  return platform_nvol_storage_write_key(path_ptr, key_ptr);
}

static signed char file_storage_read_key(const char *path_ptr, uint8_t key_ptr[32]) {
  return platform_nvol_storage_read_key(path_ptr, key_ptr);
}

static signed char file_storage_write_salt(const char *path_ptr,
                                           const uint8_t salt_ptr[SALT_LEN]) {
  return platform_nvol_storage_write_salt(path_ptr, salt_ptr);
}

static signed char file_storage_read_salt(const char *path_ptr, uint8_t salt_ptr[SALT_LEN]) {
  return platform_nvol_storage_read_salt(path_ptr, salt_ptr);
}

static signed char file_storage_delete(const char *path_ptr) {
  return platform_nvol_storage_delete(path_ptr);
}

static bool file_storage_exists(const char *path_ptr) {
  return platform_nvol_storage_exists(path_ptr);
}

static void file_storage_list_keys(void) {
  platform_nvol_storage_list_keys();
}

static uint8_t *file_storage_retrieve_dict_from_file(const char *filename_ptr,
                                                     const char *key_ptr,
                                                     size_t *out_len_ptr) {
  return platform_retrieve_dict_from_file(filename_ptr, key_ptr, out_len_ptr);
}

static const NvolStorageVTable file_storage_vtable = {
    .init = file_storage_init,
    .cleanup = file_storage_cleanup,
    .read = file_storage_read,
    .write = file_storage_write,
    .write_u8 = file_storage_write_u8,
    .read_u8 = file_storage_read_u8,
    .write_u32 = file_storage_write_u32,
    .read_u32 = file_storage_read_u32,
    .write_u64 = file_storage_write_u64,
    .read_u64 = file_storage_read_u64,
    .write_u16 = file_storage_write_u16,
    .read_u16 = file_storage_read_u16,
    .write_key_id = file_storage_write_key_id,
    .read_key_id = file_storage_read_key_id,
    .read_varlen = file_storage_read_varlen,
    .read_varlen_alloc = file_storage_read_varlen_alloc,
    .write_varlen = file_storage_write_varlen,
    .write_key = file_storage_write_key,
    .read_key = file_storage_read_key,
    .write_salt = file_storage_write_salt,
    .read_salt = file_storage_read_salt,
    .delete = file_storage_delete,
    .exists = file_storage_exists,
    .list_keys = file_storage_list_keys,
    .retrieve_dict_from_file = file_storage_retrieve_dict_from_file,
};

static const NvolStorageBackend file_storage_backend = {
    .id = "file",
    .name = "File-based NVOL Storage",
    .vtable = &file_storage_vtable,
};

const NvolStorageBackend *nvol_storage_backend_file(void) {
  return &file_storage_backend;
}
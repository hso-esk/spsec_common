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

#include "nvol_storage.h"
#include "nvol_storage_adapter.h"
#include "nvol_storage_registry.h"

static const NvolStorageVTable *g_active_vtable_ptr = NULL;

signed char nvol_storage_init(const char *base_path_ptr, bool use_bin_format) {
  const NvolStorageBackend *backend_ptr = nvol_storage_backend_default();
  if (!backend_ptr || !backend_ptr->vtable || !backend_ptr->vtable->init) {
    return -1;
  }
  g_active_vtable_ptr = backend_ptr->vtable;
  return backend_ptr->vtable->init(base_path_ptr, use_bin_format);
}

void nvol_storage_cleanup(void) {
  if (g_active_vtable_ptr && g_active_vtable_ptr->cleanup) {
    g_active_vtable_ptr->cleanup();
  }
  g_active_vtable_ptr = NULL;
}

signed char nvol_storage_read(const char *path_ptr, uint8_t *data_ptr, size_t max_len,
                              size_t *actual_len_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read) {
    return -1;
  }
  return g_active_vtable_ptr->read(path_ptr, data_ptr, max_len, actual_len_ptr);
}

signed char nvol_storage_write(const char *path_ptr, const uint8_t *data_ptr,
                               size_t len) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write) {
    return -1;
  }
  return g_active_vtable_ptr->write(path_ptr, data_ptr, len);
}

signed char nvol_storage_write_u8(const char *path_ptr, uint8_t value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_u8) {
    return -1;
  }
  return g_active_vtable_ptr->write_u8(path_ptr, value_ptr);
}

signed char nvol_storage_read_u8(const char *path_ptr, uint8_t *value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_u8) {
    return -1;
  }
  return g_active_vtable_ptr->read_u8(path_ptr, value_ptr);
}

signed char nvol_storage_write_u32(const char *path_ptr, uint32_t value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_u32) {
    return -1;
  }
  return g_active_vtable_ptr->write_u32(path_ptr, value_ptr);
}

signed char nvol_storage_read_u32(const char *path_ptr, uint32_t *value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_u32) {
    return -1;
  }
  return g_active_vtable_ptr->read_u32(path_ptr, value_ptr);
}

signed char nvol_storage_write_u64(const char *path_ptr, uint64_t value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_u64) {
    return -1;
  }
  return g_active_vtable_ptr->write_u64(path_ptr, value_ptr);
}

signed char nvol_storage_read_u64(const char *path_ptr, uint64_t *value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_u64) {
    return -1;
  }
  return g_active_vtable_ptr->read_u64(path_ptr, value_ptr);
}

signed char nvol_storage_write_u16(const char *path_ptr, uint16_t value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_u16) {
    return -1;
  }
  return g_active_vtable_ptr->write_u16(path_ptr, value_ptr);
}

signed char nvol_storage_read_u16(const char *path_ptr, uint16_t *value_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_u16) {
    return -1;
  }
  return g_active_vtable_ptr->read_u16(path_ptr, value_ptr);
}

signed char nvol_storage_write_key_id(const char *path_ptr, uint32_t key_id_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_key_id) {
    return -1;
  }
  return g_active_vtable_ptr->write_key_id(path_ptr, key_id_ptr);
}

signed char nvol_storage_read_key_id(const char *path_ptr, uint32_t *key_id_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_key_id) {
    return -1;
  }
  return g_active_vtable_ptr->read_key_id(path_ptr, key_id_ptr);
}

signed char nvol_storage_write_varlen(const char *path_ptr,
                                      const uint8_t *data_ptr, size_t len) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_varlen) {
    return -1;
  }
  return g_active_vtable_ptr->write_varlen(path_ptr, data_ptr, len);
}

signed char nvol_storage_read_varlen(const char *path_ptr, uint8_t *data_ptr,
                                     size_t max_len, size_t *actual_len_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_varlen) {
    return -1;
  }
  return g_active_vtable_ptr->read_varlen(path_ptr, data_ptr, max_len, actual_len_ptr);
}

signed char nvol_storage_read_varlen_alloc(const char *path_ptr, uint8_t **data_ptr,
                                           size_t *len_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_varlen_alloc) {
    return -1;
  }
  return g_active_vtable_ptr->read_varlen_alloc(path_ptr, data_ptr, len_ptr);
}

signed char nvol_storage_write_key(const char *path_ptr, const uint8_t key_ptr[32]) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_key) {
    return -1;
  }
  return g_active_vtable_ptr->write_key(path_ptr, key_ptr);
}

signed char nvol_storage_read_key(const char *path_ptr, uint8_t key_ptr[32]) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_key) {
    return -1;
  }
  return g_active_vtable_ptr->read_key(path_ptr, key_ptr);
}

signed char nvol_storage_write_salt(const char *path_ptr,
                                    const uint8_t salt_ptr[SALT_LEN]) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->write_salt) {
    return -1;
  }
  return g_active_vtable_ptr->write_salt(path_ptr, salt_ptr);
}

signed char nvol_storage_read_salt(const char *path_ptr, uint8_t salt_ptr[SALT_LEN]) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->read_salt) {
    return -1;
  }
  return g_active_vtable_ptr->read_salt(path_ptr, salt_ptr);
}

signed char nvol_storage_delete(const char *path_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->delete) {
    return -1;
  }
  return g_active_vtable_ptr->delete(path_ptr);
}

bool nvol_storage_exists(const char *path_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->exists) {
    return false;
  }
  return g_active_vtable_ptr->exists(path_ptr);
}

void nvol_storage_list_keys(void) {
  if (g_active_vtable_ptr && g_active_vtable_ptr->list_keys) {
    g_active_vtable_ptr->list_keys();
  }
}

uint8_t *retrieve_dict_from_file(const char *filename_ptr, const char *key_ptr,
                                 size_t *out_len_ptr) {
  if (!g_active_vtable_ptr || !g_active_vtable_ptr->retrieve_dict_from_file) {
    return NULL;
  }
  return g_active_vtable_ptr->retrieve_dict_from_file(filename_ptr, key_ptr, out_len_ptr);
}
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

#include "crypto_kdf.h"

int crypto_hkdf_sha256(const uint8_t *ikm_ptr, size_t ikm_len,
                       const uint8_t *salt_ptr, size_t salt_len,
                       const uint8_t *info_ptr, size_t info_len,
                       uint8_t *okm_ptr, size_t okm_len) {
  const KdfBackend *backend_ptr = kdf_backend_default();
  if (!backend_ptr || !backend_ptr->vtable || !backend_ptr->vtable->hkdf_sha256) {
    return -1;
  }
  return backend_ptr->vtable->hkdf_sha256(ikm_ptr, ikm_len, salt_ptr, salt_len, info_ptr,
                                          info_len, okm_ptr, okm_len);
}
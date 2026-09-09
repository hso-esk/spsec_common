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

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

static int mbedtls_kdf_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   uint8_t *okm, size_t okm_len) {
  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md_info) {
    return -1;
  }

  int ret = mbedtls_hkdf(md_info, salt, salt_len, ikm, ikm_len, info, info_len,
                         okm, okm_len);
  return ret == 0 ? 0 : -1;
}

static const KdfBackendVTable mbedtls_kdf_vtable = {
    .hkdf_sha256 = mbedtls_kdf_hkdf_sha256,
};

static const KdfBackend mbedtls_kdf_backend = {
    .id = "mbedtls",
    .name = "mbedTLS KDF",
    .vtable = &mbedtls_kdf_vtable,
};

const KdfBackend *kdf_backend_mbedtls(void) {
  return &mbedtls_kdf_backend;
}
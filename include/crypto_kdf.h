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

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stddef.h>
#include <stdint.h>

// Pluggable KDF backend vtable (same pattern as CryptoBackendVTable).
typedef struct KdfBackendVTable {
  int (*hkdf_sha256)(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *okm, size_t okm_len);
} KdfBackendVTable;

typedef struct KdfBackend {
  const char *id;
  const char *name;
  const KdfBackendVTable *vtable;
} KdfBackend;

#if defined(SPSEC_ENABLE_MBEDTLS)
const KdfBackend *kdf_backend_mbedtls(void);
#endif

#if defined(SPSEC_ENABLE_WOLFSSL)
const KdfBackend *kdf_backend_wolfssl(void);
#endif

const KdfBackend *kdf_backend_default(void);

// Look up a backend by id, e.g. "mbedtls" or "wolfssl". NULL if no match.
const KdfBackend *kdf_backend_by_id(const char *id_ptr);

// HKDF-SHA256 via the currently selected backend. salt/info may be NULL
// when their _len is 0. Returns 0 on success, -1 on failure.
int crypto_hkdf_sha256(const uint8_t *ikm_ptr, size_t ikm_len,
                       const uint8_t *salt_ptr, size_t salt_len,
                       const uint8_t *info_ptr, size_t info_len,
                       uint8_t *okm_ptr, size_t okm_len);

// Fills out[] with up to max_entries available backends; returns the count.
size_t kdf_backend_available(const KdfBackend *out[], size_t max_entries);

#endif /* CRYPTO_KDF_H */
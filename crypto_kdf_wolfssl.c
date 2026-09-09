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

#include <wolfssl/options.h>
#ifndef WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#endif
#ifndef HAVE_ASCON
#define HAVE_ASCON
#endif
#ifndef WOLFSSL_ASCON
#define WOLFSSL_ASCON
#endif
#include <wolfssl/wolfcrypt/hmac.h>

static int wolfssl_kdf_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   uint8_t *okm, size_t okm_len) {
  int ret = wc_HKDF(WC_SHA256, ikm, (word32)ikm_len, salt, (word32)salt_len,
                    info, (word32)info_len, okm, (word32)okm_len);
  return ret == 0 ? 0 : -1;
}

static const KdfBackendVTable wolfssl_kdf_vtable = {
    .hkdf_sha256 = wolfssl_kdf_hkdf_sha256,
};

static const KdfBackend wolfssl_kdf_backend = {
    .id = "wolfssl",
    .name = "wolfSSL KDF",
    .vtable = &wolfssl_kdf_vtable,
};

const KdfBackend *kdf_backend_wolfssl(void) {
  return &wolfssl_kdf_backend;
}
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

#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto_types.h"

typedef struct CryptoBackend CryptoBackend;

typedef struct {
  const char *id;
  const char *name;
  uint32_t capability_flags;

  int (*init)(void **state);
  void (*destroy)(void *state);

  int (*configure)(void *state, CryptoAlgorithm algorithm, const uint8_t *key,
                   size_t key_len, const uint8_t *nonce, size_t nonce_len,
                   int mac_len);

  int (*encrypt)(void *state, const uint8_t *input, size_t input_len,
                 uint8_t *output, const uint8_t *aad, size_t aad_len,
                 uint8_t *tag);

  int (*decrypt)(void *state, const uint8_t *input, size_t input_len,
                 uint8_t *output, const uint8_t *aad, size_t aad_len,
                 const uint8_t *tag);

  bool (*supports_algorithm)(const CryptoBackend *self,
                             CryptoAlgorithm algorithm);
} CryptoBackendVTable;

struct CryptoBackend {
  const char *id;
  const char *name;
  uint32_t capability_flags;
  const CryptoBackendVTable *vtable;
};

#if defined(SPSEC_ENABLE_MBEDTLS)
const CryptoBackend *crypto_backend_mbedtls(void);
#endif

#if defined(SPSEC_ENABLE_WOLFSSL)
const CryptoBackend *crypto_backend_wolfssl(void);
#endif

const CryptoBackend *crypto_backend_default(void);
const CryptoBackend *crypto_backend_by_id(const char *id);
size_t crypto_backend_available(const CryptoBackend *out[], size_t max_entries);

#endif /* CRYPTO_BACKEND_H */

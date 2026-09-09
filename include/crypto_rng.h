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

#ifndef CRYPTO_RNG_H
#define CRYPTO_RNG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(SPSEC_ENABLE_MBEDTLS)
#include <mbedtls/entropy.h>
#include <mbedtls/hmac_drbg.h>
#elif defined(SPSEC_ENABLE_WOLFSSL)
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
#include <wolfssl/wolfcrypt/random.h>
#else
#error "No crypto RNG backend selected"
#endif

typedef struct {
#if defined(SPSEC_ENABLE_MBEDTLS)
  mbedtls_entropy_context entropy;
  mbedtls_hmac_drbg_context drbg;
#elif defined(SPSEC_ENABLE_WOLFSSL)
  WC_RNG rng;
#endif
  bool initialized;
} CryptoRng;

int crypto_rng_init(CryptoRng *rng);
void crypto_rng_free(CryptoRng *rng);
int crypto_rng_get_bytes(CryptoRng *rng, uint8_t *out, size_t out_len);

#endif /* CRYPTO_RNG_H */

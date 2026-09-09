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

#include "crypto_rng.h"

#include <mbedtls/md.h>
#include <string.h>

int crypto_rng_init(CryptoRng *rng) {
  if (!rng)
    return -1;

  mbedtls_entropy_init(&rng->entropy);
  mbedtls_hmac_drbg_init(&rng->drbg);

  const char *personalization = "spsec_participant_random";
  int ret = mbedtls_hmac_drbg_seed(
      &rng->drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      mbedtls_entropy_func, &rng->entropy,
      (const unsigned char *)personalization, strlen(personalization));
  if (ret != 0) {
    mbedtls_hmac_drbg_free(&rng->drbg);
    mbedtls_entropy_free(&rng->entropy);
    rng->initialized = false;
    return -1;
  }

  rng->initialized = true;
  return 0;
}

void crypto_rng_free(CryptoRng *rng) {
  if (!rng || !rng->initialized)
    return;

  mbedtls_hmac_drbg_free(&rng->drbg);
  mbedtls_entropy_free(&rng->entropy);
  rng->initialized = false;
}

int crypto_rng_get_bytes(CryptoRng *rng, uint8_t *out, size_t out_len) {
  if (!rng || !rng->initialized || !out)
    return -1;

  return mbedtls_hmac_drbg_random(&rng->drbg, out, out_len) == 0 ? 0 : -1;
}

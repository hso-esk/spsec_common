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

int crypto_rng_init(CryptoRng *rng) {
  if (!rng)
    return -1;

  int ret = wc_InitRng(&rng->rng);
  if (ret != 0) {
    rng->initialized = false;
    return -1;
  }

  rng->initialized = true;
  return 0;
}

void crypto_rng_free(CryptoRng *rng) {
  if (!rng || !rng->initialized)
    return;

  wc_FreeRng(&rng->rng);
  rng->initialized = false;
}

int crypto_rng_get_bytes(CryptoRng *rng, uint8_t *out, size_t out_len) {
  if (!rng || !rng->initialized || !out)
    return -1;

  int ret = wc_RNG_GenerateBlock(&rng->rng, out, (word32)out_len);
  return ret == 0 ? 0 : -1;
}

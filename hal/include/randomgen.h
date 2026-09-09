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

#ifndef RANDOMGEN_H
#define RANDOMGEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto_rng.h"

typedef struct {
  CryptoRng core;
  bool initialized;
} RandomGenerator;

signed char random_generator_init(RandomGenerator *rg_ptr);
uint8_t *random_generator_get_bytes(RandomGenerator *rg_ptr, size_t num_bytes);

/** @brief Release the underlying CryptoRng (frees the HMAC-DRBG context). */
void random_generator_free(RandomGenerator *rg_ptr);

#endif
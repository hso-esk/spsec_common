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

#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include <stddef.h>

typedef enum {
  CRYPTO_ALGO_AES_GCM = 0,
  CRYPTO_ALGO_CHACHA20_POLY1305,
  CRYPTO_ALGO_ASCON128
} CryptoAlgorithm;

// Nonce length in bytes: 12 for AES-GCM/ChaCha20-Poly1305, 16 for ASCON-128.
size_t crypto_get_nonce_len(CryptoAlgorithm algo);

#endif /* CRYPTO_TYPES_H */

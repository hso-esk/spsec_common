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

#ifndef CRYPTO_BACKEND_REGISTRY_H
#define CRYPTO_BACKEND_REGISTRY_H

#include "crypto_backend.h"

const CryptoBackend *crypto_backend_default(void);
const CryptoBackend *crypto_backend_by_id(const char *id_ptr);
size_t crypto_backend_available(const CryptoBackend *out_backends_ptr[],
                                size_t max_entries);

#endif /* CRYPTO_BACKEND_REGISTRY_H */

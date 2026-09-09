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

#include "crypto_backend_registry.h"
#include "spsec_common.h"
#include <ctype.h>

#include <stddef.h>

#if !defined(SPSEC_ENABLE_MBEDTLS) && !defined(SPSEC_ENABLE_WOLFSSL)
#error                                                                         \
    "No crypto backend enabled. Set SPSEC_CRYPTO_BACKEND in CMake to 'mbedtls' or 'wolfssl'."
#endif

static const CryptoBackend *g_backends[2];
static size_t g_backend_count = 0;
static bool g_initialised = false;

static void ensure_registry_initialised(void) {
  if (g_initialised)
    return;

#if defined(SPSEC_ENABLE_MBEDTLS)
  g_backends[g_backend_count++] = crypto_backend_mbedtls();
#endif
#if defined(SPSEC_ENABLE_WOLFSSL)
  g_backends[g_backend_count++] = crypto_backend_wolfssl();
#endif
  g_initialised = true;
}

const CryptoBackend *crypto_backend_default(void) {
  ensure_registry_initialised();
  if (g_backend_count == 0) {
    return NULL;
  }
  return g_backends[0];
}

const CryptoBackend *crypto_backend_by_id(const char *id_ptr) {
  ensure_registry_initialised();

  if (g_backend_count == 0) {
    return NULL;
  }

  if (!id_ptr || *id_ptr == '\0') {
    return crypto_backend_default();
  }

  for (size_t i = 0; i < g_backend_count; ++i) {
    if (g_backends[i] && g_backends[i]->id &&
        strcmp(g_backends[i]->id, id_ptr) == 0) {
      return g_backends[i];
    }
  }

  for (size_t i = 0; i < g_backend_count; ++i) {
    if (!g_backends[i] || !g_backends[i]->name)
      continue;

    const char *name_ptr = g_backends[i]->name;
    size_t idx = 0;
    while (id_ptr[idx] && name_ptr[idx]) {
      unsigned char lhs = (unsigned char)tolower((unsigned char)id_ptr[idx]);
      unsigned char rhs = (unsigned char)tolower((unsigned char)name_ptr[idx]);
      if (lhs != rhs) {
        break;
      }
      ++idx;
    }
    if (id_ptr[idx] == '\0' && (name_ptr[idx] == '\0' || name_ptr[idx] == ' ')) {
      return g_backends[i];
    }
  }
  return NULL;
}

size_t crypto_backend_available(const CryptoBackend *out_backends_ptr[],
                                size_t max_entries) {
  ensure_registry_initialised();

  size_t written = 0;
  for (size_t i = 0; i < g_backend_count && written < max_entries; ++i) {
    if (g_backends[i]) {
      out_backends_ptr[written++] = g_backends[i];
    }
  }
  return written;
}

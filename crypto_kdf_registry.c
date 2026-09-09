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
#include "spsec_common.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>

static const KdfBackend *g_kdf_backends[2];
static size_t g_kdf_backend_count = 0;
static bool g_kdf_initialised = false;

static void ensure_kdf_registry_initialised(void) {
  if (g_kdf_initialised)
    return;

#if defined(SPSEC_ENABLE_MBEDTLS)
  g_kdf_backends[g_kdf_backend_count++] = kdf_backend_mbedtls();
#endif
#if defined(SPSEC_ENABLE_WOLFSSL)
  g_kdf_backends[g_kdf_backend_count++] = kdf_backend_wolfssl();
#endif
  g_kdf_initialised = true;
}

const KdfBackend *kdf_backend_default(void) {
  ensure_kdf_registry_initialised();
  if (g_kdf_backend_count == 0) {
    return NULL;
  }
  return g_kdf_backends[0];
}

const KdfBackend *kdf_backend_by_id(const char *id_ptr) {
  ensure_kdf_registry_initialised();

  if (g_kdf_backend_count == 0) {
    return NULL;
  }

  if (!id_ptr || *id_ptr == '\0') {
    return kdf_backend_default();
  }

  for (size_t i = 0; i < g_kdf_backend_count; ++i) {
    if (g_kdf_backends[i] && g_kdf_backends[i]->id &&
        strcmp(g_kdf_backends[i]->id, id_ptr) == 0) {
      return g_kdf_backends[i];
    }
  }

  for (size_t i = 0; i < g_kdf_backend_count; ++i) {
    if (!g_kdf_backends[i] || !g_kdf_backends[i]->name)
      continue;

    const char *name_ptr = g_kdf_backends[i]->name;
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
      return g_kdf_backends[i];
    }
  }
  return NULL;
}

size_t kdf_backend_available(const KdfBackend *out_ptr[], size_t max_entries) {
  ensure_kdf_registry_initialised();

  size_t written = 0;
  for (size_t i = 0; i < g_kdf_backend_count && written < max_entries; ++i) {
    if (g_kdf_backends[i]) {
      out_ptr[written++] = g_kdf_backends[i];
    }
  }
  return written;
}
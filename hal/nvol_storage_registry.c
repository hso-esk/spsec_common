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

#include "nvol_storage_adapter.h"
#include "spsec_common.h"
#include <ctype.h>
#include <stddef.h>
#include <string.h>

static const NvolStorageBackend *g_nvol_backends[2];
static size_t g_nvol_backend_count = 0;
static bool g_nvol_initialised = false;

static void ensure_nvol_registry_initialised(void) {
  if (g_nvol_initialised)
    return;

  g_nvol_backends[g_nvol_backend_count++] = nvol_storage_backend_file();
  g_nvol_initialised = true;
}

const NvolStorageBackend *nvol_storage_backend_default(void) {
  ensure_nvol_registry_initialised();
  if (g_nvol_backend_count == 0) {
    return NULL;
  }
  return g_nvol_backends[0];
}

const NvolStorageBackend *nvol_storage_backend_by_id(const char *id_ptr) {
  ensure_nvol_registry_initialised();

  if (g_nvol_backend_count == 0) {
    return NULL;
  }

  if (!id_ptr || *id_ptr == '\0') {
    return nvol_storage_backend_default();
  }

  for (size_t i = 0; i < g_nvol_backend_count; ++i) {
    if (g_nvol_backends[i] && g_nvol_backends[i]->id &&
        strcmp(g_nvol_backends[i]->id, id_ptr) == 0) {
      return g_nvol_backends[i];
    }
  }

  for (size_t i = 0; i < g_nvol_backend_count; ++i) {
    if (!g_nvol_backends[i] || !g_nvol_backends[i]->name)
      continue;

    const char *name_ptr = g_nvol_backends[i]->name;
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
      return g_nvol_backends[i];
    }
  }
  return NULL;
}

size_t nvol_storage_backend_available(const NvolStorageBackend *out_ptr[],
                                      size_t max_entries) {
  ensure_nvol_registry_initialised();

  size_t written = 0;
  for (size_t i = 0; i < g_nvol_backend_count && written < max_entries; ++i) {
    if (g_nvol_backends[i]) {
      out_ptr[written++] = g_nvol_backends[i];
    }
  }
  return written;
}
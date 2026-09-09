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

#ifndef NVOL_STORAGE_REGISTRY_H
#define NVOL_STORAGE_REGISTRY_H

#include "nvol_storage_adapter.h"

const NvolStorageBackend *nvol_storage_backend_default(void);
const NvolStorageBackend *nvol_storage_backend_by_id(const char *id_ptr);
const NvolStorageBackend *nvol_storage_backend_file(void);
size_t nvol_storage_backend_available(const NvolStorageBackend *out_ptr[],
                                      size_t max_entries);

#endif /* NVOL_STORAGE_REGISTRY_H */
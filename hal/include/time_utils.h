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

#ifndef PLATFORM_TIME_UTILS_H
#define PLATFORM_TIME_UTILS_H

#include <stddef.h>

// Writes log prefix into buf as: "HH:MM:SS - LEVEL - LOGGER - "
void platform_time_format(char *buf_ptr, size_t buf_size, const char *level_ptr,
                          const char *logger_ptr);

#endif

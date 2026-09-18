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

#ifndef PLATFORM_LOGGING_H
#define PLATFORM_LOGGING_H

#include <stddef.h>

// Platform log sink: writes formatted log messages to output.

/** @brief Emit already-formatted log bytes to the platform sink. */
void platform_log_write(const char *data_ptr, size_t len);

/** @brief Flush the sink and perform any pending log rotation. Once per line. */
void platform_log_flush(void);

// Direct the sink to a file with optional size-based rotation
// (path_ptr NULL = console; max_size 0 = no rotation).
void platform_log_configure_file(const char *path_ptr, size_t max_size,
                                 int max_rotated);

/** @brief Release the sink (close any open file). */
void platform_log_cleanup(void);

#endif // PLATFORM_LOGGING_H

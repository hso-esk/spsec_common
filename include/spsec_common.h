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

#ifndef SPSEC_COMMON_H
#define SPSEC_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward-declares SPsecCommChannel { CommChannel channel; uint8_t participant_id; }.

#define LOG_LEVEL_DEBUG 10
#define LOG_LEVEL_INFO 20
#define LOG_LEVEL_WARNING 30
#define LOG_LEVEL_ERROR 40
#define LOG_LEVEL_CRITICAL 50

extern int current_log_level;

// Logging config API. Level/formatting is portable; the sink
// (console/file/rotation) lives in platform/logging.c.
uint8_t is_first_bit_set(uint8_t byte);
uint8_t remove_first_bit(uint8_t byte);
void configure_logging(const char *log_level_ptr);
void configure_logging_file(const char *log_file_path_ptr, size_t max_file_size,
                            int max_rotated_files);
void configure_logging_structured(bool enable);
void log_message(int level, const char *name_ptr, const char *format_ptr, ...);
void logging_cleanup(void);
bool increment_bytearray(uint8_t *bytes_ptr, size_t len);

/* Constant-time byte comparison (0 == equal). Use for tag/MAC checks. */
int spsec_ct_memcmp(const void *a_ptr, const void *b_ptr, size_t length);

/* Secure explicit memory zeroization that will not be optimized out by compilers. */
void spsec_explicit_bzero(void *s_ptr, size_t len);
void format_byte_array(char *buffer_ptr, size_t buffer_size, const uint8_t *array_ptr,
                       size_t array_len);
void format_hex_string(char *buffer_ptr, size_t buffer_size, const uint8_t *array_ptr,
                       size_t array_len);

// do/while(0)-wrapped to avoid dangling-else bugs at call sites.
#define LOG_DEBUG(name, ...)                                                   \
  do {                                                                         \
    if (current_log_level <= LOG_LEVEL_DEBUG)                                  \
      log_message(LOG_LEVEL_DEBUG, name, __VA_ARGS__);                         \
  } while (0)
#define LOG_INFO(name, ...)                                                    \
  do {                                                                         \
    if (current_log_level <= LOG_LEVEL_INFO)                                   \
      log_message(LOG_LEVEL_INFO, name, __VA_ARGS__);                          \
  } while (0)
#define LOG_WARNING(name, ...)                                                 \
  do {                                                                         \
    if (current_log_level <= LOG_LEVEL_WARNING)                                \
      log_message(LOG_LEVEL_WARNING, name, __VA_ARGS__);                       \
  } while (0)
#define LOG_ERROR(name, ...)                                                   \
  do {                                                                         \
    if (current_log_level <= LOG_LEVEL_ERROR)                                  \
      log_message(LOG_LEVEL_ERROR, name, __VA_ARGS__);                         \
  } while (0)
#define LOG_CRITICAL(name, ...)                                                \
  do {                                                                         \
    if (current_log_level <= LOG_LEVEL_CRITICAL)                               \
      log_message(LOG_LEVEL_CRITICAL, name, __VA_ARGS__);                      \
  } while (0)

#define LOG_ARRAY(LEVEL_MACRO, name, message, array, len)                      \
  do {                                                                         \
    if (current_log_level <= LEVEL_MACRO) {                                    \
      char array_buffer[256];                                                  \
      format_byte_array(array_buffer, sizeof(array_buffer), array, len);       \
      log_message(LEVEL_MACRO, name, "%s %s", message, array_buffer);          \
    }                                                                          \
  } while (0)

#define LOG_DEBUG_ARRAY(name, message, array, len)                             \
  LOG_ARRAY(LOG_LEVEL_DEBUG, name, message, array, len)

#define LOG_INFO_ARRAY(name, message, array, len)                              \
  LOG_ARRAY(LOG_LEVEL_INFO, name, message, array, len)

#define LOG_HEX(LEVEL_MACRO, name, message, array, len)                        \
  do {                                                                         \
    if (current_log_level <= LEVEL_MACRO) {                                    \
      char hex_buffer[256];                                                    \
      format_hex_string(hex_buffer, sizeof(hex_buffer), array, len);           \
      log_message(LEVEL_MACRO, name, "%s %s", message, hex_buffer);            \
    }                                                                          \
  } while (0)

#define LOG_DEBUG_HEX(name, message, array, len)                               \
  LOG_HEX(LOG_LEVEL_DEBUG, name, message, array, len)

#define LOG_INFO_HEX(name, message, array, len)                                \
  LOG_HEX(LOG_LEVEL_INFO, name, message, array, len)

// Compile-time guard: set SPSEC_LOG_SECRETS=1 to log keys/salts/tags/plaintext.
// Disabled by default for production builds.
#ifndef SPSEC_LOG_SECRETS
#define SPSEC_LOG_SECRETS 0
#endif

#define LOG_SECRET(name, message, array, len)                                  \
  do {                                                                         \
    if (SPSEC_LOG_SECRETS && current_log_level <= LOG_LEVEL_DEBUG) {           \
      char array_buffer[256];                                                  \
      format_byte_array(array_buffer, sizeof(array_buffer), array, len);       \
      log_message(LOG_LEVEL_DEBUG, name, "%s %s", message, array_buffer);      \
    }                                                                          \
  } while (0)

#endif
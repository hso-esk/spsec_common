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

#ifndef SPSEC_ERRORS_H
#define SPSEC_ERRORS_H

#include <stdint.h>

// Unified error codes for consistent error handling across the codebase.
// Functions return 0 for success, negative for the errors below.
typedef enum {
  SPSEC_SUCCESS = 0, /**< Operation succeeded */
  SPSEC_STATUS_MSG_IGNORED =
      1, /**< Message ignored (e.g. not for this participant) */

  /* General errors */
  SPSEC_ERROR_INVALID_ARGUMENT =
      -1, /**< Invalid function argument (NULL pointer, out of range, etc.) */
  SPSEC_ERROR_INVALID_STATE = -2, /**< Operation not allowed in current state */
  SPSEC_ERROR_NOT_INITIALIZED = -3, /**< Required component not initialized */
  SPSEC_ERROR_ALREADY_INITIALIZED = -4, /**< Component already initialized */
  SPSEC_ERROR_OUT_OF_MEMORY = -5,       /**< Memory allocation failed */
  SPSEC_ERROR_TIMEOUT = -6,             /**< Operation timed out */
  SPSEC_ERROR_IO = -7,                  /**< I/O operation failed */

  /* Crypto errors */
  SPSEC_ERROR_CRYPTO_INIT = -8,     /**< Crypto backend initialization failed */
  SPSEC_ERROR_CRYPTO_ENCRYPT = -9,  /**< Encryption operation failed */
  SPSEC_ERROR_CRYPTO_DECRYPT = -10, /**< Decryption operation failed */
  SPSEC_ERROR_CRYPTO_AUTH = -11,    /**< Authentication verification failed */
  SPSEC_ERROR_CRYPTO_KEY_DERIVATION = -12, /**< Key derivation failed */
  SPSEC_ERROR_CRYPTO_INVALID_KEY = -13,    /**< Invalid or missing key */
  SPSEC_ERROR_CRYPTO_INVALID_ALGORITHM =
      -14, /**< Unsupported or invalid algorithm */

  /* Protocol errors */
  SPSEC_ERROR_PROTOCOL_INVALID_MESSAGE =
      -15, /**< Invalid message format or content */
  SPSEC_ERROR_PROTOCOL_UNEXPECTED_MESSAGE =
      -16, /**< Message received in wrong state */
  SPSEC_ERROR_PROTOCOL_MESSAGE_TOO_LARGE =
      -17, /**< Message exceeds maximum size */
  SPSEC_ERROR_PROTOCOL_INVALID_ADDRESS =
      -18, /**< Invalid CAN address or participant ID */
  SPSEC_ERROR_PROTOCOL_COUNTER_MISMATCH = -19, /**< Session counter mismatch */

  /* Register errors */
  SPSEC_ERROR_REGISTER_INVALID = -20, /**< Invalid register address */
  SPSEC_ERROR_REGISTER_READ_ONLY =
      -21, /**< Attempt to write read-only register */
  SPSEC_ERROR_REGISTER_WRITE_ONLY =
      -22, /**< Attempt to read write-only register */
  SPSEC_ERROR_REGISTER_INVALID_LENGTH =
      -23, /**< Invalid data_ptr length for register */
  SPSEC_ERROR_REGISTER_ACCESS_DENIED =
      -24, /**< Register access denied (permissions) */
  SPSEC_ERROR_REGISTER_WRITE_ONCE_VIOLATION =
      -25, /**< Attempt to overwrite write-once register */
  SPSEC_ERROR_REGISTER_NOT_INITIALIZED =
      -26, /**< Register value not initialized */

  /* Key management errors */
  SPSEC_ERROR_KEY_NOT_FOUND = -27,  /**< Required key not found */
  SPSEC_ERROR_KEY_INVALID_ID = -28, /**< Invalid key ID (reserved value) */
  SPSEC_ERROR_KEY_ALREADY_SET =
      -29, /**< Key already set (write-once violation) */
  SPSEC_ERROR_KEY_LOAD_FAILED = -30,    /**< Failed to load key from file */
  SPSEC_ERROR_KEY_INVALID_FORMAT = -31, /**< Invalid key format in file */

  /* Session errors */
  SPSEC_ERROR_SESSION_NOT_ACTIVE = -32,  /**< No active session */
  SPSEC_ERROR_SESSION_TIMEOUT = -33,     /**< Session timeout expired */
  SPSEC_ERROR_SESSION_AUTH_FAILED = -34, /**< Session authentication failed */
  SPSEC_ERROR_SESSION_INVALID_STATE =
      -35, /**< Invalid session state for operation */

  /* Channel/Network errors */
  SPSEC_ERROR_CHANNEL_INIT = -36,    /**< Channel initialization failed */
  SPSEC_ERROR_CHANNEL_SEND = -37,    /**< Failed to send message */
  SPSEC_ERROR_CHANNEL_RECEIVE = -38, /**< Failed to receive message */
  SPSEC_ERROR_CHANNEL_CLOSED = -39,  /**< Channel is closed */

  /* Time sync errors */
  SPSEC_ERROR_TIMESYNC_NOT_SYNCHRONIZED = -40, /**< Time not synchronized */
  SPSEC_ERROR_TIMESYNC_INVALID_RESPONSE =
      -41, /**< Invalid time sync response */
  SPSEC_ERROR_TIMESYNC_AUTH_FAILED =
      -42, /**< Time sync authentication failed */

  /* Internal errors */
  SPSEC_ERROR_INTERNAL = -43,        /**< Internal error (should not occur) */

  /* Platform errors */
  SPSEC_ERROR_PLATFORM_TIMER = -45,  /**< Timer operation failed */
  SPSEC_ERROR_PLATFORM_RANDOM = -46, /**< Random number generation failed */
  SPSEC_ERROR_PLATFORM_SOCKET = -47, /**< Socket operation failed */
} spsec_result_t;

// 8-bit signed type, big enough for all spsec_result_t values.
typedef int8_t spsec_ret_t;

// Static string describing error_code (never freed), or "Unknown error".
const char *spsec_error_string(spsec_result_t error_code);

static inline int spsec_is_success(spsec_result_t result) {
  return result == SPSEC_SUCCESS;
}

static inline int spsec_is_error(spsec_result_t result) {
  return result != SPSEC_SUCCESS;
}

#endif /* SPSEC_ERRORS_H */

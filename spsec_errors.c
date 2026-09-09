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

#include "spsec_errors.h"

const char *spsec_error_string(spsec_result_t error_code) {
  switch (error_code) {
  case SPSEC_SUCCESS:
    return "Success";
  case SPSEC_STATUS_MSG_IGNORED:
    return "Message ignored";

  /* General errors */
  case SPSEC_ERROR_INVALID_ARGUMENT:
    return "Invalid argument";
  case SPSEC_ERROR_INVALID_STATE:
    return "Invalid state";
  case SPSEC_ERROR_NOT_INITIALIZED:
    return "Not initialized";
  case SPSEC_ERROR_ALREADY_INITIALIZED:
    return "Already initialized";
  case SPSEC_ERROR_OUT_OF_MEMORY:
    return "Out of memory";
  case SPSEC_ERROR_TIMEOUT:
    return "Timeout";
  case SPSEC_ERROR_IO:
    return "I/O error";

  /* Crypto errors */
  case SPSEC_ERROR_CRYPTO_INIT:
    return "Crypto initialization failed";
  case SPSEC_ERROR_CRYPTO_ENCRYPT:
    return "Encryption failed";
  case SPSEC_ERROR_CRYPTO_DECRYPT:
    return "Decryption failed";
  case SPSEC_ERROR_CRYPTO_AUTH:
    return "Authentication failed";
  case SPSEC_ERROR_CRYPTO_KEY_DERIVATION:
    return "Key derivation failed";
  case SPSEC_ERROR_CRYPTO_INVALID_KEY:
    return "Invalid or missing key";
  case SPSEC_ERROR_CRYPTO_INVALID_ALGORITHM:
    return "Invalid or unsupported algorithm";

  /* Protocol errors */
  case SPSEC_ERROR_PROTOCOL_INVALID_MESSAGE:
    return "Invalid message format";
  case SPSEC_ERROR_PROTOCOL_UNEXPECTED_MESSAGE:
    return "Unexpected message in current state";
  case SPSEC_ERROR_PROTOCOL_MESSAGE_TOO_LARGE:
    return "Message too large";
  case SPSEC_ERROR_PROTOCOL_INVALID_ADDRESS:
    return "Invalid address or participant ID";
  case SPSEC_ERROR_PROTOCOL_COUNTER_MISMATCH:
    return "Session counter mismatch";

  /* Register errors */
  case SPSEC_ERROR_REGISTER_INVALID:
    return "Invalid register address";
  case SPSEC_ERROR_REGISTER_READ_ONLY:
    return "Register is read-only";
  case SPSEC_ERROR_REGISTER_WRITE_ONLY:
    return "Register is write-only";
  case SPSEC_ERROR_REGISTER_INVALID_LENGTH:
    return "Invalid register data_ptr length";
  case SPSEC_ERROR_REGISTER_ACCESS_DENIED:
    return "Register access denied";
  case SPSEC_ERROR_REGISTER_WRITE_ONCE_VIOLATION:
    return "Write-once register violation";
  case SPSEC_ERROR_REGISTER_NOT_INITIALIZED:
    return "Register not initialized";

  /* Key management errors */
  case SPSEC_ERROR_KEY_NOT_FOUND:
    return "Key not found";
  case SPSEC_ERROR_KEY_INVALID_ID:
    return "Invalid key ID";
  case SPSEC_ERROR_KEY_ALREADY_SET:
    return "Key already set (write-once)";
  case SPSEC_ERROR_KEY_LOAD_FAILED:
    return "Failed to load key from file";
  case SPSEC_ERROR_KEY_INVALID_FORMAT:
    return "Invalid key format";

  /* Session errors */
  case SPSEC_ERROR_SESSION_NOT_ACTIVE:
    return "No active session";
  case SPSEC_ERROR_SESSION_TIMEOUT:
    return "Session timeout";
  case SPSEC_ERROR_SESSION_AUTH_FAILED:
    return "Session authentication failed";
  case SPSEC_ERROR_SESSION_INVALID_STATE:
    return "Invalid session state";

  /* Channel errors */
  case SPSEC_ERROR_CHANNEL_INIT:
    return "Channel initialization failed";
  case SPSEC_ERROR_CHANNEL_SEND:
    return "Failed to send message";
  case SPSEC_ERROR_CHANNEL_RECEIVE:
    return "Failed to receive message";
  case SPSEC_ERROR_CHANNEL_CLOSED:
    return "Channel is closed";

  /* Time sync errors */
  case SPSEC_ERROR_TIMESYNC_NOT_SYNCHRONIZED:
    return "Time not synchronized";
  case SPSEC_ERROR_TIMESYNC_INVALID_RESPONSE:
    return "Invalid time sync response";
  case SPSEC_ERROR_TIMESYNC_AUTH_FAILED:
    return "Time sync authentication failed";

  /* Internal errors */
  case SPSEC_ERROR_INTERNAL:
    return "Internal error";

  /* Platform errors */
  case SPSEC_ERROR_PLATFORM_TIMER:
    return "Timer operation failed";
  case SPSEC_ERROR_PLATFORM_RANDOM:
    return "Random number generation failed";
  case SPSEC_ERROR_PLATFORM_SOCKET:
    return "Socket operation failed";

  default:
    return "Unknown error";
  }
}

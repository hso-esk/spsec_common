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

#include "crypto.h"
#include "spsec_common.h"
#include <ctype.h>

static const char *logger_name_ptr = "crypto";

static void crypto_handler_clear_aad(CryptoHandler *handler_ptr);
static spsec_ret_t ensure_backend_state(CryptoHandler *handler_ptr);

const char *crypto_algorithm_name(CryptoAlgorithm algorithm) {
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return "AES-GCM";
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return "ChaCha20-Poly1305";
  case CRYPTO_ALGO_ASCON128:
    return "Ascon-AEAD128";
  default:
    return "Unknown";
  }
}

static void normalize_algorithm_string(char *dst_ptr, size_t dst_len,
                                       const char *src_ptr) {
  size_t j = 0;
  if (dst_len == 0)
    return;

  for (size_t i = 0; src_ptr && src_ptr[i] != '\0' && j < dst_len - 1; ++i) {
    unsigned char ch = (unsigned char)src_ptr[i];
    if (isalnum(ch)) {
      dst_ptr[j++] = (char)toupper(ch);
    }
  }
  dst_ptr[j] = '\0';
}

CryptoAlgorithm crypto_algorithm_from_string(const char *value_ptr) {
  if (!value_ptr || *value_ptr == '\0') {
    return SPSEC_DEFAULT_AEAD_ALGO;
  }

  char normalized[32];
  normalize_algorithm_string(normalized, sizeof(normalized), value_ptr);

  if (normalized[0] == '\0') {
    return SPSEC_DEFAULT_AEAD_ALGO;
  }

  if (strcmp(normalized, "AESGCM") == 0) {
    return CRYPTO_ALGO_AES_GCM;
  }
  if (strcmp(normalized, "CHACHA20POLY1305") == 0) {
    return CRYPTO_ALGO_CHACHA20_POLY1305;
  }
  // Accept both ASCON128 and ASCONAEAD128 spellings
  if (strcmp(normalized, "ASCON128") == 0 ||
      strcmp(normalized, "ASCONAEAD128") == 0) {
    return CRYPTO_ALGO_ASCON128;
  }

  LOG_WARNING(logger_name_ptr, "Unknown AEAD algorithm '%s', defaulting to %s",
              value_ptr, crypto_algorithm_name(SPSEC_DEFAULT_AEAD_ALGO));
  return SPSEC_DEFAULT_AEAD_ALGO;
}

static void crypto_handler_clear_aad(CryptoHandler *handler_ptr) {
  if (!handler_ptr)
    return;

  free(handler_ptr->aad_buffer_ptr);
  handler_ptr->aad_buffer_ptr = NULL;
  handler_ptr->aad_len = 0;
}

static spsec_ret_t ensure_backend_state(CryptoHandler *handler_ptr) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (!handler_ptr->backend_ptr) {
    handler_ptr->backend_ptr = crypto_backend_default();
  }

  if (!handler_ptr->backend_ptr) {
    LOG_ERROR(logger_name_ptr, "No crypto backend_ptr available");
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  if (!handler_ptr->backend_ctx_ptr && handler_ptr->backend_ptr->vtable &&
      handler_ptr->backend_ptr->vtable->init) {
    int ret = handler_ptr->backend_ptr->vtable->init(&handler_ptr->backend_ctx_ptr);
    if (ret != 0) {
      LOG_ERROR(logger_name_ptr, "Failed to initialise backend_ptr '%s' (%d)",
                handler_ptr->backend_ptr->id, ret);
      handler_ptr->backend_ctx_ptr = NULL;
      return SPSEC_ERROR_CRYPTO_INIT;
    }
  }

  return handler_ptr->backend_ctx_ptr ? SPSEC_SUCCESS : SPSEC_ERROR_CRYPTO_INIT;
}

spsec_ret_t crypto_handler_init(CryptoHandler *handler_ptr) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  memset(handler_ptr, 0, sizeof(*handler_ptr));
  handler_ptr->backend_ptr = crypto_backend_default();
  handler_ptr->algorithm = SPSEC_DEFAULT_AEAD_ALGO;
  handler_ptr->mac_len = 8;

  return ensure_backend_state(handler_ptr);
}

void crypto_handler_destroy(CryptoHandler *handler_ptr) {
  if (!handler_ptr) {
    return;
  }

  if (handler_ptr->backend_ptr && handler_ptr->backend_ptr->vtable &&
      handler_ptr->backend_ptr->vtable->destroy) {
    handler_ptr->backend_ptr->vtable->destroy(handler_ptr->backend_ctx_ptr);
  }

  handler_ptr->backend_ctx_ptr = NULL;
  handler_ptr->backend_ptr = NULL;

  if (handler_ptr->nonce_ptr) {
    memset(handler_ptr->nonce_ptr, 0, handler_ptr->nonce_len);
    free(handler_ptr->nonce_ptr);
  }
  handler_ptr->nonce_ptr = NULL;
  handler_ptr->nonce_len = 0;

  memset(handler_ptr->key, 0, sizeof(handler_ptr->key));
  handler_ptr->key_len = 0;
  handler_ptr->mac_len = 0;

  crypto_handler_clear_aad(handler_ptr);
}

spsec_ret_t crypto_handler_use_backend(CryptoHandler *handler_ptr,
                                       const CryptoBackend *backend_ptr) {
  if (!handler_ptr || !backend_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (handler_ptr->backend_ptr == backend_ptr) {
    return ensure_backend_state(handler_ptr);
  }

  if (handler_ptr->backend_ptr && handler_ptr->backend_ptr->vtable &&
      handler_ptr->backend_ptr->vtable->destroy) {
    handler_ptr->backend_ptr->vtable->destroy(handler_ptr->backend_ctx_ptr);
  }

  handler_ptr->backend_ptr = backend_ptr;
  handler_ptr->backend_ctx_ptr = NULL;

  return ensure_backend_state(handler_ptr);
}

const CryptoBackend *crypto_handler_get_backend(const CryptoHandler *handler_ptr) {
  return handler_ptr ? handler_ptr->backend_ptr : NULL;
}

static bool backend_supports_algorithm(const CryptoBackend *backend_ptr,
                                       CryptoAlgorithm algorithm) {
  if (!backend_ptr || !backend_ptr->vtable || !backend_ptr->vtable->supports_algorithm) {
    return false;
  }
  return backend_ptr->vtable->supports_algorithm(backend_ptr, algorithm);
}

spsec_ret_t crypto_handler_select_algorithm(CryptoHandler *handler_ptr,
                                            CryptoAlgorithm algorithm) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (handler_ptr->algorithm == algorithm) {
    return SPSEC_SUCCESS;
  }

  if (!backend_supports_algorithm(handler_ptr->backend_ptr, algorithm)) {
    LOG_ERROR(logger_name_ptr, "Backend '%s' does not support algorithm %s",
              handler_ptr->backend_ptr ? handler_ptr->backend_ptr->id : "(null)",
              crypto_algorithm_name(algorithm));
    return SPSEC_ERROR_CRYPTO_INVALID_ALGORITHM;
  }

  handler_ptr->algorithm = algorithm;
  return SPSEC_SUCCESS;
}

CryptoAlgorithm crypto_handler_get_algorithm(const CryptoHandler *handler_ptr) {
  if (!handler_ptr) {
    return SPSEC_DEFAULT_AEAD_ALGO;
  }
  return handler_ptr->algorithm;
}

static spsec_ret_t store_nonce(CryptoHandler *handler_ptr, const uint8_t *nonce_ptr,
                               size_t nonce_len) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  uint8_t *buffer_ptr = (uint8_t *)malloc(nonce_len);
  if (!buffer_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate nonce_ptr buffer_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  memcpy(buffer_ptr, nonce_ptr, nonce_len);

  if (handler_ptr->nonce_ptr) {
    memset(handler_ptr->nonce_ptr, 0, handler_ptr->nonce_len);
    free(handler_ptr->nonce_ptr);
  }

  handler_ptr->nonce_ptr = buffer_ptr;
  handler_ptr->nonce_len = nonce_len;
  return SPSEC_SUCCESS;
}

spsec_ret_t crypto_handler_set_context(CryptoHandler *handler_ptr, uint8_t *key_ptr,
                                       uint8_t *nonce_ptr, size_t nonce_len,
                                       int mac_len) {
  if (!handler_ptr || !key_ptr || !nonce_ptr) {
    LOG_ERROR(logger_name_ptr,
              "Invalid parameters passed to crypto_handler_set_context");
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (ensure_backend_state(handler_ptr) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  memcpy(handler_ptr->key, key_ptr, KEY_LEN);
  handler_ptr->key_len = KEY_LEN;
  handler_ptr->mac_len = mac_len;

  if (store_nonce(handler_ptr, nonce_ptr, nonce_len) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  crypto_handler_clear_aad(handler_ptr);

  if (!handler_ptr->backend_ptr->vtable || !handler_ptr->backend_ptr->vtable->configure) {
    LOG_ERROR(logger_name_ptr, "Backend '%s' does not implement configure()",
              handler_ptr->backend_ptr->id);
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  int ret = handler_ptr->backend_ptr->vtable->configure(
      handler_ptr->backend_ctx_ptr, handler_ptr->algorithm, handler_ptr->key, handler_ptr->key_len,
      handler_ptr->nonce_ptr, handler_ptr->nonce_len, handler_ptr->mac_len);
  if (ret != 0) {
    LOG_ERROR(logger_name_ptr, "Failed to configure backend_ptr '%s' (%d)",
              handler_ptr->backend_ptr->id, ret);
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  return SPSEC_SUCCESS;
}

static spsec_ret_t crypto_handler_encrypt_internal(
    CryptoHandler *handler_ptr, const uint8_t *input_ptr, size_t input_len,
    uint8_t *output_ptr, const uint8_t *aad_ptr, size_t aad_len, uint8_t *tag_ptr) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (ensure_backend_state(handler_ptr) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  if (!handler_ptr->backend_ptr || !handler_ptr->backend_ptr->vtable ||
      !handler_ptr->backend_ptr->vtable->encrypt) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  int ret = handler_ptr->backend_ptr->vtable->encrypt(
      handler_ptr->backend_ctx_ptr, input_ptr, input_len, output_ptr, aad_ptr, aad_len, tag_ptr);
  return ret == 0 ? SPSEC_SUCCESS : SPSEC_ERROR_CRYPTO_ENCRYPT;
}

static spsec_ret_t crypto_handler_decrypt_internal(
    CryptoHandler *handler_ptr, const uint8_t *input_ptr, size_t input_len,
    uint8_t *output_ptr, const uint8_t *aad_ptr, size_t aad_len, const uint8_t *tag_ptr) {
  if (!handler_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (ensure_backend_state(handler_ptr) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  if (!handler_ptr->backend_ptr || !handler_ptr->backend_ptr->vtable ||
      !handler_ptr->backend_ptr->vtable->decrypt) {
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  int ret = handler_ptr->backend_ptr->vtable->decrypt(
      handler_ptr->backend_ctx_ptr, input_ptr, input_len, output_ptr, aad_ptr, aad_len, tag_ptr);
  return ret == 0 ? SPSEC_SUCCESS : SPSEC_ERROR_CRYPTO_DECRYPT;
}

spsec_ret_t crypto_handler_encrypt(CryptoHandler *handler_ptr, uint8_t *data_ptr,
                                   size_t data_len, uint8_t *ciphertext_ptr,
                                   uint8_t *tag_ptr) {
  return crypto_handler_encrypt_internal(handler_ptr, data_ptr, data_len,
                                         ciphertext_ptr, NULL, 0, tag_ptr);
}

spsec_ret_t
crypto_handler_encrypt_with_assoc_data(CryptoHandler *handler_ptr,
                                       uint8_t *data_ptr, size_t data_len,
                                       uint8_t *ciphertext_ptr, uint8_t *tag_ptr,
                                       const uint8_t *assoc_data_ptr, size_t assoc_len) {
  return crypto_handler_encrypt_internal(
      handler_ptr, data_ptr, data_len, ciphertext_ptr, assoc_data_ptr, assoc_len, tag_ptr);
}

spsec_ret_t crypto_handler_decrypt(CryptoHandler *handler_ptr,
                                   uint8_t *ciphertext_ptr, size_t cipher_len,
                                   uint8_t *tag_ptr, uint8_t *plaintext_ptr) {
  return crypto_handler_decrypt_internal(handler_ptr, ciphertext_ptr, cipher_len,
                                         plaintext_ptr, NULL, 0, tag_ptr);
}

spsec_ret_t crypto_handler_decrypt_with_assoc_data(
    CryptoHandler *handler_ptr, uint8_t *ciphertext_ptr, size_t cipher_len,
    uint8_t *tag_ptr, uint8_t *plaintext_ptr, const uint8_t *assoc_data_ptr,
    size_t assoc_len) {
  return crypto_handler_decrypt_internal(handler_ptr, ciphertext_ptr, cipher_len,
                                         plaintext_ptr, assoc_data_ptr, assoc_len,
                                         tag_ptr);
}

spsec_ret_t crypto_handler_update(CryptoHandler *handler_ptr, uint8_t *data_ptr,
                                  size_t len) {
  if (!handler_ptr || !data_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  crypto_handler_clear_aad(handler_ptr);

  handler_ptr->aad_buffer_ptr = (uint8_t *)malloc(len);
  if (!handler_ptr->aad_buffer_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AAD buffer_ptr");
    return SPSEC_ERROR_OUT_OF_MEMORY;
  }

  memcpy(handler_ptr->aad_buffer_ptr, data_ptr, len);
  handler_ptr->aad_len = len;
  return SPSEC_SUCCESS;
}

spsec_ret_t crypto_handler_get_digest(CryptoHandler *handler_ptr, uint8_t *digest_ptr,
                                      size_t *digest_len_ptr) {
  if (!handler_ptr || !digest_ptr || !digest_len_ptr) {
    return SPSEC_ERROR_INVALID_ARGUMENT;
  }

  if (!handler_ptr->aad_buffer_ptr || handler_ptr->aad_len == 0) {
    LOG_ERROR(logger_name_ptr, "AAD buffer_ptr not initialised before get_digest");
    return SPSEC_ERROR_INVALID_STATE;
  }

  if (crypto_handler_encrypt_internal(handler_ptr, NULL, 0, NULL,
                                      handler_ptr->aad_buffer_ptr, handler_ptr->aad_len,
                                      digest_ptr) != SPSEC_SUCCESS) {
    return SPSEC_ERROR_CRYPTO_ENCRYPT;
  }

  *digest_len_ptr = (size_t)handler_ptr->mac_len;
  crypto_handler_clear_aad(handler_ptr);
  return SPSEC_SUCCESS;
}

spsec_ret_t setup_crypto_context_and_calculate_tag(
    CryptoHandler *crypto_handler_ptr, uint8_t *key_ptr, uint8_t *nonce_ptr,
    size_t nonce_len, uint8_t *assoc_data_ptr, size_t assoc_len,
    uint8_t *auth_tag_ptr, size_t tag_size) {
  LOG_DEBUG(logger_name_ptr,
            "setup_crypto_context_and_calculate_tag: nonce_len=%zu, "
            "assoc_len=%zu, tag_size=%zu",
            nonce_len, assoc_len, tag_size);
  LOG_SECRET(logger_name_ptr, "setup_crypto_context_and_calculate_tag: key_ptr:", key_ptr, KEY_LEN);
  LOG_SECRET(logger_name_ptr, "setup_crypto_context_and_calculate_tag: nonce_ptr:", nonce_ptr, nonce_len);
  LOG_SECRET(logger_name_ptr, "setup_crypto_context_and_calculate_tag: assoc_data_ptr:", assoc_data_ptr,
            assoc_len);

  if (crypto_handler_set_context(crypto_handler_ptr, key_ptr, nonce_ptr, nonce_len,
                                 (int)tag_size) != SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "crypto_handler_set_context failed");
    return SPSEC_ERROR_CRYPTO_INIT;
  }

  if (crypto_handler_update(crypto_handler_ptr, assoc_data_ptr, assoc_len) !=
      SPSEC_SUCCESS) {
    LOG_ERROR(logger_name_ptr, "crypto_handler_update failed");
    return SPSEC_ERROR_CRYPTO_ENCRYPT;
  }

  spsec_ret_t ret =
      crypto_handler_get_digest(crypto_handler_ptr, auth_tag_ptr, &tag_size);
  if (ret == SPSEC_SUCCESS) {
    LOG_SECRET(logger_name_ptr, "setup_crypto_context_and_calculate_tag: computed auth_tag:", auth_tag_ptr, tag_size);
  } else {
    LOG_ERROR(logger_name_ptr, "crypto_handler_get_digest failed: %d", ret);
  }
  return ret;
}

// Nonce length in bytes: 12 for AES-GCM/ChaCha20-Poly1305, 16 for ASCON-128.
size_t crypto_get_nonce_len(CryptoAlgorithm algo) {
  switch (algo) {
  case CRYPTO_ALGO_AES_GCM:
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return 12;
  case CRYPTO_ALGO_ASCON128:
    return 16;
  default:
    return 12; // Default to 12 for unknown algorithms
  }
}

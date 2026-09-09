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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "crypto_backend.h"
#include "keys.h"
#include "spsec_errors.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef SPSEC_DEFAULT_AEAD_ALGO
#define SPSEC_DEFAULT_AEAD_ALGO CRYPTO_ALGO_AES_GCM
#endif

typedef struct CryptoHandler {
  const CryptoBackend *backend_ptr;
  void *backend_ctx_ptr;
  CryptoAlgorithm algorithm;
  int mac_len;
  uint8_t *nonce_ptr;
  size_t nonce_len;
  uint8_t key[KEY_LEN];
  size_t key_len;
  uint8_t *aad_buffer_ptr;
  size_t aad_len;
} CryptoHandler;

spsec_ret_t crypto_handler_init(CryptoHandler *handler_ptr);
void crypto_handler_destroy(CryptoHandler *handler_ptr);
spsec_ret_t crypto_handler_use_backend(CryptoHandler *handler_ptr,
                                       const CryptoBackend *backend_ptr);
const CryptoBackend *crypto_handler_get_backend(const CryptoHandler *handler_ptr);
spsec_ret_t crypto_handler_select_algorithm(CryptoHandler *handler_ptr,
                                            CryptoAlgorithm algorithm);
CryptoAlgorithm crypto_handler_get_algorithm(const CryptoHandler *handler_ptr);
const char *crypto_algorithm_name(CryptoAlgorithm algorithm);
CryptoAlgorithm crypto_algorithm_from_string(const char *value_ptr);
spsec_ret_t crypto_handler_set_context(CryptoHandler *handler_ptr, uint8_t *key_ptr,
                                       uint8_t *nonce_ptr, size_t nonce_len,
                                       int mac_len);
spsec_ret_t crypto_handler_update(CryptoHandler *handler_ptr, uint8_t *data_ptr,
                                  size_t len);
spsec_ret_t crypto_handler_get_digest(CryptoHandler *handler_ptr, uint8_t *digest_ptr,
                                      size_t *digest_len_ptr);
spsec_ret_t setup_crypto_context_and_calculate_tag(
    CryptoHandler *crypto_handler_ptr, uint8_t *key_ptr, uint8_t *nonce_ptr,
    size_t nonce_len, uint8_t *assoc_data_ptr, size_t assoc_len,
    uint8_t *auth_tag_ptr, size_t tag_size);
size_t crypto_get_nonce_len(CryptoAlgorithm algo);

spsec_ret_t crypto_handler_encrypt(CryptoHandler *handler_ptr, uint8_t *data_ptr,
                                   size_t data_len, uint8_t *ciphertext_ptr,
                                   uint8_t *tag_ptr);
spsec_ret_t
crypto_handler_encrypt_with_assoc_data(CryptoHandler *handler_ptr,
                                        uint8_t *data_ptr, size_t data_len,
                                        uint8_t *ciphertext_ptr, uint8_t *tag_ptr,
                                        const uint8_t *assoc_data_ptr, size_t assoc_len);

spsec_ret_t crypto_handler_decrypt(CryptoHandler *handler_ptr,
                                   uint8_t *ciphertext_ptr, size_t cipher_len,
                                   uint8_t *tag_ptr, uint8_t *plaintext_ptr);
spsec_ret_t crypto_handler_decrypt_with_assoc_data(
    CryptoHandler *handler_ptr, uint8_t *ciphertext_ptr, size_t cipher_len,
    uint8_t *tag_ptr, uint8_t *plaintext_ptr, const uint8_t *assoc_data_ptr,
    size_t assoc_len);

#endif /* CRYPTO_H */
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

#include "crypto_backend.h"
#include "keys.h"
#include "spsec_common.h"
#include "spsec_registers.h"

#include <mbedtls/chachapoly.h>
#include <mbedtls/gcm.h>

typedef struct {
  mbedtls_gcm_context gcm;
  mbedtls_chachapoly_context chachapoly;
  uint8_t key[KEY_LEN];
  uint8_t nonce[REQUIRED_NONCE_LEN];
  size_t nonce_len;
  size_t mac_len;
  CryptoAlgorithm algorithm;
} MbedtlsBackendState;

static int mbedtls_backend_init(void **state_out) {
  MbedtlsBackendState *state =
      (MbedtlsBackendState *)calloc(1, sizeof(MbedtlsBackendState));
  if (!state)
    return -1;

  mbedtls_gcm_init(&state->gcm);
  mbedtls_chachapoly_init(&state->chachapoly);
  *state_out = state;
  return 0;
}

static void mbedtls_backend_destroy(void *state_ptr) {
  if (!state_ptr)
    return;

  MbedtlsBackendState *state = (MbedtlsBackendState *)state_ptr;
  mbedtls_gcm_free(&state->gcm);
  mbedtls_chachapoly_free(&state->chachapoly);
  memset(state, 0, sizeof(*state));
  free(state);
}

static int mbedtls_backend_configure(void *state_ptr, CryptoAlgorithm algorithm,
                                     const uint8_t *key, size_t key_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     int mac_len) {
  MbedtlsBackendState *state = (MbedtlsBackendState *)state_ptr;
  if (!state || !key || key_len != KEY_LEN || !nonce)
    return -1;

  /* Match the wolfSSL backend: reject non-positive tag lengths and clamp to the
   * 16-byte full-tag size so a bad mac_len can never overflow tag buffers. */
  if (mac_len <= 0)
    return -1;

  state->algorithm = algorithm;
  state->mac_len = (size_t)mac_len > 16 ? 16 : (size_t)mac_len;

  memcpy(state->key, key, KEY_LEN);
  memset(state->nonce, 0, sizeof(state->nonce));
  state->nonce_len =
      nonce_len > REQUIRED_NONCE_LEN ? REQUIRED_NONCE_LEN : nonce_len;
  memcpy(state->nonce, nonce, state->nonce_len);

  int ret = 0;
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    mbedtls_gcm_free(&state->gcm);
    mbedtls_gcm_init(&state->gcm);
    ret = mbedtls_gcm_setkey(&state->gcm, MBEDTLS_CIPHER_ID_AES, key,
                             KEY_LEN * 8);
    break;
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    mbedtls_chachapoly_free(&state->chachapoly);
    mbedtls_chachapoly_init(&state->chachapoly);
    ret = mbedtls_chachapoly_setkey(&state->chachapoly, key);
    break;
  default:
    ret = -1;
    break;
  }

  return ret == 0 ? 0 : -1;
}

static int encrypt_aes_gcm(MbedtlsBackendState *state, const uint8_t *input,
                           size_t input_len, uint8_t *output,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *tag_out) {
  int ret = mbedtls_gcm_starts(&state->gcm, MBEDTLS_GCM_ENCRYPT, state->nonce,
                               state->nonce_len, aad, aad_len);
  if (ret != 0)
    return -1;

  if (input_len > 0) {
    if (!input || !output)
      return -1;

    ret = mbedtls_gcm_update(&state->gcm, input_len, input, output);
    if (ret != 0)
      return -1;
  }

  ret = mbedtls_gcm_finish(&state->gcm, tag_out, state->mac_len);
  return ret == 0 ? 0 : -1;
}

static int decrypt_aes_gcm(MbedtlsBackendState *state, const uint8_t *input,
                           size_t input_len, uint8_t *output,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *tag) {
  int ret = mbedtls_gcm_starts(&state->gcm, MBEDTLS_GCM_DECRYPT, state->nonce,
                               state->nonce_len, aad, aad_len);
  if (ret != 0)
    return -1;

  if (input_len > 0) {
    if (!input || !output)
      return -1;

    ret = mbedtls_gcm_update(&state->gcm, input_len, input, output);
    if (ret != 0)
      return -1;
  }

  uint8_t computed_tag[16];
  ret = mbedtls_gcm_finish(&state->gcm, computed_tag, state->mac_len);
  if (ret != 0)
    return -1;

  if (spsec_ct_memcmp(tag, computed_tag, state->mac_len) != 0) {
    /* Do not release unverified plaintext to the caller's buffer. */
    if (output && input_len > 0)
      memset(output, 0, input_len);
    return -1;
  }

  return 0;
}

static int encrypt_chachapoly(MbedtlsBackendState *state, const uint8_t *input,
                              size_t input_len, uint8_t *output,
                              const uint8_t *aad, size_t aad_len,
                              uint8_t *tag_out) {
  uint8_t nonce12[12] = {0};
  if (state->nonce_len < sizeof(nonce12))
    return -1;

  memcpy(nonce12, state->nonce, sizeof(nonce12));

  int ret = mbedtls_chachapoly_starts(&state->chachapoly, nonce12,
                                      MBEDTLS_CHACHAPOLY_ENCRYPT);
  if (ret != 0)
    return -1;

  if (aad_len > 0 && aad) {
    ret = mbedtls_chachapoly_update_aad(&state->chachapoly, aad, aad_len);
    if (ret != 0)
      return -1;
  }

  if (input_len > 0) {
    if (!input || !output)
      return -1;

    ret =
        mbedtls_chachapoly_update(&state->chachapoly, input_len, input, output);
    if (ret != 0)
      return -1;
  }

  uint8_t full_tag[16];
  ret = mbedtls_chachapoly_finish(&state->chachapoly, full_tag);
  if (ret != 0)
    return -1;

  size_t copy_len = (size_t)state->mac_len <= sizeof(full_tag)
                        ? (size_t)state->mac_len
                        : sizeof(full_tag);
  memcpy(tag_out, full_tag, copy_len);
  return 0;
}

static int decrypt_chachapoly(MbedtlsBackendState *state, const uint8_t *input,
                              size_t input_len, uint8_t *output,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *tag) {
  uint8_t nonce12[12] = {0};
  if (state->nonce_len < sizeof(nonce12))
    return -1;

  memcpy(nonce12, state->nonce, sizeof(nonce12));

  int ret = mbedtls_chachapoly_starts(&state->chachapoly, nonce12,
                                      MBEDTLS_CHACHAPOLY_DECRYPT);
  if (ret != 0)
    return -1;

  if (aad_len > 0 && aad) {
    ret = mbedtls_chachapoly_update_aad(&state->chachapoly, aad, aad_len);
    if (ret != 0)
      return -1;
  }

  if (input_len > 0) {
    if (!input || !output)
      return -1;

    ret =
        mbedtls_chachapoly_update(&state->chachapoly, input_len, input, output);
    if (ret != 0)
      return -1;
  }

  uint8_t full_tag[16];
  ret = mbedtls_chachapoly_finish(&state->chachapoly, full_tag);
  if (ret != 0)
    return -1;

  size_t cmp_len =
      state->mac_len <= sizeof(full_tag) ? state->mac_len : sizeof(full_tag);
  if (spsec_ct_memcmp(tag, full_tag, cmp_len) != 0) {
    /* Do not release unverified plaintext to the caller's buffer. */
    if (output && input_len > 0)
      memset(output, 0, input_len);
    return -1;
  }

  return 0;
}

static int mbedtls_backend_encrypt(void *state_ptr, const uint8_t *input,
                                   size_t input_len, uint8_t *output,
                                   const uint8_t *aad, size_t aad_len,
                                   uint8_t *tag_out) {
  MbedtlsBackendState *state = (MbedtlsBackendState *)state_ptr;
  if (!state || !tag_out)
    return -1;

  switch (state->algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return encrypt_aes_gcm(state, input, input_len, output, aad, aad_len,
                           tag_out);
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return encrypt_chachapoly(state, input, input_len, output, aad, aad_len,
                              tag_out);
  default:
    return -1;
  }
}

static int mbedtls_backend_decrypt(void *state_ptr, const uint8_t *input,
                                   size_t input_len, uint8_t *output,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *tag) {
  MbedtlsBackendState *state = (MbedtlsBackendState *)state_ptr;
  if (!state || !tag)
    return -1;

  switch (state->algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return decrypt_aes_gcm(state, input, input_len, output, aad, aad_len, tag);
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return decrypt_chachapoly(state, input, input_len, output, aad, aad_len,
                              tag);
  default:
    return -1;
  }
}

static bool mbedtls_backend_supports(const CryptoBackend *self,
                                     CryptoAlgorithm algorithm) {
  (void)self;
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return true;
  default:
    return false;
  }
}

static const CryptoBackendVTable MBEDTLS_VTABLE = {
    .id = "mbedtls",
    .name = "mbedTLS",
    .capability_flags = 0,
    .init = mbedtls_backend_init,
    .destroy = mbedtls_backend_destroy,
    .configure = mbedtls_backend_configure,
    .encrypt = mbedtls_backend_encrypt,
    .decrypt = mbedtls_backend_decrypt,
    .supports_algorithm = mbedtls_backend_supports};

static const CryptoBackend MBEDTLS_BACKEND = {
    .id = "mbedtls",
    .name = "mbedTLS builtin crypto",
    .capability_flags = SPSEC_CAPABILITY_AES_GCM |
                        SPSEC_CAPABILITY_CHACHA20_POLY1305 |
                        SPSEC_CAPABILITY_BACKEND_MBEDTLS,
    .vtable = &MBEDTLS_VTABLE};

const CryptoBackend *crypto_backend_mbedtls(void) {
  return &MBEDTLS_BACKEND;
}

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

#include <wolfssl/options.h>
#ifndef WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#endif
#ifndef HAVE_ASCON
#define HAVE_ASCON
#endif
#ifndef WOLFSSL_ASCON
#define WOLFSSL_ASCON
#endif
#undef WOLFSSL_MIN_AUTH_TAG_SZ
#define WOLFSSL_MIN_AUTH_TAG_SZ 8

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <limits.h>

static const char *logger_name = "crypto";

typedef struct {
  Aes aes;
  CryptoAlgorithm algorithm;
  uint8_t key[KEY_LEN];
  uint8_t nonce[REQUIRED_NONCE_LEN];
  size_t nonce_len;
  int mac_len;
  bool aes_key_set;
  bool configured;
} WolfSSLBackendState;

static int g_wolfcrypt_refcount = 0;

static int retain_wolfcrypt(void) {
  if (g_wolfcrypt_refcount == 0) {
    int ret = wolfCrypt_Init();
    if (ret != 0) {
      LOG_ERROR(logger_name, "wolfCrypt_Init failed (%d)", ret);
      return -1;
    }
  }
  ++g_wolfcrypt_refcount;
  return 0;
}

static void release_wolfcrypt(void) {
  if (g_wolfcrypt_refcount > 0) {
    --g_wolfcrypt_refcount;
    if (g_wolfcrypt_refcount == 0) {
      wolfCrypt_Cleanup();
    }
  }
}

static size_t clamp_ascon_tag(int mac_len) {
  if (mac_len <= 0)
    return 0;

  size_t len = (size_t)mac_len;
  if (len > ASCON_AEAD128_TAG_SZ) {
    len = ASCON_AEAD128_TAG_SZ;
  }
  return len;
}

static int encrypt_aes_gcm(WolfSSLBackendState *state, const uint8_t *input,
                           size_t input_len, uint8_t *output,
                           const uint8_t *aad, size_t aad_len,
                           uint8_t *tag_out) {
  if (!state->aes_key_set)
    return -1;

  uint8_t dummy_in = 0;
  uint8_t dummy_out = 0;
  const uint8_t *in_ptr = input_len > 0 ? input : &dummy_in;
  uint8_t *out_ptr = input_len > 0 ? output : &dummy_out;

  int ret = wc_AesGcmEncrypt(&state->aes, out_ptr, in_ptr, (word32)input_len,
                             state->nonce, (word32)state->nonce_len, tag_out,
                             (word32)state->mac_len, aad_len > 0 ? aad : NULL,
                             (word32)aad_len);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AesGcmEncrypt failed (%d)", ret);
    return -1;
  }
  return 0;
}

static int decrypt_aes_gcm(WolfSSLBackendState *state, const uint8_t *input,
                           size_t input_len, uint8_t *output,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *tag) {
  if (!state->aes_key_set)
    return -1;

  uint8_t dummy_in = 0;
  uint8_t dummy_out = 0;
  const uint8_t *in_ptr = input_len > 0 ? input : &dummy_in;
  uint8_t *out_ptr = input_len > 0 ? output : &dummy_out;

  int ret = wc_AesGcmDecrypt(&state->aes, out_ptr, in_ptr, (word32)input_len,
                             state->nonce, (word32)state->nonce_len, tag,
                             (word32)state->mac_len, aad_len > 0 ? aad : NULL,
                             (word32)aad_len);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AesGcmDecrypt failed (%d)", ret);
    return -1;
  }
  return 0;
}

static int encrypt_chachapoly(WolfSSLBackendState *state, const uint8_t *input,
                              size_t input_len, uint8_t *output,
                              const uint8_t *aad, size_t aad_len,
                              uint8_t *tag_out) {
  ChaChaPoly_Aead ctx;
  uint8_t nonce[CHACHA20_POLY1305_AEAD_IV_SIZE];

  // nonce is salt-padded to REQUIRED_NONCE_LEN (SPsec302); we use the low
  // 12 bytes so the timestamp/counter is included.
  if (state->nonce_len < sizeof(nonce))
    return -1;

  memcpy(nonce, state->nonce, sizeof(nonce));

  int ret = wc_ChaCha20Poly1305_Init(&ctx, state->key, nonce,
                                     CHACHA20_POLY1305_AEAD_ENCRYPT);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_Init (enc) failed (%d)", ret);
    return -1;
  }

  if (aad_len > 0 && aad) {
    ret = wc_ChaCha20Poly1305_UpdateAad(&ctx, aad, (word32)aad_len);
    if (ret != 0) {
      LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_UpdateAad failed (%d)", ret);
      return -1;
    }
  }

  if (input_len > 0) {
    ret = wc_ChaCha20Poly1305_UpdateData(&ctx, input, output,
                                         (word32)input_len);
    if (ret != 0) {
      LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_UpdateData failed (%d)", ret);
      return -1;
    }
  }

  uint8_t full_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
  ret = wc_ChaCha20Poly1305_Final(&ctx, full_tag);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_Final (enc) failed (%d)", ret);
    return -1;
  }

  size_t copy_len = (size_t)state->mac_len <= sizeof(full_tag)
                        ? (size_t)state->mac_len
                        : sizeof(full_tag);
  memcpy(tag_out, full_tag, copy_len);
  return 0;
}

static int decrypt_chachapoly(WolfSSLBackendState *state, const uint8_t *input,
                              size_t input_len, uint8_t *output,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *tag) {
  if (!tag)
    return -1;

  ChaChaPoly_Aead ctx;
  uint8_t nonce[CHACHA20_POLY1305_AEAD_IV_SIZE];

  // nonce is salt-padded to REQUIRED_NONCE_LEN (SPsec302); we use the low
  // 12 bytes so the timestamp/counter is included.
  if (state->nonce_len < sizeof(nonce))
    return -1;

  memcpy(nonce, state->nonce, sizeof(nonce));

  int ret = wc_ChaCha20Poly1305_Init(&ctx, state->key, nonce,
                                     CHACHA20_POLY1305_AEAD_DECRYPT);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_Init (dec) failed (%d)", ret);
    return -1;
  }

  if (aad_len > 0 && aad) {
    ret = wc_ChaCha20Poly1305_UpdateAad(&ctx, aad, (word32)aad_len);
    if (ret != 0) {
      LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_UpdateAad failed (%d)", ret);
      return -1;
    }
  }

  if (input_len > 0) {
    ret = wc_ChaCha20Poly1305_UpdateData(&ctx, input, output,
                                         (word32)input_len);
    if (ret != 0) {
      LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_UpdateData failed (%d)", ret);
      return -1;
    }
  }

  uint8_t full_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
  ret = wc_ChaCha20Poly1305_Final(&ctx, full_tag);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_ChaCha20Poly1305_Final (dec) failed (%d)", ret);
    return -1;
  }

  size_t cmp_len = (size_t)state->mac_len <= sizeof(full_tag)
                       ? (size_t)state->mac_len
                       : sizeof(full_tag);
  if (spsec_ct_memcmp(full_tag, tag, cmp_len) != 0) {
    if (output && input_len > 0)
      memset(output, 0, input_len);
    return -1;
  }

  return 0;
}

static int encrypt_ascon(WolfSSLBackendState *state, const uint8_t *input,
                         size_t input_len, uint8_t *output, const uint8_t *aad,
                         size_t aad_len, uint8_t *tag_out) {
  if (aad_len > UINT32_MAX || input_len > UINT32_MAX) {
    LOG_ERROR(logger_name, "ASCON input too large");
    return -1;
  }

  if (state->nonce_len < ASCON_AEAD128_NONCE_SZ)
    return -1;

  wc_AsconAEAD128 ctx;
  uint8_t key16[ASCON_AEAD128_KEY_SZ];
  uint8_t nonce16[ASCON_AEAD128_NONCE_SZ];
  uint8_t full_tag[ASCON_AEAD128_TAG_SZ];

  // Use least significant 128 bits (last 16 bytes) of the 32-byte key
  memcpy(key16, state->key + 16, sizeof(key16));
  /* state->nonce is always REQUIRED_NONCE_LEN (16 bytes) padded with pre-shared
   * salt per SPsec302 specification. ASCON-128 uses all 16 bytes of nonce. */
  memcpy(nonce16, state->nonce, sizeof(nonce16));

  LOG_SECRET(logger_name, "ASCON encrypt: full key (32 bytes):", state->key, 32);
  LOG_SECRET(logger_name, "ASCON encrypt: key16 (last 16 bytes):", key16,
            ASCON_AEAD128_KEY_SZ);
  LOG_SECRET(logger_name, "ASCON encrypt: nonce16:", nonce16,
            ASCON_AEAD128_NONCE_SZ);
  LOG_SECRET(logger_name, "ASCON encrypt: AAD:", aad, aad_len);
  LOG_DEBUG(logger_name, "ASCON encrypt: input_len=%zu, aad_len=%zu", input_len,
            aad_len);

  if (wc_AsconAEAD128_Init(&ctx) != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_Init failed");
    return -1;
  }

  int ret = wc_AsconAEAD128_SetKey(&ctx, key16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetNonce(&ctx, nonce16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetAD(&ctx, aad_len > 0 ? aad : NULL,
                                (word32)aad_len);
  if (ret != 0) {
    LOG_ERROR(logger_name, "ASCON configure failed (%d)", ret);
    wc_AsconAEAD128_Clear(&ctx);
    return -1;
  }

  if (input_len > 0) {
    ret = wc_AsconAEAD128_EncryptUpdate(&ctx, output, input,
                                        (word32)input_len);
  } else {
    uint8_t dummy_in = 0;
    uint8_t dummy_out = 0;
    ret = wc_AsconAEAD128_EncryptUpdate(&ctx, &dummy_out, &dummy_in, 0);
  }

  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_EncryptUpdate failed (%d)", ret);
    wc_AsconAEAD128_Clear(&ctx);
    return -1;
  }

  ret = wc_AsconAEAD128_EncryptFinal(&ctx, full_tag);
  wc_AsconAEAD128_Clear(&ctx);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_EncryptFinal failed (%d)", ret);
    return -1;
  }

  LOG_SECRET(logger_name, "ASCON encrypt: full_tag (16 bytes):", full_tag,
            ASCON_AEAD128_TAG_SZ);
  size_t copy_len = clamp_ascon_tag(state->mac_len);
  LOG_SECRET(logger_name, "ASCON encrypt: tag_out (truncated):", full_tag, copy_len);
  LOG_DEBUG(logger_name, "ASCON encrypt: copy_len=%zu, mac_len=%d", copy_len,
            state->mac_len);
  memcpy(tag_out, full_tag, copy_len);
  return 0;
}

static int decrypt_ascon(WolfSSLBackendState *state, const uint8_t *input,
                         size_t input_len, uint8_t *output, const uint8_t *aad,
                         size_t aad_len, const uint8_t *tag) {
  if (!tag)
    return -1;

  if (aad_len > UINT32_MAX || input_len > UINT32_MAX) {
    LOG_ERROR(logger_name, "ASCON input too large");
    return -1;
  }

  if (state->nonce_len < ASCON_AEAD128_NONCE_SZ)
    return -1;

  int ret = 0;
  wc_AsconAEAD128 dec_ctx;
  wc_AsconAEAD128 enc_ctx;
  uint8_t key16[ASCON_AEAD128_KEY_SZ];
  uint8_t nonce16[ASCON_AEAD128_NONCE_SZ];
  uint8_t full_tag[ASCON_AEAD128_TAG_SZ];
  uint8_t *scratch = NULL;

  // Use least significant 128 bits (last 16 bytes) of the 32-byte key
  memcpy(key16, state->key + 16, sizeof(key16));
  /* state->nonce is always REQUIRED_NONCE_LEN (16 bytes) padded with pre-shared
   * salt per SPsec302 specification. ASCON-128 uses all 16 bytes of nonce. */
  memcpy(nonce16, state->nonce, sizeof(nonce16));

  if (wc_AsconAEAD128_Init(&dec_ctx) != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_Init (dec) failed");
    return -1;
  }

  ret = wc_AsconAEAD128_SetKey(&dec_ctx, key16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetNonce(&dec_ctx, nonce16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetAD(&dec_ctx, aad_len > 0 ? aad : NULL,
                                (word32)aad_len);
  if (ret != 0) {
    LOG_ERROR(logger_name, "ASCON decrypt configure failed (%d)", ret);
    wc_AsconAEAD128_Clear(&dec_ctx);
    return -1;
  }

  if (input_len > 0) {
    ret = wc_AsconAEAD128_DecryptUpdate(&dec_ctx, output, input,
                                        (word32)input_len);
  } else {
    uint8_t dummy_in = 0;
    uint8_t dummy_out = 0;
    ret = wc_AsconAEAD128_DecryptUpdate(&dec_ctx, &dummy_out, &dummy_in, 0);
  }

  wc_AsconAEAD128_Clear(&dec_ctx);

  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_DecryptUpdate failed (%d)", ret);
    return -1;
  }

  if (wc_AsconAEAD128_Init(&enc_ctx) != 0) {
    LOG_ERROR(logger_name, "wc_AsconAEAD128_Init (enc) failed");
    return -1;
  }

  ret = wc_AsconAEAD128_SetKey(&enc_ctx, key16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetNonce(&enc_ctx, nonce16);
  if (ret == 0)
    ret = wc_AsconAEAD128_SetAD(&enc_ctx, aad_len > 0 ? aad : NULL,
                                (word32)aad_len);
  if (ret != 0) {
    LOG_ERROR(logger_name, "ASCON re-encrypt configure failed (%d)", ret);
    wc_AsconAEAD128_Clear(&enc_ctx);
    return -1;
  }

  if (input_len > 0) {
    scratch = (uint8_t *)malloc(input_len);
    if (!scratch) {
      LOG_ERROR(logger_name, "Failed to allocate ASCON scratch buffer");
      wc_AsconAEAD128_Clear(&enc_ctx);
      return -1;
    }

    ret = wc_AsconAEAD128_EncryptUpdate(&enc_ctx, scratch, output,
                                        (word32)input_len);
  } else {
    uint8_t dummy_in = 0;
    uint8_t dummy_out = 0;
    ret = wc_AsconAEAD128_EncryptUpdate(&enc_ctx, &dummy_out, &dummy_in, 0);
  }

  if (ret == 0)
    ret = wc_AsconAEAD128_EncryptFinal(&enc_ctx, full_tag);

  wc_AsconAEAD128_Clear(&enc_ctx);
  free(scratch);

  if (ret != 0) {
    LOG_ERROR(logger_name, "ASCON tag recompute failed (%d)", ret);
    return -1;
  }

  size_t cmp_len = clamp_ascon_tag(state->mac_len);
  if (spsec_ct_memcmp(tag, full_tag, cmp_len) != 0) {
    LOG_ERROR(logger_name, "ASCON auth tag mismatch");
    if (output && input_len > 0)
      memset(output, 0, input_len);
    return -1;
  }

  return 0;
}

static int wolfssl_backend_init(void **state_out) {
  if (!state_out)
    return -1;

  if (retain_wolfcrypt() != 0)
    return -1;

  WolfSSLBackendState *state =
      (WolfSSLBackendState *)calloc(1, sizeof(WolfSSLBackendState));
  if (!state) {
    release_wolfcrypt();
    return -1;
  }

  int ret = wc_AesInit(&state->aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    LOG_ERROR(logger_name, "wc_AesInit failed (%d)", ret);
    free(state);
    release_wolfcrypt();
    return -1;
  }

  *state_out = state;
  return 0;
}

static void wolfssl_backend_destroy(void *state_ptr) {
  /* A NULL state means init never succeeded (its failure path already released
   * the wolfCrypt refcount), so a spurious destroy(NULL) must be a no-op — else
   * it drops the global refcount while another handler is still using it. */
  if (!state_ptr)
    return;

  WolfSSLBackendState *state = (WolfSSLBackendState *)state_ptr;
  wc_AesFree(&state->aes);
  memset(state, 0, sizeof(*state));
  free(state);
  release_wolfcrypt();
}

static int wolfssl_backend_configure(void *state_ptr, CryptoAlgorithm algorithm,
                                     const uint8_t *key, size_t key_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     int mac_len) {
  WolfSSLBackendState *state = (WolfSSLBackendState *)state_ptr;
  if (!state || !key || !nonce || key_len != KEY_LEN || mac_len <= 0) {
    return -1;
  }

  state->algorithm = algorithm;
  state->mac_len = mac_len > 16 ? 16 : mac_len;

  memcpy(state->key, key, KEY_LEN);
  memset(state->nonce, 0, sizeof(state->nonce));
  /* Clamp nonce to REQUIRED_NONCE_LEN (16 bytes). The nonce passed here should
   * already be REQUIRED_NONCE_LEN bytes with salt padding per SPsec302
   * specification. */
  state->nonce_len =
      nonce_len > REQUIRED_NONCE_LEN ? REQUIRED_NONCE_LEN : nonce_len;
  memcpy(state->nonce, nonce, state->nonce_len);

  state->aes_key_set = false;

  int ret = 0;
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    if (state->nonce_len == 0)
      return -1;
    ret = wc_AesGcmSetKey(&state->aes, state->key, KEY_LEN);
    if (ret != 0) {
      LOG_ERROR(logger_name, "wc_AesGcmSetKey failed (%d)", ret);
      return -1;
    }
    state->aes_key_set = true;
    break;
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    if (state->nonce_len < CHACHA20_POLY1305_AEAD_IV_SIZE)
      return -1;
    break;
  case CRYPTO_ALGO_ASCON128:
    if (state->nonce_len < ASCON_AEAD128_NONCE_SZ)
      return -1;
    break;
  default:
    return -1;
  }

  state->configured = true;
  return 0;
}

static int wolfssl_backend_encrypt(void *state_ptr, const uint8_t *input,
                                   size_t input_len, uint8_t *output,
                                   const uint8_t *aad, size_t aad_len,
                                   uint8_t *tag_out) {
  WolfSSLBackendState *state = (WolfSSLBackendState *)state_ptr;
  if (!state || !state->configured || !tag_out)
    return -1;
  if (input_len > 0 && (!input || !output))
    return -1;

  switch (state->algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return encrypt_aes_gcm(state, input, input_len, output, aad, aad_len,
                           tag_out);
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return encrypt_chachapoly(state, input, input_len, output, aad, aad_len,
                              tag_out);
  case CRYPTO_ALGO_ASCON128:
    return encrypt_ascon(state, input, input_len, output, aad, aad_len,
                         tag_out);
  default:
    return -1;
  }
}

static int wolfssl_backend_decrypt(void *state_ptr, const uint8_t *input,
                                   size_t input_len, uint8_t *output,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *tag) {
  WolfSSLBackendState *state = (WolfSSLBackendState *)state_ptr;
  if (!state || !state->configured || !output)
    return -1;
  if (input_len > 0 && (!input || !output))
    return -1;

  switch (state->algorithm) {
  case CRYPTO_ALGO_AES_GCM:
    return decrypt_aes_gcm(state, input, input_len, output, aad, aad_len, tag);
  case CRYPTO_ALGO_CHACHA20_POLY1305:
    return decrypt_chachapoly(state, input, input_len, output, aad, aad_len,
                              tag);
  case CRYPTO_ALGO_ASCON128:
    return decrypt_ascon(state, input, input_len, output, aad, aad_len, tag);
  default:
    return -1;
  }
}

static bool wolfssl_backend_supports(const CryptoBackend *self,
                                     CryptoAlgorithm algorithm) {
  (void)self;
  switch (algorithm) {
  case CRYPTO_ALGO_AES_GCM:
  case CRYPTO_ALGO_CHACHA20_POLY1305:
  case CRYPTO_ALGO_ASCON128:
    return true;
  default:
    return false;
  }
}

static const CryptoBackendVTable WOLFSSL_VTABLE = {
    .id = "wolfssl",
    .name = "wolfSSL",
    .capability_flags = 0,
    .init = wolfssl_backend_init,
    .destroy = wolfssl_backend_destroy,
    .configure = wolfssl_backend_configure,
    .encrypt = wolfssl_backend_encrypt,
    .decrypt = wolfssl_backend_decrypt,
    .supports_algorithm = wolfssl_backend_supports};

static const CryptoBackend WOLFSSL_BACKEND = {
    .id = "wolfssl",
    .name = "wolfSSL crypto",
    .capability_flags =
        SPSEC_CAPABILITY_AES_GCM | SPSEC_CAPABILITY_CHACHA20_POLY1305 |
        SPSEC_CAPABILITY_ASCON128 | SPSEC_CAPABILITY_BACKEND_WOLFSSL,
    .vtable = &WOLFSSL_VTABLE};

const CryptoBackend *crypto_backend_wolfssl(void) {
  return &WOLFSSL_BACKEND;
}

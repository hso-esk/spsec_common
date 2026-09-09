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

#ifndef KEYS_H
#define KEYS_H

#include <stdbool.h>
#include <stdint.h>

#define KEY_LEN 32
/* Pre-shared salt length: 8 (default) or 12 (fills 16-byte nonce). */
#ifndef SALT_LEN
#define SALT_LEN 8
#endif
#define REQUIRED_NONCE_LEN 16

/* Acceptance window for data-plane replay protection (150 reference ticks = 15 ms). */
#define SPSEC_ACCEPT_WINDOW_TICKS 150

/* Associated data length for data-plane AEAD: CAN ID (4) + length byte (1). */
#define DATA_AAD_LEN 5

#define KEY_SELECTOR_ZERO 1
#define KEY_SELECTOR_SESSION 2
#define KEY_SELECTOR_SEED 13
#define KEY_SELECTOR_INTEGRATOR 14
#define KEY_SELECTOR_PROVISIONING 15

extern const uint8_t spsec_key_selectors[];

typedef struct {
  uint8_t key[KEY_LEN];
  uint32_t key_id; // 32-bit Key ID
} SPsecKey;

SPsecKey *spseckey_new(uint32_t key_id, const uint8_t data_ptr[KEY_LEN]);
void spseckey_free(SPsecKey *key_ptr);

typedef struct {
  uint8_t salt[SALT_LEN];
} SPsecSalt;

SPsecSalt *spsecsalt_new(const uint8_t data_ptr[SALT_LEN]);
int8_t spsecsalt_set(SPsecSalt *salt_ptr, const uint8_t *data_ptr);
void spsecsalt_free(SPsecSalt *salt_ptr);
int8_t spsecsalt_init(SPsecSalt *salt_ptr, const uint8_t *data_ptr);
uint8_t *spsecsalt_get_salt(SPsecSalt *salt_ptr);

int8_t spseckey_init(SPsecKey *key_ptr, const uint32_t key_id,
                     const uint8_t *data_ptr);
uint8_t *spseckey_get_key(SPsecKey *key_ptr);
uint32_t *spseckey_get_id(SPsecKey *key_ptr);
int8_t spseckey_set_id(SPsecKey *key_ptr, const uint32_t key_id);

int8_t spseckey_set(SPsecKey *key_ptr, const uint8_t *data_ptr);
// Returns 0 on success, -1 if no RNG source was available
int8_t spseckey_generate(SPsecKey *key_ptr);
void spseckey_invalidate(SPsecKey *key_ptr);

typedef struct {
  SPsecSalt *
      spsec_salt[4]; // 0 = zero, 1 = provisioning, 2 = integrator, 3 = seed
  SPsecKey
      *spsec_keys[4]; // 0 = zero, 1 = provisioning, 2 = integrator, 3 = seed

  uint8_t even_key[KEY_LEN];
  uint8_t odd_key[KEY_LEN];
  uint8_t even_key_ts_part[5];
  uint8_t odd_key_ts_part[5];
  bool use_odd_key; // reflects last timestamp passed to
                    // communication_keys_update
  uint8_t csalt[4]; // Communication Key Derivation Salt (received from time
                    // sync response)
} CommunicationKeys;

int8_t communication_keys_init(CommunicationKeys *commkeys_ptr);
void communication_keys_destroy(CommunicationKeys *commkeys_ptr);

#endif
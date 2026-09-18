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

#include "keys.h"
#include "spsec_common.h"
#include "randomgen.h"
#if defined(__linux__)
#include <sys/random.h>
#endif

static const char *logger_name_ptr = "keys";

static void zeroize_key_and_salt(SPsecKey **key_ptr, SPsecSalt **salt_ptr);

// Pre-shared keys persist across sessions; only factory reset erases them.

const uint8_t spsec_key_selectors[] = {
    KEY_SELECTOR_ZERO,
    KEY_SELECTOR_PROVISIONING,
    KEY_SELECTOR_INTEGRATOR,
    KEY_SELECTOR_SEED,
};

// Caller owns the result and must free it with spseckey_free().
SPsecKey *spseckey_new(uint32_t key_id, const uint8_t data_ptr[KEY_LEN]) {
  SPsecKey *key_ptr = malloc(sizeof(SPsecKey));
  if (!key_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate memory for SPsecKey");
    return NULL;
  }
  key_ptr->key_id = key_id;
  memcpy(key_ptr->key, data_ptr, KEY_LEN);

  return key_ptr;
}

void spseckey_free(SPsecKey *key_ptr) {
  if (key_ptr) {
    memset(key_ptr->key, 0, KEY_LEN);
    free(key_ptr);
  }
}

SPsecSalt *spsecsalt_new(const uint8_t data_ptr[SALT_LEN]) {
  SPsecSalt *salt_ptr = malloc(sizeof(SPsecSalt));
  if (!salt_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate memory for SPsecSalt");
    return NULL;
  }
  memcpy(salt_ptr->salt, data_ptr, SALT_LEN);

  return salt_ptr;
}

void spsecsalt_free(SPsecSalt *salt_ptr) {
  if (salt_ptr) {
    memset(salt_ptr->salt, 0, SALT_LEN);
    free(salt_ptr);
  }
}

// Uses data_ptr if given, otherwise generates a random key.
int8_t spseckey_init(SPsecKey *key_ptr, const uint32_t key_id,
                     const uint8_t *data_ptr) {
  if (!data_ptr) {
    spseckey_generate(key_ptr);
    return 0;
  }
  memcpy(key_ptr->key, data_ptr, KEY_LEN);
  // set key_id
  key_ptr->key_id = key_id;
  return 0;
}

uint8_t *spseckey_get_key(SPsecKey *key_ptr) {
  return key_ptr->key;
}

uint32_t *spseckey_get_id(SPsecKey *key_ptr) {
  return &key_ptr->key_id;
}

int8_t spseckey_set(SPsecKey *key_ptr, const uint8_t *data_ptr) {
  if (key_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "key is NULL");
    return -1;
  }
  if (data_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "data_ptr is NULL");
    return -1;
  }
  LOG_SECRET(logger_name_ptr, "Setting key", data_ptr, KEY_LEN);
  memcpy(key_ptr->key, data_ptr, KEY_LEN);
  LOG_INFO(logger_name_ptr, "Key set successfully");
  return 0;
}

int8_t spseckey_set_id(SPsecKey *key_ptr, const uint32_t key_id) {
  if (key_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "key is NULL");
    return -1;
  }
  LOG_INFO(logger_name_ptr, "Setting key ID to %u", key_id);
  key_ptr->key_id = key_id;
  return 0;
}

void spseckey_generate(SPsecKey *key_ptr) {
  if (!key_ptr)
    return;
#if defined(__linux__)
  if (getrandom(key_ptr->key, KEY_LEN, 0) == (ssize_t)KEY_LEN) {
    return;
  }
#endif
  RandomGenerator rg;
  if (random_generator_init(&rg) == 0) {
    uint8_t *rnd_ptr = random_generator_get_bytes(&rg, KEY_LEN);
    if (rnd_ptr) {
      memcpy(key_ptr->key, rnd_ptr, KEY_LEN);
      free(rnd_ptr);
      random_generator_free(&rg);
      return;
    }
    random_generator_free(&rg);
  }
}

// Zeroes key + ID; call before overwriting so a half-written key is never
// accepted as valid.
void spseckey_invalidate(SPsecKey *key_ptr) {
  if (key_ptr) {
    spsec_explicit_bzero(key_ptr->key, KEY_LEN);
    key_ptr->key_id = 0;
  }
}

int8_t spsecsalt_init(SPsecSalt *salt_ptr, const uint8_t *data_ptr) {
  if (!data_ptr) {
    LOG_ERROR(logger_name_ptr, "Required salt not provided");
    return -1;
  }
  memcpy(salt_ptr->salt, data_ptr, SALT_LEN);
  return 0;
}

uint8_t *spsecsalt_get_salt(SPsecSalt *salt_ptr) {
  if (salt_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "salt is NULL");
    return NULL;
  }
  return salt_ptr->salt;
}

int8_t spsecsalt_set(SPsecSalt *salt_ptr, const uint8_t *data_ptr) {
  if (salt_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "salt is NULL");
    return -1;
  }
  if (data_ptr == NULL) {
    LOG_ERROR(logger_name_ptr, "data_ptr is NULL");
    return -1;
  }
  LOG_SECRET(logger_name_ptr, "Setting salt", data_ptr, SALT_LEN);
  memcpy(salt_ptr->salt, data_ptr, SALT_LEN);
  return 0;
}

// =================

int8_t communication_keys_init(CommunicationKeys *commkeys_ptr) {
  if (!commkeys_ptr) {
    LOG_ERROR(logger_name_ptr, "NULL CommunicationKeys pointer");
    return -1;
  }

  // Initialize all pointers to NULL first
  for (int i = 0; i < 4; i++) {
    commkeys_ptr->spsec_salt[i] = NULL;
  }
  for (int i = 0; i < 4; i++) {
    commkeys_ptr->spsec_keys[i] = NULL;
  }

  // Need to prepeare at least zero key
  uint8_t zero_key[KEY_LEN] = {0};
  commkeys_ptr->spsec_keys[0] = spseckey_new(0, zero_key);
  if (!commkeys_ptr->spsec_keys[0]) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate zero key");
    return -1;
  }

  LOG_SECRET(logger_name_ptr, "Current Zero key data", commkeys_ptr->spsec_keys[0]->key, KEY_LEN);

  // All-zero salt matches the all-zero key: the known discoverability
  // default (decision D-1), not a value to validate against.
  uint8_t zero_salt[SALT_LEN] = {0};
  commkeys_ptr->spsec_salt[0] = spsecsalt_new(zero_salt);
  if (!commkeys_ptr->spsec_salt[0]) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate zero salt");
    return -1;
  }
  LOG_DEBUG(logger_name_ptr, "Current Zero salt address: %p",
            commkeys_ptr->spsec_salt[0]);
  LOG_SECRET(logger_name_ptr, "Current Zero salt data", commkeys_ptr->spsec_salt[0]->salt, SALT_LEN);

  // Initialize other fields for even/odd rolling keys
  memset(commkeys_ptr->even_key, 0, KEY_LEN);
  memset(commkeys_ptr->odd_key, 0, KEY_LEN);
  memset(commkeys_ptr->even_key_ts_part, 0, sizeof(commkeys_ptr->even_key_ts_part));
  memset(commkeys_ptr->odd_key_ts_part, 0, sizeof(commkeys_ptr->odd_key_ts_part));
  commkeys_ptr->use_odd_key = false;
  memset(commkeys_ptr->csalt, 0,
         4); // Initialize csalt to zero (will be set from time sync response)

  LOG_INFO(logger_name_ptr, "Communication keys initialized successfully");
  return 0;
}

void communication_keys_destroy(CommunicationKeys *commkeys_ptr) {
  if (!commkeys_ptr)
    return;

  // Wipe then free every stored key/salt (provisioning/integrator/seed as well
  // as zero) so secret material does not linger in freed heap pages.
  for (int i = 0; i < 4; i++) {
    zeroize_key_and_salt(&commkeys_ptr->spsec_keys[i], &commkeys_ptr->spsec_salt[i]);
  }

  // Wipe the live rolling session keys and the derivation salt too.
  spsec_explicit_bzero(commkeys_ptr->even_key, KEY_LEN);
  spsec_explicit_bzero(commkeys_ptr->odd_key, KEY_LEN);
  memset(commkeys_ptr->even_key_ts_part, 0, sizeof(commkeys_ptr->even_key_ts_part));
  memset(commkeys_ptr->odd_key_ts_part, 0, sizeof(commkeys_ptr->odd_key_ts_part));
  memset(commkeys_ptr->csalt, 0, sizeof(commkeys_ptr->csalt));

  LOG_INFO(logger_name_ptr, "Communication keys destroyed");
}

static void zeroize_key_and_salt(SPsecKey **key_ptr, SPsecSalt **salt_ptr) {
  if (key_ptr && *key_ptr) {
    spsec_explicit_bzero((*key_ptr)->key, KEY_LEN);
    (*key_ptr)->key_id = 0;
    free(*key_ptr);
    *key_ptr = NULL;
  }
  if (salt_ptr && *salt_ptr) {
    spsec_explicit_bzero((*salt_ptr)->salt, SALT_LEN);
    free(*salt_ptr);
    *salt_ptr = NULL;
  }
}


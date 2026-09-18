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

// Helpers to map key/salt selectors to registers and validate lengths.

#ifndef SPSEC_MAPPING_H
#define SPSEC_MAPPING_H

#include "spsec_registers.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
  uint8_t reg;
  uint32_t expected_len;
} SpsecRegisterSpec;

static inline bool spsec_is_known_register(uint8_t reg,
                                           uint32_t *out_expected_len_ptr) {
  static const SpsecRegisterSpec specs[] = {
      {SPSEC_REG_STATUS, 1},
      {SPSEC_REG_LAST_SECURITY_EVENT, 2},
      {SPSEC_REG_PROVISIONING_KEY, KEY_LEN},
      {SPSEC_REG_INTEGRATOR_KEY, KEY_LEN},
      {SPSEC_REG_SEED_KEY, KEY_LEN},
      {SPSEC_REG_PROVISIONING_KEY_SALT, SALT_LEN},
      {SPSEC_REG_INTEGRATOR_KEY_SALT, SALT_LEN},
      {SPSEC_REG_SEED_KEY_SALT, SALT_LEN},
      {SPSEC_REG_PROVISIONING_KEY_ID, 4},
      {SPSEC_REG_INTEGRATOR_KEY_ID, 4},
      {SPSEC_REG_SEED_KEY_ID, 4},
      {SPSEC_REG_SECURE_HEARTBEAT_TIMING, 1},
      {SPSEC_REG_SECURE_HEARTBEAT_MONITOR, 4},
      {SPSEC_REG_SYNC_ROLE_ACTIVATION, 1}, // SPsec302 V40: 63h, 8 bits
      {SPSEC_REG_PARTICIPANT_ID, 1},       // SPsec302 V40: 60h, 8 bits (1-127)
      {SPSEC_REG_CAN_FD_BIT_RATE, 2},      // SPsec302 V40: 7Bh, 16 bits
      {SPSEC_REG_MANUFACTURER_RESET, 4},   // SPsec302 V40: 7Fh, 32 bits
      {SPSEC_REG_DEVICE_IDENTIFICATION, 0}, // SPsec302 V40: 81h, string (variable length)
      {SPSEC_REG_MCU_SERIAL_NUMBER, 16},       // SPsec302 V40: 82h, 128 bits
      {SPSEC_REG_CODE_UPDATE_CAPABILITIES, 4}, // SPsec302 V40: 90h, 32 bits
      {SPSEC_REG_PUBLIC_AUTH_KEY, KEY_LEN},    // SPsec302 V40: 91h, 256 bits (public key)
      {SPSEC_REG_CODE_UPDATE_FILE, SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN},
      {SPSEC_REG_CORE_VERSION_INFO, 0},
      {SPSEC_REG_MAPPING_VERSION_INFO, 0},
  };
  for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) {
    if (specs[i].reg == reg) {
      if (out_expected_len_ptr)
        *out_expected_len_ptr = specs[i].expected_len;
      return true;
    }
  }
  return false;
}

static inline uint8_t spsec_key_reg_for_selector(uint8_t selector) {
  switch (selector) {
  case 1:
    return SPSEC_REG_PROVISIONING_KEY;
  case 2:
    return SPSEC_REG_INTEGRATOR_KEY;
  case 3:
    return SPSEC_REG_SEED_KEY;
  default:
    return 0; // invalid
  }
}

static inline uint8_t spsec_key_id_reg_for_selector(uint8_t selector) {
  switch (selector) {
  case 1:
    return SPSEC_REG_PROVISIONING_KEY_ID;
  case 2:
    return SPSEC_REG_INTEGRATOR_KEY_ID;
  case 3:
    return SPSEC_REG_SEED_KEY_ID;
  default:
    return 0; // invalid
  }
}

static inline uint8_t spsec_salt_reg_for_selector(uint8_t selector) {
  switch (selector) {
  case 1:
    return SPSEC_REG_PROVISIONING_KEY_SALT;
  case 2:
    return SPSEC_REG_INTEGRATOR_KEY_SALT;
  case 3:
    return SPSEC_REG_SEED_KEY_SALT;
  default:
    return 0; // invalid
  }
}

#endif // SPSEC_MAPPING_H

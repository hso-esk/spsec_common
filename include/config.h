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

#ifndef CONFIG_H
#define CONFIG_H

#include "crypto_types.h"
#include <stdbool.h>
#include <stdint.h>

/* Session timeout defaults, also used directly by session_handshake.c when
 * initializing a session before config is consulted. */
#define DEFAULT_SESSION_TIMEOUT_US 10000000ULL        /* 10 seconds */
#define DEFAULT_SESSION_RESPONSE_TIMEOUT_US 100000ULL /* 100ms */

// Centralized ParticipantConfig struct + load/save/validate helpers, so
// config isn't scattered across the codebase.

// When the Sync role draws a fresh Communication Key Derivation Salt (csalt).
typedef enum {
  /** Once per process start (default). */
  SPSEC_CSALT_REGEN_POWER_UP = 0,
  /** On every transition from WAITING to SECURE. */
  SPSEC_CSALT_REGEN_SECURE_ENTRY = 1
} spsec_csalt_regen_mode_t;

// All configurable parameters for a participant instance.
typedef struct {
  /* Network configuration */
  const char *secure_interface_ptr;   /**< Secure CAN interface name */
  const char *insecure_interface_ptr; /**< Insecure CAN interface name */

  /* Participant identity */
  uint8_t participant_id; /**< Participant ID (7-bit, 1-127) */

  /* Key management */
  const char *keys_file_ptr; /**< Path to keys file (optional) */

  /* Time synchronization */
  bool enable_timesync_role;        /**< Enable time sync authority role */
  /* Offsets in reference 0.1ms ticks, converted to timer domain at use. */
  uint16_t timesync_offset;         /**< Time sync offset in reference 0.1ms ticks */
  uint16_t broadcast_offset;        /**< Broadcast offset in reference 0.1ms ticks */
  int timesync_retry_delay_seconds; /**< Time sync retry delay */
  uint64_t timesync_broadcast_interval_us; /**< Time sync broadcast interval */
  /**< Silence window after which an invalid sync broadcast triggers restart recovery. */
  uint64_t timesync_broadcast_wait_us;
  /**< When the Sync role draws a fresh Communication Key Derivation Salt. */
  spsec_csalt_regen_mode_t csalt_regen_mode;

  /* Crypto configuration */
  CryptoAlgorithm crypto_algorithm; /**< AEAD algorithm to use */
  bool auth_only_mode;              /**< Enable authentication-only mode */

  /* Heartbeat configuration */
  uint8_t heartbeat_timing; /**< Heartbeat cycle time (enum value) */

  /* Session configuration */
  uint64_t session_timeout_us;          /**< Overall session timeout */
  uint64_t session_response_timeout_us; /**< Response timeout */

  /* Warning state configuration */
  uint64_t warning_hold_time_us; /**< Warning state hold time */

  /* CAN FD bitrate configuration */
  uint8_t can_nominal_bitrate; /**< CAN nominal bitrate */
  uint8_t can_data_bitrate;    /**< CAN data_ptr bitrate */

  /* Logging configuration */
  const char *log_level_ptr; /**< Log level string */
  const char *log_file_ptr;  /**< Log file path (NULL for stdout) */
  bool log_structured;   /**< Enable structured (JSON) logging */

  /* Version information */
  char core_version_info[16];      /**< Core version string */
  char mapping_version_info[16];   /**< Mapping version string */
  char device_identification[128]; /**< Device identification string */
} ParticipantConfig;

int config_init_defaults(ParticipantConfig *config_ptr);

// Timer tick resolution (ns) for a SPSEC_CAN_DATA_* bitrate value from
// spsec_registers.h; 100000 for anything unrecognized.
uint32_t spsec_tick_ns_for_data_bitrate(uint8_t can_data_bitrate);

// Largest data-plane acceptance window for the given timer tick resolution.
uint32_t spsec_max_accept_window_ticks(uint32_t tick_ns);

// JSON config file (TOML support planned).
int config_load_from_file(ParticipantConfig *config_ptr, const char *config_file_ptr);
int config_save_to_file(const ParticipantConfig *config_ptr,
                        const char *config_file_ptr);

// Checks required fields and value ranges; logs details on failure.
int config_validate(const ParticipantConfig *config_ptr);

void config_print(const ParticipantConfig *config_ptr);
uint8_t config_get_default_participant_id(void);
const char *config_get_default_secure_interface(void);
const char *config_get_default_insecure_interface(void);
const char *config_get_default_log_level(void);

#endif /* CONFIG_H */

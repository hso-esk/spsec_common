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

#include "can_bitrate.h"
#include "config.h"
#include "crypto.h"
#include "timer.h"

#include "spsec_common.h"
#include "spsec_registers.h"

static const char *logger_name_ptr = "config";

/* Default values */
#define DEFAULT_PARTICIPANT_ID 123
#define DEFAULT_SECURE_IF "vcan0"
#define DEFAULT_INSECURE_IF "vcan1"
#define DEFAULT_LOG_LEVEL "INFO"
#define DEFAULT_TIMESYNC_RETRY_DELAY_SECONDS 2
/* Timesync broadcast interval (10s default). */
#define DEFAULT_TIMESYNC_BROADCAST_INTERVAL_US 10000000ULL

/* Wait window before an unverified sync broadcast triggers restart recovery (30s). */
#define DEFAULT_TIMESYNC_BROADCAST_WAIT_US 30000000ULL /* 30 s */
#define DEFAULT_WARNING_HOLD_TIME_US 5000000ULL       /* 5 seconds */

int config_init_defaults(ParticipantConfig *config_ptr) {
  if (!config_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid config_ptr pointer");
    return -1;
  }

  memset(config_ptr, 0, sizeof(*config_ptr));

  /* Network defaults */
  config_ptr->secure_interface_ptr = DEFAULT_SECURE_IF;
  config_ptr->insecure_interface_ptr = DEFAULT_INSECURE_IF;

  /* Participant identity */
  config_ptr->participant_id = DEFAULT_PARTICIPANT_ID;

  /* Key management */
  config_ptr->keys_file_ptr = NULL;

  /* Time synchronization */
  config_ptr->enable_timesync_role = false;
  config_ptr->timesync_offset = 0;
  config_ptr->broadcast_offset = 0;
  config_ptr->timesync_retry_delay_seconds = DEFAULT_TIMESYNC_RETRY_DELAY_SECONDS;
  config_ptr->timesync_broadcast_interval_us =
      DEFAULT_TIMESYNC_BROADCAST_INTERVAL_US;
  config_ptr->timesync_broadcast_wait_us = DEFAULT_TIMESYNC_BROADCAST_WAIT_US;
  config_ptr->csalt_regen_mode = SPSEC_CSALT_REGEN_POWER_UP;

  /* Crypto configuration */
  config_ptr->crypto_algorithm = SPSEC_DEFAULT_AEAD_ALGO;
  config_ptr->auth_only_mode = false;

  /* Heartbeat configuration */
  config_ptr->heartbeat_timing = SPSEC_HEARTBEAT_8S;

  /* Session configuration */
  config_ptr->session_timeout_us = DEFAULT_SESSION_TIMEOUT_US;
  config_ptr->session_response_timeout_us = DEFAULT_SESSION_RESPONSE_TIMEOUT_US;

  /* Warning state configuration */
  config_ptr->warning_hold_time_us = DEFAULT_WARNING_HOLD_TIME_US;

  /* CAN FD bitrate configuration */
  config_ptr->can_nominal_bitrate = SPSEC_CAN_NOMINAL_1000KBPS;
  config_ptr->can_data_bitrate = SPSEC_CAN_DATA_1MBPS;

  /* Logging configuration */
  config_ptr->log_level_ptr = DEFAULT_LOG_LEVEL;
  config_ptr->log_file_ptr = NULL;
  config_ptr->log_structured = false;

  /* Version information */
  strncpy(config_ptr->core_version_info, "0.33",
          sizeof(config_ptr->core_version_info) - 1);
  strncpy(config_ptr->mapping_version_info, "302-0.33",
          sizeof(config_ptr->mapping_version_info) - 1);
  config_ptr->device_identification[0] = '\0';

  return 0;
}

uint32_t spsec_tick_ns_for_data_bitrate(uint8_t can_data_bitrate) {
  // Scale tick resolution proportionally with the actual CAN FD data bitrate
  uint32_t bps = can_bitrate_data_to_bps(can_data_bitrate);
  if (bps == 0)
    return 100000; // unrecognized: fall back to the standard 100us tick
  uint64_t tick_ns = 100000000000ULL / (uint64_t)bps;
  return tick_ns > 0 ? (uint32_t)tick_ns : 1;
}

uint32_t spsec_max_accept_window_ticks(uint32_t tick_ns) {
  if (tick_ns == 0)
    return 0;
  return (uint32_t)(2048ULL * (uint64_t)tick_ns / SPSEC_REFERENCE_TICK_NS);
}

int config_load_from_file(ParticipantConfig *config_ptr, const char *config_file_ptr) {
  if (!config_ptr || !config_file_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid arguments");
    return -1;
  }

  /* Unimplemented: configuration is currently passed via CLI arguments. */
  LOG_WARNING(logger_name_ptr, "Configuration file loading not yet implemented");
  return -1;
}

int config_save_to_file(const ParticipantConfig *config_ptr,
                        const char *config_file_ptr) {
  if (!config_ptr || !config_file_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid arguments");
    return -1;
  }

  /* See config_load_from_file() above - same deliberate-stub rationale,
   * zero current callers. */
  LOG_WARNING(logger_name_ptr, "Configuration file saving not yet implemented");
  return -1;
}

int config_validate(const ParticipantConfig *config_ptr) {
  if (!config_ptr) {
    LOG_ERROR(logger_name_ptr, "Invalid config_ptr pointer");
    return -1;
  }

  /* Validate participant ID */
  if (config_ptr->participant_id == 0 || config_ptr->participant_id > 127) {
    LOG_ERROR(logger_name_ptr, "Invalid participant ID: %u (must be 1-127)",
              config_ptr->participant_id);
    return -1;
  }

  /* Validate interface names */
  if (!config_ptr->secure_interface_ptr || strlen(config_ptr->secure_interface_ptr) == 0) {
    LOG_ERROR(logger_name_ptr, "Secure interface name not set");
    return -1;
  }

  if (!config_ptr->insecure_interface_ptr || strlen(config_ptr->insecure_interface_ptr) == 0) {
    LOG_ERROR(logger_name_ptr, "Insecure interface name not set");
    return -1;
  }

  /* Validate timeouts */
  if (config_ptr->session_timeout_us == 0) {
    LOG_ERROR(logger_name_ptr, "Session timeout must be > 0");
    return -1;
  }

  if (config_ptr->session_response_timeout_us == 0) {
    LOG_ERROR(logger_name_ptr, "Session response timeout must be > 0");
    return -1;
  }

  return 0;
}

void config_print(const ParticipantConfig *config_ptr) {
  // Route through the logging HAL (not printf/stdout) so it works on any target.
  if (!config_ptr) {
    LOG_INFO(logger_name_ptr, "Config: NULL");
    return;
  }

  LOG_INFO(logger_name_ptr, "Participant Configuration:");
  LOG_INFO(logger_name_ptr, "  Participant ID: %u", config_ptr->participant_id);
  LOG_INFO(logger_name_ptr, "  Secure Interface: %s",
           config_ptr->secure_interface_ptr ? config_ptr->secure_interface_ptr : "NULL");
  LOG_INFO(logger_name_ptr, "  Insecure Interface: %s",
           config_ptr->insecure_interface_ptr ? config_ptr->insecure_interface_ptr : "NULL");
  LOG_INFO(logger_name_ptr, "  Keys File: %s",
           config_ptr->keys_file_ptr ? config_ptr->keys_file_ptr : "not set");
  LOG_INFO(logger_name_ptr, "  Time Sync Role: %s",
           config_ptr->enable_timesync_role ? "enabled" : "disabled");
  LOG_INFO(logger_name_ptr, "  Crypto Algorithm: %d", (int)config_ptr->crypto_algorithm);
  LOG_INFO(logger_name_ptr, "  Auth Only Mode: %s",
           config_ptr->auth_only_mode ? "enabled" : "disabled");
  LOG_INFO(logger_name_ptr, "  Heartbeat Timing: %u", config_ptr->heartbeat_timing);
  LOG_INFO(logger_name_ptr, "  Log Level: %s",
           config_ptr->log_level_ptr ? config_ptr->log_level_ptr : "NULL");
  LOG_INFO(logger_name_ptr, "  Log File: %s",
           config_ptr->log_file_ptr ? config_ptr->log_file_ptr : "stdout");
}

uint8_t config_get_default_participant_id(void) {
  return DEFAULT_PARTICIPANT_ID;
}

const char *config_get_default_secure_interface(void) {
  return DEFAULT_SECURE_IF;
}

const char *config_get_default_insecure_interface(void) {
  return DEFAULT_INSECURE_IF;
}

const char *config_get_default_log_level(void) {
  return DEFAULT_LOG_LEVEL;
}

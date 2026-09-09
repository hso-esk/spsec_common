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

#ifndef SPSEC_REGISTERS_H
#define SPSEC_REGISTERS_H

#include <stdint.h>

#define SPSEC_CAPABILITY_AES_GCM (1U << 0)
#define SPSEC_CAPABILITY_CHACHA20_POLY1305 (1U << 1)
#define SPSEC_CAPABILITY_ASCON128 (1U << 2)
#define SPSEC_CAPABILITY_BACKEND_MBEDTLS (1U << 4)
#define SPSEC_CAPABILITY_BACKEND_WOLFSSL (1U << 5)

// Register definitions per SPsec201 V0.33 and SPsec302 CAN FD Mapping V0.33.

/* Register Address Definitions */
typedef enum {
  /* 00h-1Fh: Reserved */

  /* 20h-2Fh: Keys (Write-Only) */
  SPSEC_REG_PROVISIONING_KEY = 0x21, /* 256 bits */
  SPSEC_REG_INTEGRATOR_KEY = 0x22,   /* 256 bits */
  SPSEC_REG_SEED_KEY = 0x23,         /* 256 bits */

  /* 30h-3Fh: Key Salt (Write-Only) */
  SPSEC_REG_PROVISIONING_KEY_SALT = 0x31, /* 64 bits */
  SPSEC_REG_INTEGRATOR_KEY_SALT = 0x32,   /* 64 bits */
  SPSEC_REG_SEED_KEY_SALT = 0x33,         /* 64 bits */

  /* 40h-4Fh: Key ID (Read-Write) */
  SPSEC_REG_PROVISIONING_KEY_ID = 0x41, /* 32 bits */
  SPSEC_REG_INTEGRATOR_KEY_ID = 0x42,   /* 32 bits */
  SPSEC_REG_SEED_KEY_ID = 0x43,         /* 32 bits */

  /* 50h-5Fh: SPsec Information (Read-Only) */
  SPSEC_REG_STATUS = 0x50,               /* 8 bits */
  SPSEC_REG_LAST_SECURITY_EVENT = 0x51,  /* 16 bits */
  SPSEC_REG_CORE_VERSION_INFO = 0x58,    /* String */
  SPSEC_REG_MAPPING_VERSION_INFO = 0x59, /* String */

  /* 60h-7Fh: SPsec Configuration (Read-Write) */
  SPSEC_REG_PARTICIPANT_ID = 0x60,           /* 8 bits, range 1-127 */
  SPSEC_REG_SECURE_HEARTBEAT_TIMING = 0x61,  /* 8 bits */
  SPSEC_REG_SECURE_HEARTBEAT_MONITOR = 0x62, /* 32 bits */
  SPSEC_REG_SYNC_ROLE_ACTIVATION = 0x63,     /* 8 bits */
  SPSEC_REG_CAN_FD_BIT_RATE = 0x7B,          /* 16 bits, write-only */
  SPSEC_REG_MANUFACTURER_RESET = 0x7F,       /* 32 bits, write-only */

  /* 80h-8Fh: SPsec Device Information (Read-Only) */
  SPSEC_REG_DEVICE_IDENTIFICATION = 0x81, /* String */
  SPSEC_REG_MCU_SERIAL_NUMBER = 0x82,     /* 128 bits */

  /* 90h-9Fh: Code Updates */
  SPSEC_REG_CODE_UPDATE_CAPABILITIES = 0x90, /* 32 bits, read-only */
  SPSEC_REG_PUBLIC_AUTH_KEY = 0x91,          /* Read-only */
  SPSEC_REG_CODE_UPDATE_FILE = 0x92,         /* Write-only */

  /* D0h-EFh: Manufacturer Specific (Read-Write) */
  SPSEC_REG_MANUFACTURER_SPECIFIC_START = 0xD0,
  SPSEC_REG_MANUFACTURER_SPECIFIC_END = 0xEF
} spsec_register_t;

/* Maximum length of the Code Update File (0x92), 4096 bytes. */
#ifndef SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN
#define SPSEC_REG_CODE_UPDATE_FILE_MAX_LEN 4096U
#endif

/* SPsec Participant States as defined in the specification */
typedef enum {
  SPSEC_STATE_NOT_SET = 0,
  SPSEC_STATE_WAITING = 1,
  SPSEC_STATE_SECURE = 2,
  SPSEC_STATE_WARNING = 3,
  SPSEC_STATE_CONFIGURATION = 4,
  SPSEC_STATE_SHUTDOWN = 5
} spsec_state_t;

/* State transition events */
typedef enum {
  SPSEC_EVENT_STARTUP = 0,
  SPSEC_EVENT_SECURITY_ESTABLISHED,
  SPSEC_EVENT_SECURITY_EVENT,
  SPSEC_EVENT_EVENTS_CLEAR,
  SPSEC_EVENT_SECURITY_ABORT,
  SPSEC_EVENT_ENTER_CONFIG,
  SPSEC_EVENT_EXIT_CONFIG,
  SPSEC_EVENT_SHUTDOWN
} spsec_event_t;

/* Secure Heartbeat Timing Values (61h) */
typedef enum {
  SPSEC_HEARTBEAT_DISABLED = 0,
  SPSEC_HEARTBEAT_8S = 1,
  SPSEC_HEARTBEAT_4S = 2,
  SPSEC_HEARTBEAT_2S = 3,
  SPSEC_HEARTBEAT_1S = 4,
  SPSEC_HEARTBEAT_500MS = 5,
  SPSEC_HEARTBEAT_250MS = 6,
  /* 80h-8Fh: Manufacturer specific cycle time */
  SPSEC_HEARTBEAT_MANUFACTURER_MIN = 0x80,
  SPSEC_HEARTBEAT_MANUFACTURER_MAX = 0x8F
} spsec_heartbeat_timing_t;

/* CAN FD Nominal Bitrate Values */
typedef enum {
  SPSEC_CAN_NOMINAL_1000KBPS = 0, /* Mandatory */
  SPSEC_CAN_NOMINAL_800KBPS = 1,
  SPSEC_CAN_NOMINAL_500KBPS = 2, /* Mandatory */
  SPSEC_CAN_NOMINAL_250KBPS = 3, /* Mandatory */
  /* A0-FF: manufacturer specific */
  SPSEC_CAN_NOMINAL_MANUFACTURER_MIN = 0xA0,
  SPSEC_CAN_NOMINAL_MANUFACTURER_MAX = 0xFF
} spsec_can_nominal_bitrate_t;

/* CAN FD Data Bitrate Values */
typedef enum {
  SPSEC_CAN_DATA_1MBPS = 0, /* Mandatory */
  SPSEC_CAN_DATA_2MBPS = 1, /* Mandatory */
  SPSEC_CAN_DATA_4MBPS = 2,
  SPSEC_CAN_DATA_5MBPS = 3, /* Mandatory */
  SPSEC_CAN_DATA_8MBPS = 4,
  SPSEC_CAN_DATA_10MBPS = 5,
  /* A0-FF: manufacturer specific */
  SPSEC_CAN_DATA_MANUFACTURER_MIN = 0xA0,
  SPSEC_CAN_DATA_MANUFACTURER_MAX = 0xFF
} spsec_can_data_bitrate_t;

/* Key Selector Values */
typedef enum {
  SPSEC_KEY_SELECTOR_RESERVED = 0,
  SPSEC_KEY_SELECTOR_ZERO_KEY = 1,
  SPSEC_KEY_SELECTOR_SESSION_KEY = 2,
  SPSEC_KEY_SELECTOR_EVEN_COMM_KEY = 3,
  SPSEC_KEY_SELECTOR_ODD_COMM_KEY = 4,
  SPSEC_KEY_SELECTOR_PARAM_AUTH_KEY = 5,
  /* 6-12: Reserved */
  SPSEC_KEY_SELECTOR_SEED_KEY = 13,
  SPSEC_KEY_SELECTOR_INTEGRATOR_KEY = 14,
  SPSEC_KEY_SELECTOR_PROVISIONING_KEY = 15
} spsec_key_selector_t;

/* Register Access Types */
typedef enum {
  SPSEC_ACCESS_READ_ONLY = 0x01,
  SPSEC_ACCESS_WRITE_ONLY = 0x02,
  SPSEC_ACCESS_READ_WRITE = 0x03
} spsec_access_type_t;

/* Security Event Codes (CAN FD specific) */
typedef enum {
  /* Default value */
  SPSEC_NO_SEC_EVENT = 0x0000,

  /* Group 5Exxh – Secure Session Events */
  SPSEC_SESS_HELLO_KEY_NOT_FOUND = 0x5E01,
  SPSEC_SESS_FINISH_AUTH_FAILURE = 0x5E02,
  SPSEC_SESS_RESPONSE_TIMEOUT = 0x5E03,
  SPSEC_SESS_TIMEOUT = 0x5E04,
  SPSEC_SESS_KEY_AUTH_FAILURE = 0x5E05,

  /* Group FExxh – Time Sync Events */
  SPSEC_SYNC_REQ_AUTH_FAILURE = 0xFE00,
  SPSEC_SYNC_REQ_TIMEOUT = 0xFE01,
  SPSEC_SYNC_REFR_AUTH_FAILURE = 0xFE0E,
  SPSEC_SYNC_REFR_TIMEOUT = 0xFE0F,

  /* Group EExxh – Secure Data Plane Events */
  SPSEC_SDP_AUTH_FAILURE = 0xEE00,
  SPSEC_SDP_HB_LOSS_BASE = 0xEF00, /* Add participant ID */

  /* Optional Group DExxh – Data Link Layer Events */
  SPSEC_DLL_RX_OVERRUN = 0xDE01,
  SPSEC_DLL_TX_OVERRUN = 0xDE02,
  SPSEC_DLL_ADRID_GUARD = 0xDE03,
  SPSEC_DLL_DUP_FRAME_IGNORED = 0xDE04
} spsec_security_event_t;

/* Participant ID Constants */
typedef enum {
  SPSEC_SYNC_PARTICIPANT_ID = 0x01,
  SPSEC_DEFAULT_PARTICIPANT_ID = 0x7E,
  SPSEC_CONFIG_PARTICIPANT_ID = 0x7F
} spsec_participant_id_t;

/* Special Values */
typedef enum {
  SPSEC_KEY_ID_INVALID = 0x00000000,
  SPSEC_KEY_ID_RESERVED = (int32_t)0xFFFFFFFF,
  SPSEC_MANUFACTURER_RESET_VALUE = 0x1D04E5E1,
  SPSEC_HEARTBEAT_MONITOR_NONE = 0x00000000,
  SPSEC_HEARTBEAT_MONITOR_ALL = (int32_t)0xFFFFFFFF
} spsec_special_values_t;

/* Sync Role Activation Values */
typedef enum {
  SPSEC_SYNC_ROLE_OFF = 0,
  SPSEC_SYNC_ROLE_ON = 1
} spsec_sync_role_t;

/* Data Structures */

/* SPsec Status Register (50h) */
typedef union {
  uint8_t raw;
  struct {
    uint8_t state : 4;    /* Bits 0-3: Current FSA state */
    uint8_t reserved : 3; /* Bits 4-6: Reserved */
    uint8_t alert : 1;    /* Bit 7: Alert flag */
  } bits;
} spsec_status_t;

/* Secure Heartbeat Monitoring (62h) */
typedef struct {
  uint8_t participant_ids[4];          /* Up to 4 participant IDs to monitor */
  uint64_t last_heartbeat_received[4]; /* Last heartbeat timestamp per
                                          participant ID */
} spsec_heartbeat_monitor_t;

/* CAN FD Bit Rate Register (7Bh) */
typedef union {
  uint16_t raw;
  struct {
    uint8_t nominal_bitrate; /* Lower 8 bits: nominal bitrate */
    uint8_t data_bitrate;    /* Upper 8 bits: data bitrate */
  } rates;
} spsec_can_fd_bitrate_t;

/* Device Information */
typedef struct {
  uint8_t serial[16]; /* 128-bit MCU serial number */
} spsec_mcu_serial_t;

/* Code Update Capabilities (90h) */
typedef union {
  uint32_t raw;
  struct {
    uint32_t update_capable : 1; /* Bit 0: Code update capability */
    uint32_t reserved : 23;      /* Bits 1-23: Reserved */
    uint32_t manufacturer : 8;   /* Bits 24-31: Manufacturer specific */
  } bits;
} spsec_code_update_capabilities_t;

/* Security Stamp Structure (CAN FD) */
typedef struct {
  uint16_t timestamp_lsb : 12; /* Bits 0-11: LSB of timestamp */
  uint16_t padding_bytes : 4;  /* Bits 12-15: Number of padding bytes */
  uint64_t auth_tag;           /* Bits 16-79: Authentication tag */
} __attribute__((packed)) spsec_security_stamp_t;

/* Security Event Helpers */
static inline uint16_t spsec_heartbeat_loss_event(uint8_t participant_id) {
  return SPSEC_SDP_HB_LOSS_BASE + participant_id;
}

/* Configuration Helpers */
static inline spsec_can_fd_bitrate_t
spsec_create_bitrate_config(spsec_can_nominal_bitrate_t nominal,
                            spsec_can_data_bitrate_t data_bitrate) {
  spsec_can_fd_bitrate_t config;
  config.rates.nominal_bitrate = (uint8_t)nominal;
  config.rates.data_bitrate = (uint8_t)data_bitrate;
  return config;
}

#endif /* SPSEC_REGISTERS_H */

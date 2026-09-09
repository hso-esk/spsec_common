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

#ifndef DEVICE_INFO_H
#define DEVICE_INFO_H

#include <stddef.h>
#include <stdint.h>

// Platform hooks for device identification / MCU serial. Currently mocked
// with default values; embedded ports should read real hardware here.

// Device ID string, register 81h (SPsec302 V40 2.3.6).
signed char device_info_get_identification(char *buffer_ptr, size_t buffer_size);

// 128-bit MCU serial number, register 82h (SPsec302 V40 2.3.6).
signed char device_info_get_mcu_serial(uint8_t *serial_ptr);

// Public key for verifying code-update files, register 91h (SPsec302 V40
// 2.3.7.2). Size is KEY_LEN from spsec_mapping.h's SPSEC_REG_PUBLIC_AUTH_KEY.
signed char device_info_get_public_auth_key(uint8_t *key_ptr, size_t *key_size_ptr);

// Code-update capability flags, register 90h (bit 0: update capable).
uint32_t device_info_get_code_update_capabilities(void);

#endif // DEVICE_INFO_H

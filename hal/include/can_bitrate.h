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

#ifndef CAN_BITRATE_H
#define CAN_BITRATE_H

#include "spsec_registers.h"

// Platform hook to apply CAN FD bitrate config from register 7Bh.
signed char can_bitrate_apply(const char *interface_name_ptr,
                              spsec_can_fd_bitrate_t bitrate_config);

// Nominal bitrate enum -> bps (0 if invalid).
uint32_t can_bitrate_nominal_to_bps(uint8_t nominal_enum);

// Data-phase bitrate enum -> bps (0 if invalid).
uint32_t can_bitrate_data_to_bps(uint8_t data_enum);

#endif // CAN_BITRATE_H

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

#ifndef DLL_EVENTS_H
#define DLL_EVENTS_H

#include "spsec_registers.h"
#include <stdbool.h>
#include <stdint.h>

// Optional DLL security events (SPsec302 V40 Section 8.2).

// DLL event detection context.
typedef struct {
  uint32_t last_received_can_id; // Last received CAN ID for duplicate detection
  uint64_t last_received_timestamp; // Timestamp of last received frame
  // Track own used CAN IDs for the address guard. Must hold every registered
  // control-plane ID: cpmt 0..12 (13 types) x 2 addressing modes = 26. Sized to
  // 32 for headroom; an undersized array silently drops IDs from the guard set.
  uint32_t own_can_ids[32];
  uint8_t own_can_id_count;         // Number of own CAN IDs tracked
  bool rx_overrun_detected;         // Receive buffer overrun flag
  bool tx_overrun_detected;         // Transmit buffer overrun flag
} DLLEventContext;

signed char dll_events_init(DLLEventContext *ctx_ptr,
                            uint8_t own_participant_id);

void dll_events_cleanup(DLLEventContext *ctx_ptr);

// DLL_RX_OVERRUN (0xDE01). Returns 0 or the event code.
uint16_t dll_events_check_rx_overrun(DLLEventContext *ctx_ptr);

// DLL_TX_OVERRUN (0xDE02). Returns 0 or the event code.
uint16_t dll_events_check_tx_overrun(DLLEventContext *ctx_ptr);

// DLL_ADRID_GUARD (0xDE03): flags a frame using our own registered CAN ID.
uint16_t dll_events_check_address_guard(DLLEventContext *ctx_ptr,
                                        uint32_t can_id);

// DLL_DUP_FRAME_IGNORED (0xDE04): flags a repeat of the last-seen frame.
uint16_t dll_events_check_duplicate_frame(DLLEventContext *ctx_ptr,
                                          uint32_t can_id,
                                          uint64_t current_timestamp);

// Register a CAN ID as ours, for the address guard check above.
void dll_events_register_own_can_id(DLLEventContext *ctx_ptr, uint32_t can_id);

// Runs all DLL checks on a received frame; returns the first event code hit, or 0.
uint16_t dll_events_process_received_frame(DLLEventContext *ctx_ptr,
                                           uint32_t can_id,
                                           uint64_t current_timestamp);

#endif // DLL_EVENTS_H

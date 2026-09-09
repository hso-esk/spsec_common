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

// utils_bytes.h

#ifndef UTILS_BYTES_H
#define UTILS_BYTES_H

#include <stddef.h>
#include <stdint.h>

// Convert a 32-bit little-endian byte array to host-endian uint32_t.
static inline uint32_t bytes_to_u32_le(const uint8_t b[4]) {
  return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}

// Write a 32-bit value into a 4-byte little-endian array.
static inline void u32_to_bytes_le(uint32_t value, uint8_t out_ptr[4]) {
  out_ptr[0] = (uint8_t)(value & 0xFF);
  out_ptr[1] = (uint8_t)((value >> 8) & 0xFF);
  out_ptr[2] = (uint8_t)((value >> 16) & 0xFF);
  out_ptr[3] = (uint8_t)((value >> 24) & 0xFF);
}

// Convert a 64-bit little-endian byte array to host-endian uint64_t.
static inline uint64_t bytes_to_u64_le(const uint8_t b_ptr[8]) {
  return ((uint64_t)b_ptr[0]) | ((uint64_t)b_ptr[1] << 8) | ((uint64_t)b_ptr[2] << 16) |
         ((uint64_t)b_ptr[3] << 24) | ((uint64_t)b_ptr[4] << 32) |
         ((uint64_t)b_ptr[5] << 40) | ((uint64_t)b_ptr[6] << 48) |
         ((uint64_t)b_ptr[7] << 56);
}

// Write a 64-bit value into an 8-byte little-endian array.
static inline void u64_to_bytes_le(uint64_t value, uint8_t out_ptr[8]) {
  out_ptr[0] = (uint8_t)(value & 0xFF);
  out_ptr[1] = (uint8_t)((value >> 8) & 0xFF);
  out_ptr[2] = (uint8_t)((value >> 16) & 0xFF);
  out_ptr[3] = (uint8_t)((value >> 24) & 0xFF);
  out_ptr[4] = (uint8_t)((value >> 32) & 0xFF);
  out_ptr[5] = (uint8_t)((value >> 40) & 0xFF);
  out_ptr[6] = (uint8_t)((value >> 48) & 0xFF);
  out_ptr[7] = (uint8_t)((value >> 56) & 0xFF);
}

// Copy at most dst_len bytes from src to dst; returns number of bytes copied.
// If src_len < dst_len, remaining bytes in dst are left unchanged.
static inline size_t bounded_copy(uint8_t *dst_ptr, size_t dst_len,
                                  const uint8_t *src_ptr, size_t src_len) {
  if (!dst_ptr || !src_ptr || dst_len == 0 || src_len == 0)
    return 0;
  size_t n = dst_len < src_len ? dst_len : src_len;
  for (size_t i = 0; i < n; i++)
    dst_ptr[i] = src_ptr[i];
  return n;
}

#endif // UTILS_BYTES_H

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

#ifndef TIMER_H
#define TIMER_H

#include <stddef.h>

#include <stdint.h>
#if !(defined(SDK_OS_BAREMETAL) || defined(LPC55_SERIES))
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#endif

// Timestamp is serialized as a 64-bit little-endian tick counter.
// Default resolution is 100us (0.1ms), scalable via timer_set_tick_ns().

#if defined(SDK_OS_BAREMETAL) || defined(LPC55_SERIES)
typedef struct {
  uint8_t timestamp[8];
  uint64_t tick_base; // 64-bit ticks (tick_ns each) at start reference
  uint8_t seconds_symbol_index;
  uint32_t tick_ns; // tick resolution in nanoseconds (default 100000)

  // DWT cycle counter based timekeeping
  uint64_t start_cycles64; // 64-bit cycle count at (re)start
  uint64_t cycle_high;  // high 32-bit overflow accumulator (multiple of 2^32)
  uint32_t last_cyccnt; // last observed DWT->CYCCNT (low 32 bits)
} FreeRunningTimer;
#else
typedef struct {
  uint8_t timestamp[8];
  pthread_mutex_t lock;
  // atomic_bool not volatile: fixes a real -fsanitize=thread race between
  // timer_thread's read and timer_destroy's write.
  atomic_bool running;
  pthread_t thread;
  int thread_started; // guards timer_destroy()'s pthread_join against a
                       // never-created thread handle
  struct timespec start_mono; // CLOCK_MONOTONIC reference
  uint64_t tick_base;         // 64-bit ticks (tick_ns each) at start_mono

  uint8_t seconds_symbol_index;
  uint32_t tick_ns; // tick resolution in ns (default 100000); read under
                     // `lock`, so changing it after init is race-free
  int synced; // 0 until first authoritative timestamp; gates the
              // backward-jump guard until the random start epoch is replaced
} FreeRunningTimer;
#endif

// Start timer at base resolution; seconds_symbol_index scales speed.
signed char timer_init(FreeRunningTimer *timer_ptr, uint8_t seconds_symbol_index);
void timer_destroy(FreeRunningTimer *timer_ptr);

// Set the tick resolution in nanoseconds.
void timer_set_tick_ns(FreeRunningTimer *timer_ptr, uint32_t tick_ns);
uint32_t timer_get_tick_ns(FreeRunningTimer *timer_ptr);

// The reference tick all bitrate-independent tick counts are expressed in
// (0.1 ms), regardless of the timer's actual configured resolution.
#define SPSEC_REFERENCE_TICK_NS 100000ULL

// Convert reference 0.1ms ticks into the timer's actual tick domain.
static inline uint64_t timer_reference_ticks(FreeRunningTimer *timer_ptr,
                                             uint64_t ref_ticks) {
  return ref_ticks * SPSEC_REFERENCE_TICK_NS / (uint64_t)timer_get_tick_ns(timer_ptr);
}
void timer_get_timestamp(FreeRunningTimer *timer_ptr, uint8_t *timestamp_ptr);
signed char timer_set_timestamp(FreeRunningTimer *timer_ptr,
                                uint8_t *timestamp_ptr);
uint64_t timer_get_difference(FreeRunningTimer *timer_ptr, uint8_t *timestamp_ptr);
uint64_t timer_get_current_time_us(FreeRunningTimer *timer_ptr);

void platform_time_format(char *buf_ptr, size_t buf_size, const char *level_ptr,
                          const char *logger_ptr);

#endif
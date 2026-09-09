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

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include "spsec_common.h"
#include "logging.h"
#include "timer.h"
#include <stdarg.h>
#include <string.h>
#include <strings.h>

int current_log_level = LOG_LEVEL_INFO;
static bool g_structured_output = false;

// Formats one segment and hands it to the platform log sink (HAL) -- the
// only coupling between the portable log formatter and the OS.
static void log_write(const char *fmt_ptr, ...) {
  char buf[256];
  va_list args_ptr;
  va_start(args_ptr, fmt_ptr);
  int n = vsnprintf(buf, sizeof(buf), fmt_ptr, args_ptr);
  va_end(args_ptr);
  if (n < 0)
    return;
  size_t len = (n < (int)sizeof(buf)) ? (size_t)n : sizeof(buf) - 1;
  platform_log_write(buf, len);
}

// Print a literal string segment without using dynamic precision ("%.*s"),
// which is unsupported by some printf implementations (e.g.,
// DbgConsole_Printf).
static void log_print_literal_segment(const char *start_ptr, int len) {
  // Print in small chunks to avoid large stack buffers
  enum { CHUNK = 64 };
  int offset = 0;
  while (offset < len) {
    int chunk_len = len - offset;
    if (chunk_len > CHUNK)
      chunk_len = CHUNK;
    char buf[CHUNK + 1];
    for (int i = 0; i < chunk_len; ++i)
      buf[i] = start_ptr[offset + i];
    buf[chunk_len] = '\0';
    log_write("%s", buf);
    offset += chunk_len;
  }
}

// Build a small integer format_ptr string with explicit width digits instead of
// "%*". suffix_ptr examples: "d", "ld", "lld", "u", "x", "X", etc.
static void build_width_format(char *out_ptr, size_t out_size, bool zero_pad,
                               int width, const char *suffix_ptr) {
  // Ensure minimal capacity
  if (out_size == 0)
    return;
  size_t pos = 0;
  out_ptr[pos++] = '%';
  if (pos < out_size && zero_pad)
    out_ptr[pos++] = '0';
  if (width > 0) {
    // Convert width to decimal digits
    char tmp[10];
    int n = 0;
    unsigned int w = (unsigned int)width;
    do {
      tmp[n++] = (char)('0' + (w % 10));
      w /= 10;
    } while (w != 0 && n < (int)sizeof(tmp));
    // reverse into out_ptr
    while (n > 0 && pos < out_size)
      out_ptr[pos++] = tmp[--n];
  }
  // append suffix_ptr
  for (size_t i = 0; suffix_ptr[i] != '\0' && pos < out_size; ++i)
    out_ptr[pos++] = suffix_ptr[i];
  // zero-terminate
  out_ptr[(pos < out_size) ? pos : (out_size - 1)] = '\0';
}

// Print size_t without relying on "%zu" (not supported by some printf backends)
static void log_print_size_t_decimal(size_t value, bool zero_pad, int width) {
  // Convert value to decimal string (no dynamic allocation)
  char digits[32];
  int n = 0;
  size_t v = value;
  do {
    digits[n++] = (char)('0' + (int)(v % 10));
    v /= 10;
  } while (v != 0 && n < (int)sizeof(digits));

  int pad = width - n;
  if (pad < 0)
    pad = 0;
  char pad_char = zero_pad ? '0' : ' ';

  for (int i = 0; i < pad; ++i)
    log_write("%c", pad_char);

  for (int i = n - 1; i >= 0; --i)
    log_write("%c", digits[i]);
}

// Print an unsigned integer in hexadecimal without relying on backend
// zero-padding support
static void log_print_hex_unsigned(unsigned long long value, bool uppercase,
                                   bool zero_pad, int width) {
  // Convert value to hex string (no dynamic allocation)
  char digits[32];
  size_t n = 0;
  if (value == 0) {
    digits[n++] = '0';
  } else {
    while (value != 0 && n < sizeof(digits)) {
      unsigned int nibble = (unsigned int)(value & 0xFu);
      char base = uppercase ? 'A' : 'a';
      if (nibble < 10)
        digits[n++] = (char)('0' + nibble);
      else
        digits[n++] = (char)((int)base + ((int)nibble - 10));
      value >>= 4;
    }
  }

  size_t pad = (width > (int)n) ? (size_t)(width - (int)n) : 0;
  char pad_char = zero_pad ? '0' : ' ';

  for (size_t i = 0; i < pad; ++i)
    log_write("%c", pad_char);

  while (n > 0) {
    log_write("%c", digits[--n]);
  }
}

static void print_formatted_message(const char *format_ptr, va_list args_ptr) {
  const char *p_ptr = format_ptr;
  while (*p_ptr) {
    if (*p_ptr != '%') {
      const char *start_ptr = p_ptr;
      while (*p_ptr && *p_ptr != '%')
        p_ptr++;
      int len = (int)(p_ptr - start_ptr);
      if (len > 0)
        log_print_literal_segment(start_ptr, len);
      continue;
    }

    p_ptr++; // skip '%'
    if (*p_ptr == '%') {
      log_write("%%");
      p_ptr++;
      continue;
    }

    bool zero_pad = false;
    int width = 0;

    if (*p_ptr == '0') {
      zero_pad = true;
      p_ptr++;
    }

    while (*p_ptr >= '0' && *p_ptr <= '9') {
      width = width * 10 + (*p_ptr - '0');
      p_ptr++;
    }

    bool is_size_t = false;
    if (*p_ptr == 'z') {
      is_size_t = true;
      p_ptr++;
    }

    // Support for 'l' and 'll' length modifiers
    bool is_long = false;
    bool is_long_long = false;
    if (*p_ptr == 'l') {
      is_long = true;
      p_ptr++;
      if (*p_ptr == 'l') {
        is_long_long = true;
        p_ptr++;
      }
    }

    char spec = *p_ptr ? *p_ptr++ : '\0';
    switch (spec) {
    case 'd': {
      if (is_long_long) {
        long long v = va_arg(args_ptr, long long);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "lld");
          log_write(fmt_ptr, v);
        } else
          log_write("%lld", v);
      } else if (is_long) {
        long v = va_arg(args_ptr, long);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "ld");
          log_write(fmt_ptr, v);
        } else
          log_write("%ld", v);
      } else {
        int v = va_arg(args_ptr, int);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "d");
          log_write(fmt_ptr, v);
        } else
          log_write("%d", v);
      }
      break;
    }
    case 'u': {
      if (is_size_t) {
        size_t v = va_arg(args_ptr, size_t);
        log_print_size_t_decimal(v, zero_pad, width);
      } else if (is_long_long) {
        unsigned long long v = va_arg(args_ptr, unsigned long long);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "llu");
          log_write(fmt_ptr, v);
        } else
          log_write("%llu", v);
      } else if (is_long) {
        unsigned long v = va_arg(args_ptr, unsigned long);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "lu");
          log_write(fmt_ptr, v);
        } else
          log_write("%lu", v);
      } else {
        unsigned int v = va_arg(args_ptr, unsigned int);
        if (width > 0) {
          char fmt_ptr[16];
          build_width_format(fmt_ptr, sizeof(fmt_ptr), zero_pad, width, "u");
          log_write(fmt_ptr, v);
        } else
          log_write("%u", v);
      }
      break;
    }
    case 'x': {
      unsigned long long v;
      if (is_long_long)
        v = va_arg(args_ptr, unsigned long long);
      else if (is_long)
        v = (unsigned long long)va_arg(args_ptr, unsigned long);
      else
        v = (unsigned long long)va_arg(args_ptr, unsigned int);
      log_print_hex_unsigned(v, false, zero_pad, width);
      break;
    }
    case 'X': {
      unsigned long long v;
      if (is_long_long)
        v = va_arg(args_ptr, unsigned long long);
      else if (is_long)
        v = (unsigned long long)va_arg(args_ptr, unsigned long);
      else
        v = (unsigned long long)va_arg(args_ptr, unsigned int);
      log_print_hex_unsigned(v, true, zero_pad, width);
      break;
    }
    case 'p': {
      void *v_ptr = va_arg(args_ptr, void *);
      log_write("%p", v_ptr);
      break;
    }
    case 's': {
      const char *s_ptr = va_arg(args_ptr, const char *);
      if (!s_ptr)
        s_ptr = "(null)";
      log_write("%s", s_ptr);
      break;
    }
    case 'c': {
      int c = va_arg(args_ptr, int);
      log_write("%c", c);
      break;
    }
    default: {
      // Fallback: print the percent and the spec as-is
      log_write("%%");
      if (spec)
        log_write("%c", spec);
      break;
    }
    }
  }
}

uint8_t is_first_bit_set(uint8_t byte) {
  return (byte & 0x80) != 0;
}

uint8_t remove_first_bit(uint8_t byte) {
  return byte & 0x7F;
}

void configure_logging(const char *log_level_ptr) {
  if (strcasecmp(log_level_ptr, "DEBUG") == 0)
    current_log_level = LOG_LEVEL_DEBUG;
  else if (strcasecmp(log_level_ptr, "INFO") == 0)
    current_log_level = LOG_LEVEL_INFO;
  else if (strcasecmp(log_level_ptr, "WARNING") == 0)
    current_log_level = LOG_LEVEL_WARNING;
  else if (strcasecmp(log_level_ptr, "ERROR") == 0)
    current_log_level = LOG_LEVEL_ERROR;
  else if (strcasecmp(log_level_ptr, "CRITICAL") == 0)
    current_log_level = LOG_LEVEL_CRITICAL;
}

// File sink + rotation live in platform/logging.c, so portable code stays
// free of filesystem/stdio deps; these just forward to it.
void configure_logging_file(const char *log_file_path_ptr, size_t max_file_size,
                            int max_rotated_files) {
  platform_log_configure_file(log_file_path_ptr, max_file_size, max_rotated_files);
}

void configure_logging_structured(bool enable) { g_structured_output = enable; }

void logging_cleanup(void) { platform_log_cleanup(); }

void log_message(int level, const char *name_ptr, const char *format_ptr, ...) {
  if (level < current_log_level)
    return;

  const char *level_str[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
  char prefix[64];
  platform_time_format(prefix, sizeof(prefix), level_str[level / 10 - 1], name_ptr);

  if (g_structured_output) {
    /* Structured JSON logging */
    log_write("{\"timestamp\":\"%s\",\"level\":\"%s\",\"logger\":\"%s\","
              "\"message\":\"",
              prefix, level_str[level / 10 - 1], name_ptr);
    va_list args_ptr;
    va_start(args_ptr, format_ptr);
    /* Message string is written directly into JSON output. */
    print_formatted_message(format_ptr, args_ptr);
    va_end(args_ptr);
    log_write("\"}\n");
  } else {
    /* Plain text logging */
    log_write("%s", prefix);
    va_list args_ptr;
    va_start(args_ptr, format_ptr);
    print_formatted_message(format_ptr, args_ptr);
    va_end(args_ptr);
    log_write("\n");
  }

  platform_log_flush();
}

void format_byte_array(char *buffer_ptr, size_t buffer_size, const uint8_t *array_ptr,
                       size_t array_len) {
  if (buffer_size == 0)
    return;

  static const char hex[] = "0123456789ABCDEF";
  size_t pos = 0;

  // Opening bracket
  if (pos < buffer_size - 1)
    buffer_ptr[pos++] = '[';

  for (size_t i = 0; i < array_len; ++i) {
    if (i > 0) {
      if (pos < buffer_size - 1)
        buffer_ptr[pos++] = ' ';
    }

    uint8_t b = array_ptr[i];
    char hi = hex[(b >> 4) & 0x0F];
    char lo = hex[b & 0x0F];

    if (pos < buffer_size - 1)
      buffer_ptr[pos++] = hi;
    if (pos < buffer_size - 1)
      buffer_ptr[pos++] = lo;
  }

  if (pos < buffer_size - 1)
    buffer_ptr[pos++] = ']';

  buffer_ptr[pos < buffer_size ? pos : (buffer_size - 1)] = '\0';
}

void format_hex_string(char *buffer_ptr, size_t buffer_size, const uint8_t *array_ptr,
                       size_t array_len) {
  if (!buffer_ptr || buffer_size == 0)
    return;
  buffer_ptr[0] = '\0';
  if (!array_ptr || array_len == 0)
    return;

  static const char hex[] = "0123456789abcdef";
  size_t pos = 0;
  for (size_t i = 0; i < array_len && pos + 2 < buffer_size; ++i) {
    buffer_ptr[pos++] = hex[(array_ptr[i] >> 4) & 0x0F];
    buffer_ptr[pos++] = hex[array_ptr[i] & 0x0F];
  }
  buffer_ptr[pos] = '\0';
}

// Increments a little-endian byte array; returns true on overflow.
bool increment_bytearray(uint8_t *bytes_ptr, size_t len) {
  bool carry = true;
  for (size_t i = 0; i < len; i++) {
    if (carry) {
      if (bytes_ptr[i] == 255) {
        bytes_ptr[i] = 0;
      } else {
        bytes_ptr[i]++;
        carry = false;
      }
    }
  }
  return carry; // true = overflow occurred, false = no overflow
}

// Constant-time byte compare (0 = equal). Timing depends only on length,
// not where a mismatch is -- safe for comparing auth tags/MACs.
int spsec_ct_memcmp(const void *a_ptr, const void *b_ptr, size_t length) {
  const volatile uint8_t *pa_ptr = (const volatile uint8_t *)a_ptr;
  const volatile uint8_t *pb_ptr = (const volatile uint8_t *)b_ptr;
  uint8_t diff = 0;
  for (size_t i = 0; i < length; i++) {
    diff |= (uint8_t)(pa_ptr[i] ^ pb_ptr[i]);
  }
  return diff;
}

// Zeroes memory in a way the compiler won't optimize away.
void spsec_explicit_bzero(void *s_ptr, size_t len) {
  if (!s_ptr || len == 0)
    return;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
  explicit_bzero(s_ptr, len);
#else
  volatile unsigned char *p_ptr = (volatile unsigned char *)s_ptr;
  while (len--) {
    *p_ptr++ = 0;
  }
#endif
}
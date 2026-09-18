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

#include "messages.h"
#include "spsec_common.h"

static const char *logger_name_ptr = "messages_core";

// Safety margin before counter wrap to prevent nonce reuse.
#define SESSION_CNT_WRAP_MARGIN 1000u

// Builds a nonce from the session counter and shared salt (little-endian).

int8_t generate_nonce_from_session_cnt(uint32_t session_cnt, uint8_t **nonce_ptr,
                                       SPsecSalt *spsec_salt_ptr) {
  if (session_cnt >= UINT32_MAX - SESSION_CNT_WRAP_MARGIN) {
    LOG_ERROR(logger_name_ptr,
              "Session counter %u is within %u of wrapping - refusing to "
              "generate a nonce to avoid reuse; session must be re-established",
              session_cnt, SESSION_CNT_WRAP_MARGIN);
    return -4;
  }

  size_t counter_len = sizeof(session_cnt);
  size_t nonce_len = REQUIRED_NONCE_LEN; // Default for session/control plane

  // Zero-initialized so bytes beyond counter and salt remain zero-padded
  *nonce_ptr = (uint8_t *)calloc(1, nonce_len);
  if (!*nonce_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate nonce memory");
    return -3;
  }

  // Copy session counter first (little-endian, lowest bytes first)
  (*nonce_ptr)[0] = (uint8_t)(session_cnt & 0xFF);
  (*nonce_ptr)[1] = (uint8_t)((session_cnt >> 8) & 0xFF);
  (*nonce_ptr)[2] = (uint8_t)((session_cnt >> 16) & 0xFF);
  (*nonce_ptr)[3] = (uint8_t)((session_cnt >> 24) & 0xFF);

  // Append salt to higher bytes (pre-shared per SPsec 2.3.2), clamped to
  // SALT_LEN so an 8-byte salt is not over-read into a 12-byte gap.
  size_t salt_bytes = nonce_len - counter_len;
  if (salt_bytes > SALT_LEN)
    salt_bytes = SALT_LEN;
  memcpy(*nonce_ptr + counter_len, spsec_salt_ptr->salt, salt_bytes);

  LOG_SECRET(logger_name_ptr, "Generated extended nonce (LE counter + salt):", *nonce_ptr,
            nonce_len);

  return 0;
}

// Main wrapper for SPsec messages
SPsecMessage *spsecmessage_new(uint8_t msg_type, void *msg_content_ptr) {
  SPsecMessage *msg_ptr = malloc(sizeof(SPsecMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->msg_type = msg_type;
  msg_ptr->msg_content_ptr = msg_content_ptr;
  return msg_ptr;
}

// Frees the wrapper only; content is caller-owned.
void spsecmessage_free(SPsecMessage *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr);
  }
}

void spsecmessage_dispose(SPsecMessage *msg_ptr) {
  if (!msg_ptr) {
    return;
  }
  // Free nested buffers via type-specific destructor before freeing wrapper.
  switch (msg_ptr->msg_type) {
  case MSGTYPE_APP_DATA:
    spsecappdata_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_HEARTBEAT:
    spsecheartbeat_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_SYNC_TIME_BROADCAST:
    spsecsynctimebroadcast_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_TIME_SYNC_RESPONSE:
    timesyncresponse_free(msg_ptr->msg_content_ptr);
    break;
  case MSGTYPE_CLIENT_WRITE_SEGMENT:
    spsecwritesegmentrequest_free(msg_ptr->msg_content_ptr);
    break;
  default:
    free(msg_ptr->msg_content_ptr);
    break;
  }
  spsecmessage_free(msg_ptr);
}

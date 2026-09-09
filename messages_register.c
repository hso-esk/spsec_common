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

static const char *logger_name_ptr = "messages_register";

// --- Read Initiate ---

SPsecReadInitiateMessage *spsecreadinitiatemessage_new(uint8_t participant_id,
                                                       uint32_t cnt,
                                                       uint8_t reg,
                                                       uint32_t len) {
  SPsecReadInitiateMessage *msg_ptr = malloc(sizeof(SPsecReadInitiateMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->participant_id = participant_id;
  msg_ptr->cnt = cnt;
  msg_ptr->reg = reg;
  msg_ptr->len = len;

  msg_ptr->plaintext[0] = reg;
  msg_ptr->plaintext[1] = 0xFF;
  msg_ptr->plaintext[2] = 0xFF;
  msg_ptr->plaintext[3] = 0xFF;

  uint8_t length[4];
  length[0] = (uint8_t)(len & 0xFF);
  length[1] = (uint8_t)((len >> 8) & 0xFF);
  length[2] = (uint8_t)((len >> 16) & 0xFF);
  length[3] = (uint8_t)((len >> 24) & 0xFF);

  memcpy(msg_ptr->plaintext + 4, length, 4);

  return msg_ptr;
}
char spsecreadinitiatemessage_parse_plaintext(
    SPsecReadInitiateMessage *msg_ptr) {
  msg_ptr->reg = msg_ptr->plaintext[0];
  msg_ptr->len = (uint32_t)msg_ptr->plaintext[4] |
                 ((uint32_t)msg_ptr->plaintext[5] << 8) |
                 ((uint32_t)msg_ptr->plaintext[6] << 16) |
                 ((uint32_t)msg_ptr->plaintext[7] << 24);
  LOG_DEBUG(logger_name_ptr, "Parsed Read Initiate Message: reg=%u, len=%u",
            msg_ptr->reg, msg_ptr->len);
  return 0;
}

void spsecreadinitiatemessage_free(SPsecReadInitiateMessage *msg_ptr) {
  free(msg_ptr);
}

SPsecClientReadSegmentRequest *
spsecreadsegmentrequest_new(uint8_t participant_id, uint32_t cnt) {
  SPsecClientReadSegmentRequest *req_ptr =
      malloc(sizeof(SPsecClientReadSegmentRequest));
  if (!req_ptr)
    return NULL;
  req_ptr->participant_id = participant_id;
  req_ptr->cnt = cnt;
  return req_ptr;
}
void spsecreadsegmentrequest_free(SPsecClientReadSegmentRequest *msg_ptr) {
  free(msg_ptr);
}

SPsecServerReadSegmentResponse *
spsecreadsegmentresponse_new(uint8_t participant_id, uint32_t cnt,
                             uint8_t *data_ptr, uint32_t data_len) {
  SPsecServerReadSegmentResponse *resp_ptr =
      malloc(sizeof(SPsecServerReadSegmentResponse));
  if (!resp_ptr)
    return NULL;
  resp_ptr->participant_id = participant_id;
  resp_ptr->cnt = cnt;
  resp_ptr->data_ptr = data_ptr;
  resp_ptr->data_len = data_len;
  // _free() unconditionally frees ciphertext_ptr, so it must start NULL until a
  // caller assigns it (otherwise it is a free of an uninitialized pointer).
  resp_ptr->ciphertext_ptr = NULL;
  return resp_ptr;
}
void spsecreadsegmentresponse_free(SPsecServerReadSegmentResponse *msg_ptr) {
  if (msg_ptr) {
    // Free the data_ptr pointer if it exists
    if (msg_ptr->data_ptr) {
      free(msg_ptr->data_ptr);
    }
    // Free the ciphertext_ptr pointer if it exists
    if (msg_ptr->ciphertext_ptr) {
      free(msg_ptr->ciphertext_ptr);
    }
    free(msg_ptr);
  }
}

// --- Write Initiate ---
SPsecWriteInitiateMessage *spsecwriteinitiatemessage_new(uint8_t participant_id,
                                                         uint32_t cnt,
                                                         uint8_t reg,
                                                         uint32_t len) {
  SPsecWriteInitiateMessage *msg_ptr =
      malloc(sizeof(SPsecWriteInitiateMessage));
  if (!msg_ptr)
    return NULL;

  msg_ptr->participant_id = participant_id;
  msg_ptr->cnt = cnt;
  msg_ptr->reg = reg;
  msg_ptr->len = len;

  msg_ptr->plaintext[0] = reg;
  msg_ptr->plaintext[1] = 0xFF;
  msg_ptr->plaintext[2] = 0xFF;
  msg_ptr->plaintext[3] = 0xFF;

  uint8_t length[4];
  length[0] = (uint8_t)(len & 0xFF);
  length[1] = (uint8_t)((len >> 8) & 0xFF);
  length[2] = (uint8_t)((len >> 16) & 0xFF);
  length[3] = (uint8_t)((len >> 24) & 0xFF);

  memcpy(msg_ptr->plaintext + 4, length, 4);

  return msg_ptr;
}

char spsecwriteinitiatemessage_parse_plaintext(
    SPsecWriteInitiateMessage *msg_ptr) {
  msg_ptr->reg = msg_ptr->plaintext[0];
  msg_ptr->len = (uint32_t)msg_ptr->plaintext[4] |
                 ((uint32_t)msg_ptr->plaintext[5] << 8) |
                 ((uint32_t)msg_ptr->plaintext[6] << 16) |
                 ((uint32_t)msg_ptr->plaintext[7] << 24);
  LOG_DEBUG(logger_name_ptr, "Parsed Write Initiate Request: reg=%u, len=%u",
            msg_ptr->reg, msg_ptr->len);
  return 0;
}

char spsecwritesegmentmessage_parse_plaintext(
    SPsecClientWriteSegmentResponse *msg_ptr) {
  msg_ptr->err = msg_ptr->plaintext[0];
  LOG_DEBUG(logger_name_ptr, "Parsed Write Segment Response: err=%u", msg_ptr->err);
  return 0;
}

void spsecwriteinitiatemessage_free(SPsecWriteInitiateMessage *msg_ptr) {
  free(msg_ptr);
}

SPsecClientWriteSegmentRequest *
spsecwritesegmentrequest_new(uint8_t participant_id, uint32_t cnt,
                             uint8_t *data_ptr, uint8_t data_len) {
  SPsecClientWriteSegmentRequest *req_ptr =
      malloc(sizeof(SPsecClientWriteSegmentRequest));
  if (!req_ptr)
    return NULL;

  // Set address to 0 for now, will be set later
  req_ptr->address = 0;

  req_ptr->participant_id = participant_id;
  req_ptr->cnt = cnt;
  req_ptr->data_ptr = malloc(data_len);
  if (!req_ptr->data_ptr) {
    free(req_ptr);
    return NULL;
  }
  memcpy(req_ptr->data_ptr, data_ptr, data_len);
  req_ptr->data_len = data_len;

  req_ptr->ciphertext_ptr = malloc(data_len);
  if (!req_ptr->ciphertext_ptr) {
    free(req_ptr->data_ptr);
    free(req_ptr);
    return NULL;
  }

  memset(req_ptr->auth_tag, 0, AUTH_TAG_SIZE); // Initialize auth tag to zero

  return req_ptr;
}

void spsecwritesegmentrequest_free(SPsecClientWriteSegmentRequest *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr->data_ptr);
    free(msg_ptr->ciphertext_ptr);
    free(msg_ptr);
  }
}

SPsecClientWriteSegmentResponse *
spsecwritesegmentresponse_new(uint8_t participant_id, uint32_t cnt,
                              uint8_t err) {
  SPsecClientWriteSegmentResponse *msg_ptr =
      malloc(sizeof(SPsecClientWriteSegmentResponse));
  if (!msg_ptr)
    return NULL;

  msg_ptr->participant_id = participant_id;
  msg_ptr->cnt = cnt;
  msg_ptr->err = err;

  msg_ptr->plaintext[0] = err;
  msg_ptr->plaintext[1] = 0xFF;
  msg_ptr->plaintext[2] = 0xFF;
  msg_ptr->plaintext[3] = 0xFF;

  return msg_ptr;
}

void spsecwritesegmentresponse_free(SPsecClientWriteSegmentResponse *msg_ptr) {
  free(msg_ptr);
}

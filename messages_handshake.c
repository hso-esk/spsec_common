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

static const char *logger_name_ptr = "messages_handshake";

// SPsec Session establishment messages
SPsecClientHelloMessage *spsecclienthello_new(uint8_t participant_id,
                                              uint8_t key_selector,
                                              const uint8_t *random_ptr) {
  SPsecClientHelloMessage *msg_ptr = malloc(sizeof(SPsecClientHelloMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->participant_id = participant_id;
  msg_ptr->key_selector[0] = key_selector;

  // Set bytes 2-4 (indexes 1-3) to 0xFF
  msg_ptr->key_selector[1] = 0xFF;
  msg_ptr->key_selector[2] = 0xFF;
  msg_ptr->key_selector[3] = 0xFF;

  memcpy(msg_ptr->random, random_ptr, RANDOM_SIZE);
  return msg_ptr;
}

void spsecclienthello_free(SPsecClientHelloMessage *msg_ptr) {
  free(msg_ptr);
}

SPsecServerHelloMessage *spsecserverhello_new(uint8_t participant_id,
                                              const uint8_t *random_ptr) {
  SPsecServerHelloMessage *msg_ptr = malloc(sizeof(SPsecServerHelloMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->participant_id = participant_id;
  memcpy(msg_ptr->random, random_ptr, RANDOM_SIZE);
  return msg_ptr;
}

void spsecserverhello_free(SPsecServerHelloMessage *msg_ptr) {
  free(msg_ptr);
}

SPsecClientFinishedMessage *spsecclientfinished_new(uint8_t participant_id,
                                                    uint32_t cnt) {
  LOG_DEBUG(logger_name_ptr,
            "spsecclientfinished_new with participant_id=%d, cnt=%d",
            participant_id, cnt);

  SPsecClientFinishedMessage *msg_ptr =
      malloc(sizeof(SPsecClientFinishedMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->participant_id = participant_id;
  msg_ptr->cnt = cnt;

  LOG_DEBUG(logger_name_ptr, "Allocated SPsecClientFinishedMessage at %p", msg_ptr);

  return msg_ptr;
}

void spsecclientfinished_free(SPsecClientFinishedMessage *msg_ptr) {
  free(msg_ptr);
}

SPsecServerFinishedMessage *spsecserverfinished_new(uint8_t participant_id,
                                                    uint32_t cnt) {
  SPsecServerFinishedMessage *msg_ptr =
      malloc(sizeof(SPsecServerFinishedMessage));
  if (!msg_ptr)
    return NULL;

  msg_ptr->participant_id = participant_id;
  msg_ptr->cnt = cnt;

  return msg_ptr;
}

void spsecserverfinished_free(SPsecServerFinishedMessage *msg_ptr) {
  free(msg_ptr);
}

// --- ConfigurationSessionAuthTagData constructor and destructor ---
ConfigurationSessionAuthTagData *authtagparticipantdata_new(void) {
  ConfigurationSessionAuthTagData *data_ptr =
      (ConfigurationSessionAuthTagData *)malloc(
          sizeof(ConfigurationSessionAuthTagData));
  if (data_ptr) {
    memset(data_ptr, 0, sizeof(ConfigurationSessionAuthTagData));
  }
  return data_ptr;
}

void authtagparticipantdata_free(ConfigurationSessionAuthTagData *data_ptr) {
  if (data_ptr) {
    free(data_ptr);
  }
}

// Called one time to provide an initial unpredictable starting value for the
// session counter
uint32_t calculate_shared_cnt(ConfigurationSessionAuthTagData *data_ptr) {
  uint8_t xor_result[4];

  // Log values of used server and client random_ptr for debugging
  LOG_SECRET(logger_name_ptr, "Client Random", data_ptr->cli_random,
            RANDOM_SIZE);
  LOG_SECRET(logger_name_ptr, "Server Random", data_ptr->srv_random,
            RANDOM_SIZE);

  // Perform XOR between cli_random and srv_random
  for (int i = 0; i < 4; i++) {
    xor_result[i] = data_ptr->cli_random[i] ^ data_ptr->srv_random[i];
  }

  // Convert the XOR ret to uint32_t (assuming little-endian)
  uint32_t shared_cnt = 0;
  shared_cnt |= (uint32_t)(xor_result[0]) << 0;
  shared_cnt |= (uint32_t)(xor_result[1]) << 8;
  shared_cnt |= (uint32_t)(xor_result[2]) << 16;
  shared_cnt |= (uint32_t)(xor_result[3]) << 24;

  LOG_INFO(logger_name_ptr, "Calculated shared counter: %u (0x%08x)", shared_cnt,
           shared_cnt);

  return shared_cnt;
}

SPsecSessionTerminateMessage *
spsecsessionterminatemsg_new(uint8_t participant_id, uint32_t cnt) {
  SPsecSessionTerminateMessage *req_ptr =
      malloc(sizeof(SPsecSessionTerminateMessage));
  if (!req_ptr)
    return NULL;
  req_ptr->participant_id = participant_id;
  req_ptr->cnt = cnt;

  return req_ptr;
}

void spsecsessionterminatemsg_free(SPsecSessionTerminateMessage *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr);
  }
}

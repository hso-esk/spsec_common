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

static const char *logger_name_ptr = "messages_session";

// SPsec time synchronization messages
SPsecTimeSyncRequest *timesyncrequest_new(uint8_t participant_id,
                                          const uint8_t *random_ptr) {
  SPsecTimeSyncRequest *req_ptr = malloc(sizeof(SPsecTimeSyncRequest));
  if (!req_ptr)
    return NULL;
  req_ptr->participant_id = participant_id;
  memcpy(req_ptr->random, random_ptr, 16);
  return req_ptr;
}

void timesyncrequest_free(SPsecTimeSyncRequest *msg_ptr) {
  free(msg_ptr);
}

SPsecTimeSyncResponse *timesyncresponse_new(uint8_t *timestamp_ptr,
                                            uint8_t *csalt_ptr,
                                            uint8_t *auth_tag_ptr,
                                            size_t auth_tag_len,
                                            uint8_t participant_id) {
  SPsecTimeSyncResponse *resp_ptr = malloc(sizeof(SPsecTimeSyncResponse));
  if (!resp_ptr)
    return NULL;
  memcpy(resp_ptr->timestamp, timestamp_ptr, 8);
  if (csalt_ptr) {
    memcpy(resp_ptr->csalt, csalt_ptr, 4);
  } else {
    memset(resp_ptr->csalt, 0, 4);
  }
  resp_ptr->auth_tag_ptr = malloc(auth_tag_len);
  if (!resp_ptr->auth_tag_ptr) {
    free(resp_ptr);
    return NULL;
  }
  memcpy(resp_ptr->auth_tag_ptr, auth_tag_ptr, auth_tag_len);
  resp_ptr->auth_tag_len = auth_tag_len;
  resp_ptr->participant_id = participant_id;
  return resp_ptr;
}

// Frees the response and its owned auth tag.
void timesyncresponse_free(SPsecTimeSyncResponse *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr->auth_tag_ptr);
    free(msg_ptr);
  }
}

// SPsec App data
AppData *appdata_new(uint32_t address, uint8_t *data_ptr, size_t data_len) {
  AppData *ad_ptr = malloc(sizeof(AppData));
  if (!ad_ptr)
    return NULL;
  ad_ptr->address = address;
  ad_ptr->data_len = data_len;
  if (data_len > 0) {
    ad_ptr->data_ptr = malloc(data_len);
    if (!ad_ptr->data_ptr) {
      free(ad_ptr);
      return NULL;
    }
    if (data_ptr) {
      memcpy(ad_ptr->data_ptr, data_ptr, data_len);
    } else {
      memset(ad_ptr->data_ptr, 0, data_len);
    }
  } else {
    ad_ptr->data_ptr = NULL;
  }
  return ad_ptr;
}

void appdata_free(AppData *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr->data_ptr);
    free(msg_ptr);
  }
}

SPsecAppData *spsecappdata_new(uint32_t address, uint8_t *secure_data_ptr,
                               size_t secure_data_len, uint8_t padding_size,
                               uint8_t *timestamp_ptr, uint8_t *auth_tag_ptr,
                               size_t auth_tag_len) {
  SPsecAppData *sad_ptr = malloc(sizeof(SPsecAppData));
  if (!sad_ptr)
    return NULL;

  sad_ptr->address = address;
  sad_ptr->secure_data_ptr = malloc(secure_data_len);
  if (!sad_ptr->secure_data_ptr) {
    free(sad_ptr);
    return NULL;
  }
  memcpy(sad_ptr->secure_data_ptr, secure_data_ptr, secure_data_len);
  sad_ptr->secure_data_len = secure_data_len;

  sad_ptr->padding_size = padding_size;
  memcpy(sad_ptr->timestamp, timestamp_ptr, 8);

  sad_ptr->auth_tag_ptr = malloc(auth_tag_len);
  if (!sad_ptr->auth_tag_ptr) {
    free(sad_ptr->secure_data_ptr);
    free(sad_ptr);
    return NULL;
  }
  memcpy(sad_ptr->auth_tag_ptr, auth_tag_ptr, auth_tag_len);
  sad_ptr->auth_tag_len = auth_tag_len;

  return sad_ptr;
}

void spsecappdata_free(SPsecAppData *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr->secure_data_ptr);
    free(msg_ptr->auth_tag_ptr);
    free(msg_ptr);
  }
}

// SPsec Secure Heartbeat message implementation
SPsecHeartbeatMessage *spsecheartbeat_new(uint8_t participant_id,
                                          uint8_t status) {
  SPsecHeartbeatMessage *msg_ptr = malloc(sizeof(SPsecHeartbeatMessage));
  if (!msg_ptr)
    return NULL;

  msg_ptr->participant_id = participant_id;
  msg_ptr->status = status;

  uint8_t hb_data[2];
  hb_data[0] = 0xFF;
  hb_data[1] = 0xFF;
  msg_ptr->app_data_ptr = appdata_new(0, hb_data, 2);
  msg_ptr->spsec_app_data_ptr = NULL;
  if (!msg_ptr->app_data_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for heartbeat");
    free(msg_ptr);
    return NULL;
  }

  LOG_INFO(logger_name_ptr,
           "Created heartbeat message for participant %d with status 0x%02x",
           participant_id, status);

  return msg_ptr;
}

void spsecheartbeat_free(SPsecHeartbeatMessage *msg_ptr) {
  if (msg_ptr) {
    if (msg_ptr->app_data_ptr) {
      appdata_free(msg_ptr->app_data_ptr);
    }

    if (msg_ptr->spsec_app_data_ptr) {
      spsecappdata_free(msg_ptr->spsec_app_data_ptr);
    }
    free(msg_ptr);
  }
}

SPsecSyncTimeBroadcastMessage *spsecsynctimebroadcast_new(uint16_t correction) {
  SPsecSyncTimeBroadcastMessage *msg_ptr =
      malloc(sizeof(SPsecSyncTimeBroadcastMessage));
  if (!msg_ptr)
    return NULL;
  // Initialize time correction (optional field)
  msg_ptr->cor[0] = (uint8_t)(correction & 0xFF);        // Low byte
  msg_ptr->cor[1] = (uint8_t)((correction >> 8) & 0xFF); // High byte
  // Optional owned buffers start NULL so _free() is always safe.
  msg_ptr->app_data_ptr = NULL;
  msg_ptr->spsec_app_data_ptr = NULL;

  // LOG_DEBUG(logger_name_ptr, "Created sync time broadcast message");
  return msg_ptr;
}

int8_t set_spsecsynctimebroadcast_timestamp(
    SPsecSyncTimeBroadcastMessage *msg_ptr, uint8_t *timestamp_ptr) {
  memcpy(msg_ptr->timestamp, timestamp_ptr, TIMESTAMP_SIZE);

  uint8_t tb_data[TIMESTAMP_SIZE + 2];
  memcpy(tb_data, msg_ptr->timestamp, TIMESTAMP_SIZE);
  memcpy(tb_data + TIMESTAMP_SIZE, msg_ptr->cor, 2);

  appdata_free(msg_ptr->app_data_ptr);
  msg_ptr->app_data_ptr = appdata_new(0, tb_data, TIMESTAMP_SIZE + 2);
  if (!msg_ptr->app_data_ptr) {
    LOG_ERROR(logger_name_ptr, "Failed to allocate AppData for sync time broadcast");
    return -1;
  }

  LOG_DEBUG_ARRAY(logger_name_ptr, "Set timestamp_ptr in sync time broadcast message:",
                  msg_ptr->timestamp, TIMESTAMP_SIZE);
  return 0;
}

void spsecsynctimebroadcast_free(SPsecSyncTimeBroadcastMessage *msg_ptr) {
  if (msg_ptr) {
    if (msg_ptr->app_data_ptr) {
      appdata_free(msg_ptr->app_data_ptr);
    }
    if (msg_ptr->spsec_app_data_ptr) {
      spsecappdata_free(msg_ptr->spsec_app_data_ptr);
    }
    free(msg_ptr);
  }
}

// SPsec Internal Event message implementation
SPsecInternalEventMessage *spsecinternalevent_new(uint8_t reg,
                                                  uint32_t data) {
  SPsecInternalEventMessage *msg_ptr =
      malloc(sizeof(SPsecInternalEventMessage));
  if (!msg_ptr)
    return NULL;
  msg_ptr->reg = reg;
  msg_ptr->data = data;
  return msg_ptr;
}

void spsecinternalevent_free(SPsecInternalEventMessage *msg_ptr) {
  if (msg_ptr) {
    free(msg_ptr);
  }
}

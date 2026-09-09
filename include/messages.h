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

#ifndef MESSAGES_H
#define MESSAGES_H

#include "keys.h"
#include <stddef.h>
#include <stdint.h>

#define RANDOM_SIZE 16
#define KEY_SELECTOR_SIZE 4
#define AUTH_TAG_SIZE 8
#define TIMESTAMP_SIZE 8

// Control plane authentication tag size (8 bytes)
#define SECURITY_STAMP_SIZE 10

// Message types
#define MSGTYPE_APP_DATA 21

#define MSGTYPE_CLIENT_HELLO 1
#define MSGTYPE_SERVER_HELLO 2

#define MSGTYPE_CLIENT_FINISHED 3
#define MSGTYPE_SERVER_FINISHED 4

#define MSGTYPE_CLIENT_READ_INITIATE 5
#define MSGTYPE_SERVER_READ_INITIATE 6

#define MSGTYPE_CLIENT_READ_SEGMENT 7
#define MSGTYPE_SERVER_READ_SEGMENT 8

#define MSGTYPE_CLIENT_WRITE_INITIATE 9
#define MSGTYPE_SERVER_WRITE_INITIATE 10

#define MSGTYPE_CLIENT_WRITE_SEGMENT 11
#define MSGTYPE_SERVER_WRITE_SEGMENT 12

#define MSGTYPE_CLIENT_TERMINATE 13
#define MSGTYPE_SERVER_TERMINATE 14

#define MSGTYPE_TIME_SYNC_REQUEST 15
#define MSGTYPE_TIME_SYNC_RESPONSE 16

#define MSGTYPE_SYNC_TIME_BROADCAST 17
#define MSGTYPE_HEARTBEAT 18
#define MSGTYPE_SECURITY_EVENT 19
#define MSGTYPE_INTERNAL_EVENT 20

// SPsec message types
#define CPMT_SESS_HELLO 0
#define CPMT_SESS_FINISH 1
#define CPMT_SESS_RDINIT 2    // Read Initiate
#define CPMT_SESS_RDSEG 3     // Read Segment
#define CPMT_SESS_WRINIT 4    // Write Initiate
#define CPMT_SESS_WRSEG 5     // Write Segment
#define CPMT_SESS_TERMINATE 6 // Session Terminate

#define CPMT_AUTH_TIME 8
#define CPMT_SYNC 9
#define CPMT_HB 10
#define CPMT_EVT 11
#define CPMT_INTERN_EVT 12
#define CPMT_INTERN_RD 13

// Main wrapper for SPsec messages
typedef struct {
  uint8_t msg_type;
  void *msg_content_ptr;
} SPsecMessage;
SPsecMessage *spsecmessage_new(uint8_t msg_type, void *msg_content_ptr);
void spsecmessage_free(SPsecMessage *msg_ptr);

// Frees an SPsecMessage and its content via the right free for msg_type.
// A plain free(msg->msg_content_ptr) leaks heap owned by content types like
// app-data/heartbeat/sync-broadcast — use this for messages of unknown type.
void spsecmessage_dispose(SPsecMessage *msg_ptr);

// SPsec Session establishment messages
typedef struct {
  uint8_t participant_id;
  uint8_t key_selector[KEY_SELECTOR_SIZE]; // (0: key_selector, 1: 0xFF,
                                           // 2: 0xFF, 3: 0xFF)
  uint8_t random[RANDOM_SIZE];
} SPsecClientHelloMessage;
SPsecClientHelloMessage *spsecclienthello_new(uint8_t participant_id,
                                              uint8_t key_selector,
                                              const uint8_t *random_ptr);
void spsecclienthello_free(SPsecClientHelloMessage *msg_ptr);

typedef struct {
  uint8_t participant_id;
  uint8_t random[RANDOM_SIZE];
} SPsecServerHelloMessage;
SPsecServerHelloMessage *spsecserverhello_new(uint8_t participant_id,
                                              const uint8_t *random_ptr);
void spsecserverhello_free(SPsecServerHelloMessage *msg_ptr);

typedef struct {
  uint8_t participant_id;
  uint32_t cnt; // but send only low 8-bit message counter
  uint8_t auth_tag[AUTH_TAG_SIZE];

  uint32_t address; // required to calculate auth_tag accordint to SPsec302
} SPsecClientFinishedMessage;
SPsecClientFinishedMessage *spsecclientfinished_new(uint8_t participant_id,
                                                    uint32_t cnt);
// SPsecClientFinishedMessage* spsecclientfinished_new(uint8_t participant_id,
// uint8_t cnt, uint8_t* auth_tag);
void spsecclientfinished_free(SPsecClientFinishedMessage *msg_ptr);

typedef struct {
  uint8_t participant_id;
  uint32_t cnt; // but send only low 8-bit message counter
  uint8_t auth_tag[AUTH_TAG_SIZE];

  uint32_t address; // required to calculate auth_tag accordint to SPsec302
} SPsecServerFinishedMessage;
SPsecServerFinishedMessage *spsecserverfinished_new(uint8_t participant_id,
                                                    uint32_t cnt);
void spsecserverfinished_free(SPsecServerFinishedMessage *msg_ptr);

// SPsec Read/Write messages
typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  uint8_t reg;            // Register number
  uint32_t len;           // Length of buffer of data to read

  uint32_t address;
  uint8_t plaintext[8];
  uint8_t ciphertext[8];
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecReadInitiateMessage;
SPsecReadInitiateMessage *spsecreadinitiatemessage_new(uint8_t participant_id,
                                                       uint32_t cnt,
                                                       uint8_t reg,
                                                       uint32_t len);
char spsecreadinitiatemessage_parse_plaintext(
    SPsecReadInitiateMessage *msg_ptr);
void spsecreadinitiatemessage_free(SPsecReadInitiateMessage *msg_ptr);

typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)

  uint32_t address;
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecClientReadSegmentRequest;
SPsecClientReadSegmentRequest *
spsecreadsegmentrequest_new(uint8_t participant_id, uint32_t cnt);
void spsecreadsegmentrequest_free(SPsecClientReadSegmentRequest *msg_ptr);

typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  uint8_t *data_ptr;      // Register data
  uint32_t data_len;      // Length of data

  uint32_t address;
  uint8_t *ciphertext_ptr; // Pointer to ciphertext data, length is the
                           // same as plaintext
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecServerReadSegmentResponse;
SPsecServerReadSegmentResponse *
spsecreadsegmentresponse_new(uint8_t participant_id, uint32_t cnt,
                             uint8_t *data_ptr, uint32_t data_len);
void spsecreadsegmentresponse_free(SPsecServerReadSegmentResponse *msg_ptr);

// Session Write messages
typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  uint8_t reg;            // Register number
  uint32_t len;           // Length of data to write

  uint32_t address;
  uint8_t plaintext[8];
  uint8_t ciphertext[8];
  uint8_t auth_tag[AUTH_TAG_SIZE];

  // SPsecSessionAEADdata* session_data; // Pointer to session AEAD data
  // SPsecSessionAEADdata session_aead_data;
} SPsecWriteInitiateMessage;

SPsecWriteInitiateMessage *spsecwriteinitiatemessage_new(uint8_t participant_id,
                                                         uint32_t cnt,
                                                         uint8_t reg,
                                                         uint32_t len);
char spsecwriteinitiatemessage_parse_plaintext(
    SPsecWriteInitiateMessage *msg_ptr);
void spsecwriteinitiatemessage_free(SPsecWriteInitiateMessage *msg_ptr);

typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  uint8_t *data_ptr;      // Register data
  uint8_t data_len;       // Length of data

  uint32_t address;
  uint8_t *ciphertext_ptr; // Pointer to ciphertext data, length is the
                           // same as plaintext
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecClientWriteSegmentRequest;
SPsecClientWriteSegmentRequest *
spsecwritesegmentrequest_new(uint8_t participant_id, uint32_t cnt,
                             uint8_t *data_ptr, uint8_t data_len);
void spsecwritesegmentrequest_free(SPsecClientWriteSegmentRequest *msg_ptr);

typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  uint8_t err;            // Error code

  uint32_t address;
  uint8_t plaintext[4];
  uint8_t ciphertext[4];
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecClientWriteSegmentResponse;
SPsecClientWriteSegmentResponse *
spsecwritesegmentresponse_new(uint8_t participant_id, uint32_t cnt,
                              uint8_t err);
char spsecwritesegmentmessage_parse_plaintext(
    SPsecClientWriteSegmentResponse *msg_ptr);
void spsecwritesegmentresponse_free(SPsecClientWriteSegmentResponse *msg_ptr);

typedef struct {
  uint8_t participant_id; // Participant ID
  uint32_t cnt;           // Shared message counter (32-bit)
  // uint8_t st;   // Status register value (50h) - only in server response

  uint32_t address;
  uint8_t auth_tag[AUTH_TAG_SIZE];
} SPsecSessionTerminateMessage;

SPsecSessionTerminateMessage *
spsecsessionterminatemsg_new(uint8_t participant_id, uint32_t cnt);
// SPsecSessionTerminateMessage
// *spsecsessionterminatemsg_new_with_status(uint8_t participant_id, uint32_t
// cnt, uint8_t status);
void spsecsessionterminatemsg_free(SPsecSessionTerminateMessage *msg_ptr);

// SPsec time synchronization messages
typedef struct {
  uint8_t participant_id;
  uint8_t random[RANDOM_SIZE];
} SPsecTimeSyncRequest;

SPsecTimeSyncRequest *timesyncrequest_new(uint8_t participant_id,
                                          const uint8_t *random_ptr);
void timesyncrequest_free(SPsecTimeSyncRequest *msg_ptr);

typedef struct {
  uint8_t timestamp[8];
  uint8_t csalt[4]; // Communication Key Derivation Salt
  uint8_t *auth_tag_ptr;
  size_t auth_tag_len;
  uint8_t participant_id;
} SPsecTimeSyncResponse;
SPsecTimeSyncResponse *timesyncresponse_new(uint8_t *timestamp_ptr,
                                            uint8_t *csalt_ptr,
                                            uint8_t *auth_tag_ptr,
                                            size_t auth_tag_len,
                                            uint8_t participant_id);
void timesyncresponse_free(SPsecTimeSyncResponse *msg_ptr);

// SPsec App data
typedef struct {
  uint32_t address;
  uint8_t *data_ptr;
  size_t data_len;
} AppData;
AppData *appdata_new(uint32_t address, uint8_t *data_ptr, size_t data_len);
void appdata_free(AppData *msg_ptr);

typedef struct {
  uint32_t address;
  uint8_t *secure_data_ptr;
  size_t secure_data_len;
  uint8_t padding_size;
  uint8_t timestamp[8];
  uint8_t *auth_tag_ptr;
  size_t auth_tag_len;
} SPsecAppData;
SPsecAppData *spsecappdata_new(uint32_t address, uint8_t *secure_data_ptr,
                               size_t secure_data_len, uint8_t padding_size,
                               uint8_t *timestamp_ptr, uint8_t *auth_tag_ptr,
                               size_t auth_tag_len);
void spsecappdata_free(SPsecAppData *msg_ptr);

typedef struct {
  uint8_t timestamp[TIMESTAMP_SIZE];
  uint8_t cor[2]; // time correction

  AppData *app_data_ptr;
  SPsecAppData *spsec_app_data_ptr;
} SPsecSyncTimeBroadcastMessage;
SPsecSyncTimeBroadcastMessage *spsecsynctimebroadcast_new(uint16_t correction);
// Returns 0 on success, -1 if the AppData allocation failed (msg_ptr is left
// unmodified except for the timestamp/cor copy; app_data_ptr stays NULL).
int8_t set_spsecsynctimebroadcast_timestamp(
    SPsecSyncTimeBroadcastMessage *msg_ptr, uint8_t *timestamp_ptr);
void spsecsynctimebroadcast_free(SPsecSyncTimeBroadcastMessage *msg_ptr);

// SPsec Secure Heartbeat message
typedef struct {
  uint8_t participant_id;
  uint8_t status; // Content of status register (50h)
  // Structure required to create a security stamp with timestamp
  AppData *app_data_ptr;
  SPsecAppData *spsec_app_data_ptr;
} SPsecHeartbeatMessage;
SPsecHeartbeatMessage *spsecheartbeat_new(uint8_t participant_id,
                                          uint8_t status);
void spsecheartbeat_free(SPsecHeartbeatMessage *msg_ptr);

// SPsec Internal Event message (CPMT_INTERN_EVT)
typedef struct {
  uint8_t reg;   // Register number reporting the event
  uint32_t data; // Data content of the register (up to 32 bits)
} SPsecInternalEventMessage;
SPsecInternalEventMessage *spsecinternalevent_new(uint8_t reg,
                                                  uint32_t data);
void spsecinternalevent_free(SPsecInternalEventMessage *msg_ptr);

// Structure for holding cryptographic/session data for authentication tag
// creation)
typedef struct {
  uint8_t key_selector[KEY_SELECTOR_SIZE]; // (0: key_selector, 1: 0xFF,
                                           // 2: 0xFF, 3: 0xFF)
  uint8_t cli_random[RANDOM_SIZE];
  uint8_t srv_random[RANDOM_SIZE];
  uint8_t cli_auth_tag[AUTH_TAG_SIZE]; // 64-bit authentication tag
  uint32_t address;                    // 32-bit address

  SPsecSalt *spsec_salt_ptr; // Pointer to the salt for this session
} ConfigurationSessionAuthTagData;

ConfigurationSessionAuthTagData *authtagparticipantdata_new(void);
void authtagparticipantdata_free(ConfigurationSessionAuthTagData *data_ptr);

uint32_t calculate_shared_cnt(ConfigurationSessionAuthTagData *data_ptr);
int8_t generate_nonce_from_session_cnt(uint32_t session_cnt, uint8_t **nonce_ptr,
                                     SPsecSalt *spsec_salt_ptr);

#endif
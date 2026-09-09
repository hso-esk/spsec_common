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

#ifndef SPSEC_MBEDTLS_CONFIG_H
#define SPSEC_MBEDTLS_CONFIG_H

#include "fsl_device_registers.h"
#include "fsl_hashcrypt.h"

#include <stdlib.h>

/* Core cryptographic primitives required by SPsec */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C

/* Key derivation and deterministic random_ptr generation */
#define MBEDTLS_HKDF_C
#define MBEDTLS_HMAC_DRBG_C

/* Platform helpers */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO calloc
#define MBEDTLS_PLATFORM_FREE_MACRO free
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* Enable NXP Hashcrypt-based hardware acceleration */
#define MBEDTLS_FREESCALE_HASHCRYPT_AES
#define MBEDTLS_FREESCALE_HASHCRYPT_SHA256

#define MBEDTLS_AES_ALT
#define MBEDTLS_AES_SETKEY_ENC_ALT
#define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_ENCRYPT_ALT
#define MBEDTLS_AES_DECRYPT_ALT

#define MBEDTLS_SHA256_ALT
#define MBEDTLS_SHA256_ALT_NO_224

#define MBEDTLS_AES_CRYPT_CBC_ALT
#define MBEDTLS_AES_CRYPT_CTR_ALT

/* Disable TLS, PKI and ECC stacks */
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_BADMAC_LIMIT
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION

#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT
#undef MBEDTLS_CERTS_C

#undef MBEDTLS_PK_C
#undef MBEDTLS_PK_PARSE_C
#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_PKCS1_V15
#undef MBEDTLS_PKCS1_V21
#undef MBEDTLS_RSA_C

#undef MBEDTLS_ECP_C
#undef MBEDTLS_ECDH_C
#undef MBEDTLS_ECDSA_C

#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

#include "mbedtls/check_config.h"

#endif /* SPSEC_MBEDTLS_CONFIG_H */

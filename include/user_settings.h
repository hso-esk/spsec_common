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

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* WolfSSL User Settings for SPsec Participant */

/* Enable WolfCrypt Only (Disable SSL/TLS Layer) */
#ifndef WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY
#endif

/* Algorithm Selection */

/* Enable AES-GCM */
#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif
#ifndef HAVE_AES_DECRYPT
#define HAVE_AES_DECRYPT
#endif
#ifndef HAVE_AES_ENCRYPT
#define HAVE_AES_ENCRYPT
#endif

/* Enable ChaCha20-Poly1305 */
#ifndef HAVE_CHACHA
#define HAVE_CHACHA
#endif
#ifndef HAVE_POLY1305
#define HAVE_POLY1305
#endif

/* Enable ASCON */
#ifndef HAVE_ASCON
#define HAVE_ASCON
#endif
#ifndef WOLFSSL_ASCON
#define WOLFSSL_ASCON
#endif
/* Require experimental settings for ASCON in some versions */
#ifndef WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#endif
#ifndef WOLFSSL_MIN_AUTH_TAG_SZ
#define WOLFSSL_MIN_AUTH_TAG_SZ 8
#endif

/* Enable HKDF and dependencies */
#ifndef HAVE_HKDF
#define HAVE_HKDF
#endif
#ifndef WOLFSSL_SHA256
#define WOLFSSL_SHA256
#endif
#ifndef WOLFSSL_HMAC
#define WOLFSSL_HMAC
#endif

/* Disable Unused Algorithms */
#ifndef NO_RSA
#define NO_RSA
#endif
#ifndef NO_AES_CBC
#define NO_AES_CBC
#endif
#ifndef NO_DSA
#define NO_DSA
#endif
#ifndef NO_DH
#define NO_DH
#endif
#ifndef NO_MD5
#define NO_MD5
#endif
#ifndef NO_SHA
#define NO_SHA /* SHA-1 */
#endif
#ifndef NO_SHA512
#define NO_SHA512 /* Only SHA256 is used */
#endif
#ifndef NO_RC4
#define NO_RC4
#endif
#ifndef NO_DES3
#define NO_DES3
#endif
#ifndef NO_HC128
#define NO_HC128
#endif
#ifndef NO_RABBIT
#define NO_RABBIT
#endif
#ifndef NO_PSK
#define NO_PSK
#endif
#ifndef NO_PWDBASED
#define NO_PWDBASED
#endif
#ifndef NO_MD4
#define NO_MD4
#endif
#ifndef NO_CMAC
#define NO_CMAC
#endif

/* Disable ASN.1 / X.509 if not strictly needed by RNG/HKDF */
/* #define NO_ASN */

/* System / Platform Settings */
/* Use OS RNG */
/* #define WOLFSSL_NO_RNG */ /* Do NOT define this; RNG is required */

#endif /* USER_SETTINGS_H */

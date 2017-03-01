/*
 * EAP server/peer: EAP-FRM shared routines
 * Copyright (c) 2008, Fernando Bernal Hidalgo <fbernal@um.es>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef EAP_FRM_COMMON_H
#define EAP_FRM_COMMON_H

#define EAP_FRM_OPCODE_FRM_1 1
#define EAP_FRM_OPCODE_FRM_2 2
#define EAP_FRM_OPCODE_FRM_3 3
#define EAP_FRM_OPCODE_FRM_4 4
#define EAP_FRM_OPCODE_FAIL 5
#define EAP_FRM_OPCODE_PROTECTED_FAIL 6

/* Failure-Code in FRM-Fail and FRM-Protected-Fail */
#define EAP_FRM_FAIL_PSK_NOT_FOUND 0x00000001
#define EAP_FRM_FAIL_AUTHENTICATION_FAILURE 0x00000002
#define EAP_FRM_FAIL_AUTHORIZATION_FAILURE 0x00000003

#define EAP_FRM_RAND_LEN 32
#define EAP_FRM_MAX_SK_LEN 32
#define EAP_FRM_MAX_PK_LEN 32
#define EAP_FRM_MAX_MIC_LEN 32

#define EAP_FRM_VENDOR_IETF		0x00000000
#define EAP_FRM_CIPHER_RESERVED	0x000000
#define EAP_FRM_CIPHER_AES		0x000001
#define EAP_FRM_CIPHER_SHA256		0x000002


#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct eap_frm_csuite {
	u8 vendor[4];
	u8 specifier[2];
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

int eap_frm_supported_ciphersuite(int vendor, int specifier);
int eap_frm_derive_keys(const u8 *psk, size_t psk_len, int vendor,
			 int specifier,
			 const u8 *rand_client, const u8 *rand_server,
			 const u8 *id_client, size_t id_client_len,
			 const u8 *id_server, size_t id_server_len,
			 u8 *msk, u8 *emsk, u8 *sk, size_t *sk_len,
			 u8 *pk, size_t *pk_len);
size_t eap_frm_mic_len(int vendor, int specifier);
int eap_frm_compute_mic(const u8 *sk, size_t sk_len, int vendor,
			 int specifier, const u8 *data, size_t len, u8 *mic);

#endif /* EAP_FRM_COMMON_H */

/*
 * AES-based functions
 *
 * - AES Key Wrap Algorithm (128-bit KEK) (RFC3394)
 * - One-Key CBC MAC (OMAC1) hash with AES-128
 * - AES-128 CTR mode encryption
 * - AES-128 EAX mode encryption/decryption
 * - AES-128 CBC
 *
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
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

#ifndef AES_WRAP_H
#define AES_WRAP_H

u16 hmac_wrap (const u8 *kek, const u8 *plain,  u16 plain_len, u8 *cipher); //fernando

u16 hmac_unwrap (const u8 *kek, const u8 *cipher, u16 cipher_len, u8 *hmac); //fernando

u16 build_message1( u8 *Kas,  u16 Kas_len,
                    u8 *id_A, u16 id_A_len, 
                    u8 *id_B, u16 id_B_len,
                    u8 *Na  , u16 Na_len,
                    u32 SEQas, 
                    u8 **message1_ptr);

u16 build_message2( u8 *Kbs, u16 Kbs_len,
                    u8 *id_B, u16 id_B_len, 
                    u8 *Nb, u16 Nb_len,
                    u8 *message1, u16 message1_len, 
                    u8 **message2_ptr);

void build_message3_and_4 ( u8 *Kas, u16 Kas_len,
                            u8 *Kbs, u16 Kbs_len,
                            u8 *Ns, u16 Ns_len,
                            u8 *Kab, u16 Kab_len,
                            u32 LKab, 
                            u32 SEQsa,
                            u8 *message1, u16 message1_len, 
                            u8 *message2, u16 message2_len, 
                            u8 **message3_ptr, u16 *message3_len,
                            u8 **message4_ptr, u16 *message4_len);

int process_and_check_message3( u8 *Kbs, u16 Kbs_len,
                                u8 *Nb_orig, u16 Nb_orig_len,
                                u8 *message3, u16 message3_len,
                                u8 **Kab_ptr, u16 *Kab_len_ptr, u32 *LKab_ptr );

int process_and_check_message4( u8 *Kas, u16 Kas_len,
				u8 *Ksmk, u16 Ksmk_len,
                                u8 *Na_orig, u16 Na_orig_len,
                                u8 *message4, u16 message4_len,
                                u32 *LKab_ptr, u8 *Kab );


u16 generate_nonce(u8 **buffer, u16 min, u16 max);


int aes_wrap(const u8 *kek, int n, const u8 *plain, u8 *cipher);
int aes_unwrap(const u8 *kek, int n, const u8 *cipher, u8 *plain);
int omac1_aes_128_vector(const u8 *key, size_t num_elem,
			 const u8 *addr[], const size_t *len, u8 *mac);
int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac);
int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out);
int aes_128_ctr_encrypt(const u8 *key, const u8 *nonce,
			u8 *data, size_t data_len);
int aes_128_eax_encrypt(const u8 *key, const u8 *nonce, size_t nonce_len,
			const u8 *hdr, size_t hdr_len,
			u8 *data, size_t data_len, u8 *tag);
int aes_128_eax_decrypt(const u8 *key, const u8 *nonce, size_t nonce_len,
			const u8 *hdr, size_t hdr_len,
			u8 *data, size_t data_len, const u8 *tag);
int aes_128_cbc_encrypt(const u8 *key, const u8 *iv, u8 *data,
			size_t data_len);
int aes_128_cbc_decrypt(const u8 *key, const u8 *iv, u8 *data,
			size_t data_len);

#endif /* AES_WRAP_H */
u16 build_message1_extended( u8 *Kas,  u16 Kas_len,
                    u8 *id_A, u16 id_A_len, 
                    u8 *id_B, u16 id_B_len,
					u8 *id_S2, u16 id_S2_len,
                    u8 *Na  , u16 Na_len,
                    u32 SEQas, 
                    u8 **message1_ptr);

u16 build_message2_extended( u8 *Kbl, u16 Kbl_len,
                    u8 *Nb, u16 Nb_len,
                    u8 *message1, u16 message1_len, 
                    u8 **message2_ptr);

void build_message3_extended(u8 *Kls, u16 Kls_len,
		u8 *Kbl, u16 Kbl_len,
		u8 *Nl, u16 Nl_len,
		u8 * id_L, u16 id_L_len,
		u8 * message1, u16 message1_len,
		u8 *message2, u16 message2_len,
		u8 **message3_ptr, u16 *message3_len,
		u8 **message4_ptr, u16 *message4_len,
		u8 **id_B, u16 * id_B_len,
		u8 **Nb, u16 *Nb_len);

void build_message4_extended(u8 *Kas, u16 Kas_len,
				 u8 *Kls, u16 Kls_len,
				 u8 *SMKas, u16 SMKas_len,
				 u8 *Ns, u16 Ns_len,
				 u8 *message3, u16 message3_len,
				 u8 *message4, u16 message4_len,
				 u8 **message5_ptr, u16 *message5_len,
				 u8 **message6_ptr, u16 *message6_len);

void build_message5_extended (u8 * Kls, u16 Kls_len,
				u8 * Kbl, u16 Kbl_len,
				u8 *id_B, u16 id_B_len,
				u8 * Nb, u16 Nb_len,
				u8 * Nll, u16 Nll_len,
				u32 SEQal,
				u8 *message6, u16 message6_len,
				u8 **message7_ptr, u16 *message7_len,
				u8 **message8_ptr, u16 *message8_len);

void process_and_check_message6_extended(u8 * Kbl, u16 Kbl_len,
			   u8 * message8, u16 message8_len,
			   u8 **Kab_ptr, u16 *Kab_len_ptr);

void process_and_check_message7_extended( u8 * Kas, u16 Kas_len,
							u8 * SMKas, u16 SMKas_len,
							u8 * message9, u16 message9_len,
							u8 * message10, u16 message10_len,
							u8 **Kab_ptr, u16 *Kab_len_ptr);


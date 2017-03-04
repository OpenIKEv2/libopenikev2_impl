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

#include "./utils/includes.h"

#include "./utils/common.h"
#include "aes_wrap.h"
#include "crypto.h"
#include <openssl/rand.h>
#include "../utils/prf_plus.h"
#ifdef INTERNAL_AES
#include "aes.c"
#endif /* INTERNAL_AES */

/*#if !defined(EAP_TLS_FUNCS) || defined(EAP_TLS_NONE)
#include "aes.c"
#endif
*/
#ifndef CONFIG_NO_AES_WRAP

/**
 * aes_wrap - Wrap keys with AES Key Wrap Algorithm (128-bit KEK) (RFC3394)
 * @kek: 16-octet Key encryption key (KEK)
 * @n: Length of the plaintext key in 64-bit units; e.g., 2 = 128-bit = 16
 * bytes
 * @plain: Plaintext key to be wrapped, n * 64 bits
 * @cipher: Wrapped key, (n + 1) * 64 bits
 * Returns: 0 on success, -1 on failure
 */
int aes_wrap(const u8 *kek, int n, const u8 *plain, u8 *cipher)
{
	u8 *a, *r, b[16];
	int i, j;
	void *ctx;

	a = cipher;
	r = cipher + 8;

	/* 1) Initialize variables. */
	os_memset(a, 0xa6, 8);
	os_memcpy(r, plain, 8 * n);

	ctx = aes_encrypt_init(kek, 16);
	if (ctx == NULL)
		return -1;

	/* 2) Calculate intermediate values.
	 * For j = 0 to 5
	 *     For i=1 to n
	 *         B = AES(K, A | R[i])
	 *         A = MSB(64, B) ^ t where t = (n*j)+i
	 *         R[i] = LSB(64, B)
	 */
	for (j = 0; j <= 5; j++) {
		r = cipher + 8;
		for (i = 1; i <= n; i++) {
			os_memcpy(b, a, 8);
			os_memcpy(b + 8, r, 8);
			aes_encrypt(ctx, b, b);
			os_memcpy(a, b, 8);
			a[7] ^= n * j + i;
			os_memcpy(r, b + 8, 8);
			r += 8;
		}
	}
	aes_encrypt_deinit(ctx);

	/* 3) Output the results.
	 *
	 * These are already in @cipher due to the location of temporary
	 * variables.
	 */

	return 0;
}

#endif /* CONFIG_NO_AES_WRAP */


/**
 * aes_unwrap - Unwrap key with AES Key Wrap Algorithm (128-bit KEK) (RFC3394)
 * @kek: Key encryption key (KEK)
 * @n: Length of the plaintext key in 64-bit units; e.g., 2 = 128-bit = 16
 * bytes
 * @cipher: Wrapped key to be unwrapped, (n + 1) * 64 bits
 * @plain: Plaintext key, n * 64 bits
 * Returns: 0 on success, -1 on failure (e.g., integrity verification failed)
 */
int aes_unwrap(const u8 *kek, int n, const u8 *cipher, u8 *plain)
{
	u8 a[8], *r, b[16];
	int i, j;
	void *ctx;

	/* 1) Initialize variables. */
	os_memcpy(a, cipher, 8);
	r = plain;
	os_memcpy(r, cipher + 8, 8 * n);

	ctx = aes_decrypt_init(kek, 16);
	if (ctx == NULL)
		return -1;

	/* 2) Compute intermediate values.
	 * For j = 5 to 0
	 *     For i = n to 1
	 *         B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	 *         A = MSB(64, B)
	 *         R[i] = LSB(64, B)
	 */
	for (j = 5; j >= 0; j--) {
		r = plain + (n - 1) * 8;
		for (i = n; i >= 1; i--) {
			os_memcpy(b, a, 8);
			b[7] ^= n * j + i;

			os_memcpy(b + 8, r, 8);
			aes_decrypt(ctx, b, b);
			os_memcpy(a, b, 8);
			os_memcpy(r, b + 8, 8);
			r -= 8;
		}
	}
	aes_decrypt_deinit(ctx);

	/* 3) Output results.
	 *
	 * These are already in @plain due to the location of temporary
	 * variables. Just verify that the IV matches with the expected value.
	 */
	for (i = 0; i < 8; i++) {
		if (a[i] != 0xa6)
			return -1;
	}

	return 0;
}


#define BLOCK_SIZE 16

#ifndef CONFIG_NO_AES_OMAC1

static void gf_mulx(u8 *pad)
{
	int i, carry;

	carry = pad[0] & 0x80;
	for (i = 0; i < BLOCK_SIZE - 1; i++)
		pad[i] = (pad[i] << 1) | (pad[i + 1] >> 7);
	pad[BLOCK_SIZE - 1] <<= 1;
	if (carry)
		pad[BLOCK_SIZE - 1] ^= 0x87;
}


/**
 * omac1_aes_128_vector - One-Key CBC MAC (OMAC1) hash with AES-128
 * @key: 128-bit key for the hash operation
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for MAC (128 bits, i.e., 16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int omac1_aes_128_vector(const u8 *key, size_t num_elem,
			 const u8 *addr[], const size_t *len, u8 *mac)
{
	void *ctx;
	u8 cbc[BLOCK_SIZE], pad[BLOCK_SIZE];
	const u8 *pos, *end;
	size_t i, e, left, total_len;

	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	os_memset(cbc, 0, BLOCK_SIZE);

	total_len = 0;
	for (e = 0; e < num_elem; e++)
		total_len += len[e];
	left = total_len;

	e = 0;
	pos = addr[0];
	end = pos + len[0];

	while (left >= BLOCK_SIZE) {
		for (i = 0; i < BLOCK_SIZE; i++) {
			cbc[i] ^= *pos++;
			if (pos >= end) {
				e++;
				pos = addr[e];
				end = pos + len[e];
			}
		}
		if (left > BLOCK_SIZE)
			aes_encrypt(ctx, cbc, cbc);
		left -= BLOCK_SIZE;
	}

	os_memset(pad, 0, BLOCK_SIZE);
	aes_encrypt(ctx, pad, pad);
	gf_mulx(pad);

	if (left || total_len == 0) {
		for (i = 0; i < left; i++) {
			cbc[i] ^= *pos++;
			if (pos >= end) {
				e++;
				pos = addr[e];
				end = pos + len[e];
			}
		}
		cbc[left] ^= 0x80;
		gf_mulx(pad);
	}

	for (i = 0; i < BLOCK_SIZE; i++)
		pad[i] ^= cbc[i];
	aes_encrypt(ctx, pad, mac);
	aes_encrypt_deinit(ctx);
	return 0;
}


/**
 * omac1_aes_128 - One-Key CBC MAC (OMAC1) hash with AES-128 (aka AES-CMAC)
 * @key: 128-bit key for the hash operation
 * @data: Data buffer for which a MAC is determined
 * @data_len: Length of data buffer in bytes
 * @mac: Buffer for MAC (128 bits, i.e., 16 bytes)
 * Returns: 0 on success, -1 on failure
 *
 * This is a mode for using block cipher (AES in this case) for authentication.
 * OMAC1 was standardized with the name CMAC by NIST in a Special Publication
 * (SP) 800-38B.
 */
int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}

#endif /* CONFIG_NO_AES_OMAC1 */


/**
 * aes_128_encrypt_block - Perform one AES 128-bit block operation
 * @key: Key for AES
 * @in: Input data (16 bytes)
 * @out: Output of the AES block operation (16 bytes)
 * Returns: 0 on success, -1 on failure
 */
int aes_128_encrypt_block(const u8 *key, const u8 *in, u8 *out)
{
	void *ctx;
	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	aes_encrypt(ctx, in, out);
	aes_encrypt_deinit(ctx);
	return 0;
}


#ifndef CONFIG_NO_AES_CTR

/**
 * aes_128_ctr_encrypt - AES-128 CTR mode encryption
 * @key: Key for encryption (16 bytes)
 * @nonce: Nonce for counter mode (16 bytes)
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes
 * Returns: 0 on success, -1 on failure
 */
int aes_128_ctr_encrypt(const u8 *key, const u8 *nonce,
			u8 *data, size_t data_len)
{
	void *ctx;
	size_t j, len, left = data_len;
	int i;
	u8 *pos = data;
	u8 counter[BLOCK_SIZE], buf[BLOCK_SIZE];

	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	os_memcpy(counter, nonce, BLOCK_SIZE);

	while (left > 0) {
		aes_encrypt(ctx, counter, buf);

		len = (left < BLOCK_SIZE) ? left : BLOCK_SIZE;
		for (j = 0; j < len; j++)
			pos[j] ^= buf[j];
		pos += len;
		left -= len;

		for (i = BLOCK_SIZE - 1; i >= 0; i--) {
			counter[i]++;
			if (counter[i])
				break;
		}
	}
	aes_encrypt_deinit(ctx);
	return 0;
}

#endif /* CONFIG_NO_AES_CTR */


#ifndef CONFIG_NO_AES_EAX

/**
 * aes_128_eax_encrypt - AES-128 EAX mode encryption
 * @key: Key for encryption (16 bytes)
 * @nonce: Nonce for counter mode
 * @nonce_len: Nonce length in bytes
 * @hdr: Header data to be authenticity protected
 * @hdr_len: Length of the header data bytes
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes
 * @tag: 16-byte tag value
 * Returns: 0 on success, -1 on failure
 */
int aes_128_eax_encrypt(const u8 *key, const u8 *nonce, size_t nonce_len,
			const u8 *hdr, size_t hdr_len,
			u8 *data, size_t data_len, u8 *tag)
{
	u8 *buf;
	size_t buf_len;
	u8 nonce_mac[BLOCK_SIZE], hdr_mac[BLOCK_SIZE], data_mac[BLOCK_SIZE];
	int i;

	if (nonce_len > data_len)
		buf_len = nonce_len;
	else
		buf_len = data_len;
	if (hdr_len > buf_len)
		buf_len = hdr_len;
	buf_len += 16;

	buf = os_malloc(buf_len);
	if (buf == NULL)
		return -1;

	os_memset(buf, 0, 15);

	buf[15] = 0;
	os_memcpy(buf + 16, nonce, nonce_len);
	omac1_aes_128(key, buf, 16 + nonce_len, nonce_mac);

	buf[15] = 1;
	os_memcpy(buf + 16, hdr, hdr_len);
	omac1_aes_128(key, buf, 16 + hdr_len, hdr_mac);

	aes_128_ctr_encrypt(key, nonce_mac, data, data_len);
	buf[15] = 2;
	os_memcpy(buf + 16, data, data_len);
	omac1_aes_128(key, buf, 16 + data_len, data_mac);

	os_free(buf);

	for (i = 0; i < BLOCK_SIZE; i++)
		tag[i] = nonce_mac[i] ^ data_mac[i] ^ hdr_mac[i];

	return 0;
}


/**
 * aes_128_eax_decrypt - AES-128 EAX mode decryption
 * @key: Key for decryption (16 bytes)
 * @nonce: Nonce for counter mode
 * @nonce_len: Nonce length in bytes
 * @hdr: Header data to be authenticity protected
 * @hdr_len: Length of the header data bytes
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes
 * @tag: 16-byte tag value
 * Returns: 0 on success, -1 on failure, -2 if tag does not match
 */
int aes_128_eax_decrypt(const u8 *key, const u8 *nonce, size_t nonce_len,
			const u8 *hdr, size_t hdr_len,
			u8 *data, size_t data_len, const u8 *tag)
{
	u8 *buf;
	size_t buf_len;
	u8 nonce_mac[BLOCK_SIZE], hdr_mac[BLOCK_SIZE], data_mac[BLOCK_SIZE];
	int i;

	if (nonce_len > data_len)
		buf_len = nonce_len;
	else
		buf_len = data_len;
	if (hdr_len > buf_len)
		buf_len = hdr_len;
	buf_len += 16;

	buf = os_malloc(buf_len);
	if (buf == NULL)
		return -1;

	os_memset(buf, 0, 15);

	buf[15] = 0;
	os_memcpy(buf + 16, nonce, nonce_len);
	omac1_aes_128(key, buf, 16 + nonce_len, nonce_mac);

	buf[15] = 1;
	os_memcpy(buf + 16, hdr, hdr_len);
	omac1_aes_128(key, buf, 16 + hdr_len, hdr_mac);

	buf[15] = 2;
	os_memcpy(buf + 16, data, data_len);
	omac1_aes_128(key, buf, 16 + data_len, data_mac);

	os_free(buf);

	for (i = 0; i < BLOCK_SIZE; i++) {
		if (tag[i] != (nonce_mac[i] ^ data_mac[i] ^ hdr_mac[i]))
			return -2;
	}

	aes_128_ctr_encrypt(key, nonce_mac, data, data_len);

	return 0;
}

#endif /* CONFIG_NO_AES_EAX */


#ifndef CONFIG_NO_AES_CBC

/**
 * aes_128_cbc_encrypt - AES-128 CBC encryption
 * @key: Encryption key
 * @iv: Encryption IV for CBC mode (16 bytes)
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
int aes_128_cbc_encrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
	void *ctx;
	u8 cbc[BLOCK_SIZE];
	u8 *pos = data;
	int i, j, blocks;

	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	os_memcpy(cbc, iv, BLOCK_SIZE);

	blocks = data_len / BLOCK_SIZE;
	for (i = 0; i < blocks; i++) {
		for (j = 0; j < BLOCK_SIZE; j++)
			cbc[j] ^= pos[j];
		aes_encrypt(ctx, cbc, cbc);
		os_memcpy(pos, cbc, BLOCK_SIZE);
		pos += BLOCK_SIZE;
	}
	aes_encrypt_deinit(ctx);
	return 0;
}


/**
 * aes_128_cbc_decrypt - AES-128 CBC decryption
 * @key: Decryption key
 * @iv: Decryption IV for CBC mode (16 bytes)
 * @data: Data to decrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
int aes_128_cbc_decrypt(const u8 *key, const u8 *iv, u8 *data, size_t data_len)
{
	void *ctx;
	u8 cbc[BLOCK_SIZE], tmp[BLOCK_SIZE];
	u8 *pos = data;
	int i, j, blocks;

	ctx = aes_decrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	os_memcpy(cbc, iv, BLOCK_SIZE);

	blocks = data_len / BLOCK_SIZE;
	for (i = 0; i < blocks; i++) {
		os_memcpy(tmp, pos, BLOCK_SIZE);
		aes_decrypt(ctx, pos, pos);
		for (j = 0; j < BLOCK_SIZE; j++)
			pos[j] ^= cbc[j];
		os_memcpy(cbc, tmp, BLOCK_SIZE);
		pos += BLOCK_SIZE;
	}
	aes_decrypt_deinit(ctx);
	return 0;
}

#endif /* CONFIG_NO_AES_CBC */

//LO NUESTRO

/********************************************************************/
/*       HMAC- WRAP/UNWRAP + UTILITY FUNCTIONS                      */
/********************************************************************/

/**
 * hmac_wrap - Wrapping an HMAC with an AES KEK  (RFC3394)(RFC3537)
 * @kek: Encryption key (16 bytes)
 * @plain: The HMAC to be wrapped (must be allocated)
 * @plain_len: The HMAC length to be wrapped
 * @cipher: The returned wrapped HMAC (must be allocated)
 * Returns: Size in bytes of the wrapped HMAC on success, 0 on failure
 */
u16 hmac_wrap (const u8 *kek, const u8 *plain, u16 plain_len, u8 *cipher){

    u8 pad_len = 0;
    // Get the pad length
    if ((2 + plain_len) % 8) {
       pad_len = 8 - ((2 +plain_len) % 8);
    }

    // Allocate memory for padded hmac
    u8 *lkey_pad = malloc(2 + plain_len + pad_len);

    u16 temp_plain_len = htons(plain_len);

    // Build the padded hmac
    memcpy(&lkey_pad[0], &temp_plain_len, 2); // the length of hmac
    memcpy(&lkey_pad[2], plain, plain_len); // followed by the hmac
    RAND_bytes(&lkey_pad[plain_len+2], pad_len); // and endded with random values (padding)

    // prepare variables to call aes_wrap
    u16 n = (2 + plain_len + pad_len) / 8;  // how many 64-bit blocks are there?

    // All the buffers passed to aes_wrap function
    // must have the necesary memory allocated.
    if (aes_wrap(kek, n, lkey_pad, cipher)==0){
        free (lkey_pad);
        return 2 + plain_len + pad_len + 8;
    }
    else {
        free (lkey_pad);
        return 0;
    }
}


/**
 * hmac_unwrap - Unwrap HMAC with AES Key Wrap Algorithm (128-bit KEK) (RFC3394)(RFC3537)
 * @kek: Encryption key (16 bytes)
 * @cipher: The wrapped HMAC to be unwrapped (must be allocated)
 * @cypher_len: The wrapped HMAC length to be unwrapped
 * @hmac: The returned unwrapped HMAC (must be allocated)
 * Returns: Unwrapped HMAC size on success, 0 on failure
 */
u16 hmac_unwrap(const u8 *kek, const u8 *cipher, u16 cypher_len, u8 *hmac)
{
    // if cipher aren't 64-bit blocks, exit with an error
    if (cypher_len % 8 != 0) {
        return -1;
    }

    // get ready the variables to call aes_unwrap
    u16 n = (cypher_len / 8) - 1;

    // Allocate memory to store the lkey_pad
    u8 *lkey_pad = malloc (cypher_len);

    // call aes_unwrap
    u16 ret = aes_unwrap(kek, n, cipher, lkey_pad);
    // if error, exit
    if (ret != 0)
        return 0;

    // extract hmac length from lkey_pad
    u16 temp_hmac_len;
    memcpy (&temp_hmac_len,&lkey_pad[0],2);
    u16 hmac_len= ntohs(temp_hmac_len);

    u8 pad_len = (cypher_len-8) - (2 + hmac_len);
    // if pad length is greather than 7, error
    if ( pad_len > 7 )
        return 0;

    // extract hmac form lkey_pad
    memcpy (hmac,&lkey_pad[2],hmac_len);

    // free allocated memory
    free(lkey_pad);
    return hmac_len;

}


/**
 * print_hex - Print a buffer in hexadecimal notation, 32 bytes per line, in blocks of 8 bytes
 * @buffer: the buffer to be printed
 * @buffer_len: the buffer size
 */
void print_hex(u8 *buffer, u16 buffer_len){
    int i;
    for(i=0; i < buffer_len; i++)
    {
        if (i % 8 == 0) printf (" ");
        if (i % 32 == 0) printf ("\n");
        printf("%02X",(u8)buffer[i]);

    }
    printf("\n");
}


/**
 * generate_nonce - Generates a random sized buffer between min and max (max included)
 *                  with random information inside. Used to build nonces.
 * @buffer: pointer to store the resulting nonce (musn't be allocated, allocated inside)
 * @min: The minimum size of the resulting nonce
 * @max: The maximun size of the resulting nonce
 * Returns: The nonce size on success, 0 on failure
 */
u16 generate_nonce(u8 **buffer, u16 min, u16 max){
    u8 nonce_len = 0;

    if (min > max) {
        *buffer = NULL;
        return 0;
    }
    else if (min < 8){
        *buffer = NULL;
        return 0;
    }
    else if (min == max)
        nonce_len = min;
    else {
        RAND_bytes(&nonce_len, 1);
        nonce_len = (nonce_len % (max - min + 1)) + min;
    }

    u8 *nonce = malloc (nonce_len);
    RAND_bytes(nonce, nonce_len);

    *buffer = nonce;
    return nonce_len;
}


/**
 * add_payload - Add a payload in a buffer
 * @buffer_dest: Destination buffer for the payload
 * @pos: The position to add the payload in the destination buffer
 * @buffer_orig: The data to be stored in the payload
 * @len: The length of the data
 * Returns: The position of the byte just after the added payload, (pos + len + 1)
 */
u16 add_payload(u8 * buffer_dest, u16 pos, u8 * buffer_orig, u16 len){
    u16 temp_len = htons(len);
    memcpy (&buffer_dest[pos], &temp_len, 2);
    pos += 2;
    memcpy(&buffer_dest[pos],buffer_orig,len); pos += len;
    return pos;
}


/**
 * get_payload - Get a payload from a buffer
 * @buffer: source buffer from the payload is read
 * @pos: The position of the source buffer that the payload begins
 * @payload_ptr: a pointer to store the new buffer with the data of the payload (musn't be allocated, allocated inside)
 * Returns: The size of the returned buffer.
 */
u16 get_payload(u8 * buffer, u16 *pos, u8 **payload_ptr){
    u16 temp_len;
    memcpy (&temp_len, &buffer[*pos],2);
    u16 payload_len = ntohs(temp_len);
    *pos += 2;
    u8 *payload = malloc(payload_len);
    memcpy (payload, &buffer[*pos], payload_len);
    *pos += payload_len;
    *payload_ptr = payload;
    return payload_len;
}


/**
 * build_message1 - Generates the message 1 in A (MN)
 * Returns: message1 length.
 */
u16 build_message1( u8 *Kas,  u16 Kas_len,
                    u8 *id_A, u16 id_A_len,
                    u8 *id_B, u16 id_B_len,
                    u8 *Na  , u16 Na_len,
                    u32 SEQas,
                    u8 **message1_ptr)
                {
    u8 *towrap=NULL;
    u8 *wrapped=NULL;

    // Buffers for wrapping
    towrap = malloc(Na_len + 4 + id_B_len + 6);
    wrapped = malloc(Na_len + 4 + id_B_len + 6 + 32);

    // Build the message 1
    u32 temp_seq = htonl(SEQas);

    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, Na             , Na_len  );
    towrap_len = add_payload(towrap, towrap_len,(u8*) &temp_seq , 4       );
    towrap_len = add_payload(towrap, towrap_len, id_B           , id_B_len   );

    u16 wrapped_len = hmac_wrap(Kas, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        return 0;
    }

    u8 *message1 = malloc( id_A_len + wrapped_len + 4 );

    u16 message1_len = 0;
    message1_len = add_payload(message1, message1_len, id_A   , id_A_len    );
    message1_len = add_payload(message1, message1_len, wrapped, wrapped_len );

    free (towrap);
    free (wrapped);

    *message1_ptr = message1;
    return message1_len;
}

/**
 * build_message2 - Generates the message 2 in B (AP)
 * Returns: message2 length.
 */
u16 build_message2( u8 *Kbs, u16 Kbs_len,
                    u8 *id_B, u16 id_B_len,
                    u8 *Nb, u16 Nb_len,
                    u8 *message1, u16 message1_len,
                    u8 **message2_ptr)
                { // TO BE EXECUTED IN B
    u8 *towrap=NULL;
    u8 *wrapped=NULL;

    // Extract id_A from message 1
    u16 message1_pos = 0;
    u8 *id_A = NULL;
    u16 id_A_len = get_payload(message1, &message1_pos, &id_A);

    // Buffers for wrapping
    towrap = malloc(Nb_len + id_A_len + 4);
    wrapped = malloc(Nb_len + id_A_len + 4 + 32);

    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, Nb , Nb_len  );
    towrap_len = add_payload(towrap, towrap_len, id_A , id_A_len  );

    u16 wrapped_len = hmac_wrap(Kbs, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        return 0;
    }

    u8 *message2 = malloc(id_B_len + wrapped_len + message1_len + 6);

    u16 message2_len = 0;
    message2_len = add_payload(message2, message2_len, id_B   , id_B_len    );
    message2_len = add_payload(message2, message2_len, wrapped   , wrapped_len    );

    free (towrap);
    free (wrapped);

    *message2_ptr = message2;
    return message2_len;

}

/**
 * build_message3_and_4 - Generates the message 3 and 4 in S (AAA)
 */
void build_message3_and_4 ( u8 *Kas, u16 Kas_len,
                            u8 *Kbs, u16 Kbs_len,
                            u8 *Ns, u16 Ns_len,
                            u8 *Kab, u16 Kab_len,
                            u32 LKab,
                            u32 SEQsa,
                            u8 *message1, u16 message1_len,
                            u8 *message2, u16 message2_len,
                            u8 **message3_ptr, u16 *message3_len,
                            u8 **message4_ptr, u16 *message4_len
)
                { // TO BE EXECUTED IN S
    u8 *towrap=NULL;
    u8 *tounwrap=NULL;
    u8 *wrapped=NULL;
    u8 *unwrapped=NULL;

    u16 LKab_len = 4;
    u32 temp_LKab = htonl(LKab);

    // Parse message 1
    // Getting id_A from message 1
    u16 message1_pos = 0;
    u8 *id_A = NULL;
    u16 id_A_len = get_payload(message1, &message1_pos, &id_A);
    // Unwrapping {Na, SEQas, id_B}Kas
    u16 tounwrap_len = get_payload(message1, &message1_pos, &tounwrap);
    unwrapped = malloc(tounwrap_len-8);
    u16 unwrapped_len = hmac_unwrap(Kas, tounwrap, tounwrap_len, unwrapped);
    if (unwrapped_len <= 0){
        free (tounwrap);
        free (unwrapped);
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    u16 pos1 = 0;
    // Getting Na
    u8 *Na = NULL;
    u16 Na_len = get_payload(unwrapped,&pos1, &Na);
    // Getting SEQas
    u32 temp_SEQas, SEQas;
    u8 *temp = NULL;
    u16 SEQas_len = get_payload(unwrapped,&pos1,&temp);
    memcpy(&temp_SEQas,temp,4);
    SEQas = ntohl(temp_SEQas);
    // Getting id_B
    u8 *id_B_wrapped = NULL;
    u16 id_B_wrapped_len = get_payload(unwrapped,&pos1, &id_B_wrapped);

    // Free unwrapping buffers
    free (tounwrap);
    free (unwrapped);

    // Parse message 2
    u16 message2_pos = 0;
    // Getting id_B
    u8 *id_B = NULL;
    u16 id_B_len = get_payload(message2,&message2_pos, &id_B);

    // Unwrapping {Nb,id_A}Kbs
    tounwrap_len = get_payload(message2, &message2_pos, &tounwrap);
    unwrapped = malloc(tounwrap_len-8);
    unwrapped_len = hmac_unwrap(Kbs, tounwrap, tounwrap_len, unwrapped);
    if (unwrapped_len <= 0){
        free (tounwrap);
        free (unwrapped);
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    u16 pos = 0;
    u8 *Nb = NULL;
    u16 Nb_len = get_payload(unwrapped,&pos, &Nb);
    u8 *id_A_wrapped = NULL;
    u16 id_A_wrapped_len = get_payload(unwrapped,&pos, &id_A_wrapped);

    // Free unwrapping buffers
    free (tounwrap);
    free (unwrapped);

    // Test id_A
    if ((id_A_len != id_A_wrapped_len) && memcmp(id_A, id_A_wrapped, id_A_len)!=0) {
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    // Test id_B
    if ((id_B_len != id_B_wrapped_len) && memcmp(id_B, id_B_wrapped, id_B_len)!=0) {
        *message3_len = 0;
        *message4_len = 0;
        return;
    }
    // Here we must test the SEQas number.
    if (SEQas != SEQsa) {
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    // Build message 3
    // Buffers for wrapping
    towrap = malloc(id_A_len + id_B_len + Na_len + Nb_len + Ns_len + Kab_len + LKab_len + 14);
    wrapped = malloc(id_A_len + id_B_len + Na_len + Nb_len + Ns_len + Kab_len + LKab_len + 14 + 32);


    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, id_A , id_A_len  );
    towrap_len = add_payload(towrap, towrap_len, id_B , id_B_len  );
    towrap_len = add_payload(towrap, towrap_len, Na , Na_len  );
    towrap_len = add_payload(towrap, towrap_len, Nb , Nb_len  );
    towrap_len = add_payload(towrap, towrap_len, Ns , Ns_len  );
    towrap_len = add_payload(towrap, towrap_len, Kab , Kab_len  );
    towrap_len = add_payload(towrap, towrap_len, (u8*) &temp_LKab , 4  );

    u16 wrapped_len = hmac_wrap(Kbs, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    *message3_ptr = wrapped;
    *message3_len = wrapped_len;


    free (towrap);

    // Build message 4
    // Buffers for wrapping
    towrap = malloc(id_A_len + id_B_len + Na_len + Nb_len + Ns_len + LKab_len + 12 );
    wrapped = malloc(id_A_len + id_B_len + Na_len + Nb_len + Ns_len + LKab_len + 12 + 32 );


    towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, id_A , id_A_len  );
    towrap_len = add_payload(towrap, towrap_len, id_B , id_B_len  );
    towrap_len = add_payload(towrap, towrap_len, Na , Na_len  );
    towrap_len = add_payload(towrap, towrap_len, Nb , Nb_len  );
    towrap_len = add_payload(towrap, towrap_len, Ns , Ns_len  );
    towrap_len = add_payload(towrap, towrap_len, (u8*) &temp_LKab , 4  );

    wrapped_len = hmac_wrap(Kas, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        free (*message3_ptr);
        *message3_len = 0;
        *message4_len = 0;
        return;
    }

    *message4_ptr = wrapped;
    *message4_len = wrapped_len;

    free (towrap);
}



/**
 * process_and_check_message3 - Checks the message 3 integrity and gets Kab and its lifetime in B (AP)
 * Returns: 1 on success, 0 on failure
 */
int process_and_check_message3( u8 *Kbs, u16 Kbs_len,
                                u8 *Nb_orig, u16 Nb_orig_len,
                                u8 *message3, u16 message3_len,
                                u8 **Kab_ptr, u16 *Kab_len_ptr, u32 *LKab_ptr )
                { // TO BE EXECUTED IN B
    u8 *towrap=NULL;
    u8 *tounwrap=NULL;
    u8 *wrapped=NULL;
    u8 *unwrapped=NULL;

    // Parse message 3
    // Unwrapping message3
    u16 tounwrap_len = message3_len;
    tounwrap = message3;
    unwrapped = malloc(tounwrap_len-8);
    u16 unwrapped_len = hmac_unwrap(Kbs, tounwrap, tounwrap_len, unwrapped);
    if (unwrapped_len <= 0){
        free (unwrapped);
        // return failure
        return 0;
    }

    u16 pos3 = 0;
    // Getting id_A
    u8 *id_A = NULL;
    u16 id_A_len = get_payload(unwrapped,&pos3, &id_A);
    // Getting id_B
    u8 *id_B = NULL;
    u16 id_B_len = get_payload(unwrapped,&pos3, &id_B);
    // Getting Na
    u8 *Na = NULL;
    u16 Na_len = get_payload(unwrapped,&pos3, &Na);
    // Getting Nb
    u8 *Nb = NULL;
    u16 Nb_len = get_payload(unwrapped,&pos3, &Nb);
    // Getting Ns
    u8 *Ns = NULL;
    u16 Ns_len = get_payload(unwrapped,&pos3, &Ns);
    // Getting Kab
    u8 *Kab = NULL;
    u16 Kab_len = get_payload(unwrapped,&pos3, &Kab);
    // Getting LKab
    u32 temp_LKab, LKab;
    u8 *temp = NULL;
    u16 LKab_len = get_payload(unwrapped,&pos3,&temp);
    memcpy(&temp_LKab,temp,4);
    LKab = ntohl(temp_LKab);


    // Free unwrapping buffers
    free (unwrapped);
    // Check if the received nonces are equal to the originals
    if (memcmp(Nb,Nb_orig,Nb_len)!=0){
        // Return failure
        return 0;
    }

    // Store Kab and its LKab lifetime
    *Kab_ptr = Kab;
    *Kab_len_ptr = Kab_len;
    *LKab_ptr = LKab;

    // Return success
    return 1;
}


/**
 * process_and_check_message4 - Checks the message 4 integrity and gets the lifetime of Kab in A (MN)
 * Returns: 1 on success, 0 on failure
 */
int process_and_check_message4( u8 *Kas, u16 Kas_len,
				u8 *Ksmk, u16 Ksmk_len,
                                u8 *Na_orig, u16 Na_orig_len,
                                u8 *message4, u16 message4_len,
                                u32 *LKab_ptr, u8 *Kab )
                { // TO BE EXECUTED IN A
    u8 *towrap=NULL;
    u8 *tounwrap=NULL;
    u8 *wrapped=NULL;
    u8 *unwrapped=NULL;

    // Parse message 4
    // Unwrapping message4
    u16 tounwrap_len = message4_len;
    tounwrap = message4;
    unwrapped = malloc(tounwrap_len-8);
    u16 unwrapped_len = hmac_unwrap(Kas, tounwrap, tounwrap_len, unwrapped);
    if (unwrapped_len <= 0){
        free (unwrapped);
        return 0;
    }


    u16 pos4 = 0;
    // Getting id_A
    u8 *id_A = NULL;
    u16 id_A_len = get_payload(unwrapped,&pos4, &id_A);
    // Getting id_B
    u8 *id_B = NULL;
    u16 id_B_len = get_payload(unwrapped,&pos4, &id_B);
    // Getting Na
    u8 *Na = NULL;
    u16 Na_len = get_payload(unwrapped,&pos4, &Na);
    // Getting Nb
    u8 *Nb = NULL;
    u16 Nb_len = get_payload(unwrapped,&pos4, &Nb);
    // Getting Ns
    u8 *Ns = NULL;
    u16 Ns_len = get_payload(unwrapped,&pos4, &Ns);
    // Getting LKab
    u32 temp_LKab, LKab;
    u8 *temp = NULL;
    u16 LKab_len = get_payload(unwrapped,&pos4,&temp);
    memcpy(&temp_LKab,temp,4);
    LKab = ntohl(temp_LKab);
    //derive the kab key

    u8 *key_derived = (u8 *) malloc(80*sizeof(u8));
    u16 sequence_len = id_A_len+id_B_len+Na_len+Nb_len+Ns_len;
    u8 *sequence = (u8 *) malloc(sequence_len*sizeof(u8));
    u8 *index_seq = sequence;
    memcpy(index_seq,id_A,id_A_len);
    index_seq+=id_A_len;
    memcpy(index_seq,id_B,id_B_len);
    index_seq+=id_B_len;
    memcpy(index_seq,Na,Na_len);
    index_seq+=Na_len;
    memcpy(index_seq,Nb,Nb_len);
    index_seq+=Nb_len;
    memcpy(index_seq,Ns,Ns_len);
    PRF_plus(4,Ksmk,Ksmk_len,sequence,sequence_len,key_derived);
    u16 Kab_len = 64;
    memcpy(Kab, key_derived,Kab_len);
    print_hex(Kab,Kab_len);

    free (unwrapped);

    // Check if the received nonces are equal to the originals
    if (memcmp(Na,Na_orig,Na_len)!=0){
        // Return failure
        return 0;
    }

    // Store the LKab lifetime
    *LKab_ptr = LKab;

    // Return success
    return 1;
}



/**
 * build_message1 - Generates the message 1 in A (MN)
 * Returns: message1 length.
 */
u16 build_message1_extended( u8 *Kas,  u16 Kas_len,
                    u8 *id_A, u16 id_A_len,
                    u8 *id_B, u16 id_B_len,
					u8 *id_S2, u16 id_S2_len,
                    u8 *Na  , u16 Na_len,
                    u32 SEQas,
                    u8 **message1_ptr)
                {
    u8 *towrap=NULL;
    u8 *wrapped=NULL;

    // Buffers for wrapping
    towrap = malloc(Na_len + 4 + id_S2_len + 6);
    wrapped = malloc(Na_len + 4 + id_S2_len + 6 + 32);

    // Build the message 1
    u32 temp_seq = htonl(SEQas);

    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, Na             , Na_len  );
    towrap_len = add_payload(towrap, towrap_len,(u8*) &temp_seq , 4       );
    towrap_len = add_payload(towrap, towrap_len, id_S2           , id_S2_len   );

    u16 wrapped_len = hmac_wrap(Kas, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        return 0;
    }

    u8 *message1 = malloc( id_A_len + id_B_len  + wrapped_len + 6 );

    u16 message1_len = 0;
    message1_len = add_payload(message1, message1_len, id_A   , id_A_len    );
    message1_len = add_payload(message1, message1_len, id_B   , id_B_len    );
    message1_len = add_payload(message1, message1_len, wrapped, wrapped_len );

    free (towrap);
    free (wrapped);

    *message1_ptr = message1;
    return message1_len;
}

/**
 * build_message2 - Generates the message 2 in B (AP)
 * Returns: message2 length.
 */
u16 build_message2_extended( u8 *Kbl, u16 Kbl_len,
                    u8 *Nb, u16 Nb_len,
                    u8 *message1, u16 message1_len,
                    u8 **message2_ptr)
                { // TO BE EXECUTED IN B
    u8 *towrap=NULL;
    u8 *wrapped=NULL;

    // Extract id_A from message 1
    u16 message1_pos = 0;
    u8 *id_A = NULL;
    u16 id_A_len = get_payload(message1, &message1_pos, &id_A);
    u8 *id_B =NULL;
    u16 id_B_len = get_payload(message1, &message1_pos, &id_B);
    // Buffers for wrapping
    towrap = malloc(Nb_len + id_A_len + 4);
    wrapped = malloc(Nb_len + id_A_len + 4 + 32);

    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, Nb , Nb_len  );
    towrap_len = add_payload(towrap, towrap_len, id_A , id_A_len  );

    u16 wrapped_len = hmac_wrap(Kbl, towrap, towrap_len, wrapped);

    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        return 0;
    }

    u8 *message2 = malloc(id_B_len + wrapped_len + 4);

    u16 message2_len = 0;
    message2_len = add_payload(message2, message2_len, id_B   , id_B_len    );
    message2_len = add_payload(message2, message2_len, wrapped   , wrapped_len    );

    free (towrap);
    free (wrapped);

    *message2_ptr = message2;
    return message2_len;

}

void build_message3_extended(u8 *Kls, u16 Kls_len,
		u8 *Kbl, u16 Kbl_len,
		u8 *Nl, u16 Nl_len,
		u8 * id_L, u16 id_L_len,
		u8 * message1, u16 message1_len,
		u8 *message2, u16 message2_len,
		u8 **message3_ptr, u16 *message3_len,
		u8 **message4_ptr, u16 *message4_len,
		u8 ** id_B_r, u16 * id_B_len_r,
		u8 ** Nb, u16 * Nb_len)
{
    u8 *towrap=NULL;
    u8 *wrapped=NULL;

    // Extract id_A from message 1
    u16 message1_pos = 0;
    u16 message2_pos =0;

    u8 *id_A = NULL;
    u16 id_A_len = get_payload(message1, &message1_pos, &id_A);
    u8 *id_B =NULL;
    u16 id_B_len = get_payload(message1, &message1_pos, &id_B);
    u8 *wrapped_m1 = NULL;
    u16 wrapped_m1_len = get_payload(message1, &message1_pos, &wrapped_m1);

    u8 *id_B_2 = NULL;
    u16 id_B_len2 = get_payload(message2,&message2_pos, &id_B_2);

    *id_B_r = id_B_2;
    *id_B_len_r = id_B_len2;

    // Unwrapping {Nb,id_A}Kbl
    u8 *tounwrap = NULL;
    u16 tounwrap_len = get_payload(message2, &message2_pos, &tounwrap);
    u8 *unwrapped = malloc(tounwrap_len-8);
    u16 unwrapped_len = hmac_unwrap(Kbl, tounwrap, tounwrap_len, unwrapped);
    if (unwrapped_len <= 0){
       	free (tounwrap);
       	free (unwrapped);
	return;
    }
    u16 pos = 0;
    u8 *Nb2 = NULL;
    u16 Nb2_len = get_payload(unwrapped,&pos, &Nb2);
    u8 *id_A_wrapped = NULL;
    u16 id_A_wrapped_len = get_payload(unwrapped,&pos, &id_A_wrapped);
    *Nb = Nb2;
    *Nb_len = Nb2_len;

    // Free unwrapping buffers
    free (tounwrap);
    free (unwrapped);


    // Buffers for wrapping
    towrap = malloc(Nl_len + id_A_len + 4);
    wrapped = malloc(Nl_len + id_A_len + 4 + 32);

    u16 towrap_len = 0;
    towrap_len = add_payload(towrap, towrap_len, Nl , Nl_len  );
    towrap_len = add_payload(towrap, towrap_len, id_A , id_A_len  );

    u16 wrapped_len = hmac_wrap(Kls, towrap, towrap_len, wrapped);
    if (wrapped_len <= 0){
        free (towrap);
        free (wrapped);
        return 0;
    }
    u8 *message3 = malloc(id_L_len + wrapped_len + 4);
    *message3_len = add_payload(message3, *message3_len, id_L   , id_L_len    );
    *message3_len = add_payload(message3, *message3_len, wrapped   , wrapped_len    );
    free (towrap);
    free (wrapped);
    *message3_ptr = message3;

    u8 *message4 = malloc(id_A_len + wrapped_m1_len + 4 );
    *message4_len = 0;
    *message4_len = add_payload(message4, *message4_len, id_A, id_A_len);
    *message4_len = add_payload(message4, *message4_len, wrapped_m1 , wrapped_m1_len);
    *message4_ptr = message4;

}

void build_message4_extended(u8 *Kas, u16 Kas_len,
				 u8 *Kls, u16 Kls_len,
				 u8 *SMKas, u16 SMKas_len,
				 u8 *Ns, u16 Ns_len,
				 u8 *message3, u16 message3_len,
				 u8 *message4, u16 message4_len,
				 u8 **message5_ptr, u16 *message5_len,
				 u8 **message6_ptr, u16 *message6_len)
{
	// Parse message 2
	u16 message3_pos = 0;
	// Getting id_L
	u8 *id_L = NULL;
	u16 id_L_len = get_payload(message3,&message3_pos, &id_L);
	// Unwrapping {Nl,id_A}Kls
	u8 *tounwrap = NULL;
	u16 tounwrap_len = get_payload(message3, &message3_pos, &tounwrap);
	u8 *unwrapped = malloc(tounwrap_len-8);
	u16 unwrapped_len = hmac_unwrap(Kls, tounwrap, tounwrap_len, unwrapped);
	if (unwrapped_len <= 0){
	   free (tounwrap);
	   free (unwrapped);
	   *message5_len = 0;
	   *message6_len = 0;
	   return;
	 }
     u16 pos = 0;
	 u8 *Nl = NULL;
	 u16 Nl_len = get_payload(unwrapped,&pos, &Nl);
	 u8 *id_A_wrapped = NULL;
	 u16 id_A_wrapped_len = get_payload(unwrapped,&pos, &id_A_wrapped);

	 // Free unwrapping buffers
	 free (tounwrap);
	 free (unwrapped);

	//Unwrapping {Na,SEQAS,L}Kas
	u16 message4_pos =0;
	u8 *id_A = NULL;
	u16 id_A_len = get_payload(message4,&message4_pos, &id_A);
	tounwrap_len = get_payload(message4, &message4_pos, &tounwrap);
	unwrapped = malloc(tounwrap_len-8);
	unwrapped_len= hmac_unwrap(Kas,tounwrap, tounwrap_len, unwrapped);
	if(unwrapped_len <= 0) {
		free(tounwrap);
		free(unwrapped);
		*message5_len =0;
		*message6_len =0;
		return;
	}
	pos =0;
	u8 *Na = NULL;
	u16 Na_len = get_payload(unwrapped, &pos, &Na);

	//derive key
	u8 *key = (u8 *) malloc(80*sizeof(u8));
	u16 sequence_len = id_A_len + id_L_len + Na_len + Nl_len + Ns_len;
	u8 * sequence = malloc(sequence_len * sizeof(u8));
	u8 * index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_L, id_L_len);
	index += id_L_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nl, Nl_len);
	index += Nl_len;
	memcpy(index, Ns, Ns_len);
	index += Ns_len;

	PRF_plus(4,SMKas,64,sequence,sequence_len,key);

	u8 *Kal = malloc(64*sizeof(u8));
	memcpy(Kal,key, 64);
	u16 Kal_len = 64;

	free(key);

	//format messages
	u8 * towrap5 = malloc (id_A_wrapped_len + id_L_len + Na_len + Nl_len + Ns_len + 10);
	u8 * wrapped5 =  malloc (id_A_wrapped_len + id_L_len + Na_len + Nl_len + Ns_len + 10 + 32);
	u16 towrap5_len = 0;
	towrap5_len = add_payload(towrap5, towrap5_len, id_A_wrapped, id_A_wrapped_len);
	towrap5_len = add_payload(towrap5, towrap5_len, id_L, id_L_len);
	towrap5_len = add_payload(towrap5, towrap5_len, Na, Na_len);
	towrap5_len = add_payload(towrap5, towrap5_len, Nl, Nl_len);
	towrap5_len = add_payload(towrap5, towrap5_len, Ns, Ns_len);

	u16 wrapped5_len = hmac_wrap(Kas, towrap5, towrap5_len, wrapped5);

    	if (wrapped5_len <= 0){
        	free (towrap5);
	        free (wrapped5);
	        return 0;
    	}

	u8 * towrap6 = malloc (id_A_wrapped_len + id_L_len + Na_len + Nl_len + Ns_len + Kal_len + 12);
    u8 * wrapped6 =  malloc (id_A_wrapped_len + id_L_len + Na_len + Nl_len + Ns_len + Kal_len + 12 + 32);
    u16 towrap6_len = 0;
    towrap6_len = add_payload(towrap6, towrap6_len, id_A_wrapped, id_A_wrapped_len);
    towrap6_len = add_payload(towrap6, towrap6_len, id_L, id_L_len);
    towrap6_len = add_payload(towrap6, towrap6_len, Na, Na_len);
    towrap6_len = add_payload(towrap6, towrap6_len, Nl, Nl_len);
    towrap6_len = add_payload(towrap6, towrap6_len, Ns, Ns_len);
	towrap6_len = add_payload(towrap6, towrap6_len, Kal, Kal_len);

    u16 wrapped6_len = hmac_wrap(Kls, towrap6, towrap6_len, wrapped6);

    if (wrapped6_len <= 0){
        free (towrap6);
        free (wrapped6);
        return 0;
    }

	*message5_ptr  = wrapped5;
	*message5_len = wrapped5_len;

	*message6_ptr = wrapped6;
	*message6_len = wrapped6_len;

}

void build_message5_extended (u8 * Kls, u16 Kls_len,
				u8 * Kbl, u16 Kbl_len,
				u8 *id_B, u16 id_B_len,
				u8 * Nb, u16 Nb_len,
				u8 * Nll, u16 Nll_len,
				u32 SEQal,
				u8 *message6, u16 message6_len,
				u8 **message7_ptr, u16 *message7_len,
				u8 **message8_ptr, u16 *message8_len)
{
	//unwrapping message 6
	u8 * tounwrap = message6;
	u16 tounwrap_len = message6_len;
	u8 *unwrapped = NULL;
	unwrapped = malloc(tounwrap_len-8);
	u16 unwrapped_len = hmac_unwrap(Kls, tounwrap, tounwrap_len, unwrapped);

	if (unwrapped_len <= 0){
	   free (tounwrap);
	   free (unwrapped);
	   *message7_len = 0;
	   *message8_len = 0;
	   return;
	 }
    u16 pos = 0;
	u8 *id_A = NULL;
	u16 id_A_len = get_payload(unwrapped,&pos, &id_A);
	u8 *id_L = NULL;
	u16 id_L_len = get_payload(unwrapped,&pos, &id_L);
	u8 *Na = NULL;
	u16 Na_len = get_payload(unwrapped,&pos, &Na);
	u8 *Nl = NULL;
	u16 Nl_len = get_payload(unwrapped,&pos, &Nl);
	u8 *Ns = NULL;
	u16 Ns_len = get_payload(unwrapped,&pos, &Ns);
	u8 *Kal = NULL;
	u16 Kal_len = get_payload(unwrapped,&pos, &Kal);

	//Derive K2al  with Kal

	//para K2ab  nonces Na, Nb, Nll
	//para Kal nonces Na, Nl, Ns
	u8 *key = (u8 *) malloc(80*sizeof(u8));
	u16 sequence_len = id_A_len + id_L_len + Na_len + Nl_len + Ns_len;
	u8 * sequence = malloc(sequence_len * sizeof(u8));
	u8 * index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_L, id_L_len);
	index += id_L_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nl, Nl_len);
	index += Nl_len;
	memcpy(index, Ns, Ns_len);
	index += Ns_len;

	PRF_plus(4,Kal,64,sequence,sequence_len,key);

	u8 *K2al = malloc(64*sizeof(u8));
	memcpy(K2al,key, 64);
	u16 K2al_len = 64;

	free(key);
	free(sequence);

	key = (u8 *) malloc(80*sizeof(u8));
	sequence_len = id_A_len + id_B_len + Na_len + Nb_len + Nll_len;
	sequence = malloc(sequence_len * sizeof(u8));
	index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_B, id_B_len);
	index += id_B_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nb, Nb_len);
	index += Nb_len;
	memcpy(index, Nll, Nll_len);
	index += Nll_len;

	PRF_plus(4,Kal,64,sequence,sequence_len,key);

	u8 *K2ab = malloc(64*sizeof(u8));
	memcpy(K2ab,key, 64);
	u16 K2ab_len = 64;

	free(key);


	//format messages
	u32 temp_seq = htonl(SEQal);

	u8 * towrap7 = malloc (id_A_len + id_B_len + Na_len + Nb_len + Nll_len + 4 + 12);
    u8 * wrapped7 =  malloc (id_A_len + id_B_len + Na_len + Nb_len + Nll_len + 4 + 12 + 32);
    u16 towrap7_len = 0;
    towrap7_len = add_payload(towrap7, towrap7_len, id_A, id_A_len);
    towrap7_len = add_payload(towrap7, towrap7_len, id_B, id_B_len);
    towrap7_len = add_payload(towrap7, towrap7_len, Na, Na_len);
    towrap7_len = add_payload(towrap7, towrap7_len, Nb, Nb_len);
    towrap7_len = add_payload(towrap7, towrap7_len, Nll, Nll_len);
    towrap7_len = add_payload(towrap7, towrap7_len, (u8*) &temp_seq , 4);
    u16 wrapped7_len = hmac_wrap(K2al, towrap7, towrap7_len, wrapped7);

    if (wrapped7_len <= 0){
        free (towrap7);
        free (wrapped7);
        return 0;
    }

	*message7_ptr  = wrapped7;
	*message7_len = wrapped7_len;

	u8 * towrap8 = malloc (id_A_len + id_B_len + Na_len + Nb_len + Nll_len + K2ab_len + 12);
    u8 * wrapped8 =  malloc (id_A_len + id_B_len + Na_len + Nb_len + Nll_len + K2ab_len + 12 + 32);
    u16 towrap8_len = 0;
    towrap8_len = add_payload(towrap8, towrap8_len, id_A, id_A_len);
    towrap8_len = add_payload(towrap8, towrap8_len, id_B, id_B_len);
    towrap8_len = add_payload(towrap8, towrap8_len, Na, Na_len);
    towrap8_len = add_payload(towrap8, towrap8_len, Nb, Nb_len);
    towrap8_len = add_payload(towrap8, towrap8_len, Nll, Nll_len);
	towrap8_len = add_payload(towrap8, towrap8_len, K2ab , K2ab_len);

    u16 wrapped8_len = hmac_wrap(Kbl, towrap8, towrap8_len, wrapped8);

    if (wrapped8_len <= 0){
        free (towrap8);
        free (wrapped8);
        return 0;
    }

	*message8_ptr  = wrapped8;
	*message8_len = wrapped8_len;
}

void process_and_check_message6_extended(u8 * Kbl, u16 Kbl_len,
			   u8 * message8, u16 message8_len,
			   u8 **Kab_ptr, u16 *Kab_len_ptr)
{
	//unwrapping message 6
	u8 * tounwrap = message8;
	u16 tounwrap_len = message8_len;
	u8 *unwrapped = NULL;
	unwrapped = malloc(tounwrap_len-8);
	u16 unwrapped_len = hmac_unwrap(Kbl, tounwrap, tounwrap_len, unwrapped);

	if (unwrapped_len <= 0){
	   free (tounwrap);
	   free (unwrapped);
	   return;
	 }
    u16 pos = 0;
	u8 *id_A = NULL;
	u16 id_A_len = get_payload(unwrapped,&pos, &id_A);
	u8 *id_B = NULL;
	u16 id_B_len = get_payload(unwrapped,&pos, &id_B);
	u8 *Na = NULL;
	u16 Na_len = get_payload(unwrapped,&pos, &Na);
	u8 *Nb = NULL;
	u16 Nb_len = get_payload(unwrapped,&pos, &Nb);
	u8 *Nl = NULL;
	u16 Nl_len = get_payload(unwrapped,&pos, &Nl);
	u8 *Kab = NULL;
	u16 Kab_len = get_payload(unwrapped,&pos, &Kab);

	*Kab_ptr = Kab;
    *Kab_len_ptr = Kab_len;
}

void process_and_check_message7_extended( u8 * Kas, u16 Kas_len,
							u8 * SMKas, u16 SMKas_len,
							u8 * message9, u16 message9_len,
							u8 * message10, u16 message10_len,
							u8 **Kab_ptr, u16 *Kab_len_ptr)
{
	//unwrapping message 6
	u8 * tounwrap = message9;
	u16 tounwrap_len = message9_len;
	u8 *unwrapped = NULL;
	unwrapped = malloc(tounwrap_len-8);
	u16 unwrapped_len = hmac_unwrap(Kas, tounwrap, tounwrap_len, unwrapped);

	if (unwrapped_len <= 0){
	   free (tounwrap);
	   free (unwrapped);
	   return;
	 }
    u16 pos = 0;
	u8 *id_A = NULL;
	u16 id_A_len = get_payload(unwrapped,&pos, &id_A);
	u8 *id_L = NULL;
	u16 id_L_len = get_payload(unwrapped,&pos, &id_L);
	u8 *Na = NULL;
	u16 Na_len = get_payload(unwrapped,&pos, &Na);
	u8 *Nl = NULL;
	u16 Nl_len = get_payload(unwrapped,&pos, &Nl);
	u8 *Ns = NULL;
	u16 Ns_len = get_payload(unwrapped,&pos, &Ns);

	//Derive Kal
	u8 *key = (u8 *) malloc(80*sizeof(u8));
	u16 sequence_len = id_A_len + id_L_len + Na_len + Nl_len + Ns_len;
	u8 * sequence = malloc(sequence_len * sizeof(u8));
	u8 * index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_L, id_L_len);
	index += id_L_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nl, Nl_len);
	index += Nl_len;
	memcpy(index, Ns, Ns_len);
	index += Ns_len;

	PRF_plus(4,SMKas,64,sequence,sequence_len,key);

	u8 *Kal = malloc(64*sizeof(u8));
	memcpy(Kal,key, 64);
	u16 Kal_len = 64;

	free(key);
	free(sequence);
	//Derive K2al
	//Root key kal

	key = (u8 *) malloc(80*sizeof(u8));
	sequence_len = id_A_len + id_L_len + Na_len + Nl_len + Ns_len;
	sequence = malloc(sequence_len * sizeof(u8));
	index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_L, id_L_len);
	index += id_L_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nl, Nl_len);
	index += Nl_len;
	memcpy(index, Ns, Ns_len);
	index += Ns_len;

	PRF_plus(4,Kal,64,sequence,sequence_len,key);

	u8 *K2al = malloc(64*sizeof(u8));
	memcpy(K2al,key, 64);
	u16 K2al_len = 64;

	free(key);
	free(sequence);

	tounwrap = message10;
	tounwrap_len = message10_len;
	unwrapped = NULL;
	unwrapped = malloc(tounwrap_len-8);
	unwrapped_len = hmac_unwrap(K2al, tounwrap, tounwrap_len, unwrapped);

	if (unwrapped_len <= 0){
	   free (tounwrap);
	   free (unwrapped);
	   return;
	 }
    	pos = 0;
	id_A = NULL;
	id_A_len = get_payload(unwrapped,&pos, &id_A);
	u8 *id_B = NULL;
	u16 id_B_len = get_payload(unwrapped,&pos, &id_B);
	Na = NULL;
	Na_len = get_payload(unwrapped,&pos, &Na);
	u8 *Nb = NULL;
	u16 Nb_len = get_payload(unwrapped,&pos, &Nb);
	u8 *Nll = NULL;
	u16 Nll_len = get_payload(unwrapped,&pos, &Nll);
	u32 *SEQal = NULL;
	u16 SEQal_len = get_payload(unwrapped,&pos, &SEQal);

	SEQal = ntohl(SEQal);

	//Derive Kab
	//Root key Kal Na Nb Nl

	key = (u8 *) malloc(80*sizeof(u8));
	sequence_len = id_A_len + id_B_len + Na_len + Nb_len + Nll_len;
	sequence = malloc(sequence_len * sizeof(u8));
	index = sequence;

	memcpy(index, id_A, id_A_len);
	index += id_A_len;
	memcpy(index, id_B, id_B_len);
	index += id_B_len;
	memcpy(index, Na, Na_len);
	index += Na_len;
	memcpy(index, Nb, Nb_len);
	index += Nb_len;
	memcpy(index, Nll, Nll_len);
	index += Nll_len;

	PRF_plus(4,Kal,64,sequence,sequence_len,key);

	u8 *K2ab = malloc(64*sizeof(u8));
	memcpy(K2ab,key, 64);
	u16 K2ab_len = 64;

	free(key);


	*Kab_ptr = K2ab;
    	*Kab_len_ptr = K2ab_len;


}

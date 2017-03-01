/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
*                                                                         *
*   This library is free software; you can redistribute it and/or         *
*   modify it under the terms of the GNU Lesser General Public            *
*   License as published by the Free Software Foundation; either          *
*   version 2.1 of the License, or (at your option) any later version.    *
*                                                                         *
*   This library is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
*   Lesser General Public License for more details.                       *
*                                                                         *
*   You should have received a copy of the GNU Lesser General Public      *
*   License along with this library; if not, write to the Free Software   *
*   Foundation, Inc., 51 Franklin St, Fifth Floor,                        *
*   Boston, MA  02110-1301  USA                                           *
***************************************************************************/
#include "cipheropenssl.h"

#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <assert.h>

namespace openikev2 {

    CipherOpenSSL::CipherOpenSSL( Enums::ENCR_ID encr_algo, Enums::INTEG_ID integ_algo, auto_ptr< ByteArray > encr_key, auto_ptr< ByteArray > integ_key ) {
        // Initializes the crypto context
        EVP_CIPHER_CTX_init( &ctx );

        // store the keys
        this->encr_key = encr_key;
        this->integ_key = integ_key;

        // creates the openssl EVP for the ENCR transform
        switch ( encr_algo ) {
            case Enums::ENCR_DES:
                assert ( this->encr_key->size() == 8 );
                this->encr_evp = ( EVP_CIPHER* ) EVP_des_cbc();
                this->encr_block_size = EVP_CIPHER_block_size( this->encr_evp );
                break;

            case Enums::ENCR_3DES:
                assert ( this->encr_key->size() == 24 );
                this->encr_evp = ( EVP_CIPHER* ) EVP_des_ede3_cbc();
                this->encr_block_size = EVP_CIPHER_block_size( this->encr_evp );
                break;

            case Enums::ENCR_AES_CBC:
                if ( this->encr_key->size() == 16 )
                    this->encr_evp = ( EVP_CIPHER* ) EVP_aes_128_cbc();
                else if ( this->encr_key->size() == 24 )
                    this->encr_evp = ( EVP_CIPHER* ) EVP_aes_192_cbc();
                else if ( this->encr_key->size() == 32 )
                    this->encr_evp = ( EVP_CIPHER* ) EVP_aes_256_cbc();
                else
                    assert( "AES key size not supported" && 0 );
                this->encr_block_size = EVP_CIPHER_block_size( this->encr_evp );
                break;

            case Enums::ENCR_NONE:
                assert ( this->encr_key.get() == NULL );
                this->encr_evp = NULL;
                this->encr_block_size = 0;
                break;

            default:
                assert( "encryption algorithm not supported" && 0 );
        }


        // creates the openssl EVP for the INTEG transform
        switch ( integ_algo ) {
            case Enums::AUTH_HMAC_MD5_96:
                assert ( this->integ_key->size() == 16 );
                this->integ_evp = ( EVP_MD* ) EVP_md5();
                this->integ_hash_size = 12;
                break;

            case Enums::AUTH_HMAC_SHA1_96:
                assert ( this->integ_key->size() == 20 );
                this->integ_evp = ( EVP_MD* ) EVP_sha1();
                this->integ_hash_size = 12;
                break;

            case Enums::AUTH_NONE:
                assert ( this->integ_key.get() == NULL );
                this->integ_evp = NULL;
                this->integ_hash_size = 0;
                break;

            default:
                assert ( "integrity algorithm not supported" && 0 );
        }
    }

    CipherOpenSSL::~CipherOpenSSL() {
        EVP_CIPHER_CTX_cleanup( &ctx );
    }

    auto_ptr< ByteArray > CipherOpenSSL::encrypt( ByteArray & plain_text, ByteArray & initialization_vector ) {
        assert ( ( plain_text.size() % this->encr_block_size ) == 0 );

        int outlen = 0;

        // the ciphertext will have the same size as plain_text
        auto_ptr<ByteArray> ciphertext ( new ByteArray( plain_text.size() ) );

        // Initializes crypto operation
        uint8_t result = EVP_EncryptInit_ex( &this->ctx, this->encr_evp, NULL, this->encr_key->getRawPointer(), initialization_vector.getRawPointer() );
        assert( result );

        // Turn-off auto padding
        EVP_CIPHER_CTX_set_padding( &this->ctx, 0 );

        // Encrypt data
        result = EVP_EncryptUpdate( &this->ctx, ciphertext->getRawPointer(), &outlen, plain_text.getRawPointer(), plain_text.size() );
        ciphertext->setSize( outlen );
        assert( result );
        assert ( outlen == plain_text.size() );

        // finalize encryption
        result = EVP_EncryptFinal_ex( &ctx, ciphertext->getRawPointer() + outlen, &outlen );
        assert( result );

        // no need to finalize since no padding is needed
        return ciphertext;
    }


    auto_ptr< ByteArray > CipherOpenSSL::decrypt( ByteArray & cipher_text, ByteArray & initialization_vector ) {
        assert ( ( cipher_text.size() % this->encr_block_size ) == 0 );

        // the ciphertext will have the same size as plain_text
        auto_ptr<ByteArray> plaintext ( new ByteArray( cipher_text.size() ) );

        // Initializes crypto operation
        int outlen;
        uint8_t result = EVP_DecryptInit_ex( &this->ctx, this->encr_evp, NULL, this->encr_key->getRawPointer(), initialization_vector.getRawPointer() );
        assert( result );

        // Turn-off auto padding
        EVP_CIPHER_CTX_set_padding( &this->ctx, 0 );

        // decrypt data
        result = EVP_DecryptUpdate( &this->ctx, plaintext->getRawPointer(), &outlen, cipher_text.getRawPointer(), cipher_text.size() );
        plaintext->setSize( outlen );
        assert( result );
        assert ( outlen == cipher_text.size() );

        // finalize decryption
        result = EVP_DecryptFinal_ex( &ctx, plaintext->getRawPointer() + outlen, &outlen );
        assert( result );

        // no need to finalize since no padding is needed
        return plaintext;
    }


    auto_ptr< ByteArray > CipherOpenSSL::computeIntegrity( ByteArray & data_buffer ) {
        return this->hmac( data_buffer, *this->integ_key );
    }

    auto_ptr< ByteArray > CipherOpenSSL::hmac( ByteArray & data_buffer, ByteArray & hmac_key ) {
        auto_ptr<ByteArray> result ( new ByteArray( EVP_MD_size( this->integ_evp ) ) );

        uint32_t hsize = 0;
        HMAC( this->integ_evp, hmac_key.getRawPointer(), hmac_key.size(), data_buffer.getRawPointer(), data_buffer.size(), result->getRawPointer(), &hsize );

        // The integ hash size may be shorter than real hash result
        result->setSize( this->integ_hash_size );

        return result;
    }
}

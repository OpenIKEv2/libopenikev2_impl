/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef CIPHER_OPENSSL_H
#define CIPHER_OPENSSL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <cstdlib>
#include <memory>

#include <libopenikev2/cipher.h>
#include <libopenikev2/proposal.h>
#include <libopenikev2/bytearray.h>

#include <openssl/evp.h>

using namespace std;

namespace openikev2 {

    /**
        This class implements a Cipher, using the OpenSSL library.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class CipherOpenSSL : public Cipher {

            /****************************** ATTRIBUTES ******************************/
        protected:
            EVP_CIPHER_CTX ctx;             /**< OpenSSL context used in crypto operations */
            EVP_CIPHER *encr_evp;           /**< OpenSSL representation of the crypto algorithm */
            EVP_MD *integ_evp;              /**< OpenSSL representation of the HMAC algorithm */
        public:
            auto_ptr<ByteArray> encr_key;   /**< Key used to crypt and decrypt */
            auto_ptr<ByteArray> integ_key;  /**< Key used to compute HMAC of messages */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new CipherOpenSSL, setting the indicated parameters.
             * @param proposal Proposal containing the ENCR and INTEG transforms
             * @param encr_key Encryption key
             * @param integ_key Integrity key
             */
            CipherOpenSSL( Enums::ENCR_ID encr_algo, Enums::INTEG_ID integ_algo, auto_ptr<ByteArray> encr_key, auto_ptr<ByteArray> integ_key );

            virtual auto_ptr<ByteArray> encrypt( ByteArray& plain_text, ByteArray& initialization_vector );

            virtual auto_ptr<ByteArray> decrypt( ByteArray& cipher_text, ByteArray& initialization_vector );

            virtual auto_ptr<ByteArray> computeIntegrity( ByteArray& data_buffer );

            virtual auto_ptr<ByteArray> hmac( ByteArray& data_buffer, ByteArray& hmac_key );

            virtual ~CipherOpenSSL();
    };
};
#endif

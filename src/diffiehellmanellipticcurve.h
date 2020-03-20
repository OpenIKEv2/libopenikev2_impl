/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2DIFFIEHELLMANELLIPTICCURVE_H
#define OPENIKEV2DIFFIEHELLMANELLIPTICCURVE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_OPENSSL_ECDH_H

#include <libopenikev2/diffiehellman.h>
#include <openssl/ecdh.h>

namespace openikev2 {
    /**
      This class implements the DiffieHellman abstract class for EC groups using OpenSSL library.
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class DiffieHellmanEllipticCurve : public DiffieHellman {
            /****************************** ATTRIBUTES ******************************/
        protected:
            BN_CTX* bn_ctx;                     /**< BIGNUM context */
            EC_KEY* ec_key;                     /**< Private key */
            auto_ptr<ByteArray> shared_secret;  /**< Shared secret */
            auto_ptr<ByteArray> public_key;     /**< Public key */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a DiffieHellmanEllipticCurve object, using the indicated group id.
             * @param group_id Group id for the DiffieHellmanEllipticCurve object
             */
            DiffieHellmanEllipticCurve( Enums::DH_ID group_id );

            virtual ByteArray& getPublicKey() const;

            virtual void generateSharedSecret( const ByteArray& peer_public_key ) ;

            virtual ByteArray& getSharedSecret() const;

            virtual ~DiffieHellmanEllipticCurve();
    };
}

#endif

#endif

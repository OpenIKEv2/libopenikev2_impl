/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
 *   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
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
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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

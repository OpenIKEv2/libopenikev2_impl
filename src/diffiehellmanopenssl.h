/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef DIFFIEHELLMAN_OPENSSL_H
#define DIFFIEHELLMAN_OPENSSL_H

#include <libopenikev2/diffiehellman.h>
#include <openssl/dh.h>

namespace openikev2 {

    /**
        This class implements the DiffieHellman abstract class for MODP groups using OpenSSL library.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class DiffieHellmanOpenSSL : public DiffieHellman {

            /****************************** ATTRIBUTES ******************************/
        protected:
            DH *dh;                             /**< OpenSSL Diffie-Hellman context*/
            uint32_t dh_key_size;               /**< Size of the keys of this group */
            auto_ptr<ByteArray> shared_secret;  /**< Shared secret */
            auto_ptr<ByteArray> public_key;     /**< Public key */

        public:
            /**
             * Creates a DiffieHellmanOpenSSL object, using the indicated group id.
             * @param group_id Group id for the DiffieHellman object
             */
            DiffieHellmanOpenSSL( Enums::DH_ID group_id );

            virtual ByteArray& getPublicKey() const;

            virtual void generateSharedSecret( const ByteArray& peer_public_key ) ;

            virtual ByteArray& getSharedSecret() const;

            virtual ~DiffieHellmanOpenSSL();
    };
}
#endif

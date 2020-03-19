/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef KEYRING_OPENSSL_H
#define KEYRING_OPENSSL_H

#include <libopenikev2/keyring.h>
#include <openssl/hmac.h>
#include <libopenikev2/proposal.h>

namespace openikev2 {

    /**
        This class implements KeyRing interface using OpenSSL to generate keys.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class KeyRingOpenSSL : public KeyRing {

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new KeyRing with indicated parameters.
             * @param proposal Proposal containing selected protocols and transform to be used.
             * @param prf_transform PRF to be used. If NULL, use the contained in the proposal instead
             */
            KeyRingOpenSSL( const Proposal &proposal, const PseudoRandomFunction& prf );

            virtual ~KeyRingOpenSSL();
    };
};
#endif

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
#ifndef KEYRING_OPENSSL_H
#define KEYRING_OPENSSL_H

#include <libopenikev2/keyring.h>
#include <openssl/hmac.h>
#include <libopenikev2/proposal.h>

namespace openikev2 {

    /**
        This class implements KeyRing interface using OpenSSL to generate keys.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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

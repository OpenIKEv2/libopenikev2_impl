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
#ifndef AUTHGENERATORAUTHGENERATORPSK_H
#define AUTHGENERATORAUTHGENERATORPSK_H

#include "authgenerator.h"

namespace openikev2 {

    /**
     Implementation of AuthGenerator using the standard PSK authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class AuthGeneratorPsk : public AuthGenerator {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<ByteArray> psk;                        /**< Pre-shared key */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AuthGeneratorPsk with the indicated pre-shared key
             * @param psk Binary Pre-shared key
             */
            AuthGeneratorPsk( auto_ptr<ByteArray> psk );
            
            /**
             * Creates a new AuthGeneratorPsk with the indicated pre-shared key
             * @param psk Textual pre-shared key
             */
            AuthGeneratorPsk( string psk );

            virtual AutoVector<Payload_CERT> generateCertificatePayloads( const IkeSa& ike_sa, const vector<Payload_CERT_REQ*> payload_cert_req_r );
            virtual auto_ptr<Payload_AUTH> generateAuthPayload( const IkeSa& ike_sa );
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthGenerator> clone() const;

            virtual ~AuthGeneratorPsk();

    };

}

#endif

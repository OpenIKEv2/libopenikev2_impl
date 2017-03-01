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
#ifndef OPENIKEV2AUTHVERIFIERPSK_H
#define OPENIKEV2AUTHVERIFIERPSK_H

#include "authverifier.h"

namespace openikev2 {

    /**
     Implementation of AuthVerifier using the standard PSK authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class AuthVerifierPsk : public AuthVerifier {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<ByteArray> psk;                                /**< Pre-shared key */

             /****************************** METHODS ******************************/
       public:
            /**
             * Creates a new AuthVerifierPsk setting its pre-shared key
             * @param psk Binary pre-shared key
             */
            AuthVerifierPsk( auto_ptr<ByteArray> psk );
            
            /**
             * Creates a new AuthVerifierPsk setting its pre-shared key
             * @param psk Textual pre-shared key
             */
            AuthVerifierPsk( string psk );
            
            virtual AutoVector<Payload_CERT_REQ> generateCertificateRequestPayloads( const IkeSa& ike_sa );
            virtual bool verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa );
            virtual vector<Enums::AUTH_METHOD> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthVerifier> clone() const;
            virtual ~AuthVerifierPsk();

    };

}

#endif

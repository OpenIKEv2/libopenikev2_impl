/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHVERIFIERPSK_H
#define OPENIKEV2AUTHVERIFIERPSK_H

#include "authverifier.h"

namespace openikev2 {

    /**
     Implementation of AuthVerifier using the standard PSK authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
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

/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef AUTHGENERATORAUTHGENERATORPSK_H
#define AUTHGENERATORAUTHGENERATORPSK_H

#include "authgenerator.h"

namespace openikev2 {

    /**
     Implementation of AuthGenerator using the standard PSK authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
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

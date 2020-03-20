/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHGENERATORBTNS_H
#define OPENIKEV2AUTHGENERATORBTNS_H

#include "authgenerator.h"

namespace openikev2 {

    /**
     Implementation of AuthGenerator using the BTNS authentication method. This method actually don't perform authentication
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AuthGeneratorBtns : public AuthGenerator {
            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AuthGeneratorBtns
             */
            AuthGeneratorBtns( );

            virtual AutoVector<Payload_CERT> generateCertificatePayloads( const IkeSa& ike_sa, const vector<Payload_CERT_REQ*> payload_cert_req_r );
            virtual auto_ptr<Payload_AUTH> generateAuthPayload( const IkeSa& ike_sa );
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthGenerator> clone() const;

            virtual ~AuthGeneratorBtns();
    };
}

#endif

/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHVERIFIERBTNS_H
#define OPENIKEV2AUTHVERIFIERBTNS_H

#include "authverifier.h"

namespace openikev2 {

    /**
     Implementation of AuthVerifier using the BTNS authentication method. This method actually don't perform authentication.
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AuthVerifierBtns : public AuthVerifier{
            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AuthVerifierBtns
             * @return
             */
            AuthVerifierBtns( );

            virtual AutoVector<Payload_CERT_REQ> generateCertificateRequestPayloads( const IkeSa& ike_sa );
            virtual bool verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa );
            virtual vector<Enums::AUTH_METHOD> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthVerifier> clone() const;
            virtual ~AuthVerifierBtns();

    };

}

#endif

/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHVERIFIER_H
#define OPENIKEV2AUTHVERIFIER_H

#include <libopenikev2/printable.h>
#include <libopenikev2/ikesa.h>

namespace openikev2 {

    /**
     This abstract class represents an AUTH verifier, that performs the AUTH payload verification tasks
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AuthVerifier : public Printable {
            /****************************** METHODS ******************************/
        public:
            /**
             * Generates the Certificate Request payloads indicate to the peer the preferred CAs
             * @param ike_sa IkeSa
             * @return The Certificate Request payload collection
             */
            virtual AutoVector<Payload_CERT_REQ> generateCertificateRequestPayloads( const IkeSa& ike_sa ) = 0;

            /**
             * Verifies the AUTH payload included in the AUTH message
             * @param received_message Received AUTH message to be verified
             * @param ike_sa IkeSa
             * @return TRUE if the AUTH payload can be verified. FALSE otherwise
             */
            virtual bool verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa ) = 0;

            /**
             * Gets the supported auth methods
             * @return Supported AUTH methods
             */
            virtual vector<Enums::AUTH_METHOD> getSupportedMethods( ) const = 0;

            /**
             * Clones this AuthVerifier
             * @return A new cloned AuthVerifier
             */
            virtual auto_ptr<AuthVerifier> clone() const = 0;

            virtual string toStringTab( uint8_t tabs ) const = 0;

            virtual ~AuthVerifier();
    };

}

#endif

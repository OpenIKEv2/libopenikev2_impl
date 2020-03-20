/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHGENERATOR_H
#define OPENIKEV2AUTHGENERATOR_H

#include <libopenikev2/printable.h>
#include <libopenikev2/ikesa.h>

namespace openikev2 {

    /**
     This abstract class represents an AUTH generator, that performs the AUTH payload generation tasks
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AuthGenerator : public Printable {
            /****************************** METHODS ******************************/
        public:
            /**
             * Generates the Certificate Payloads to be included in the IKE_AUTH message
             * @param ike_sa IkeSa
             * @param payload_cert_req_r Received Certificate Request payloads
             * @return The Certificate Payload collection to be included in the IKE_AUTH message
             */
            virtual AutoVector<Payload_CERT> generateCertificatePayloads( const IkeSa& ike_sa, const vector<Payload_CERT_REQ*> payload_cert_req_r ) = 0;

            /**
             * Generate the AUTH payload to be included in the AUTH message
             * @param ike_sa IkeSa
             * @return The new AUTH payload
             */
            virtual auto_ptr<Payload_AUTH> generateAuthPayload( const IkeSa& ike_sa ) = 0;

            /**
            * Clones this AuthGenerator
            * @return A new cloned AuthGenerator
            */
            virtual auto_ptr<AuthGenerator> clone() const = 0;

            virtual string toStringTab( uint8_t tabs ) const = 0;

            virtual ~AuthGenerator();

    };

}

#endif

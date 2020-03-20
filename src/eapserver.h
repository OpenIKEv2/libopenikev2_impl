/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2EAPSERVER_H
#define OPENIKEV2EAPSERVER_H


#include "eapmethod.h"
#include <libopenikev2/payload_eap.h>
#include <libopenikev2/eappacket.h>
#include <libopenikev2/id.h>
#include <vector>

namespace openikev2 {

    /**
     Abstract class that represents an EAP authenticator (server side)
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapServer : public EapMethod {
            /****************************** METHODS ******************************/
        public:
            /**
             * Generates the Initial EAP request message to be included in the IKE_AUTH response
             * @param peer_id Peer ID
             * @return EAP payload to be included in the IKE_AUTH response
             */
            virtual auto_ptr<Payload_EAP> generateInitialEapRequest( const ID& peer_id ) = 0;

            /**
             * Processes the EAP response and generates the next EAP request, EAP success or EAP failure message
             * @param eap_response Received EAP response
             * @return EAP request, succes or failure message to be sent
             */
            virtual auto_ptr<Payload_EAP> processEapResponse( const Payload_EAP& eap_response ) = 0;


            virtual void processFinish();

            /**
             * Gets the supported EAP methods
             * @return Supported EAP methods
             */
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const = 0;

            /**
             * Clones this EapServer
             * @return A new cloned EapServer
             */
            virtual auto_ptr<EapServer> clone() const = 0;

            virtual string toStringTab( uint8_t tabs ) const = 0;

            virtual ~EapServer();
    };

}

#endif

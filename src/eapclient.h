/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#ifndef OPENIKEV2EAPCLIENT_H
#define OPENIKEV2EAPCLIENT_H

#include "eapmethod.h"
#include <libopenikev2/payload_eap.h>
#include <vector>

namespace openikev2 {

    /**
     Abstract class that represents an EAP authenticator (client side)
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapClient : public EapMethod {
            /****************************** METHODS ******************************/
        public:
            /**
             * Processes an EAP request and generates the adecuated response (iniiator only)
             * @param eap_request The received EAP request
             * @return The adecuated response. NULL if an error is found.
             */
            virtual auto_ptr<Payload_EAP> processEapRequest( const Payload_EAP& eap_request ) = 0;

            /**
             * Processes an EAP success (initiator only)
             * @param eap_success The received EAP success
             * @return The adecuated response. NULL if an error is found.
             */
            virtual void processEapSuccess( const Payload_EAP& eap_success ) = 0;

            /**
             * Clones this EapClient
             * @return A new cloned EapClient
             */
            virtual auto_ptr<EapClient> clone() const = 0;

            /**
             * Gets the supported EAP methods
             * @return Supported EAP methods
             */
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const = 0;

            virtual string toStringTab( uint8_t tabs ) const = 0;

            virtual ~EapClient();
    };

}

#endif

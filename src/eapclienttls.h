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

#ifndef OPENIKEV2EAPCLIENTTLS_H
#define OPENIKEV2EAPCLIENTTLS_H

#include "eapclient.h"

namespace openikev2 {
    class EapSm;

    /**
     Implementation of EapClient for the EAP-TLS method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapClientTls : public EapClient {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<EapSm> eap_sm;                 /**< EAP State Machine */
            string ca_certificate;                  /**< Path to the CA certificate */
            string client_certificate;              /**< Path to the client certificate */
            string client_private_key;              /**< Path to the client private key */
            string client_private_key_password;     /**< Password of the client private key */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new EapClientTls object
             * @param ca_certificate Path to the CA certificate
             * @param client_certificate Path to the client certificate
             * @param client_private_key Path to the client private key
             * @param client_private_key_password Password of the client private key
             */
            EapClientTls( string ca_certificate, string client_certificate, string client_private_key, string client_private_key_password );

            virtual auto_ptr<Payload_EAP> processEapRequest( const Payload_EAP& eap_request );
            virtual void processEapSuccess( const Payload_EAP & eap_success );
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<EapClient> clone() const;

            virtual ~EapClientTls();
    };
}

#endif

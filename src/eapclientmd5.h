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
#ifndef OPENIKEV2EAPCLIENTMD5_H
#define OPENIKEV2EAPCLIENTMD5_H

#include "eapclient.h"

namespace openikev2 {
    class EapSm;

    /**
     Implementation of EapClient for the EAP MD5-Challenge method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class EapClientMd5 : public EapClient {
            /****************************** ATTRIBUTES ******************************/
        protected:
            string client_password;                 /**< Client password */
            auto_ptr<EapSm> eap_sm;                 /**< EAP State Machine */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new EapClientMd5
             * @param client_password Client password
             */
            EapClientMd5( string client_password );

            virtual auto_ptr< Payload_EAP > processEapRequest( const Payload_EAP & eap_request );
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual void processEapSuccess( const Payload_EAP& eap_success );
            virtual auto_ptr<EapClient> clone() const;
            virtual ~EapClientMd5();

    };

}

#endif

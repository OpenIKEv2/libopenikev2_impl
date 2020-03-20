/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2EAPCLIENTMD5_H
#define OPENIKEV2EAPCLIENTMD5_H

#include "eapclient.h"

namespace openikev2 {
    class EapSm;

    /**
     Implementation of EapClient for the EAP MD5-Challenge method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
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

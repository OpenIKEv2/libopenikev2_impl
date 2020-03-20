/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2EAPCLIENTFRM_H
#define OPENIKEV2EAPCLIENTFRM_H

#include "eapclient.h"


namespace openikev2 {
    class EapSm;

    /**
     Implementation of EapClient for the EAP FRM method
     @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class EapClientFrm : public EapClient {
            /****************************** ATTRIBUTES ******************************/
        protected:
            string client_data;                 /**< Client password */
            auto_ptr<EapSm> eap_sm;             /**< EAP State Machine */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new EapClientFrm
             * @param client_data Client data
             */
            EapClientFrm( string client_data );

            virtual auto_ptr<Payload_EAP> processEapRequest( const Payload_EAP& eap_request );
            virtual void processEapSuccess( const Payload_EAP& eap_success );
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<EapClient> clone() const;

            virtual ~EapClientFrm();

    };

}

#endif

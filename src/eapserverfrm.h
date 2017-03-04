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
#ifndef OPENIKEV2EAPSERVERFRM_H
#define OPENIKEV2EAPSERVERFRM_H


#include "eapserver.h"

#include <map>

namespace openikev2 {
    class EapSm;
    /**
     This class implements the EapServer abstract class, using the method FRM
     @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class EapServerFrm : public EapServer {
            /****************************** ATTRIBUTES ******************************/
        protected:

            auto_ptr<ByteArray> challenge;
	        auto_ptr<EapSm> eap_sm;             /**< EAP State Machine */
	        string peer_id;
            string aaa_server_addr, aaa_server_secret;
            uint16_t aaa_server_port;

            /****************************** METHODS ******************************/
        protected:

            /**
             * Loads the user/password information from "filename"
             * @param filename File name where user/password information is stored.
             */
            //virtual void readMapFile( string filename );

            /**
             * Reads a line of the user/password file
             * @param line Line wth the user/password information
             */
            //virtual void readLine( string line );

        public:
            /**
             * Creates a new EapServerFrm
             * @param server_data Server data
             */
            EapServerFrm ( string aaa_server_addr, uint16_t aaa_server_port, string aaa_server_secret);

            virtual auto_ptr<Payload_EAP> generateInitialEapRequest( const ID& peer_id  );
            virtual auto_ptr<Payload_EAP> processEapResponse( const Payload_EAP& eap_response );
            virtual void processFinish();
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<EapServer> clone() const;
            virtual ~EapServerFrm();

    };

}

#endif

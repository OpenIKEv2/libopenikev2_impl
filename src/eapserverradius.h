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
#ifndef OPENIKEV2EAPSERVERRADIUS_H
#define OPENIKEV2EAPSERVERRADIUS_H

#include "radiusmessage.h"
#include "udpsocket.h"
#include "eapserver.h"


#include <libopenikev2/payload_eap.h>
#include <libopenikev2/eappacket.h>
#include <libopenikev2/id.h>
#include <libopenikev2/socketaddress.h>

namespace openikev2 {

    /**
        This class implements the EapServer abstract class, acting as an EAP authentication (pass-through) between the client and a RADIUS server
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class EapServerRadius : public EapServer {
        protected:
            auto_ptr<RadiusAttribute> server_state;
            auto_ptr<UdpSocket> socket;
            auto_ptr<SocketAddress> server_socket_address;
            auto_ptr<ByteArray> secret;
            uint8_t seq_number;
            auto_ptr<ByteArray> username;

        protected:
            virtual void sendRadiusMessage( RadiusMessage& radius_message );
            virtual auto_ptr<RadiusMessage> receiveRadiusMessage(const ByteArray& request_message_authenticator );
            virtual void getMsk(RadiusMessage& radius_message, RadiusMessage & access_request_message);
            virtual auto_ptr<ByteArray> decryptKey(const ByteArray& key_attr, const ByteArray & authenticator);
            
            EapServerRadius( const EapServerRadius& other );

        public:
            EapServerRadius( string server_address, uint16_t server_port, string secret );
            virtual auto_ptr<Payload_EAP> generateInitialEapRequest( const ID& peer_id );
            virtual auto_ptr<Payload_EAP> processEapResponse( const Payload_EAP& eap_response );
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual auto_ptr<EapServer> clone() const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual ~EapServerRadius();

    };

}

#endif

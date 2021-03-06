/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef AAACONTROLLERIMPLOPENIKE_H
#define AAACONTROLLERIMPLOPENIKE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/mutex.h>
#include <libopenikev2/autovector.h>
#include <libopenikev2/eappacket.h>
#include <libopenikev2/aaasender.h>
#include <libopenikev2/aaacontrollerimpl.h>
#include "threadposix.h"
#include "radiusmessage.h"
#include "udpsocket.h"
#include "aaasenderradius.h"
#include <libopenikev2/bytearray.h>

#include <libopenikev2/payload_eap.h>
#include <libopenikev2/id.h>
#include <libopenikev2/socketaddress.h>

#include <map>

using namespace std;

namespace openikev2 {

    /**
        This class contains the AAAController implementation using RADIUS protocol
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AAAControllerImplRadius : public AAAControllerImpl, public ThreadPosix {
            /****************************** ATTRIBUTES ******************************/
        protected:
            map<uint8_t, AAASenderRadius*> senders_map;

            auto_ptr<UdpSocket> socket;
            //auto_ptr<SocketAddress> server_socket_address;
            //auto_ptr<ByteArray> secret;
            uint8_t seq_number;
            //auto_ptr<ByteArray> username;
            uint16_t listen_port;

            auto_ptr<Mutex> mutex_senders_map; /**< Mutex to protect acceses to the senders map */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AAAController implementation for Radius server.
             */
            AAAControllerImplRadius( );


            /**
             * Sends a AAA message to the AAA server using the proper protocol.
             * @param eap_msg Eap message to be sent
             * @param sender Sender that waits for a AAA response.
             */
            virtual void AAA_send( AAASender& eap_sender );

            virtual void AAA_send( AAASenderRadius& sender );



            void sendRadiusMessage( auto_ptr<RadiusMessage> radius_message, AAASenderRadius& eap_sender );
            auto_ptr< ByteArray > getMsk( RadiusMessage & radius_message, RadiusMessage & access_request_message, const ByteArray& secret ) ;
            auto_ptr< ByteArray > decryptKey( const ByteArray & key_attr, const ByteArray & authenticator, const ByteArray& secret ) ;
            auto_ptr<RadiusMessage> receiveRadiusMessage( ) ;

            void receiveEapMessage( ) ;

            /**
             * Performs main thread funcionality (waiting for Radius responses)
             */
            virtual void run();

            virtual ~AAAControllerImplRadius();
    };

}

#endif

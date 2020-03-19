/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef AAASENDERRADIUS_H
#define AAASENDERRADIUS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/eappacket.h>


#include <libopenikev2/bytearray.h>
#include <libopenikev2/semaphore.h>
#include <libopenikev2/aaasender.h>
#include "radiusmessage.h"


namespace openikev2 {

    /**
        This abstract class represents objects that want to receive AAA responses.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class AAASenderRadius : public AAASender {
        /****************************** ATTRIBUTES ******************************/
        public:
            auto_ptr<RadiusMessage> aaa_radius_request;
            auto_ptr<RadiusMessage> aaa_radius_response;

            /**
             * This method is called when AAA controller receives the response.
             */
            virtual void AAA_receive( auto_ptr<EapPacket> eap_packet ) = 0;

            virtual ~AAASenderRadius();
    };
}
#endif

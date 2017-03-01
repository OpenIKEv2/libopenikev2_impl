/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
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
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alejandro_perez@dif.um.es>
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
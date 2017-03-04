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
#include "ikesaexecuter.h"

#include <libopenikev2/ikesa.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/log.h>

namespace openikev2 {
    IkeSaExecuter::IkeSaExecuter( IkeSaControllerImplOpenIKE& ike_sa_controller, uint16_t id ) :
            ike_sa_controller ( ike_sa_controller ) {
        this->id = id;
    }

    IkeSaExecuter::~IkeSaExecuter( ) {}

    void IkeSaExecuter::run( ) {
        // Do forever
        while ( true ) {
            // Get the next waiting IkeSa
            IkeSa & ike_sa = ike_sa_controller.getScheduledIkeSa();
            Log::writeLockedMessage( "IkeSaExecuter[" + intToString ( this->id ) + "]", "Assigned to an IKE_SA=" + Printable::toHexString( &ike_sa.my_spi, 8 ), Log::LOG_THRD, true );

            // Execute the next Command on the IkeSa
            IkeSa::IKE_SA_ACTION action = ike_sa.processCommand();
            bool exit = ( action == IkeSa::IKE_SA_ACTION_DELETE_IKE_SA ) ? true : false;
            ike_sa_controller.checkIkeSa( ike_sa, exit );
        }
    }
}

/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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

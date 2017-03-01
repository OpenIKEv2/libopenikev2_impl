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
#include "ipseccontrollerimplopenike.h"

#include <libopenikev2/sendrekeychildsareqcommand.h>
#include <libopenikev2/senddeletechildsareqcommand.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/log.h>

namespace openikev2 {

    IpsecControllerImplOpenIKE::IpsecControllerImplOpenIKE() {
    }


    IpsecControllerImplOpenIKE::~IpsecControllerImplOpenIKE() {
    }

    void IpsecControllerImplOpenIKE::processExpire( const IpAddress & src, const IpAddress & dst, uint32_t rekeyed_spi, bool hard ) {
        auto_ptr<Command> command;
        ByteBuffer spi ( 4 );
        spi.writeInt32( rekeyed_spi );

        // If it is a soft expiration
        if ( !hard ) {
            Log::writeLockedMessage( "IpsecController", "Recv SOFT expiration: Child SA SPI=" + spi.toString(), Log::LOG_IPSC, true );
            command.reset( new SendRekeyChildSaReqCommand( rekeyed_spi ) );
        }
        else if ( hard ) {
            Log::writeLockedMessage( "IpsecController", "Recv HARD expiration: Child SA SPI=" + spi.toString(), Log::LOG_IPSC, true );
            command.reset ( new SendDeleteChildSaReqCommand( rekeyed_spi ) );
        }

        bool exist_ike_sa = IkeSaController::pushCommandByChildSaSpi( rekeyed_spi, command, false );

        // If ike_sa was not found
        if ( !exist_ike_sa ) {
            Log::writeLockedMessage( "IpsecController", "Does not exist any IKE_SA with controlling such SPI", Log::LOG_WARN, true );
        }
    }

}


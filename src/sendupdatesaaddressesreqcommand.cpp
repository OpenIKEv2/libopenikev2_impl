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
#include "sendupdatesaaddressesreqcommand.h"

#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2/log.h>
#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/eventbus.h>

namespace openikev2 {

    SendUpdateSaAddressesReqCommand::SendUpdateSaAddressesReqCommand( auto_ptr<IpAddress> new_sa_address )
            : Command( true ) {
        this->new_sa_address = new_sa_address;
    }

    SendUpdateSaAddressesReqCommand::~SendUpdateSaAddressesReqCommand() {}

    IkeSa::IKE_SA_ACTION SendUpdateSaAddressesReqCommand::executeCommand( IkeSa & ike_sa ) {
        // Check IKE_SA state
        if ( ike_sa.getState() < IkeSa::STATE_IKE_SA_ESTABLISHED ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "Transition error: event=[Start UPDATE_SA_ADDRESS] state=[" + IkeSa::IKE_SA_STATE_STR( ike_sa.getState() ) + "]", Log::LOG_ERRO, true );
            EventBus::getInstance().sendBusEvent( auto_ptr<BusEvent> ( new BusEventIkeSa( BusEventIkeSa::IKE_SA_FAILED, ike_sa ) ) );
            return IkeSa::IKE_SA_ACTION_DELETE_IKE_SA;
        }
        else if ( ike_sa.getState() > IkeSa::STATE_IKE_SA_ESTABLISHED ) {
            ike_sa.pushDeferredCommand( auto_ptr<Command> ( new SendUpdateSaAddressesReqCommand( this->new_sa_address->clone() ) ) );
            return IkeSa::IKE_SA_ACTION_CONTINUE;
        }

        auto_ptr<IpAddress> old_src_address = ike_sa.my_addr->getIpAddress().clone();
        
        // Update the IPsec SAs
        IpsecController::updateIpsecSaAddresses(*old_src_address, *this->new_sa_address);
        
        // Update the IPsec Policies
        IpsecController::updateIpsecPolicyAddresses(*old_src_address, *this->new_sa_address);
        
        // Update the src address in the IkeSa
        ike_sa.my_addr->setIpAddress( this->new_sa_address->clone() );
        
        // Create the UPDATE_SA_ADDRESSES notification
        auto_ptr<Payload_NOTIFY> notify_request ( new Payload_NOTIFY( ( Payload_NOTIFY::NOTIFY_TYPE ) 16400, Enums::PROTO_NONE ) );

        // Start the Informational exchange
        AutoVector<Payload> payloads;
        payloads->push_back( notify_request.release() );
        return ike_sa.createGenericInformationalRequest( payloads );
    }

    string SendUpdateSaAddressesReqCommand::getCommandName( ) const {
        return "SEND_UPDATE_SA_ADDRESSES_REQ";
    }
}



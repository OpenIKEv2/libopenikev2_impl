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
#include "notifycontroller_update_sa_addresses.h"

#include <libopenikev2/log.h>

#include <libopenikev2/boolattribute.h>

#include <libopenikev2/ipseccontroller.h>

namespace openikev2 {

    NotifyController_UPDATE_SA_ADDRESSES::NotifyController_UPDATE_SA_ADDRESSES()
            : NotifyController() {}

    IkeSa::NOTIFY_ACTION NotifyController_UPDATE_SA_ADDRESSES::processNotify( Payload_NOTIFY & notify, Message & message, IkeSa & ike_sa, ChildSa * child_sa ) {
        assert( notify.notification_type == ( Payload_NOTIFY::NOTIFY_TYPE ) 16400 );

        // Check notify field correction
        if ( notify.protocol_id > Enums::PROTO_IKE || notify.spi_value.get() || notify.notification_data.get() ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "INVALID SYNTAX in UPDATE_SA_ADDRESSES notify", Log::LOG_ERRO, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        if ( message.exchange_type != Message::INFORMATIONAL || message.message_type != Message::REQUEST ) {
            Log::writeMessage( ike_sa.getLogId(), "UPDATE_SA_ADDRESSES notification received in invalid message", Log::LOG_ERRO, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        BoolAttribute * attribute = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<BoolAttribute>( "mobike_enabled" );
        if ( attribute == NULL || !attribute->value ) {
            Log::writeMessage( ike_sa.getLogId(), "MOBIKE is not enabled for this IKE_SA. Omitting exchange", Log::LOG_WARN, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        // Change the address
        Log::writeMessage( ike_sa.getLogId(), "Updating peer address. old_peer_addr=" + ike_sa.peer_addr->toString() + " new_peer_addr=" + message.getSrcAddress().toString(), Log::LOG_INFO, true );

        // Update the src address in the IkeSa
        auto_ptr<IpAddress> old_dst_address = ike_sa.peer_addr->getIpAddress().clone();
        ike_sa.peer_addr = message.getSrcAddress().clone();

        // Update SAs and policies
        IpsecController::updateIpsecSaAddresses( *old_dst_address, message.getSrcAddress().getIpAddress() );
        IpsecController::updateIpsecPolicyAddresses( *old_dst_address, message.getSrcAddress().getIpAddress() );

        return IkeSa::NOTIFY_ACTION_CONTINUE;

    }

    NotifyController_UPDATE_SA_ADDRESSES::~NotifyController_UPDATE_SA_ADDRESSES() {}
}


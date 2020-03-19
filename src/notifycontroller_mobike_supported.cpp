/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "notifycontroller_mobike_supported.h"

#include <libopenikev2/log.h>

#include <libopenikev2/boolattribute.h>


namespace openikev2 {

    NotifyController_MOBIKE_SUPPORTED::NotifyController_MOBIKE_SUPPORTED()
            : NotifyController() {}

    NotifyController_MOBIKE_SUPPORTED::~NotifyController_MOBIKE_SUPPORTED() {}

    IkeSa::NOTIFY_ACTION NotifyController_MOBIKE_SUPPORTED::processNotify( Payload_NOTIFY & notify, Message & message, IkeSa & ike_sa, ChildSa * child_sa ) {
        assert( notify.notification_type == ( Payload_NOTIFY::NOTIFY_TYPE ) 16396 );

        // Check notify field correction
        if ( notify.protocol_id > Enums::PROTO_IKE || notify.spi_value.get() || notify.notification_data.get() ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "INVALID SYNTAX in MOBIKE_SUPPORTED notify. Omitting notify", Log::LOG_ERRO, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        if ( message.exchange_type != Message::IKE_AUTH ) {
            Log::writeMessage( ike_sa.getLogId(), "MOBIKE_SUPPORTED notification received in invalid message. Omitting notify", Log::LOG_ERRO, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        // If message is a request
        if ( message.message_type == Message::REQUEST ) {
            BoolAttribute * attribute = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<BoolAttribute>( "mobike_supported" );
            if ( attribute == NULL || !attribute->value ) {
                Log::writeMessage( ike_sa.getLogId(), "MOBIKE is not allowed", Log::LOG_WARN, true );
                return IkeSa::NOTIFY_ACTION_CONTINUE;
            }

            Log::writeMessage( ike_sa.getLogId(), "MOBIKE is enabled for this IKE_SA", Log::LOG_INFO, true );
            ike_sa.getIkeSaConfiguration().attributemap->addAttribute ( "mobike_enabled", auto_ptr<Attribute> ( new BoolAttribute( true ) ) );

            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        // if message is a response
        else {
            BoolAttribute* attribute = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<BoolAttribute>( "mobike_supported" );
            if ( attribute == NULL || !attribute->value ) {
                Log::writeMessage( ike_sa.getLogId(), "MOBIKE processing is not allowed", Log::LOG_WARN, true );
                return IkeSa::NOTIFY_ACTION_CONTINUE;
            }

            Log::writeMessage( ike_sa.getLogId(), "MOBIKE is enabled for this IKE_SA", Log::LOG_INFO, true );
            ike_sa.getIkeSaConfiguration().attributemap->addAttribute ( "mobike_enabled", auto_ptr<Attribute> ( new BoolAttribute( true ) ) );

            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        return IkeSa::NOTIFY_ACTION_CONTINUE;
    }

    void NotifyController_MOBIKE_SUPPORTED::addNotify( Message & message, IkeSa & ike_sa, ChildSa * child_sa ) {
        if ( message.exchange_type != Message::IKE_AUTH  )
            return ;

        BoolAttribute* attribute = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<BoolAttribute>( "mobike_supported" );
        if ( attribute == NULL || !attribute->value )
            return ;

        auto_ptr<Payload_NOTIFY> notify ( new Payload_NOTIFY( ( Payload_NOTIFY::NOTIFY_TYPE ) 16396, Enums::PROTO_NONE ) );

        message.addPayloadNotify( notify, true );
    }

}


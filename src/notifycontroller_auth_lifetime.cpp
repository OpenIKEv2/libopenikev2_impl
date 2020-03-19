/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "notifycontroller_auth_lifetime.h"

#include <libopenikev2/log.h>
#include <libopenikev2/int32attribute.h>

#include "ikesareauthenticator.h"

namespace openikev2 {

    NotifyController_AUTH_LIFETIME::NotifyController_AUTH_LIFETIME()
            : NotifyController() {}

    NotifyController_AUTH_LIFETIME::~NotifyController_AUTH_LIFETIME() {}

    IkeSa::NOTIFY_ACTION NotifyController_AUTH_LIFETIME::processNotify( Payload_NOTIFY& notify, Message& message, IkeSa& ike_sa, ChildSa* child_sa ) {
        assert( notify.notification_type == 16403 );

        // If we are original authentication responders, we cannot receive AUTH_LIFETIME
        if ( !ike_sa.is_auth_initiator ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "Original authentication responder cannot receive AUTH_LIFETIME. Do nothing with this notify", Log::LOG_ERRO, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        // If received in a IKE_AUTH response or in an INFORMATIONAL request
        if ( ( message.exchange_type == Message::IKE_AUTH && message.message_type == Message::RESPONSE ) ||
                ( message.exchange_type == Message::INFORMATIONAL && message.message_type == Message::REQUEST ) ) {
            ByteBuffer temp( *notify.notification_data );
            int32_t time = temp.readInt32();

            // deletes the old reauthenticator (if exists)
            ike_sa.attributemap->deleteAttribute( "reauthenticator" );
            ike_sa.attributemap->addAttribute( "reauthenticator", auto_ptr<Attribute> ( new IkeSaReauthenticator( ike_sa.my_spi, time ) ) );

            Log::writeLockedMessage( ike_sa.getLogId(), "Peer desires to force a reauthentication in " + intToString( time ) + " seconds", Log::LOG_WARN, true );
            return IkeSa::NOTIFY_ACTION_CONTINUE;
        }

        return IkeSa::NOTIFY_ACTION_CONTINUE;
    }

    void NotifyController_AUTH_LIFETIME::addNotify( Message& message, IkeSa& ike_sa, ChildSa* child_sa ) {
        if ( message.exchange_type != Message::IKE_AUTH || message.message_type != Message::RESPONSE )
            return ;

        // Get the reauthentication time from the configuration system
        Int32Attribute* attribute = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<Int32Attribute>( "reauth_time" );
        if ( attribute == NULL )
            return ;

        int32_t time = attribute->value;

        // deletes the old reauthenticator (if exists)
        ike_sa.attributemap->deleteAttribute( "reauthenticator" );
        ike_sa.attributemap->addAttribute( "reauthenticator", auto_ptr<Attribute> ( new IkeSaReauthenticator( ike_sa.my_spi, time + 10 ) ) );

        Log::writeLockedMessage( ike_sa.getLogId(), "We desire to force a reauthentication in " + intToString( time + 10 ) + " seconds", Log::LOG_WARN, true );

        auto_ptr<ByteBuffer> temp ( new ByteBuffer( 4 ) );
        temp->writeInt32( time );

        auto_ptr<Payload_NOTIFY> notify ( new Payload_NOTIFY(
                                              ( Payload_NOTIFY::NOTIFY_TYPE ) 16403,
                                              Enums::PROTO_NONE, auto_ptr<ByteArray> ( NULL ),
                                              auto_ptr<ByteArray> ( temp )
                                          )
                                        );
        message.addPayloadNotify( notify, true );
    }
}

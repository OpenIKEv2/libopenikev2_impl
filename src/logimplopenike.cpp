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
#include "logimplopenike.h"

#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/buseventchildsa.h>
#include <libopenikev2/buseventcore.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/ikesa.h>
#include <libopenikev2/exception.h>
#include <stdio.h>

namespace openikev2 {

    LogImplOpenIKE::LogImplOpenIKE( ) {
        this->log_file = stdout;
        this->show_extra_info = true;
        this->log_mask = Log::LOG_INFO | Log::LOG_ERRO;
        setbuf( log_file, NULL );

        // register this for all the event types in the event bus
        EventBus::getInstance().registerBusObserver( *this, BusEvent::IKE_SA_EVENT );
        EventBus::getInstance().registerBusObserver( *this, BusEvent::CHILD_SA_EVENT );
        EventBus::getInstance().registerBusObserver( *this, BusEvent::CORE_EVENT );
    }

    LogImplOpenIKE::~LogImplOpenIKE() {}

    void LogImplOpenIKE::showExtraInfo( bool show_extra_info ) {
        this->show_extra_info = show_extra_info;
    }

    void LogImplOpenIKE::setLogMask( uint16_t log_mask ) {
        this->log_mask = log_mask;
    }

    void LogImplOpenIKE::open( string file_name ) {
        if ( this->log_file != stdout )
            fclose( log_file );

        log_file = fopen( file_name.c_str(), "wt" );
        if ( log_file == NULL ) {
            log_file = stdout;
            throw FileSystemException( "Cannot create log file." );
        }

        setbuf( log_file, NULL );
    }

    void LogImplOpenIKE::close( ) {
        if ( log_file != stdout )
            fclose( log_file );
    }

    void LogImplOpenIKE::notifyBusEvent( const BusEvent& event ) {
        // IKE_SA_EVENT
        if ( event.type == BusEvent::IKE_SA_EVENT ) {
            BusEventIkeSa& busevent = ( BusEventIkeSa& ) event;
            ByteBuffer temp( ByteArray( &busevent.ike_sa.my_spi, 8 ) );
            string fixed_string = " IKE_SA=" + temp.toString() + " PEER_IP=[" + busevent.ike_sa.peer_addr->toString() + "]";

            if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_CREATED )
                Log::writeMessage( "Event Bus", "IKE_SA created" + fixed_string, Log::LOG_EBUS, true );
            else if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_DELETED )
                Log::writeLockedMessage( "EventBus", "IKE_SA deleted" + fixed_string, Log::LOG_EBUS, true );
            else if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_ESTABLISHED )
                Log::writeLockedMessage( "EventBus", "IKE_SA established" + fixed_string, Log::LOG_EBUS, true );
            else if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_REKEYED )
                Log::writeLockedMessage( "EventBus", "IKE_SA rekeyed" + fixed_string + " new_spi=" + Printable::toHexString( ( uint8_t* ) & ( ( IkeSa* ) busevent.data ) ->my_spi, 8 ), Log::LOG_EBUS, true );
            else if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_FAILED )
                Log::writeLockedMessage( "EventBus", "IKE_SA failed" + fixed_string, Log::LOG_EBUS, true );
            else
                Log::writeLockedMessage( "EventBus", "Unknown IKE_SA event" + fixed_string + " event=[" + intToString( busevent.ike_sa_event_type ) + "]", Log::LOG_EBUS, true );
        }
        // CORE_EVENT
        else if ( event.type == BusEvent::CORE_EVENT ) {
            BusEventCore& busevent = ( BusEventCore& ) event;
            if ( busevent.core_event_type == BusEventCore::ALL_SAS_CLOSED )
                Log::writeMessage( "EventBus", "All SAs closed", Log::LOG_EBUS, true );
            else
                Log::writeLockedMessage( "EventBus", "Unknown CORE event=[" + intToString( busevent.core_event_type ) + "]", Log::LOG_EBUS, true );
        }
        // CHILD_SA_EVENT
        else if ( event.type == BusEvent::CHILD_SA_EVENT ) {
            BusEventChildSa& busevent = ( BusEventChildSa& ) event;

            string fixed_string = " IKE_SA=" + Printable::toHexString( &busevent.ike_sa.my_spi, 8 ) + " PEER_IP=[" + busevent.ike_sa.peer_addr->toString() + "] CHILD_SA=" + busevent.child_sa.getId()->toString();

            if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_CREATED )
                Log::writeLockedMessage( "EventBus", "New CHILD_SA" + fixed_string, Log::LOG_EBUS, true );
            else if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_DELETED )
                Log::writeLockedMessage( "EventBus", "Del CHILD_SA" + fixed_string + " Count=[" + intToString( *( ( uint16_t * ) busevent.data ) ) + "]", Log::LOG_EBUS, true );
            else if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_ESTABLISHED )
                Log::writeLockedMessage( "EventBus", "CHILD_SA Established" + fixed_string + " Count=[" + intToString( *( ( uint16_t * ) busevent.data ) ) + "]", Log::LOG_EBUS, true );
            else if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_REKEYED )
                Log::writeLockedMessage( "EventBus", "Rekey CHILD_SA" + fixed_string + " new_child_spi=" + ( ( ChildSa * ) ( busevent.data ) ) ->getId()->toString(), Log::LOG_EBUS, true );
            else if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_FAILED )
                Log::writeLockedMessage( "EventBus", "CHILD_SA Fail SPI=" + fixed_string, Log::LOG_EBUS, true );
            else
                Log::writeLockedMessage( "EventBus", "Unknown CHILD_SA event" + fixed_string + " event=[" + intToString( busevent.child_sa_event_type ) + "]", Log::LOG_EBUS, true );
        }
        else
            Log::writeLockedMessage( "EventBus", "Unknown bus event type=[" + intToString( event.type ) + "]", Log::LOG_EBUS, true );
    }
}


/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "ikesareauthenticator.h"
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/ikesa.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/senddeleteikesareqcommand.h>

namespace openikev2 {

    IkeSaReauthenticator::IkeSaReauthenticator( uint64_t spi, uint32_t timeout ) {
        this->alarm.reset ( new Alarm( *this, timeout * 1000 ) );
        AlarmController::addAlarm( *this->alarm );
        this->alarm->reset();
        this->spi = spi;
        EventBus::getInstance().registerBusObserver( *this, BusEventIkeSa::IKE_SA_EVENT );
    }

    IkeSaReauthenticator::~IkeSaReauthenticator() {
        AlarmController::removeAlarm( *this->alarm );
        EventBus::getInstance().removeBusObserver( *this );
    }

    void IkeSaReauthenticator::notifyAlarm( Alarm & alarm ) {
        IkeSaController::pushCommandByIkeSaSpi( this->spi, auto_ptr<Command> ( new SendDeleteIkeSaReqCommand() ), true );
    }

    void IkeSaReauthenticator::notifyBusEvent( const BusEvent & event ) {
        if ( event.type == BusEvent::IKE_SA_EVENT ) {
            BusEventIkeSa & busevent = ( BusEventIkeSa& ) event;

            if ( busevent.ike_sa.my_spi != this->spi )
                return ;

            if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_REKEYED ) {
                this->spi = ( ( IkeSa* ) busevent.data ) ->my_spi;
            }
        }
    }

    auto_ptr<Attribute> IkeSaReauthenticator::cloneAttribute( ) const {
        // THIS OBJECT CANNOT BE CLONED
        assert( 0 );
    }

    string IkeSaReauthenticator::toStringTab( uint8_t tabs ) const {
        return "<IKE_SA_REAUTHENTICATOR>\n";
    }
}

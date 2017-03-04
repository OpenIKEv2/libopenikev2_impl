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
#include "alarmcontrollerimplopenike.h"
#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/autolock.h>
#include <libopenikev2/log.h>

#include <algorithm>
#include <unistd.h>

namespace openikev2 {

    AlarmControllerImplOpenIKE::AlarmControllerImplOpenIKE( uint32_t msec_interval ) {
        this->msec_interval = msec_interval;
        this->mutex_alarm_collection = ThreadController::getMutex();
    }

    AlarmControllerImplOpenIKE::~AlarmControllerImplOpenIKE() {}

    void AlarmControllerImplOpenIKE::run( ) {
        Log::writeLockedMessage( "AlarmController", "Start: Thread ID=[" + intToString( thread_id ) + "]", Log::LOG_THRD, true );

        while ( true ) {
            try {
                // wait for another clock tic
                usleep( msec_interval * 1000 );

                // locks the alarm collection
                AutoLock auto_lock( *this->mutex_alarm_collection );

                // for all the alarms in the collection
                for ( vector<Alarm*>::iterator it = alarm_collection->begin(); it != alarm_collection->end(); it++ ) {
                    Alarm *alarm = *it;

                    // locks the alarm
                    AutoLock auto_lock_alarm( *alarm->mutex );

                    // if the alarm is disabled, then do not process this one
                    if ( !alarm->enabled )
                        continue;

                    // decrement the alarm left time
                    alarm->msec_left -= msec_interval;

                    // If the alarm is enabled has reach timeout then and is enabled then notify the alarm
                    //auto_lock.release(); this is rubbish but not sure
                    if ( alarm->msec_left <= 0 ) {
                        alarm->enabled = false;
                        alarm->notifyAlarmable();
                    }
                }
            }
            catch ( exception & ex ) {
                Log::writeLockedMessage( "AlarmController", ex.what() , Log::LOG_ERRO, true );
            }
        }
    }

    void AlarmControllerImplOpenIKE::addAlarm( Alarm& alarm ) {
        AutoLock auto_lock( *this->mutex_alarm_collection );

        // Inserts the new alarm in the collection
        this->alarm_collection->push_back( &alarm );

        Alarm* alarm_ptr = &alarm;
        Log::writeLockedMessage( "AlarmController", "Register alarm: Alarm Id=" + Printable::toHexString( &alarm_ptr , 4 ) + " Total Alarms=[" + intToString( this->alarm_collection->size() ) + "]", Log::LOG_ALRM, true );
    }

    void AlarmControllerImplOpenIKE::removeAlarm( Alarm& alarm ) {
        AutoLock auto_lock( *this->mutex_alarm_collection );

        // Finds the alarm in the collection
        vector<Alarm*>::iterator it = find ( this->alarm_collection->begin(), this->alarm_collection->end(), &alarm );
        if ( it == this->alarm_collection->end() ) {
            Alarm * alarm_ptr = &alarm;
            Log::writeLockedMessage( "AlarmController", "Alarm doesn't exist: Alarm Id=[" + Printable::toHexString( &alarm_ptr, 4 ) + "] Total Alarms=[" + intToString( this->alarm_collection->size() ) + "]", Log::LOG_WARN, true );
            return ;
        }

        // Removes the alarm from the collection
        this->alarm_collection->erase( it );

        Alarm* alarm_ptr = &alarm;
        Log::writeLockedMessage( "AlarmController", "Remove alarm: Alarm Id=[" + Printable::toHexString( &alarm_ptr, 4 ) + "] Total Alarms=[" + intToString( alarm_collection->size() ) + "]", Log::LOG_ALRM, true );
    }
}

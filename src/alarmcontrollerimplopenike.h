/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef ALARMCONTROLLERIMPLOPENIKE_H
#define ALARMCONTROLLERIMPLOPENIKE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/autovector.h>
#include <libopenikev2/alarmcontrollerimpl.h>
#include "threadposix.h"

using namespace std;

namespace openikev2 {

    /**
        This class contains the AlarmController implementation.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AlarmControllerImplOpenIKE : public AlarmControllerImpl, public ThreadPosix {
            /****************************** ATTRIBUTES ******************************/
        protected:
            AutoVector<Alarm> alarm_collection;     /**< Alarm collection */
            uint32_t msec_interval;                 /**< Interval between "clock tics" in milliseconds */
            auto_ptr<Mutex> mutex_alarm_collection; /**< Mutex to protect acceses to the alarm collection */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AlarmControllerImpl.
             */
            AlarmControllerImplOpenIKE( uint32_t msec_interval );

            /**
             * Adds the Alarm to the Alarm collection
             * @param alarm Alarm to be added
             */
            virtual void addAlarm( Alarm& alarm );

            /**
             * Removes the Alarm from the Alarm collection
             * @param alarm Alarm to be removed
             */
            virtual void removeAlarm( Alarm& alarm );

            /**
             * Performs main thread funcionality
             */
            virtual void run();

            virtual ~AlarmControllerImplOpenIKE();
    };

}

#endif

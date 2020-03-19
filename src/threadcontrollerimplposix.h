/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef THREADCONTROLLERIMPL_POSIX_H
#define THREADCONTROLLERIMPL_POSIX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/threadcontrollerimpl.h>

#include "threadposix.h"
#include "conditionposix.h"
#include "mutexposix.h"
#include "semaphoreposix.h"

namespace openikev2 {

    /**
        This class represents a ThreadController concrete implementation using POSIX threads
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class ThreadControllerImplPosix : public ThreadControllerImpl {
            /****************************** ATTRIBUTES ******************************/
        protected:
            static uint64_t current_spi;

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new ThreadControllerImpl using the POSIX implemetation
             */
            ThreadControllerImplPosix();

            virtual auto_ptr<Condition> getCondition();

            virtual auto_ptr<Mutex> getMutex();

            virtual auto_ptr<Semaphore> getSemaphore( uint32_t initial_value );

            virtual uint64_t nextSpi();

            virtual ~ThreadControllerImplPosix();
    };
};
#endif

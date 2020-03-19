/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef SEMAPHORE_POSIX_H
#define SEMAPHORE_POSIX_H
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/semaphore.h>
#include <stdint.h>
#include <semaphore.h>

namespace openikev2 {

    /**
        This class implementes the Semaphore interface using libpthread
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class SemaphorePosix : public Semaphore {

            /****************************** ATTRIBUTES ******************************/
        protected:
            sem_t semaphore;        /**< Internal POSIX semaphore */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new Semaphore
             * @param initial_value Initial value
             */
            SemaphorePosix( uint32_t initial_value );

            virtual void wait();

            virtual void post();

            virtual ~SemaphorePosix();
    };
}
#endif

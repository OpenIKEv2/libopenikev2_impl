/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef CONDITION_POSIX_H
#define CONDITION_POSIX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/condition.h>

#include "mutexposix.h"

#include <pthread.h>

namespace openikev2 {

    /**
        This class implements the Condition abstract class using POSIX conditions.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class ConditionPosix : public Condition {

            /****************************** ATTRIBUTES ******************************/
        protected:
            pthread_cond_t condition;   /**< POSIX condition */
            pthread_mutex_t mutex;      /**< POSIX mutex */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new Condition POSIX
             */
            ConditionPosix();

            virtual void wait();

            virtual void notify();

            virtual void acquire();

            virtual void release();

            virtual ~ConditionPosix();
    };
}
#endif

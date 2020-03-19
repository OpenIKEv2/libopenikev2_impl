/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef THREAD_POSIX_H
#define THREAD_POSIX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "mutexposix.h"
#include <pthread.h>
#include <stdint.h>
#include <semaphore.h>

namespace openikev2 {

    /**
        This class represents a POSIX Thread
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class ThreadPosix {
            /****************************** ATTRIBUTES ******************************/
        protected:
            static MutexPosix mutex;                /**< Mutex to protect counter acceses */
            static uint32_t thread_counter;         /**< Thread counter */
            pthread_t pthreadid;

        public:
            uint32_t thread_id;

            /****************************** METHODS ******************************/
        protected:
            /**
             * Method used in the pthread_init() to start the thread
             * @param param In this void param the thread object must be passed
             * @return NULL
             */
            static void *real_run( void *param );

        public:
            /**
             * Creates a new POSIX thread
             */
            ThreadPosix( );

            virtual void run() = 0;

            virtual void start();

            virtual void cancel();

            virtual ~ThreadPosix();
    };
};
#endif

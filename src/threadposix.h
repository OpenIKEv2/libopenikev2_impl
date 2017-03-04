/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
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

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
#include "threadposix.h"

#include <iostream>
#include <cstdlib>
#include <stdint.h>
#include <sstream>

using namespace std;

namespace openikev2 {

    MutexPosix ThreadPosix::mutex;
    uint32_t ThreadPosix::thread_counter = 0;

    ThreadPosix::ThreadPosix( ) {
        ThreadPosix::mutex.acquire();
        this->thread_id = ThreadPosix::thread_counter++;
        ThreadPosix::mutex.release();
    }

    void openikev2::ThreadPosix::start() {
        sched_param schedparam;
        schedparam.sched_priority = 3;
        pthread_attr_t attr;
        pthread_attr_init( &attr );
        pthread_attr_setinheritsched( &attr, PTHREAD_EXPLICIT_SCHED );
        pthread_attr_setschedpolicy( &attr, SCHED_RR );
        pthread_attr_setschedparam( &attr, &schedparam );

        pthread_create( &this->pthreadid, &attr, real_run, this );
    }

    ThreadPosix::~ThreadPosix( ) {
    }

    void ThreadPosix::cancel() {
        pthread_cancel( this->pthreadid );
    }

    void * ThreadPosix::real_run( void * param ) {
        ThreadPosix * thread = ( ThreadPosix* ) param;
        thread->run();
    }

}




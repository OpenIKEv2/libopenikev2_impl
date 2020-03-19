/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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
        return NULL;
    }

}




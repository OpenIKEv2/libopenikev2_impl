/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "threadcontrollerimplposix.h"


namespace openikev2 {

    uint64_t ThreadControllerImplPosix::current_spi = 1;

    ThreadControllerImplPosix::ThreadControllerImplPosix() {}

    ThreadControllerImplPosix::~ThreadControllerImplPosix() {}

    auto_ptr<Condition> ThreadControllerImplPosix::getCondition( ) {
        return auto_ptr<Condition> ( new ConditionPosix() );
    }

    auto_ptr<Mutex> ThreadControllerImplPosix::getMutex( ) {
        return auto_ptr<Mutex> ( new MutexPosix() );
    }

    auto_ptr<Semaphore> ThreadControllerImplPosix::getSemaphore( uint32_t initial_value ) {
        return auto_ptr<Semaphore> ( new SemaphorePosix( initial_value ) );
    }

    uint64_t ThreadControllerImplPosix::nextSpi( ) {
        return current_spi++;
    }

}



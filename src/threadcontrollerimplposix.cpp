/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
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



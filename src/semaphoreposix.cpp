/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "semaphoreposix.h"

namespace openikev2 {
    SemaphorePosix::SemaphorePosix( uint32_t initial_value ) {
        sem_init ( &this->semaphore, 0, initial_value );
    }

    void SemaphorePosix::wait( ) {
        sem_wait( &this->semaphore );
    }

    void SemaphorePosix::post( ) {
        sem_post( &this->semaphore );
    }

    SemaphorePosix::~SemaphorePosix() {
        sem_destroy( &this->semaphore );
    }
}

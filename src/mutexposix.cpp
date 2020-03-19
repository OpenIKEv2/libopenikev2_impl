/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "mutexposix.h"
#include <assert.h>
#include <error.h>

#include <iostream>

namespace openikev2 {

    MutexPosix::MutexPosix( ) {
        pthread_mutex_init( &this->mutex, NULL );
    }

    void MutexPosix::acquire( ) {
        pthread_mutex_lock( &this->mutex );
    }

    void MutexPosix::release( ) {
        pthread_mutex_unlock( &this->mutex );
    }

    MutexPosix::~MutexPosix( ) {
        int rv = pthread_mutex_destroy( &this->mutex );
    }
}


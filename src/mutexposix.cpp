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


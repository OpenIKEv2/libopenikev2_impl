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
#include "conditionposix.h"

#include <iostream>

namespace openikev2 {

    ConditionPosix::ConditionPosix( ) {
        pthread_mutex_init( &this->mutex, NULL );
        pthread_cond_init ( &this->condition, NULL );
    }

    void ConditionPosix::wait( ) {
        pthread_cond_wait( &this->condition, &this->mutex );
    }

    void ConditionPosix::notify( ) {
        pthread_cond_signal( &this->condition );
    }

    void ConditionPosix::acquire( ) {
        pthread_mutex_lock( &this->mutex );
    }

    void ConditionPosix::release( ) {
        pthread_mutex_unlock( &this->mutex );
    }

    ConditionPosix::~ConditionPosix() {
        pthread_mutex_destroy( &this->mutex );
        pthread_cond_destroy ( &this->condition );
    }

}


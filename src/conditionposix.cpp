/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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


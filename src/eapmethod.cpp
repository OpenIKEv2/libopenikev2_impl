/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "eapmethod.h"

namespace openikev2 {

    void EapMethod::setSharedKey( auto_ptr< ByteArray > shared_key ) {
        this->shared_key = shared_key;
    }

    ByteArray * EapMethod::getSharedKey( ) const {
        return this->shared_key.get();
    }

    EapMethod::~EapMethod() {}


}



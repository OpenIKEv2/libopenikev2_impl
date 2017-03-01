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
#include "randomopenssl.h"

#include <openssl/rand.h>

#include <assert.h>

namespace openikev2 {

    RandomOpenSSL::RandomOpenSSL() {}

    RandomOpenSSL::~ RandomOpenSSL( ) {}

    auto_ptr< ByteArray > RandomOpenSSL::getRandomBytes( uint32_t size ) {
        auto_ptr<ByteArray> result ( new ByteArray( size ) );
        RAND_bytes( result->getRawPointer(), size );
        result->setSize(size);
        
        return result;
    }

    uint32_t RandomOpenSSL::getRandomInt32( uint32_t min, uint32_t max ) {
        // ASSERT: min <= max
        assert( min <= max );

        uint32_t result;
        RAND_bytes( ( unsigned char* ) & result, 4 );
        result = result % ( max - min + 1 );
        result = result + min;

        return result;
    }

    uint64_t RandomOpenSSL::getRandomInt64( uint64_t min, uint64_t max ) {
        // ASSERT: min <= max
        assert( min <= max );

        uint64_t result;
        RAND_bytes( ( unsigned char* ) & result, 8 );
        result = result % ( max - min + 1 );
        result = result + min;

        return result;
    }
}




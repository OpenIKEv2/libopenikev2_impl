/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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




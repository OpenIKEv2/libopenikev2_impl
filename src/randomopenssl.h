/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef RANDOM_OPENSSL_H
#define RANDOM_OPENSSL_H

#include <libopenikev2/random.h>

namespace openikev2 {

    /**
        This class implements Random interface using OpenSSL library
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class RandomOpenSSL : public Random {

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new RandomOpenSSL.
             */
            RandomOpenSSL();

            virtual auto_ptr<ByteArray> getRandomBytes( uint32_t size );

            virtual uint32_t getRandomInt32( uint32_t min, uint32_t max );

            virtual uint64_t getRandomInt64( uint64_t min, uint64_t max );

            virtual ~RandomOpenSSL();

    };
};
#endif

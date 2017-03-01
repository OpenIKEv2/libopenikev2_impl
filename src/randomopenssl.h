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
#ifndef RANDOM_OPENSSL_H
#define RANDOM_OPENSSL_H

#include <libopenikev2/random.h>

namespace openikev2 {

    /**
        This class implements Random interface using OpenSSL library
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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

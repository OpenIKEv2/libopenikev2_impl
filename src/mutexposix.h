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
#ifndef MUTEX_POSIX_H
#define MUTEX_POSIX_H

#include <libopenikev2/mutex.h>
#include <pthread.h>

namespace openikev2 {

    /**
    This class implements Mutex interface, using POSIX threads for it.
    @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */

    class MutexPosix : public Mutex {
        protected:
            pthread_mutex_t mutex;      /**< POSIX mutex */
        public:
            /**
             * Creates a new Mutex POSIX
             * @return
             */
            MutexPosix();

            virtual void acquire();

            virtual void release();

            virtual ~MutexPosix();
    };
};
#endif

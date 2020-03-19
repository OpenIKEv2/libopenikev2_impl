/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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

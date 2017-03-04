/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#ifndef SEMAPHORE_POSIX_H
#define SEMAPHORE_POSIX_H
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/semaphore.h>
#include <stdint.h>
#include <semaphore.h>

namespace openikev2 {

    /**
        This class implementes the Semaphore interface using libpthread
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class SemaphorePosix : public Semaphore {

            /****************************** ATTRIBUTES ******************************/
        protected:
            sem_t semaphore;        /**< Internal POSIX semaphore */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new Semaphore
             * @param initial_value Initial value
             */
            SemaphorePosix( uint32_t initial_value );

            virtual void wait();

            virtual void post();

            virtual ~SemaphorePosix();
    };
}
#endif

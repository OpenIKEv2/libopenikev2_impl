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
#ifndef CONDITION_POSIX_H
#define CONDITION_POSIX_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/condition.h>

#include "mutexposix.h"

#include <pthread.h>

namespace openikev2 {

    /**
        This class implements the Condition abstract class using POSIX conditions.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class ConditionPosix : public Condition {

            /****************************** ATTRIBUTES ******************************/
        protected:
            pthread_cond_t condition;   /**< POSIX condition */
            pthread_mutex_t mutex;      /**< POSIX mutex */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new Condition POSIX
             */
            ConditionPosix();

            virtual void wait();

            virtual void notify();

            virtual void acquire();

            virtual void release();

            virtual ~ConditionPosix();
    };
}
#endif

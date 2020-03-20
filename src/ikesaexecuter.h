/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef IKESAEXECUTER_H
#define IKESAEXECUTER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ikesacontrollerimplopenike.h"
#include "threadposix.h"

namespace openikev2 {

    /**
        This class represents an IKE_SA executer.
        This class executes a Command on a IkeSa
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IkeSaExecuter : public ThreadPosix {
        protected:
            IkeSaControllerImplOpenIKE& ike_sa_controller;
            uint16_t id;

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new IkeSaExecuter
             */
            IkeSaExecuter( IkeSaControllerImplOpenIKE& ike_sa_controller, uint16_t id );

            virtual void run();

            virtual ~IkeSaExecuter();
    };
};
#endif

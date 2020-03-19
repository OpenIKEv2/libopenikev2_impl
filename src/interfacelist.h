/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef INTERFACELIST_H
#define INTERFACELIST_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libopenikev2/autovector.h>
#include "ipaddressopenike.h"
#include "socketaddressposix.h"

#include <vector>

using namespace std;


namespace openikev2 {

    /**
        This class represents an interface list.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class InterfaceList {
            /****************************** ATTRIBUTES ******************************/
        public:
            AutoVector<IpAddress> addresses;    /**< Collection of interface IP addresses */
            vector<string> interface_names;     /**< Collection of interface names */
            vector<uint32_t> scopes;
            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new Interface List object.
             */
            InterfaceList();

            virtual ~InterfaceList();

    };
};

#endif

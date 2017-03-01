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
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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

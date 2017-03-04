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
#include "interfacelist.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>

namespace openikev2 {
    InterfaceList::InterfaceList() {
        int rv;
        struct ifaddrs* ifs;
        struct ifaddrs* i;

        rv = getifaddrs ( &ifs );
        if ( rv != 0 )
            return ;

        for ( i = ifs; i != NULL; i = i->ifa_next ) {
            /* Skip if not up or is loopback */
            if ( !( i->ifa_flags & IFF_UP ) || ( i->ifa_flags & IFF_LOOPBACK ) )
                continue;

            /* Skip if no address */
            if ( !i->ifa_addr )
                continue;

            // Case IPv4
            if ( i->ifa_addr->sa_family == AF_INET )
                ;

#ifdef HAVE_IPv6
            // Case IPv6
            else if ( i->ifa_addr->sa_family == AF_INET6 )
                ;
#endif
            else
                continue;


            string if_name = i->ifa_name;
            this->interface_names.push_back( if_name );
            SocketAddressPosix socket_addr ( *i->ifa_addr );
            this->addresses->push_back( socket_addr.getIpAddress().clone().release() );
            this->scopes.push_back ( socket_addr.getScope() );
        }

        freeifaddrs ( ifs );
    }

    InterfaceList::~InterfaceList() {}

}



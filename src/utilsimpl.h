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
#ifndef UTILS_IMPL_H
#define UTILS_IMPL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/trafficselector.h>
#include <libopenikev2/ipaddress.h>

namespace openikev2 {

    class UtilsImpl {
        public:
            /**
             * Gets the network address and prefix length closer to the TrafficSelector specification
             * @param ts Traffic Selector
             * @param prefix This value will be filled with the prefix length
             * @return A new IpAddress representing the network address
             */
            static auto_ptr<IpAddress> trafficSelectorToIpAddress( const TrafficSelector & ts, uint16_t * prefix );

            /**
             * Gets the internal family representation from the UNIX one
             * @param unix_family Unux family representation
             * @return Internal family representation
             */
            static Enums::ADDR_FAMILY getInternalFamily( uint16_t unix_family );

            static string charToString( char *str );

            static string getPaddedString( string base, uint16_t totalsize, bool rightalign, char padchar );

            static uint16_t getUnixFamily( Enums::ADDR_FAMILY family );
    };
}
#endif

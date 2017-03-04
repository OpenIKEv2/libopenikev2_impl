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
#ifndef ADDRESSCONFIGURATION_H
#define ADDRESSCONFIGURATION_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/bytearray.h>
#include <libopenikev2/attribute.h>
#include <libopenikev2/payload_ts.h>
#include <libopenikev2/ipaddress.h>
#include "networkcontrollerimplopenike.h"

namespace openikev2 {

    /**
        This class holds the needed information about address configuration in both, IRAC and IRAS
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AddressConfiguration : public Attribute {
            /****************************** ENUMS ******************************/
        public:
            enum CONFIGURATION_ROLE{
                CONFIGURATION_IRAC,
                CONFIGURATION_IRAS,
            };

            /****************************** ATTRIBUTES ******************************/
        public:
            CONFIGURATION_ROLE role;                                    /**< Indicates if we are IRAC or IRAS */
            auto_ptr<IpAddress> assigned_address;                       /**< Assigned address in the Road Warrior scenario. Used in both IRAC & IRAS.*/
            auto_ptr<ByteArray> assigned_netmask;
            int16_t assigned_prefixlen;                       /**< Assigned netmask in the Road Warrior scenario. Used in both IRAC & IRAS.*/
            auto_ptr<IpAddress> route_dst;
            int16_t route_prefixlen;
            auto_ptr<IpAddress> default_gw;
            //auto_ptr<IpAddress> assigned_default_gw;
            int32_t tun_fd;                                             /**< TUN interface descriptor */
            string ifname;                                              /**< TUN Interface name */
            NetworkControllerImplOpenIKE& network_controller;

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new AddressConfiguration object, indicating its role
             * @param isIRAC TRUE if we are IRAC, FALSE if we are IRAS
             */
            AddressConfiguration( CONFIGURATION_ROLE role, NetworkControllerImplOpenIKE& network_controller );

            virtual auto_ptr<Attribute> cloneAttribute() const ;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~AddressConfiguration();
    };
}
#endif

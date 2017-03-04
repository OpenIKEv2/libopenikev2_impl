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
#include "addressconfiguration.h"

#include "ipaddressopenike.h"

#include <libopenikev2/log.h>
#include <assert.h>

namespace openikev2 {

    AddressConfiguration::AddressConfiguration( CONFIGURATION_ROLE role, NetworkControllerImplOpenIKE& nc )
            : network_controller( nc ) {
        this->role = role;
        int32_t tun_fd = -1;
    }

    AddressConfiguration::~AddressConfiguration() {
        if ( this->role == CONFIGURATION_IRAC ) {
            if (this->assigned_address.get() != NULL) {
	    	Log::writeLockedMessage( "AddressConfiguration", "Deleting address configuration: Rol=[IRAC] Address=[" + this->assigned_address->toString() + "]", Log::LOG_INFO, true );

	    	if ( assigned_address->getFamily() == Enums::ADDR_IPV4 ) {

        	//pedro
        	// Remove assigned address

        		network_controller.deleteAddress( *assigned_address , this->assigned_prefixlen, this->ifname );

                // Remove router rules

                	network_controller.deleteRoute ( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4),0,*default_gw,1,this->ifname);

                	network_controller.deleteRoute ( *route_dst, route_prefixlen, *assigned_address, 0, ifname);
                	//network_controller.deleteRoute ( *route_dst, route_prefixlen, *assigned_default_gw, 0, ifname);

                	network_controller.createRoute ( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4),*IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4), 0, *default_gw, 0 , ifname );
            	}
            	else if ( assigned_address->getFamily() == Enums::ADDR_IPV6 ) {
                	// closes the TUN interface
                	//close( this->tun_fd );

        		network_controller.deleteAddress( *assigned_address , this->assigned_prefixlen, this->ifname );

                // Remove router rules

                	network_controller.deleteRoute ( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6),0,*default_gw,1,this->ifname);

                	network_controller.deleteRoute ( *route_dst, route_prefixlen, *assigned_address, 0, ifname);
                	//network_controller.deleteRoute ( *route_dst, route_prefixlen, *assigned_default_gw, 0, ifname);

                	network_controller.createRoute ( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6),*IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, *default_gw, 0 , ifname );


            	}
	    }
        }
        else if (this->role == CONFIGURATION_IRAS) {
            Log::writeLockedMessage( "AddressConfiguration", "Deleting address configuration: Rol=[IRAS] Address=[" + this->assigned_address->toString() + "]", Log::LOG_INFO, true );
            network_controller.releaseAddress( *assigned_address );
        }
        else
            assert(0);
    }

    auto_ptr<Attribute> AddressConfiguration::cloneAttribute( ) const {
        assert( 0 );
    }

    string AddressConfiguration::toStringTab( uint8_t tabs ) const {
        return "ADDRESS_CONFIGURATION\n";
    }
}




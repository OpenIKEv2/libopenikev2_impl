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
#include "ipaddressopenike.h"

#include <libopenikev2/exception.h>
#include <libopenikev2/threadcontroller.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <ifaddrs.h>
#include <stdlib.h>

namespace openikev2 {

    IpAddressOpenIKE::IpAddressOpenIKE( string address ) {
        memset( &this->address, 0, sizeof( sockaddr_storage ) );

        struct in_addr inaddr;
        // If there is IPv6 support, then it has a different address size
#ifdef HAVE_IPv6
        struct in6_addr in6addr;
#endif
        // Probe if address is an IPv4 number
        if ( inet_pton( AF_INET, ( const char* ) address.c_str(), &inaddr ) > 0 ) {
            struct sockaddr_in * sa = ( sockaddr_in* ) & this->address;
            sa->sin_family = AF_INET;
            sa->sin_addr = inaddr;
            sa->sin_port = 0;
            return ;
        }

        // If address isn't an IPv4 number, if there is IPv6 support we probe if it is an IPv6 number
#ifdef HAVE_IPv6
        else if ( inet_pton( AF_INET6, ( const char* ) address.c_str(), &in6addr ) > 0 ) {
            struct sockaddr_in6 * sa = ( sockaddr_in6* ) & this->address;
            sa->sin6_family = AF_INET6;
            sa->sin6_addr = in6addr;
            sa->sin6_port = 0;
            return ;
        }
#endif

        // temporal buffer to store DNS information
        char buffer[ 2048 ];

        struct hostent hostbuf, *host_entity;
        int herr;

        // try first with IPv4
        int32_t res = gethostbyname2_r( address.c_str(), AF_INET, &hostbuf, buffer, 2048, &host_entity, &herr );
        // if not found
        if ( res ) {

#ifdef HAVE_IPv6
            // if have IPv6, try with it
            res = gethostbyname2_r( address.c_str(), AF_INET6, &hostbuf, buffer, 2048, &host_entity, &herr );
            if ( res )
#endif
                throw NetworkException( "Error resolving hostname <" + address + ">." );
        }

        // if the hostanme is not found, then throw an exception
        if ( host_entity == NULL )
            throw NetworkException( "Hostname <" + address + "> not found." );

        if ( host_entity->h_addrtype == AF_INET ) {
            sockaddr_in * addr4 = ( sockaddr_in* ) & this->address;
            memset( addr4, 0, sizeof( sockaddr_in ) );
            addr4->sin_port = 0;
            addr4->sin_family = AF_INET;
            memcpy( &addr4->sin_addr.s_addr, host_entity->h_addr_list[ 0 ], host_entity->h_length );
        }
#ifdef HAVE_IPv6
        else if ( host_entity->h_addrtype == AF_INET6 ) {
            sockaddr_in6 * addr6 = ( sockaddr_in6* ) & this->address;
            memset( addr6, 0, sizeof( sockaddr_in6 ) );
            addr6->sin6_port = 0;
            addr6->sin6_family = AF_INET6;
            memcpy( &addr6->sin6_addr, host_entity->h_addr_list[ 0 ], host_entity->h_length );
        }
#endif

        else
            throw NetworkException( "Hostname <" + address + "> has an unknown address type: " + intToString( host_entity->h_addrtype ) );
    }

    IpAddressOpenIKE::IpAddressOpenIKE( const IpAddressOpenIKE & other ) {
        memcpy( &this->address, &other.address, sizeof( sockaddr_storage ) );
    }

    IpAddressOpenIKE::IpAddressOpenIKE( Enums::ADDR_FAMILY family, auto_ptr<ByteArray> data ) {
        memset( &this->address, 0, sizeof( sockaddr_storage ) );

        if ( family == Enums::ADDR_IPV4 ) {
            assert( data->size() >= 4 );
            sockaddr_in * addr4 = ( sockaddr_in* ) & this->address;
            memset( addr4, 0, sizeof( sockaddr_in ) );
            addr4->sin_port = 0;
            addr4->sin_family = AF_INET;
            memcpy( &addr4->sin_addr.s_addr, data->getRawPointer(), 4 );
        }
#ifdef HAVE_IPv6
        else if ( family == Enums::ADDR_IPV6 ) {
            assert( data->size() >= 16 );
            sockaddr_in6 * addr6 = ( sockaddr_in6* ) & this->address;
            memset( addr6, 0, sizeof( sockaddr_in6 ) );
            addr6->sin6_port = 0;
            addr6->sin6_family = AF_INET6;
            memcpy( &addr6->sin6_addr.s6_addr, data->getRawPointer(), 16 );
        }
#endif
        else {
            assert( "Unknown address family" && 0 );
        }
    }


    openikev2::IpAddressOpenIKE::IpAddressOpenIKE( Enums::ADDR_FAMILY family ) {
        memset( &this->address, 0, sizeof( sockaddr_storage ) );
        if ( family == Enums::ADDR_IPV4 ) {
            sockaddr_in * addr4 = ( sockaddr_in* ) & this->address;
            addr4->sin_family = AF_INET;
        }
#ifdef HAVE_IPv6
        else if ( family == Enums::ADDR_IPV6 ) {
            sockaddr_in6 * addr6 = ( sockaddr_in6* ) & this->address;
            addr6->sin6_family = AF_INET6;
        }
#endif
        else {
            assert( "Unknown address family" && 0 );
        }
    }

    IpAddressOpenIKE::~IpAddressOpenIKE() {}

    auto_ptr< IpAddress > IpAddressOpenIKE::getAnyAddr( Enums::ADDR_FAMILY family ) {
        if ( family == Enums::ADDR_IPV4 )
            return auto_ptr<IpAddress> ( new IpAddressOpenIKE( "0.0.0.0" ) );
#ifdef HAVE_IPv6
        else if ( family == Enums::ADDR_IPV6 )
            return auto_ptr<IpAddress> ( new IpAddressOpenIKE( "0::0" ) );
#endif
        else
            assert( "Unknown address family" && 0 );
    }


    uint16_t IpAddressOpenIKE::getAddressSize() const {
        if ( this->address.ss_family == AF_INET )
            return 4;
#ifdef HAVE_IPv6
        if ( this->address.ss_family == AF_INET6 )
            return 16;
#endif
        else
            assert( "Unknown address family" && 0 );
    }

    string IpAddressOpenIKE::toStringTab( uint8_t tabs ) const {
        char buffer[ 100 ];
        ostringstream oss;

        // If its an IPv4 address
        if ( address.ss_family == AF_INET ) {
            sockaddr_in * sa = ( sockaddr_in* ) & this->address;
            inet_ntop( sa->sin_family, & sa->sin_addr , buffer, 100 );
            oss << buffer;
        }

#ifdef HAVE_IPv6
        else if ( address.ss_family == AF_INET6 ) {
            sockaddr_in6 * sa = ( sockaddr_in6* ) & this->address;
            inet_ntop( sa->sin6_family, & sa->sin6_addr, buffer, 100 );
            oss << buffer;

            if ( sa->sin6_scope_id != 0 ) {
                if_indextoname( sa->sin6_scope_id, buffer );
                oss << "%" << buffer;
            }
        }
#endif

        return oss.str();
    }

    auto_ptr<IpAddress> IpAddressOpenIKE::clone( ) const {
        return auto_ptr<IpAddress> ( new IpAddressOpenIKE( *this ) );
    }

    Enums::ADDR_FAMILY IpAddressOpenIKE::getFamily( ) const {
        if ( this->address.ss_family == AF_INET )
            return Enums::ADDR_IPV4;
#ifdef HAVE_IPv6
        else if ( this->address.ss_family == AF_INET6 )
            return Enums::ADDR_IPV6;
#endif

        else
            assert( "unknown address family" && 0 );
    }

    auto_ptr<ByteArray> IpAddressOpenIKE::getBytes( ) const {
        if ( this->address.ss_family == AF_INET ) {
            auto_ptr<ByteBuffer> result( new ByteBuffer( 4 ) );
            sockaddr_in* addr4 = ( sockaddr_in* ) & this->address;
            result->writeBuffer( &addr4->sin_addr.s_addr, 4 );
            return auto_ptr<ByteArray> ( result );
        }

#ifdef HAVE_IPv6
        else if ( this->address.ss_family == AF_INET6 ) {
            auto_ptr<ByteBuffer> result( new ByteBuffer( 16 ) );
            sockaddr_in6* addr6 = ( sockaddr_in6* ) & this->address;
            result->writeBuffer( &addr6->sin6_addr.s6_addr, 16 );
            return auto_ptr<ByteArray> ( result );
        }
#endif

        else
            assert( "unknown address" && 0 );
    }

    string IpAddressOpenIKE::getIfaceName() {
	if ( this->address.ss_family == AF_INET ) {

	    // Find out the interface name
            struct ifaddrs *addrs, *iap;
            struct sockaddr_in *sa;
            char wanted[32], current[32];


            sockaddr_in* addr4 = ( sockaddr_in* ) & this->address;
            inet_ntop(address.ss_family, (void *)&(addr4->sin_addr), wanted, sizeof(wanted));

            getifaddrs(&addrs);
            for (iap = addrs; iap != NULL ; iap = iap->ifa_next) {
        	if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET) {
        	    sa = (struct sockaddr_in *)(iap->ifa_addr);
        	    inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin_addr), current, sizeof(current));
        	    if (!strcmp(wanted, current)) {
        	       return string (iap->ifa_name);
        	    }
                }
            }
    	}
#ifdef HAVE_IPv6
        else if ( address.ss_family == AF_INET6 ) {
	    // Find out the interface name
            struct ifaddrs *addrs, *iap;
            struct sockaddr_in6 *sa;
            char wanted[128], current[128];


            sockaddr_in6* addr6 = ( sockaddr_in6* ) & this->address;
            inet_ntop(address.ss_family, (void *)&(addr6->sin6_addr), wanted, sizeof(wanted));

            getifaddrs(&addrs);
            for (iap = addrs; iap != NULL ; iap = iap->ifa_next) {
        	if (iap->ifa_addr && (iap->ifa_flags & IFF_UP) && iap->ifa_addr->sa_family == AF_INET6) {
        	    sa = (struct sockaddr_in6 *)(iap->ifa_addr);
        	    inet_ntop(iap->ifa_addr->sa_family, (void *)&(sa->sin6_addr), current, sizeof(current));
        	    if (!strcmp(wanted, current)) {
        	       return string (iap->ifa_name);
        	    }
                }
            }
	}
#endif
	return "";
    }

}







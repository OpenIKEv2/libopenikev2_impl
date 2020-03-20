/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "socketaddressposix.h"
#include "ipaddressopenike.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>

namespace openikev2 {

    SocketAddressPosix::SocketAddressPosix( auto_ptr< IpAddress > address, uint16_t port ) {
        this->address = address;
        this->port = port;
    }

    SocketAddressPosix::SocketAddressPosix( const SocketAddress & other ) {
        this->address = other.getIpAddress().clone();
        this->port = other.getPort();
    }

    SocketAddressPosix::SocketAddressPosix( const sockaddr & sockaddr ) {
        if ( sockaddr.sa_family == AF_INET ) {
            sockaddr_in& sin_addr4 = ( sockaddr_in& ) sockaddr;
            auto_ptr<ByteArray> addr_data ( new ByteArray( &sin_addr4.sin_addr.s_addr, 4 ) );
            this->address.reset ( new IpAddressOpenIKE( Enums::ADDR_IPV4, addr_data ) );
            this->port = ntohs( sin_addr4.sin_port );
        }
#ifdef HAVE_IPv6
        else if ( sockaddr.sa_family == AF_INET6 ) {
            sockaddr_in6& sin_addr6 = ( sockaddr_in6& ) sockaddr;
            auto_ptr<ByteArray> addr_data ( new ByteArray( &sin_addr6.sin6_addr.s6_addr, 16 ) );
            this->address.reset ( new IpAddressOpenIKE( Enums::ADDR_IPV6, addr_data ) );
            this->port = ntohs( sin_addr6.sin6_port );
	    this->scope = ntohl (sin_addr6.sin6_scope_id);
        }
#endif
        else {
            assert ( 0 && "invalid family" );
        }
    }

    SocketAddressPosix::~SocketAddressPosix() {
    }

    auto_ptr<sockaddr> SocketAddressPosix::getSockAddr() const {
        if ( this->address->getFamily() == Enums::ADDR_IPV4 ) {
            sockaddr_in* sin_addr4 = new sockaddr_in;
            memset( sin_addr4, 0, sizeof( sockaddr_in ) );
            sin_addr4->sin_family = AF_INET;
            sin_addr4->sin_port = htons( this->port );
            memcpy( &sin_addr4->sin_addr.s_addr, this->address->getBytes()->getRawPointer(), 4 );
            return auto_ptr<sockaddr> ( ( sockaddr* ) sin_addr4 );
        }

#ifdef HAVE_IPv6
        else if ( this->address->getFamily() == Enums::ADDR_IPV6 ) {
            sockaddr_in6* sin_addr6 = new sockaddr_in6;
            memset( sin_addr6, 0, sizeof( sockaddr_in6 ) );
            sin_addr6->sin6_family = AF_INET6;
            sin_addr6->sin6_port = htons( this->port );
            memcpy( &sin_addr6->sin6_addr.s6_addr, this->address->getBytes()->getRawPointer(), 16 );
            return auto_ptr<sockaddr> ( ( sockaddr* ) sin_addr6 );
        }
#endif
        else
            assert ( 0 && "invalid family" );

    }

    uint32_t SocketAddressPosix::getSockAddrSize() const {
        if ( this->address->getFamily() == Enums::ADDR_IPV4 )
            return sizeof( sockaddr_in );
#ifdef HAVE_IPv6
        else if ( this->address->getFamily() == Enums::ADDR_IPV6 )
            return sizeof( sockaddr_in6 );
#endif
        else
            assert ( 0 && "invalid family" );
    }

    IpAddress & SocketAddressPosix::getIpAddress() const {
        return *this->address;
    }

    uint16_t SocketAddressPosix::getPort() const {
        return this->port;
    }

    uint32_t SocketAddressPosix::getScope() const {
        return this->scope;
    }

    auto_ptr< SocketAddress > SocketAddressPosix::clone() const {
        return auto_ptr<SocketAddress> ( new SocketAddressPosix( *this ) );
    }

    string SocketAddressPosix::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << this->address->toString() << "#" << this->port;

        return oss.str();
    }


    void SocketAddressPosix::setIpAddress( auto_ptr< IpAddress > ip_address ) {
        this->address = ip_address;
    }

    void SocketAddressPosix::setPort( uint16_t port ) {
        this->port = port;
    }
}





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
#include "udpsocket.h"

#include <libopenikev2/exception.h>
#include <libopenikev2/enums.h>
#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/autolock.h>

#include "interfacelist.h"
#include "socketaddressposix.h"
#include <net/if.h>
#include <string.h>

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

namespace openikev2 {

    UdpSocket::UdpSocket( ) {
        // creates the socket set
        FD_ZERO( &this->socket_set );

        // creates the mutexes
        this->mutex_read = ThreadController::getMutex();
        this->mutex_write = ThreadController::getMutex();
    }

    auto_ptr< ByteArray > UdpSocket::receive( auto_ptr< SocketAddress > & src_addr, auto_ptr< SocketAddress > & dst_addr ) {
        // Creates remote address and sets its size
#ifdef HAVE_IPv6
        sockaddr_in6 addr;
        socklen_t addr_length = sizeof( sockaddr_in6 );
#else

        sockaddr_in addr;
        socklen_t addr_length = sizeof( sockaddr_in );
#endif

        // while no data is available
        while ( true ) {
            // locks the read lock
            usleep (1000);          // Workaround to allow others processes to access the mutex/resource (glibc bug???)
            AutoLock auto_lock( *this->mutex_read );

            // set the maximum time to wait for data (we may need to do this in order to update the FD set)
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;

            // copy the fdset so that it doesn't get trashed by select, witch would result in the loss of all
            // fds in the set that weren't ready to be read. THANKS TO richard.powell@anite.com
            fd_set temp_set = this->socket_set;

            /* select returns 0 if timeout, 1 if input available, -1 if error. */
            int16_t rv = select ( FD_SETSIZE, &temp_set, NULL, NULL, &tv );

            // if an error occurred, throws an exception
            if ( rv < 0 )
                throw ReceivingException( strerror ( errno ) );

            // reads the data from the socket
            auto_ptr<ByteArray> received_data ( new ByteArray( MAX_MESSAGE_SIZE ) );

            for ( uint16_t i = 0; i < this->socket_collection.size(); i++ ) {
                if ( FD_ISSET( this->socket_collection[ i ].socket, &temp_set ) ) {
                    // receives thru the socket
                    int total = recvfrom ( this->socket_collection[i].socket, received_data->getRawPointer(), MAX_MESSAGE_SIZE, 0, ( sockaddr* ) & addr, &addr_length );

                    // if an error occured, throw exception
                    if ( total < 0 )
                        throw ReceivingException( strerror ( errno ) );

                    // updates the received data length
                    received_data->setSize( total );

                    // sets source and destination addresses
                    src_addr.reset( new SocketAddressPosix( ( sockaddr& ) addr ) );
                    dst_addr = this->socket_collection[ i ].sock_address->clone();
                    return received_data;
                }
            }
        }
    }

    auto_ptr< ByteArray > UdpSocket::receive( auto_ptr< SocketAddress > & src_addr, auto_ptr< SocketAddress > & dst_addr, uint32_t milliseconds ) {
        // Creates remote address and sets its size
#ifdef HAVE_IPv6
        sockaddr_in6 addr;
        socklen_t addr_length = sizeof( sockaddr_in6 );
#else
        sockaddr_in addr;
        socklen_t addr_length = sizeof( sockaddr_in );
#endif

        // locks the read lock
        AutoLock auto_lock( *this->mutex_read );

        // set the maximum time to wait for data (we need to do this in order to update the FD set)
        struct timeval tv;
        tv.tv_sec = ( milliseconds / 1000 );
        tv.tv_usec = ( milliseconds * 1000 ) % 1000000;

        // copy the fdset so that it doesn't get trashed by select, witch would result in the loss of all
        // fds in the set that weren't ready to be read. THANKS TO richard.powell@anite.com
        fd_set temp_set = this->socket_set;

        /* select returns 0 if timeout, 1 if input available, -1 if error. */
        int16_t rv = select ( FD_SETSIZE, &temp_set, NULL, NULL, &tv );

        // if an error occurred, throws an exception
        if ( rv < 0 )
            throw ReceivingException( strerror ( errno ) );

        // reads the data from the socket
        auto_ptr<ByteArray> received_data ( new ByteArray( MAX_MESSAGE_SIZE ) );

        for ( uint16_t i = 0; i < this->socket_collection.size(); i++ ) {
            if ( FD_ISSET( this->socket_collection[ i ].socket, &temp_set ) ) {
                // receives thru the socket
                int total = recvfrom ( this->socket_collection[ i ].socket, received_data->getRawPointer(), MAX_MESSAGE_SIZE, 0, ( sockaddr* ) & addr, &addr_length );

                // if an error occured, throw exception
                if ( total < 0 )
                    throw ReceivingException( strerror ( errno ) );

                // updates the received data length
                received_data->setSize( total );

                // sets source and destination addresses
                src_addr.reset( new SocketAddressPosix( ( sockaddr& ) addr ) );
                dst_addr = this->socket_collection[ i ].sock_address->clone();
                return received_data;
            }
        }

        // if the timeout expired, throw Exception
        //throw TimeoutException( "No data in the socket after wait " + intToString( milliseconds ) + " milliseconds." );
    }

    void UdpSocket::send( const SocketAddress & src_addr, const SocketAddress & dst_addr, const ByteArray & data ) {
        AutoLock auto_lock( *this->mutex_write );

        // look for the specified source address
        for ( uint16_t i = 0; i < this->socket_collection.size(); i++ ) {
            SocketAddressPosix temp_dst( dst_addr );

            if ( src_addr == *this->socket_collection[i].sock_address ) {
                // sends the data
                int32_t total = sendto( this->socket_collection[i].socket, data.getRawPointer(), data.size(), 0, temp_dst.getSockAddr().get(), temp_dst.getSockAddrSize() );

                // if an error occurred, throw Exception
                if ( total < 0 )
                    throw SendingException( strerror ( errno ) );

                // exit
                return ;
            }
        }
        // if no suittable socket has been found, throw exception
        throw SendingException( "Cannot find a suittable socket to write" );
    }

    void UdpSocket::bind( const SocketAddress& src_address ) {
        AutoLock auto_lock_read( *this->mutex_read );
        AutoLock auto_lock_write( *this->mutex_write );

        // creates the socket (depends on the family
        int sock_fd;

        if ( src_address.getIpAddress().getFamily() == Enums::ADDR_IPV4 )
            sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
#ifdef HAVE_IPv6
        else if ( src_address.getIpAddress().getFamily() == Enums::ADDR_IPV6 )
            sock_fd = socket( AF_INET6, SOCK_DGRAM, 0 );
#endif
        else
            assert ( "Unknown address family" && 0 );

        // If some error ocurrs
        if ( sock_fd <= 0 )
            throw BindingException( "Error creating DGRAM socket." );

        // Creates a new IP address
        auto_ptr<SocketAddressPosix> cloned_address ( new SocketAddressPosix ( src_address ) );

        // makes bind
        if ( ::bind ( sock_fd, cloned_address->getSockAddr().get(), cloned_address->getSockAddrSize() ) < 0 )
            throw BindingException( "Binding error with address=" + cloned_address->toString() + " reason=" + strerror( errno ) );

        // adds the socket to the collection
        SocketData socket_data = {cloned_address.release(), sock_fd};
        this->socket_collection.push_back( socket_data );

        // includes the socket in the socket set
        FD_SET( sock_fd, &this->socket_set );
    }

    void UdpSocket::bind( const SocketAddress & src_address, string interface_name ) {
        AutoLock auto_lock_read( *this->mutex_read );
        AutoLock auto_lock_write( *this->mutex_write );

        // creates the socket (depends on the family
        int sock_fd;

        if ( src_address.getIpAddress().getFamily() == Enums::ADDR_IPV4 )
            sock_fd = socket( AF_INET, SOCK_DGRAM, 0 );
#ifdef HAVE_IPv6
        else if ( src_address.getIpAddress().getFamily() == Enums::ADDR_IPV6 )
            sock_fd = socket( AF_INET6, SOCK_DGRAM, 0 );
#endif
        else
            assert ( "Unknown address family" && 0 );

        // If some error ocurrs
        if ( sock_fd <= 0 )
            throw BindingException( "Error creating DGRAM socket." );

        // Creates a new IP address
        auto_ptr<SocketAddressPosix> cloned_address ( new SocketAddressPosix ( src_address ) );
        auto_ptr<sockaddr> sockaddress = cloned_address->getSockAddr();

#ifdef HAVE_IPv6
        // make the trick for IPv6 link local
        if ( src_address.getIpAddress().getFamily() == Enums::ADDR_IPV6 ) {
            sockaddr_in6* sa_in6 = ( sockaddr_in6* ) sockaddress.get();
            if ( IN6_IS_ADDR_LINKLOCAL( sa_in6->sin6_addr.s6_addr ) ) {
                sa_in6->sin6_scope_id = if_nametoindex( interface_name.c_str() );
            }
        }
#endif

        // makes bind
        if ( ::bind ( sock_fd, sockaddress.get(), cloned_address->getSockAddrSize() ) < 0 )
            throw BindingException( "Binding error with address=" + cloned_address->toString() + " reason=" + strerror( errno ) );

        // adds the socket to the collection
        SocketData socket_data = {cloned_address.release(), sock_fd};
        this->socket_collection.push_back( socket_data );

        // includes the socket in the socket set
        FD_SET( sock_fd, &this->socket_set );
    }

    void UdpSocket::unbind( const SocketAddress & src_address ) {
        AutoLock auto_lock_read( *this->mutex_read );
        AutoLock auto_lock_write( *this->mutex_write );

        for ( vector<SocketData>::iterator it = this->socket_collection.begin(); it != this->socket_collection.end(); it++ ) {
            if ( *it->sock_address == src_address ) {
                delete it->sock_address;
                FD_CLR( it->socket, &this->socket_set );
                close( it->socket );
                this->socket_collection.erase( it );
                return;
            }
        }
    }

    UdpSocket::~UdpSocket() {
        for ( vector<SocketData>::iterator it = this->socket_collection.begin(); it != this->socket_collection.end(); it++ ) {
            delete it->sock_address;
            FD_CLR( it->socket, &this->socket_set );
            close( it->socket );
        }
    }
}









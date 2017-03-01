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
#ifndef UDPSOCKET_OPENIKE_H
#define UDPSOCKET_OPENIKE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/autovector.h>
#include <libopenikev2/log.h>
#include <libopenikev2/exception.h>

#include "socketaddressposix.h"

#include <vector>

using namespace std;

namespace openikev2 {
    /**
        This class represents an UDP socket. It is needed to bind with some IP address and port before using it
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class UdpSocket {
            /****************************** STRUCTS ******************************/
        protected:
            /**< This class represents each individual socket data */
            struct SocketData {
                SocketAddressPosix* sock_address;   /**< Socket address */
                int socket;                         /**< Socket file descriptor */
            };

            /****************************** ATTRIBUTES ******************************/
        protected:
            vector<SocketData> socket_collection;   /**< Socket collection */
            fd_set socket_set;                      /**< Struct for realice "select" operations. */
            auto_ptr<Mutex> mutex_read;             /**< Mutex to avoid simultaneous readings */
            auto_ptr<Mutex> mutex_write;            /**< Mutex to avoid simultaneous writings */

            /****************************** METHODS ******************************/
        public:

            /**
             * Creates and UDP socket (without any binding)
             */
            UdpSocket();

            /**
             * Receives data from the network
             * @param src_addr Source socket address of the message
             * @param dst_addr Destination socket address of the message
             * @return The received data
             * @throws ReceivingException An error avoids the reception of data
             */
            virtual auto_ptr<ByteArray> receive( auto_ptr<SocketAddress> &src_addr, auto_ptr<SocketAddress> &dst_addr );

            /**
             * Receives data from the network
             * @param src_addr Source socket ddress of the message (output)
             * @param dst_addr Destination socket address of the message (output)
             * @return The received data
             * @throws ReceivingException An error avoids the reception of data
             * @throws TimeoutException The specified timeout has expired without reciving any data
             */
            virtual auto_ptr<ByteArray> receive( auto_ptr<SocketAddress> &src_addr, auto_ptr<SocketAddress> &dst_addr, uint32_t milliseconds );

            /**
             * Sends data to the network
             * @param src_addr Source socket address of the message
             * @param dst_addr Destination socket address of the message
             * @param data Data to be sent
             * @throws SendingException An error avoids the sending of the data
             */
            virtual void send( const SocketAddress & src_addr, const SocketAddress & dst_addr, const ByteArray& data );

            /**
             * Adds a new socket address binding
             * @param src_addr New source socket address to bind.
             * @throws BindingException Cannot bind the indicated address/port
             */
            virtual void bind( const SocketAddress& src_address );

            /**
             * Adds a new socket address binding
             * @param src_addr New source socket address to bind.
             * @param interface_name Interface name (needed for LINK LOCAL addresses)
             * @throws BindingException Cannot bind the indicated address/port
             */
            virtual void bind( const SocketAddress& src_address, string interface_name );

            /**
            * Removes a socket address binding
            * @param src_addr Source socket address to unbind
            */
            virtual void unbind( const SocketAddress& src_address );

            virtual ~UdpSocket();
    };

    class TimeoutException : public NetworkException {
        public:
            TimeoutException( string m ) : NetworkException( "TimeoutException: " + m ) {}
    };

    class ReceivingException : public NetworkException {
        public:
            ReceivingException( string m ) : NetworkException( "ReceivingException: " + m ) {}
    };

    class SendingException : public NetworkException {
        public:
            SendingException( string m ) : NetworkException( "SendingException: " + m ) {}
    };

    class BindingException : public NetworkException {
        public:
            BindingException( string m ) : NetworkException( "BindingException: " + m ) {}
    };


};
#endif
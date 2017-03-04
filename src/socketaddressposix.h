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
#ifndef OPENIKEV2SOCKETADDRESSPOSIX_H
#define OPENIKEV2SOCKETADDRESSPOSIX_H

#include <libopenikev2/socketaddress.h>

namespace openikev2 {

    /**
     This class implements SocketAddress abstract class using standard sockets.
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class SocketAddressPosix: public SocketAddress {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<IpAddress> address;
            uint16_t port;
	    uint32_t scope;

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new SocketAddressPosix object
             * @param address IP address
             * @param port Port number
             */
            SocketAddressPosix( auto_ptr<IpAddress> address, uint16_t port );

            /**
             * Creates a new SocketAddressPosix object cloning other
             * @param other Other SocketAddress object
             */
            SocketAddressPosix( const SocketAddress& other );

            /**
             * Creates a new SocketAddressPosix object from an internal representation
             * @param other Other SocketAddress object
             */
            SocketAddressPosix( const sockaddr& sockaddr );

            /**
             * Gets the interal representation of this SockAddress
             * @return The internal representation
             */
            virtual auto_ptr<sockaddr> getSockAddr() const ;

            /**
            * Gets the internal representation size
            * @return The internal representation size
            */
            virtual uint32_t getSockAddrSize() const;

            virtual IpAddress& getIpAddress() const;

            virtual uint16_t getPort() const;

	    virtual uint32_t getScope() const;

            virtual void setIpAddress( auto_ptr<IpAddress> ip_address);

            virtual void setPort( uint16_t port );

            virtual auto_ptr<SocketAddress> clone() const;

            virtual string toStringTab( uint8_t tabs ) const;

            virtual ~SocketAddressPosix();

    };

}

#endif

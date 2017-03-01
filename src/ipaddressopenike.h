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
#ifndef IPADDRESS_OPENIKE_H
#define IPADDRESS_OPENIKE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/ipaddress.h>
#include <libopenikev2/utils.h>

#include <netinet/in.h>

namespace openikev2 {

    /**
        This class implements IpAddress abstract class using standard sockets.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */
    class IpAddressOpenIKE : public IpAddress {
        
            /****************************** ATTRIBUTES ******************************/
        protected:
            sockaddr_storage address;                   /**< System address representation */
                    
            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new IpAddressOpenIKE, setting its address in text form.
             * @param address Text representation of the address. It can be a name or an IPv4 / IPv6 number.
             */
            IpAddressOpenIKE( string address );

            /**
             * Creates a new IpAddressOpenIKE, setting its family and the address data
             * @param family Address family
             * @param data Address data
             */
            IpAddressOpenIKE( Enums::ADDR_FAMILY family, auto_ptr<ByteArray> data);                        
            
            /**
             * Creates a new IpAddressOpenIKE, setting its family and the address data to ANY
             * @param family Address family
             */
            IpAddressOpenIKE( Enums::ADDR_FAMILY family );                        
            
            /**
             * Creates a new IpAddressOpenIKE, cloning another one
             * @param other Other IpAddressOpenIKE object
             */
            IpAddressOpenIKE( const IpAddressOpenIKE& other);

            /**
             * Obtains the ANY address for the indicated family
             * @param  family Address family
             * @return A new ANY address for the indicated family
             */
            static auto_ptr<IpAddress> getAnyAddr(Enums::ADDR_FAMILY family);
            
            virtual uint16_t getAddressSize() const;

            virtual Enums::ADDR_FAMILY getFamily() const ;

            virtual auto_ptr<ByteArray> getBytes() const;

            virtual auto_ptr<IpAddress> clone() const;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual string getIfaceName();

            virtual ~IpAddressOpenIKE();

    };
};
#endif

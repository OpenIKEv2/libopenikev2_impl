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
#ifndef NETWORKCONTROLLERIMPL_OPENIKE_H
#define NETWORKCONTROLLERIMPL_OPENIKE_H


#include <libopenikev2/networkcontrollerimpl.h>
#include <libopenikev2/payload_conf.h>
#include "udpsocket.h"
#include "threadposix.h"

#include <map>



namespace openikev2 {
    class RadvdWrapper;
    /**
        This class represents the NetworkController concrete implementation used in the openikev2 program.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj.fernandez@dif.um.es, alejandro_perez@dif.um.es>
    */
    class NetworkControllerImplOpenIKE : public NetworkControllerImpl, public ThreadPosix {
            friend class AddressConfiguration;

            /****************************** ATTRIBUTES ******************************/
        protected:
            map <string, bool> used_addresses;          /**< Map of used addresses */
            auto_ptr<UdpSocket> udp_socket;             /**< UDP Socket to perform networking operations */
            bool exiting;                               /**< Indicates if we want to exit */
#ifdef EAP_SERVER_ENABLED
            RadvdWrapper *radvd;
#endif
            /****************************** METHODS ******************************/
        protected:
            /**
             * Create and opens a new TUN inteface
             * @param ifname Opened interface name
             * @return TUN file descriptor
             */
            int32_t tunOpen( string &ifname );

            int32_t getCtlFd ();

            int32_t doChFlags ( string dev, uint32_t flags );

            /**
             * Assings a new IP address at the specified interface.
             * @param addr IP Address we want to assign
             * @param prefixlen Prefix length to determine the mask
             * @param ifname Interface name to assign the new address
             */
            virtual void createAddress( const IpAddress& addr, uint8_t prefixlen, string ifname );

            virtual void refreshInterfaces();

	    virtual IpAddress * getCurrentCoA();

	    virtual IpAddress * getHoAbyCoA(const IpAddress& current_coa);

            /**
             * Removes the specified IP address at the specified interface.
             * @param addr IP Address we want to remove
             * @param prefixlen Prefix length to determine the mask
             * @param ifname Interface name to remove the address from
             */
            virtual void deleteAddress( const IpAddress& addr, uint8_t prefixlen, string ifname );

            /**
             * Creates a new route that allow traffic to reach "addr_dst" throw the specified interface
             * @param addr_dst Destination address
             * @param prefixlen Prefix lenght
             * @param ifname Interface name
             */
            virtual void createRoute( const IpAddress& addr_src, const IpAddress& addr_dst, uint8_t prefixlen, const IpAddress& gateway, int metirc, string ifname );

            virtual void deleteRoute( const IpAddress& addr_dst, uint8_t prefixlen, const IpAddress& gateway, int metric, string ifname );

            /**
             * Gets an IPv6 address from an address pool based on the fixed parameters
             * @param IkeSa IKE_SA
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv6AddressFixed( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask );


           /**
             * Gets an IPv6 address based on the peer address (like autoconf)
             * @param IkeSa IKE_SA
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv6AddressAutoconf( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask );

            /**
             * Gets an IPv4 address from an address pool based on the fixed parameters
             * @param IkeSa IKE_SA
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv4AddressFixed( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask );

            /**
             * Gets an IPv4 address from a DHCP server
             * @param child_sa ChildSa
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv4AddressDhcp( IkeSa& ike_sa, ConfigurationAttribute& attribute , auto_ptr<ByteArray> *netmask);

            /**
             * Gets an IPv6 address using the configurated method
             * @param child_sa ChildSa
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv6Address( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask  );

            /**
             * Gets an IPv4 address using the configurated method
             * @param child_sa ChildSa
             * @param attribute Received configuration attribute
             * @return A new IpAddress
             */
            virtual auto_ptr<IpAddress> generateIpv4Address( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask );

            /**
             * Register an address as used in the pool
             * @param addr Address to be registered as used
             * @return TRUE if address is not already registered. FALSE otherwise
             */
            virtual bool registerAddress( IpAddress& addr );

            /**
             * Release an address in the pool
             * @param addr Address to be released
             */
            virtual void releaseAddress( IpAddress& addr );

            /**
             * Received a message from the network
             * @return The received message
             */
            virtual auto_ptr<Message> receive( );

            /**
             * Sends a response exchange with a NOTIFY payload indicating a INVALID_IKE_SPI condition
             * @param received_message The received request
             */
            virtual void send_INVALID_IKE_SPI( Message& received_message );

        public:
            NetworkControllerImplOpenIKE();

            virtual auto_ptr<IpAddress> getIpAddress( string address );

            virtual auto_ptr<IpAddress> getIpAddress( Enums::ADDR_FAMILY family, auto_ptr<ByteArray> data );

            virtual auto_ptr<SocketAddress> getSocketAddress( string address, int port );

            virtual auto_ptr<SocketAddress> getSocketAddress( auto_ptr<IpAddress> address, int port );

            virtual void createConfigurationRequest( Message& message, IkeSa& ike_sa );

            virtual IkeSa::NEGOTIATION_ACTION processConfigurationResponse( Message& message, IkeSa& ike_sa );

            virtual IkeSa::NEGOTIATION_ACTION processConfigurationRequest( Message& message, IkeSa& ike_sa );

            virtual void createConfigurationResponse( Message& message, IkeSa& ike_sa );

            virtual void run();

            virtual void sendMessage( Message &message, Cipher* cipher );

            virtual void addSrcAddress( auto_ptr<IpAddress> new_src_address );

            virtual void removeSrcAddress( const IpAddress& src_address );

            virtual int16_t getPrefixLen( auto_ptr<ByteArray> prefix );

            virtual void exit();

            virtual void startRadvd();

            virtual ~NetworkControllerImplOpenIKE();
    };
}
#endif

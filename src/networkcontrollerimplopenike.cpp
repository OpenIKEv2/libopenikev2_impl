/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "networkcontrollerimplopenike.h"

#include <libopenikev2/log.h>
#include <libopenikev2/utils.h>
#include <libopenikev2/configuration.h>
#include <libopenikev2/cryptocontroller.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/messagereceivedcommand.h>
#include <libopenikev2/boolattribute.h>
#include <libopenikev2/stringattribute.h>
#include <libopenikev2/payload_notify.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "dhcpclient.h"
#include "libnetlink.h"
#include "udpsocket.h"
#include "addressconfiguration.h"
#include "utilsimpl.h"

#include "interfacelist.h"
#include "socketaddressposix.h"

#ifdef EAP_SERVER_ENABLED
#include "radvd_wrapper.h"
#endif

#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>

extern "C" {
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}

namespace openikev2 {

    NetworkControllerImplOpenIKE::NetworkControllerImplOpenIKE()
    : NetworkControllerImpl() {

        // Creates the socket using the correct port
        this->udp_socket.reset( new UdpSocket() );

        // initializes the exiting variable
        this->exiting = false;

        this->refreshInterfaces();

    }

    void NetworkControllerImplOpenIKE::refreshInterfaces(){
        InterfaceList interface_list;

        // For each address
        for ( uint16_t i = 0; i < interface_list.addresses->size(); i++ ) {
            try {
                this->udp_socket->bind( SocketAddressPosix( interface_list.addresses[i]->clone(), 500 ), interface_list.interface_names[i] );
                Log::writeLockedMessage( "NetworkController", "Listening from interface: Name=[" + interface_list.interface_names[ i ] + "] Address=[" + interface_list.addresses[i]->toString() + "]", Log::LOG_INFO, true );
            }
            catch ( BindingException& ex ) {
                Log::writeLockedMessage( "NetworkController", ex.what(), Log::LOG_ERRO, true );
            }
        }
    }

    IpAddress * NetworkControllerImplOpenIKE::getCurrentCoA() {
	     char coa[255];

		FILE *f = fopen("/tmp/coa", "r");
		if (f==NULL)
		{
		 Log::writeLockedMessage( "NetworkController", "File with current CoA does not exist.", Log::LOG_ERRO, true );
	     }

	     if ((fscanf(f,"%s", coa)) != 0  )  {
		IpAddress *chosen_coa = new IpAddressOpenIKE ( coa );
		fclose(f);
		return chosen_coa;
	    }
	    else {
		Log::writeLockedMessage( "NetworkController", "No CoA in file." , Log::LOG_ERRO, true );
		fclose(f);
		return NULL;
	    }
    }


    IpAddress * NetworkControllerImplOpenIKE::getHoAbyCoA(const IpAddress& current_coa) {
	 	char coa[255];
		char hoa[255];
		char searched_coa[255];

		strcpy(searched_coa,current_coa.toString().c_str());

		Log::writeLockedMessage( "NetworkController", "Looking for CoA=["+current_coa.toString()+"]...", Log::LOG_INFO, true );

		FILE *f = fopen("/root/bc.txt", "r");
		if (f==NULL)
		{
		 	Log::writeLockedMessage( "NetworkController", "File with binding cache info does not exist.", Log::LOG_ERRO, true );
	        }

		while ((fscanf(f,"%s %s", coa, hoa)) != 0  )  {
			string str_coa (coa);
			string str_hoa (hoa);
			Log::writeLockedMessage( "NetworkController", "CoA=["+ str_coa +"]...", Log::LOG_ERRO, true );

			if(strcmp(coa, searched_coa)==0){
				Log::writeLockedMessage( "NetworkController", "....found HoA=["+ str_hoa +"].", Log::LOG_INFO, true );

				IpAddress *found_hoa = new IpAddressOpenIKE ( hoa );
				fclose(f);
				return found_hoa;
			}
		}
		Log::writeLockedMessage( "NetworkController", "No CoA in file." , Log::LOG_ERRO, true );
		fclose(f);
		return NULL;

    }





int32_t NetworkControllerImplOpenIKE::getCtlFd( ) {
    int32_t s_errno;
    int32_t fd;

    fd = socket( PF_INET, SOCK_DGRAM, 0 );

    if ( fd >= 0 )
        return fd;

    s_errno = errno;

    fd = socket( PF_PACKET, SOCK_DGRAM, 0 );

    if ( fd >= 0 )
        return fd;

    fd = socket( PF_INET6, SOCK_DGRAM, 0 );

    if ( fd >= 0 )
        return fd;

    throw NetworkException( "Cannot create control socket" );
}

int32_t NetworkControllerImplOpenIKE::doChFlags( string dev, uint32_t flags ) {

    struct ifreq ifr;
    int32_t fd;
    int32_t err;

    strcpy( ifr.ifr_name, dev.c_str() );

    fd = this->getCtlFd();

    if ( fd < 0 )
        return -1;

    err = ioctl( fd, SIOCGIFFLAGS, &ifr );

    if ( err )
        throw NetworkException( "Cannot set iface flags" );

    ifr.ifr_flags |= flags;

    err = ioctl( fd, SIOCSIFFLAGS, &ifr );

    if ( err )
        throw NetworkException( "Cannot set iface flags" );

    close( fd );

    return err;
}

int32_t NetworkControllerImplOpenIKE::tunOpen( string &ifname ) {

    struct ifreq ifr;
    int fd, ret;

    fd = open( "/dev/net/tun", O_RDWR );

    if ( fd < 0 )
        throw NetworkException( "warning: could not open /dev/net/tun" );

    memset( &ifr, 0, sizeof( ifr ) );

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    strncpy( ifr.ifr_name, "rw%d", IFNAMSIZ );

    ret = ioctl( fd, TUNSETIFF, ( void * ) & ifr );

    if ( ret != 0 )
        throw NetworkException( "warning: could not configure /dev/net/tun" );

    fcntl( fd, F_SETFL, O_NONBLOCK );

    this->doChFlags( ifr.ifr_name, IFF_UP );

    ifname = ifr.ifr_name;

    return fd;
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::getIpAddress( string address ) {
    return auto_ptr<IpAddress> ( new IpAddressOpenIKE( address ) );
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::getIpAddress( Enums::ADDR_FAMILY family, auto_ptr<ByteArray> data ) {
    return auto_ptr<IpAddress> ( new IpAddressOpenIKE( family, data ) );
}

auto_ptr<SocketAddress> NetworkControllerImplOpenIKE::getSocketAddress( string address , int port) {
	auto_ptr<IpAddress> addr ( new IpAddressOpenIKE( address ) );
	return auto_ptr<SocketAddress> ( new SocketAddressPosix( addr, port) );
}

auto_ptr<SocketAddress> NetworkControllerImplOpenIKE::getSocketAddress( auto_ptr<IpAddress> address , int port) {
	return auto_ptr<SocketAddress> ( new SocketAddressPosix( address, port) );
}



void NetworkControllerImplOpenIKE::createRoute( const IpAddress& addr_src, const IpAddress& addr_dst, uint8_t prefixlen, const IpAddress& gateway, int metric, string ifname ) {
    struct {
        nlmsghdr n;
        rtmsg r;
        char buf[ 1024 ];
    }

    req;

    memset( &req, 0, sizeof( req ) );

    req.n.nlmsg_len = NLMSG_LENGTH( sizeof( struct rtmsg ) );
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    req.n.nlmsg_type = RTM_NEWROUTE;

    req.r.rtm_family = UtilsImpl::getUnixFamily( addr_dst.getFamily() );
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_dst_len = prefixlen;

    uint32_t iface =  if_nametoindex( ifname.c_str() );

    int32_t prio = metric;

    netlinkAddattr( req.n, sizeof( req ), RTA_SRC, *addr_src.getBytes() );
    netlinkAddattr( req.n, sizeof( req ), RTA_DST, *addr_dst.getBytes() );
    netlinkAddattr( req.n, sizeof( req ), RTA_GATEWAY, *gateway.getBytes() );
    netlinkAddattr( req.n, sizeof( req ), RTA_OIF, ByteArray( &iface, 4 ) );
    netlinkAddattr( req.n, sizeof( req ), RTA_PRIORITY, ByteArray( &prio, 4 ) );


    int32_t fd = netlinkOpen( 0, NETLINK_ROUTE );
    netlinkSendMsg( fd, req.n );

    if ( netlinkReceiveAck( fd ) != 0 ) {
            //close( fd );
//        cout << endl << "Error route creation. May be it already exists.";
            //throw NetworkException( "Cannot create indicated route" );
    }

    close( fd );
}

void NetworkControllerImplOpenIKE::deleteRoute( const IpAddress& addr_dst, uint8_t prefixlen, const IpAddress& gateway, int metric, string ifname ) {
    struct {
        nlmsghdr n;
        rtmsg r;
        char buf[ 1024 ];
    }

    req;

    memset( &req, 0, sizeof( req ) );

    req.n.nlmsg_len = NLMSG_LENGTH( sizeof( struct rtmsg ) );
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    req.n.nlmsg_type = RTM_DELROUTE;

    req.r.rtm_family = UtilsImpl::getUnixFamily( addr_dst.getFamily() );
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_dst_len = prefixlen;

    uint32_t iface =  if_nametoindex( ifname.c_str() );

    int32_t prio = metric;

    netlinkAddattr( req.n, sizeof( req ), RTA_DST, *addr_dst.getBytes() );
    netlinkAddattr( req.n, sizeof( req ), RTA_GATEWAY, *gateway.getBytes() );
    netlinkAddattr( req.n, sizeof( req ), RTA_OIF, ByteArray( &iface, 4 ) );


    int32_t fd = netlinkOpen( 0, NETLINK_ROUTE );
    netlinkSendMsg( fd, req.n );

    if ( netlinkReceiveAck( fd ) != 0 ) {
            //close( fd );
    //        cout << endl << "Error route deletion. May be it is already deleted.";
            //perror("AAA: ");
            //throw NetworkException( "Cannot delete indicated route" );
    }

    close( fd );
}

void NetworkControllerImplOpenIKE::createAddress( const IpAddress& addr, uint8_t prefixlen, string ifname ) {
    struct {

        struct nlmsghdr n;

        struct ifaddrmsg ifa;
        char buf[ 256 ];
    }

    req;

    memset( &req, 0, sizeof( req ) );

    req.n.nlmsg_len = NLMSG_LENGTH( sizeof( struct ifaddrmsg ) );
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = RTM_NEWADDR;
    req.ifa.ifa_family = UtilsImpl::getUnixFamily( addr.getFamily() );

    req.ifa.ifa_prefixlen = prefixlen;
    netlinkAddattr( req.n, sizeof( req ), IFA_LOCAL, *addr.getBytes() );
    req.ifa.ifa_scope = 0;
    req.ifa.ifa_flags = IFA_F_SECONDARY;

    req.ifa.ifa_index = if_nametoindex( ifname.c_str() );

    int32_t fd = netlinkOpen( 0, NETLINK_ROUTE );
    netlinkSendMsg( fd, req.n );

    if ( netlinkReceiveAck( fd ) != 0 ) {
            // cout << endl << "Error address creation. May be it is already created.";
            //close( fd );
            //throw NetworkException( "Cannot create indicated address" );
    }

    close( fd );
}


void NetworkControllerImplOpenIKE::deleteAddress( const IpAddress& addr, uint8_t prefixlen, string ifname ) {
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
        char buf[ 256 ];
    } req;

    memset( &req, 0, sizeof( req ) );

    req.n.nlmsg_len = NLMSG_LENGTH( sizeof( struct ifaddrmsg ) );
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = RTM_DELADDR;
    req.ifa.ifa_family = UtilsImpl::getUnixFamily( addr.getFamily() );

    req.ifa.ifa_prefixlen = prefixlen;
    netlinkAddattr( req.n, sizeof( req ), IFA_LOCAL, *addr.getBytes() );
    req.ifa.ifa_scope = 0;
    req.ifa.ifa_flags = IFA_F_SECONDARY;

    req.ifa.ifa_index = if_nametoindex( ifname.c_str() );

    int32_t fd = netlinkOpen( 0, NETLINK_ROUTE );
    netlinkSendMsg( fd, req.n );

    if ( netlinkReceiveAck( fd ) != 0 ) {
            //close( fd );
            //throw NetworkException( "Cannot delete indicated address" );
            // cout << endl << "Error address deletion. May be it is already deleted.";

    }

    close( fd );
}

NetworkControllerImplOpenIKE::~NetworkControllerImplOpenIKE() {
#ifdef EAP_SERVER_ENABLED
    if ( radvd != NULL )
        delete radvd;
#endif
}

void NetworkControllerImplOpenIKE::releaseAddress( IpAddress & addr ) {
    this->used_addresses[ addr.getBytes() ->toString()] = false;
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv4AddressDhcp( IkeSa& ike_sa, ConfigurationAttribute & attribute, auto_ptr<ByteArray> *netmask ) {
    auto_ptr<DhcpClient> dhcp_client( new DhcpClient( ike_sa ) );
    uint32_t subnet;
    auto_ptr<IpAddress> result = dhcp_client->requestAddress(subnet);

    auto_ptr<ByteBuffer> mask_temp ( new ByteBuffer ( 4 ) );

    char* subnet_pointer = (char *) &subnet;
    for ( uint8_t i = 0; i < 4 ; i++ ) {
        mask_temp->writeInt8( subnet_pointer[i] );
    }
    auto_ptr<ByteArray> mask ( mask_temp );

    *netmask = mask->clone();

    if ( result.get() )
        ike_sa.attributemap->addAttribute( "dhcp_client_object", auto_ptr<Attribute> ( dhcp_client ) );

    return result;
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv4AddressFixed( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask ) {
    NetworkPrefix * fixed_prefix = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "fixed_ipv4_prefix" );

    if ( fixed_prefix == NULL ) {
        Log::writeLockedMessage( "NetworkController", "Cannot find any valid IPv4 fixed address in the configuration", Log::LOG_ERRO, true );
        return auto_ptr<IpAddress> ( NULL );
    }

    assert( fixed_prefix->getNetworkAddress().getFamily() == Enums::ADDR_IPV4 );

        // get the network address data
    auto_ptr<ByteArray> fixed_prefix_data = fixed_prefix->getNetworkAddress().getBytes();

        // Generates the mask based on the prefixlen
    auto_ptr<ByteArray> mask = fixed_prefix->getMask();

    *netmask = mask->clone();

        // Generates a random address with the correct prefix
    auto_ptr<Random> random = CryptoController::getRandom();

    auto_ptr<ByteArray> generated_address_data = random->getRandomBytes( fixed_prefix_data->size() );

    for ( uint16_t i = 0; i < fixed_prefix_data->size();i++ )
        ( *generated_address_data )[ i ] = (( *fixed_prefix_data )[ i ] & ( *mask )[ i ] ) |
    (( *generated_address_data )[ i ] & ~( *mask )[ i ] );

    auto_ptr<ByteArray> alternative_address_data = generated_address_data->clone();

        // So, the generated address is

    uint8_t last_byte = ( *generated_address_data )[ 3 ];

    auto_ptr<IpAddress> address( new IpAddressOpenIKE( Enums::ADDR_IPV4, generated_address_data ) );

        // Avoid network & broadcast addresses when using IPv4 (if mask != 32)
    if ( fixed_prefix->getPrefixLen() != 32 ) {
        if ( *address == fixed_prefix->getNetworkAddress() ) {
           ( *alternative_address_data )[ 3 ] = last_byte + 1 ;
           auto_ptr<IpAddress> address2( new IpAddressOpenIKE( Enums::ADDR_IPV4, alternative_address_data ) );
           return address2;
       }
       else if ( *address == *fixed_prefix->getBroadCastAddress() ) {
           ( *alternative_address_data )[ 3 ] = last_byte - 1 ;
           auto_ptr<IpAddress> address3( new IpAddressOpenIKE( Enums::ADDR_IPV4, alternative_address_data ) );
           return address3;
       }
   }

   bool rv = this->registerAddress( *address );
   if ( !rv ) {
    Log::writeLockedMessage( "NetworkController", "Randomly chosen IPv4 address is already in use. Please, try again", Log::LOG_ERRO, true );
    return auto_ptr<IpAddress> ( NULL );
}

return address;
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv6AddressFixed( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask ) {
    NetworkPrefix * fixed_prefix = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "fixed_ipv6_prefix" );

    if ( fixed_prefix == NULL ) {
        Log::writeLockedMessage( "NetworkController", "Cannot find any valid IPv6 fixed address in the configuration", Log::LOG_ERRO, true );
        return auto_ptr<IpAddress> ( NULL );
    }

    assert( fixed_prefix->getNetworkAddress().getFamily() == Enums::ADDR_IPV6 );

        // get the network address data
    auto_ptr<ByteArray> fixed_prefix_data = fixed_prefix->getNetworkAddress().getBytes();

        // Generates the mask based on the prefixlen
    auto_ptr<ByteArray> mask = fixed_prefix->getMask();

    *netmask = mask->clone();

        // Generates a random address with the correct prefix
    auto_ptr<Random> random = CryptoController::getRandom();

    auto_ptr<ByteArray> generated_address_data = random->getRandomBytes( fixed_prefix_data->size() );

    for ( uint16_t i = 0; i < fixed_prefix_data->size();i++ )
        ( *generated_address_data )[ i ] = (( *fixed_prefix_data )[ i ] & ( *mask )[ i ] ) |
    (( *generated_address_data )[ i ] & ~( *mask )[ i ] );

        // If a suffix is requested
    if ( attribute.value->size() > 0 ) {
        uint16_t requested_suffix_len = ( *attribute.value )[ 16 ];

        auto_ptr<ByteArray> final_address_data = generated_address_data->clone();

        auto_ptr<ByteArray> mask = NetworkPrefix::getMask( 128 - requested_suffix_len, 16 );

            //Construct the final address

        for ( uint16_t i = 0; i < 16; i++ )
            ( *final_address_data )[ i ] = (( *generated_address_data )[ i ] & ( *mask )[i] ) |
        (( *attribute.value )[ i ] & ~( *mask )[i] );


            // Construct the address
        auto_ptr<IpAddress> address( new IpAddressOpenIKE( Enums::ADDR_IPV6, final_address_data->clone() ) );
        NetworkPrefix temp_prefix( address, fixed_prefix->getPrefixLen() );

            // if the suggested suffix doesn't vilate the current prefix, go with it
        if ( temp_prefix.getNetworkAddress() == fixed_prefix->getNetworkAddress() ) {
            generated_address_data = final_address_data;
        }
        else {
            Log::writeLockedMessage( "NetworkController", "Warning: Peer requests an address with an invalid prefix. Omiting proposed suffix", Log::LOG_WARN, true );
        }
    }

        // So, the generated address is
    auto_ptr<IpAddress> address( new IpAddressOpenIKE( Enums::ADDR_IPV6, generated_address_data ) );

    bool rv = this->registerAddress( *address );

    if ( !rv ) {
        Log::writeLockedMessage( "NetworkController", "Randomly chosen IPv6 address is already in use. Please, try again", Log::LOG_ERRO, true );
        return auto_ptr<IpAddress> ( NULL );
    }

    return address;
}

auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv6AddressAutoconf( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask ) {
    NetworkPrefix * autoconf_prefix = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "autoconf_ipv6_prefix" );

    if ( autoconf_prefix == NULL ) {
        Log::writeLockedMessage( "NetworkController", "Cannot find any valid IPv6 fixed address in the configuration", Log::LOG_ERRO, true );
        return auto_ptr<IpAddress> ( NULL );
    }

    assert( autoconf_prefix->getNetworkAddress().getFamily() == Enums::ADDR_IPV6 );

        // get the network address data
    auto_ptr<ByteArray> autoconf_prefix_data = autoconf_prefix->getNetworkAddress().getBytes();

        // Generates the mask based on the prefixlen
    auto_ptr<ByteArray> mask = autoconf_prefix->getMask();

    *netmask = mask->clone();

    auto_ptr<ByteArray> generated_peer_addr = ike_sa.peer_addr->getIpAddress().getBytes();

    for ( uint16_t i = 0; i < autoconf_prefix_data->size();i++ )
        ( *generated_peer_addr )[ i ] = (( *autoconf_prefix_data )[ i ] & ( *mask )[ i ] ) |
    (( *generated_peer_addr )[ i ] & ~( *mask )[ i ] );

        // If a suffix is requested
    if ( attribute.value->size() > 0 ) {
        uint16_t requested_suffix_len = ( *attribute.value )[ 16 ];

        auto_ptr<ByteArray> final_address_data = generated_peer_addr->clone();

        auto_ptr<ByteArray> mask = NetworkPrefix::getMask( 128 - requested_suffix_len, 16 );

            //Construct the final address

        for ( uint16_t i = 0; i < 16; i++ )
            ( *final_address_data )[ i ] = (( *generated_peer_addr )[ i ] & ( *mask )[i] ) |
        (( *attribute.value )[ i ] & ~( *mask )[i] );


            // Construct the address
        auto_ptr<IpAddress> address( new IpAddressOpenIKE( Enums::ADDR_IPV6, final_address_data->clone() ) );
        NetworkPrefix temp_prefix( address, autoconf_prefix->getPrefixLen() );

            // if the suggested suffix doesn't vilate the current prefix, go with it
        if ( temp_prefix.getNetworkAddress() == autoconf_prefix->getNetworkAddress() ) {
            generated_peer_addr = final_address_data;
        }
        else {
            Log::writeLockedMessage( "NetworkController", "Warning: Peer requests an address with an invalid prefix. Omiting proposed suffix", Log::LOG_WARN, true );
        }
    }

        // So, the generated address is
    auto_ptr<IpAddress> address( new IpAddressOpenIKE( Enums::ADDR_IPV6, generated_peer_addr ) );

    return address;
}



bool NetworkControllerImplOpenIKE::registerAddress( IpAddress & addr ) {
    if ( this->used_addresses[ addr.getBytes() ->toString()] )
        return false;

    this->used_addresses[ addr.getBytes() ->toString()] = true;

    return true;
}

void NetworkControllerImplOpenIKE::createConfigurationRequest( Message &message, IkeSa & ike_sa ) {
        // Message must be IKE_AUTH request
    if ( !( message.exchange_type == Message::IKE_AUTH && message.message_type == Message::REQUEST ) )
        return;

        // Check if we want to request for IPv6 address
    string request_address = "none";
    StringAttribute* request_address_attr = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<StringAttribute>( "request_address" );
    if ( request_address_attr != NULL )
        request_address = request_address_attr->value;

        // If we don't want to request any configuration, exit
    if ( request_address == "none" )
        return;

    auto_ptr<Payload_CONF> payload_conf( new Payload_CONF( Payload_CONF::CFG_REQUEST ) );

        // Creates dynamic address request configuration payload
    if ( request_address == "ipv6" || request_address == "autoconf") {
        NetworkPrefix* ipv6_suffix = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "request_ipv6_suffix" );

            // If we request a concrete suffix
        if ( ipv6_suffix != NULL ) {
            auto_ptr<ByteArray> value( new ByteArray( 17 ) );

            auto_ptr<ByteArray> mask_bytes = NetworkPrefix::getMask( 128 - ipv6_suffix->getPrefixLen(), 16 );
            auto_ptr<ByteArray> suffix_bytes = ipv6_suffix->getNetworkAddress().getBytes();

            for ( uint16_t i = 0; i < 16;i++ )
                ( *value )[ i ] = ( *suffix_bytes )[ i ] &
            ~( *mask_bytes )[ i ];

            ( *value )[ 16 ] = ipv6_suffix->getPrefixLen();

            value->setSize( 17 );

            payload_conf->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP6_ADDRESS, value ) ) );
        }

            // If no suffix is requested
        else {
            payload_conf->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP6_ADDRESS, auto_ptr<ByteArray> ( NULL ) ) ) );
        }
    }

    else if ( request_address == "ipv4" ) {
        payload_conf->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP4_ADDRESS, auto_ptr<ByteArray> ( NULL ) ) ) );
        payload_conf->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP4_NETMASK, auto_ptr<ByteArray> ( NULL ) ) ) );
            //payload_conf->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_DEFAULT_GW, auto_ptr<ByteArray> ( NULL ) ) ) );
    }

    else
        assert( 0 );

    message.addPayload( auto_ptr<Payload> ( payload_conf ), true );
}

IkeSa::NEGOTIATION_ACTION NetworkControllerImplOpenIKE::processConfigurationResponse( Message& message, IkeSa & ike_sa ) {
        // Message must be IKE_AUTH response
    if ( !( message.exchange_type == Message::IKE_AUTH && message.message_type == Message::RESPONSE ) )
        return IkeSa::NEGOTIATION_ACTION_CONTINUE;

        // Check if we want to request for IPv6 address
    string request_address = "none";
    StringAttribute* request_address_attr = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<StringAttribute>( "request_address" );
    if ( request_address_attr != NULL )
        request_address = request_address_attr->value;

        // If we don't want to request any configuration, exit
    if ( request_address == "none" )
        return IkeSa::NEGOTIATION_ACTION_CONTINUE;

        // Obtain the CONF response
    Payload_CONF& payload_conf = ( Payload_CONF& ) message.getUniquePayloadByType( Payload::PAYLOAD_CONF );

        // If we requested an IP6 address, try to find the response
    if ( request_address == "ipv6" ) {
        ConfigurationAttribute* response = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP6_ADDRESS );

        if ( response == NULL ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "No IPv6 address found in configuration response", Log::LOG_ERRO, true );
            return IkeSa::NEGOTIATION_ACTION_ERROR;
        }

        auto_ptr<IpAddress> assigned_ipv6_address = this->getIpAddress( Enums::ADDR_IPV6, response->value->clone() );
        int16_t ipv6_mask = ( *response->value )[16];

        Log::writeLockedMessage( ike_sa.getLogId(), "Setting address configuration: Rol=[IRAC] Address=[" + assigned_ipv6_address->toString() + "]", Log::LOG_INFO, true );

        auto_ptr<SocketAddressPosix> my_addr_posix ( new SocketAddressPosix (*(ike_sa.my_addr)) );
        IpAddress& src_ip = (IpAddress &) my_addr_posix->getIpAddress();

        auto_ptr<SocketAddressPosix> peer_addr_posix ( new SocketAddressPosix (*(ike_sa.peer_addr)) );
        IpAddress& dst_ip = (IpAddress &) peer_addr_posix->getIpAddress();

            // create iface with assigned address
            //string ifname;
            //int32_t tunfd = this->tunOpen( ifname );

        string ifname = src_ip.getIfaceName();
        this->createAddress( *assigned_ipv6_address, ipv6_mask, ifname );
        auto_ptr<AddressConfiguration> address_configuration( new AddressConfiguration( AddressConfiguration::CONFIGURATION_IRAC , *this ) );
            //address_configuration->tun_fd = tunfd;
        address_configuration->ifname = ifname;
        address_configuration->assigned_address = assigned_ipv6_address->clone();
        address_configuration->assigned_prefixlen = ipv6_mask;

            // Create routes if INTERNAL_IP6_SUBNET is included
        ConfigurationAttribute* subnet = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP6_SUBNET );
        if ( subnet != NULL ) {
            ByteBuffer buffer( *subnet->value );
            auto_ptr<IpAddress> route_dst = this->getIpAddress( Enums::ADDR_IPV6, buffer.readByteArray( 16 ) );
            uint8_t route_mask = buffer.readInt8();
                //this->createRoute(*IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), *route_dst, route_mask,  *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, ifname );


		//this->deleteRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, dst_ip, 0, ifname);

            this->createRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, dst_ip, 1, ifname);
            this->createRoute( *assigned_ipv6_address, *route_dst, route_mask, *assigned_ipv6_address , 0, ifname );

            address_configuration->route_dst = route_dst->clone();
            address_configuration->route_prefixlen = route_mask;
            address_configuration->default_gw = auto_ptr<IpAddress> ( new IpAddressOpenIKE (dst_ip.toString()) );
        }

        ike_sa.attributemap->addAttribute( "address_configuration", auto_ptr<Attribute> ( address_configuration ) );

    }
        // If we requested an IP6 address, but using autoconf
    else if ( request_address == "autoconf" ) {
        ConfigurationAttribute* response = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP6_ADDRESS );

        if ( response == NULL ) {
            Log::writeLockedMessage( ike_sa.getLogId(), "No IPv6 address found in configuration response", Log::LOG_ERRO, true );
            return IkeSa::NEGOTIATION_ACTION_ERROR;
        }

        auto_ptr<IpAddress> assigned_ipv6_address = this->getIpAddress( Enums::ADDR_IPV6, response->value->clone() );
        int16_t ipv6_mask = ( *response->value )[16];

        Log::writeLockedMessage( ike_sa.getLogId(), "IPv6 received, but not set. Autoconf will do. Rol=[IRAC] Address=[" + assigned_ipv6_address->toString() + "]", Log::LOG_INFO, true );
/*
            auto_ptr<SocketAddressPosix> my_addr_posix ( new SocketAddressPosix (*(ike_sa.my_addr)) );
            IpAddress& src_ip = (IpAddress &) my_addr_posix->getIpAddress();

            auto_ptr<SocketAddressPosix> peer_addr_posix ( new SocketAddressPosix (*(ike_sa.peer_addr)) );
            IpAddress& dst_ip = (IpAddress &) peer_addr_posix->getIpAddress();

            // create iface with assigned address
            //string ifname;
            //int32_t tunfd = this->tunOpen( ifname );

            string ifname = src_ip.getIfaceName();
	    // Don't needed with autoconf.
            this->createAddress( *assigned_ipv6_address, ipv6_mask, ifname );
            auto_ptr<AddressConfiguration> address_configuration( new AddressConfiguration( AddressConfiguration::CONFIGURATION_IRAC , *this ) );
            //address_configuration->tun_fd = tunfd;
            address_configuration->ifname = ifname;
            address_configuration->assigned_address = assigned_ipv6_address->clone();
            address_configuration->assigned_prefixlen = ipv6_mask;

            // Create routes if INTERNAL_IP6_SUBNET is included
            ConfigurationAttribute* subnet = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP6_SUBNET );
            if ( subnet != NULL ) {
                ByteBuffer buffer( *subnet->value );
                auto_ptr<IpAddress> route_dst = this->getIpAddress( Enums::ADDR_IPV6, buffer.readByteArray( 16 ) );
                uint8_t route_mask = buffer.readInt8();
                //this->createRoute(*IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), *route_dst, route_mask,  *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, ifname );


		//this->deleteRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, dst_ip, 0, ifname);

		this->createRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV6), 0, dst_ip, 1, ifname);
	        this->createRoute( *assigned_ipv6_address, *route_dst, route_mask, *assigned_ipv6_address , 0, ifname );

		address_configuration->route_dst = route_dst->clone();
                address_configuration->route_prefixlen = route_mask;
                address_configuration->default_gw = auto_ptr<IpAddress> ( new IpAddressOpenIKE (dst_ip.toString()) );
            }

            ike_sa.attributemap->addAttribute( "address_configuration", auto_ptr<Attribute> ( address_configuration ) );
            */
        }

        // if we requested an IP4 address, try to find the response
        else if ( request_address == "ipv4" ) {
            ConfigurationAttribute* response = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP4_ADDRESS );

            if ( response == NULL ) {
                Log::writeLockedMessage( ike_sa.getLogId(), "No IPv4 address found in configuration response", Log::LOG_ERRO, true );
                return IkeSa::NEGOTIATION_ACTION_ERROR;
            }

            auto_ptr<IpAddress> assigned_ipv4_address ( this->getIpAddress( Enums::ADDR_IPV4, response->value->clone() ) );

            ConfigurationAttribute* response2 = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP4_NETMASK );

            if ( response2 == NULL ) {
                Log::writeLockedMessage( ike_sa.getLogId(), "No IPv4 netmask found in configuration response", Log::LOG_ERRO, true );
                return IkeSa::NEGOTIATION_ACTION_ERROR;
            }
            auto_ptr<ByteArray> assigned_ipv4_netmask = response2->value->clone();
            int16_t ipv4_mask = this->getPrefixLen(assigned_ipv4_netmask->clone());


            //ConfigurationAttribute* response3 = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_DEFAULT_GW );
            //
            //if ( response3 == NULL ) {
            //    Log::writeLockedMessage( ike_sa.getLogId(), "No IPv4 default gateway address found in configuration response", Log::LOG_ERRO, true );
            //    return IkeSa::NEGOTIATION_ACTION_ERROR;
            //}
            //
            //auto_ptr<IpAddress> assigned_ipv4_default_gw ( this->getIpAddress( Enums::ADDR_IPV4, response3->value->clone() ) );


            Log::writeLockedMessage( ike_sa.getLogId(), "Setting address configuration: Rol=[IRAC] Address=[" + assigned_ipv4_address->toString() + "/"+ assigned_ipv4_netmask->toString() + "]", Log::LOG_INFO, true );

            // create iface with assigned address
            auto_ptr<SocketAddressPosix> my_addr_posix ( new SocketAddressPosix (*(ike_sa.my_addr)) );
            IpAddress& src_ip = (IpAddress &) my_addr_posix->getIpAddress();
            string ifname = "";

            ifname = src_ip.getIfaceName();

            auto_ptr<SocketAddressPosix> peer_addr_posix ( new SocketAddressPosix (*(ike_sa.peer_addr)) );
            IpAddress& dst_ip = (IpAddress &) peer_addr_posix->getIpAddress();


            //int32_t tunfd = this->tunOpen( ifname );  // Pedro

            this->createAddress( *assigned_ipv4_address, ipv4_mask, ifname );
            auto_ptr<AddressConfiguration> address_configuration( new AddressConfiguration( AddressConfiguration::CONFIGURATION_IRAC, *this ) );
            //address_configuration->tun_fd = tunfd;
            address_configuration->ifname = ifname;
            address_configuration->assigned_address = assigned_ipv4_address->clone();
            address_configuration->assigned_prefixlen = ipv4_mask;
            //address_configuration->assigned_default_gw = assigned_ipv4_default_gw->clone();


            // Create routes if INTERNAL_IP4_SUBNET is included
            ConfigurationAttribute* subnet = payload_conf.getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP4_SUBNET );
            if ( subnet != NULL ) {
                ByteBuffer buffer( *subnet->value );
                auto_ptr<IpAddress> route_dst = this->getIpAddress( Enums::ADDR_IPV4, buffer.readByteArray( 4 ) );
                uint16_t route_mask = NetworkPrefix::getPrefixLen( *buffer.readByteArray( 4 ) );

                address_configuration->route_dst = route_dst->clone();
                address_configuration->route_prefixlen = route_mask;
                address_configuration->default_gw = auto_ptr<IpAddress> ( new IpAddressOpenIKE (dst_ip.toString()) );


                this->deleteRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4), 0, dst_ip, 0, ifname);
                this->createRoute( *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4), *IpAddressOpenIKE::getAnyAddr(Enums::ADDR_IPV4), 0, dst_ip, 1, ifname);
                this->createRoute( *assigned_ipv4_address, *route_dst, route_mask, *assigned_ipv4_address , 0, ifname );


            }
            ike_sa.attributemap->addAttribute( "address_configuration", auto_ptr<Attribute>( address_configuration ) );

        }

        else
            assert( 0 );

        return IkeSa::NEGOTIATION_ACTION_CONTINUE;
    }

    IkeSa::NEGOTIATION_ACTION NetworkControllerImplOpenIKE::processConfigurationRequest( Message& message, IkeSa & ike_sa ) {
        // Message must be IKE_AUTH request
        if ( !( message.exchange_type == Message::IKE_AUTH && message.message_type == Message::REQUEST ) )
            return IkeSa::NEGOTIATION_ACTION_CONTINUE;

        // Obtain the Configuration payload (if available)
        Payload_CONF* payload_conf = ( Payload_CONF* ) message.getFirstPayloadByType( Payload::PAYLOAD_CONF );
        if ( payload_conf == NULL )
            return IkeSa::NEGOTIATION_ACTION_CONTINUE;

        // Obtains the interesting attributes from the request
        ConfigurationAttribute* ipv6_request = payload_conf->getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP6_ADDRESS );
        ConfigurationAttribute* ipv4_request = payload_conf->getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP4_ADDRESS );
        ConfigurationAttribute* ipv4_netmask = payload_conf->getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_IP4_NETMASK );
        //ConfigurationAttribute* ipv4_default_gw = payload_conf->getFirstConfigurationAttributeByType( ConfigurationAttribute::INTERNAL_DEFAULT_GW );

        // If there is an IPv6 address request, then

        if ( ipv6_request != NULL ) {
            auto_ptr<ByteArray> assigned_ipv6_netmask = auto_ptr<ByteArray> (NULL);
            auto_ptr<IpAddress> assigned_ipv6_address ( this->generateIpv6Address( ike_sa, *ipv6_request,&assigned_ipv6_netmask ) );

            if ( assigned_ipv6_address.get() == NULL )
                return IkeSa::NEGOTIATION_ACTION_ERROR;

            Log::writeLockedMessage( ike_sa.getLogId(), "Setting IPv6 address configuration: Rol=[IRAS] Address=[" + assigned_ipv6_address->toString() + "]", Log::LOG_INFO, true );

            auto_ptr<AddressConfiguration> address_configuration ( new AddressConfiguration( AddressConfiguration::CONFIGURATION_IRAS , *this ) );
            address_configuration->assigned_address = assigned_ipv6_address->clone();
            address_configuration->assigned_netmask = assigned_ipv6_netmask->clone();
            ike_sa.attributemap->addAttribute( "address_configuration", auto_ptr<Attribute> ( address_configuration ) );


        }

        // Else if there is an IPv4 address request, then
        else if ( ipv4_request != NULL ) {
            auto_ptr<ByteArray> assigned_ipv4_netmask ( NULL );
            auto_ptr<IpAddress> assigned_ipv4_address ( this->generateIpv4Address( ike_sa, *ipv4_request, &assigned_ipv4_netmask ) );


            if ( assigned_ipv4_address.get() == NULL )
                return IkeSa::NEGOTIATION_ACTION_ERROR;


            Log::writeLockedMessage( ike_sa.getLogId(), "Setting IPv4 address configuration: Rol=[IRAS] Address=[" + assigned_ipv4_address->toString() + "] Netmask=[" + assigned_ipv4_netmask->toString() + "]" , Log::LOG_INFO, true );
            //pedro
            auto_ptr<AddressConfiguration> address_configuration ( new AddressConfiguration( AddressConfiguration::CONFIGURATION_IRAS , *this ) );
            address_configuration->assigned_address = assigned_ipv4_address->clone();
            address_configuration->assigned_netmask = assigned_ipv4_netmask->clone();
            address_configuration->assigned_prefixlen = this->getPrefixLen( assigned_ipv4_netmask->clone() );
            //address_configuration->assigned_default_gw = auto_ptr<IpAddress> ( ike_sa.getIkeSaConfiguration().attributemap->getAttribute<IpAddress>( "ipv4_default_gw" ) );

            ike_sa.attributemap->addAttribute( "address_configuration", auto_ptr<Attribute> ( address_configuration ) );
        }

        return IkeSa::NEGOTIATION_ACTION_CONTINUE;
    }

    void NetworkControllerImplOpenIKE::createConfigurationResponse( Message& message, IkeSa& ike_sa ) {
        // Message must be IKE_AUTH response
        if ( !( message.exchange_type == Message::IKE_AUTH && message.message_type == Message::RESPONSE ) )
            return;

        // Get the address configurations
        AddressConfiguration* address_configuration = ike_sa.attributemap->getAttribute<AddressConfiguration> ( "address_configuration" );

        // if no configuration has been realized, return
        if ( address_configuration == NULL )
            return;

        // creates the response payload conf
        auto_ptr<Payload_CONF> result( new Payload_CONF( Payload_CONF::CFG_REPLY ) );

        if ( address_configuration->assigned_address->getFamily() == Enums::ADDR_IPV6 ) {
            NetworkPrefix* protected_subnet = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "protected_ipv6_subnet" );
            if ( protected_subnet == NULL ) {
                Log::writeLockedMessage( "NetworkController", "Cannot find the protected IPv6 subnet attribute", Log::LOG_ERRO, true );
                return;
            }

            auto_ptr<ByteBuffer> buffer( new ByteBuffer( 17 ) );
            buffer->writeByteArray( *address_configuration->assigned_address->getBytes() );
            buffer->writeInt8( 128 );
            result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP6_ADDRESS, buffer->clone() ) ) );

            buffer->reset();
            buffer->writeByteArray( *protected_subnet->getNetworkAddress().getBytes() );
            buffer->writeInt8( protected_subnet->getPrefixLen() );
            result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP6_SUBNET, auto_ptr<ByteArray> ( buffer ) ) ) );
        }

        else if ( address_configuration->assigned_address->getFamily() == Enums::ADDR_IPV4 ) {
            result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP4_ADDRESS, address_configuration->assigned_address->getBytes() ) ) );
            result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP4_NETMASK, address_configuration->assigned_netmask ) ) );

            NetworkPrefix* protected_subnet = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( "protected_ipv4_subnet" );
            if ( protected_subnet == NULL ) {
                Log::writeLockedMessage( "NetworkController", "Cannot find the protected IPv4 subnet attribute", Log::LOG_ERRO, true );
                return;
            }

            auto_ptr<ByteBuffer> buffer( new ByteBuffer( 8 ) );
            buffer->writeByteArray( *protected_subnet->getNetworkAddress().getBytes() );
            buffer->writeByteArray( *protected_subnet->getMask() );
            result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_IP4_SUBNET, auto_ptr<ByteArray> ( buffer ) ) ) );
            //result->addConfigurationAttribute( auto_ptr<ConfigurationAttribute> ( new ConfigurationAttribute( ConfigurationAttribute::INTERNAL_DEFAULT_GW, address_configuration->assigned_default_gw->getBytes() ) ) );

        }
        else
            assert( 0 );

        message.addPayload( auto_ptr<Payload> ( result ), true );
    }

    auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv6Address( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask) {
        StringAttribute * configuration_method = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<StringAttribute>( "configuration_method" );

        if ( configuration_method == NULL ) {
            Log::writeLockedMessage( "NetworkController", "Cannot find the configuration method to be used", Log::LOG_ERRO, true );
            return auto_ptr<IpAddress> ( NULL );
        }

        if ( configuration_method->value == "fixed" ){
            return this->generateIpv6AddressFixed( ike_sa, attribute, netmask );
        }
        else if ( configuration_method->value == "autoconf" ){
            return this->generateIpv6AddressAutoconf( ike_sa, attribute, netmask );
        }

        return auto_ptr<IpAddress> ( NULL );
    }

    auto_ptr<IpAddress> NetworkControllerImplOpenIKE::generateIpv4Address( IkeSa& ike_sa, ConfigurationAttribute& attribute, auto_ptr<ByteArray> *netmask ) {
        StringAttribute * configuration_method = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<StringAttribute>( "configuration_method" );

        if ( configuration_method == NULL ) {
            Log::writeLockedMessage( "NetworkController", "Cannot find the configuration method to be used", Log::LOG_ERRO, true );
            return auto_ptr<IpAddress> ( NULL );
        }

        if ( configuration_method->value == "dhcp" )
            return this->generateIpv4AddressDhcp( ike_sa, attribute, netmask );
        else if ( configuration_method->value == "fixed" )
            return this->generateIpv4AddressFixed( ike_sa, attribute, netmask );

        return auto_ptr<IpAddress> ( NULL );
    }



    auto_ptr<Message> NetworkControllerImplOpenIKE::receive( ) {
        auto_ptr<SocketAddress> src_addr;
        auto_ptr<SocketAddress> dst_addr;

        // Receive from UdpSocket
        auto_ptr<ByteArray> message_data = this->udp_socket->receive( src_addr, dst_addr );

        ByteBuffer byte_buffer( *message_data );

        return auto_ptr<Message> ( new Message( src_addr, dst_addr, byte_buffer ) );
    }

    void NetworkControllerImplOpenIKE::sendMessage( Message & message, Cipher* cipher ) {
        this->udp_socket->send( message.getSrcAddress(), message.getDstAddress(), message.getBinaryRepresentation( cipher ) );
    }


    void NetworkControllerImplOpenIKE::addSrcAddress( auto_ptr< IpAddress > new_src_address ) {
        this->udp_socket->bind( SocketAddressPosix( new_src_address, 500 ) );
    }

    void NetworkControllerImplOpenIKE::removeSrcAddress( const IpAddress& src_address ) {
        this->udp_socket->unbind( SocketAddressPosix( src_address.clone(), 500 ) );
    }

    void NetworkControllerImplOpenIKE::run( ) {
        auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();
        Log::writeLockedMessage( "NetworkController", "Start: Thread ID=[" + intToString( thread_id ) +
         "] Cookie Threshold=[" + intToString( general_conf->cookie_threshold ) +
         " half-opened IKE SAs] Max. Cookie Time=[" + intToString( general_conf->cookie_lifetime ) + " seconds]", Log::LOG_THRD, true );

        // Do forever (until a thread cancel received)
        while ( !exiting ) {
            try {
                // Waits for receive a message
                auto_ptr<Message> received_message = this->receive();

    	        //For mobility protection

		auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

		BoolAttribute* is_ha_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "is_ha" );
		bool is_ha = false;
		if (is_ha_attr  != NULL )
		    is_ha = is_ha_attr->value;

		BoolAttribute* mobility_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "mobility" );
		bool mobility = false;
		if (mobility_attr  != NULL )
		    mobility = mobility_attr->value;

		auto_ptr<SocketAddress> hoa (NULL);
		auto_ptr<SocketAddress>	coa (NULL);
		uint64_t our_spi = 0;

		if ( received_message->exchange_type == Message::IKE_SA_INIT && received_message->message_type == Message::REQUEST ){
		        Log::writeLockedMessage( "NetworkController", "Mobility: receiving IKE_SA_INIT request...", Log::LOG_WARN, true );

		        if ( mobility ) {

		            auto_ptr<IpAddress> addr (new IpAddressOpenIKE( "0::0" ));
		            hoa.reset ( new SocketAddressPosix(addr,500) );

	                    if ( ! is_ha ){
	                        coa = received_message->dst_addr->clone();
	                    }
	                    else {
	                        coa = received_message->src_addr->clone();
	                    }

		        }


			// if the threadcontroller is exiting, then omit new IKE_SA creation
			if ( exiting ) {
				Log::writeLockedMessage( "NetworkController", "Cannot create any IKE_SA because we are exiting.", Log::LOG_ERRO, true );
				continue;
			}

			// Increments the next SPI value to be used
			our_spi = IkeSaController::nextSpi();

			// Create a new IkeSa, if mobility it will be based on CoA
			auto_ptr<IkeSa> ike_sa( new IkeSa( our_spi,
					   false,
					   received_message->getDstAddress().clone(),
					   received_message->getSrcAddress().clone()
					   )
					);
			ike_sa->peer_spi = received_message->spi_i;


			if (mobility){
				ike_sa->care_of_address = coa;
				ike_sa->home_address = hoa; // Dummy value
			}

			// increments the half-open counter
			IkeSaController::incHalfOpenCounter();

			// adds this controller to the collection
			IkeSaController::addIkeSa( ike_sa );


		}
		else if ( received_message->exchange_type == Message::IKE_SA_INIT && received_message->message_type == Message::RESPONSE ){
		        Log::writeLockedMessage( "NetworkController", "Mobility: receiving IKE_SA_INIT response...", Log::LOG_WARN, true );


 			// gets our SPI value from the message
                	our_spi = received_message->is_initiator ? received_message->spi_r : received_message->spi_i;

		}
		else if ( received_message->exchange_type == Message::IKE_AUTH && received_message->message_type == Message::REQUEST ){
		        Log::writeLockedMessage( "NetworkController", "Mobility: receiving IKE_AUTH request...", Log::LOG_WARN, true );

			// gets our SPI value from the message
                	our_spi = received_message->is_initiator ? received_message->spi_r : received_message->spi_i;


		}
		else if ( received_message->exchange_type == Message::IKE_AUTH && received_message->message_type == Message::RESPONSE ){
		        Log::writeLockedMessage( "NetworkController", "Mobility: receiving IKE_AUTH response...", Log::LOG_WARN, true );


			// gets our SPI value from the message
                    Log::writeLockedMessage( "NetworkController", "Debug -FERNANDO 0", Log::LOG_WARN, true );
                	our_spi = received_message->is_initiator ? received_message->spi_r : received_message->spi_i;
                    Log::writeLockedMessage( "NetworkController", "Debug -FERNANDO 1", Log::LOG_WARN, true );

           if (mobility){

                        IkeSa* ike_sa = IkeSaController::getIkeSaByIkeSaSpi( our_spi );
			            ike_sa->my_addr = ike_sa->home_address->clone();

                        Log::writeLockedMessage( "NetworkController", "Mobility: Changing CoA to HoA in received message.", Log::LOG_WARN, true );
                        if ( ! is_ha ){
                            coa = received_message->dst_addr->clone();
                            received_message->dst_addr = ike_sa->home_address->clone();
                        }
                        else {
                            coa = received_message->src_addr->clone();
                            received_message->src_addr = ike_sa->home_address->clone();
                        }
		     }

		}
		else {
		        Log::writeLockedMessage( "NetworkController", "Mobility: receiving further exchanges...", Log::LOG_WARN, true );

		        if ( mobility ) {

		           /* StringAttribute* string_attr = general_conf->attributemap->getAttribute<StringAttribute>( "home_address" );
		            if (string_attr!=NULL ){
		                auto_ptr<IpAddress> addr (new IpAddressOpenIKE( string_attr->value ));
		                hoa.reset ( new SocketAddressPosix(addr,500) );*/

				// gets our SPI value from the message
                		our_spi = received_message->is_initiator ? received_message->spi_r : received_message->spi_i;
				IkeSa* ike_sa = IkeSaController::getIkeSaByIkeSaSpi( our_spi );

		                if ((received_message->exchange_type == Message::IKE_SA_INIT) || (received_message->exchange_type == Message::IKE_AUTH) ){
		                    Log::writeLockedMessage( "NetworkController", "Mobility: Changing CoA to HoA in received message.", Log::LOG_WARN, true );
		                    if ( ! is_ha ){
		                    	Log::writeLockedMessage( "NetworkController", "Debug 1", Log::LOG_WARN, true );

		                        coa = received_message->dst_addr->clone();

		                    	Log::writeLockedMessage( "NetworkController", "Debug 2", Log::LOG_WARN, true );

		                        received_message->dst_addr = ike_sa->home_address->clone();;

		                    	Log::writeLockedMessage( "NetworkController", "Debug 3", Log::LOG_WARN, true );

		                    }
		                    else {

		                    	Log::writeLockedMessage( "NetworkController", "Debug 4", Log::LOG_WARN, true );
		                        coa = received_message->src_addr->clone();

		                    	Log::writeLockedMessage( "NetworkController", "Debug 5", Log::LOG_WARN, true );
		                        received_message->src_addr = ike_sa->home_address->clone();;

		                    	Log::writeLockedMessage( "NetworkController", "Debug 6", Log::LOG_WARN, true );
		                    }
		                }
		                else {
		                   Log::writeLockedMessage( "NetworkController", "Mobility: NOT CHANGING CoA for HoA.", Log::LOG_WARN, true );
		                }
		            /*}*/
		        }
		                    	Log::writeLockedMessage( "NetworkController", "Debug 7", Log::LOG_WARN, true );

 			// gets our SPI value from the message
                	our_spi = received_message->is_initiator ? received_message->spi_r : received_message->spi_i;
		                    	Log::writeLockedMessage( "NetworkController", "Debug 8", Log::LOG_WARN, true );

		}


                Log::writeLockedMessage( "NetworkController", "Debug -FERNANDO 2", Log::LOG_WARN, true );
                // creates a new MessageCommand and push it to the properly IkeSa
                auto_ptr<IpAddress> src_addr = received_message->getSrcAddress().getIpAddress().clone();
		                    	Log::writeLockedMessage( "NetworkController", "Debug 9", Log::LOG_WARN, true );
                auto_ptr<Command> message_command( new MessageReceivedCommand( received_message->clone() ) );
		                    	Log::writeLockedMessage( "NetworkController", "Debug 10", Log::LOG_WARN, true );
                bool result = IkeSaController::pushCommandByIkeSaSpi( our_spi, message_command, false );

		                    	Log::writeLockedMessage( "NetworkController", "Debug 11", Log::LOG_WARN, true );
                    // If no controller is found, then show warning message
                if ( !result ) {
		                    	Log::writeLockedMessage( "NetworkController", "Debug 12", Log::LOG_WARN, true );
                    Log::writeLockedMessage( "NetworkController", "Message to an unknown IKE SA with SPI=" + Printable::toHexString( &our_spi, 8 ) + " Source Addr=[" + src_addr->toString() + "]", Log::LOG_WARN, true );
                    if ( received_message->message_type == Message::REQUEST )
                        this->send_INVALID_IKE_SPI( *received_message );
                }
		                    	Log::writeLockedMessage( "NetworkController", "Debug 13", Log::LOG_WARN, true );

            }
            catch ( Exception & ex ) {
                Log::writeLockedMessage( "NetworkController", ex.what() , Log::LOG_ERRO, true );
            }
        }
    }

    void NetworkControllerImplOpenIKE::send_INVALID_IKE_SPI( Message& received_message ) {
            // Creates a new Message (we are responders)
        Message message( received_message.getDstAddress().clone(),
           received_message.getSrcAddress().clone(),
           received_message.spi_i,
           received_message.spi_r,
           2,
           0,
           received_message.exchange_type,
                             Message::RESPONSE,                                           // IS RESPONSE ALLWAYS
                             !received_message.is_initiator,
                             false,                                                       // cannot use major version
                             received_message.message_id
                             );

        uint64_t our_spi = received_message.is_initiator ? received_message.spi_r : received_message.spi_i;

        auto_ptr<Payload> notify( new Payload_NOTIFY( Payload_NOTIFY::INVALID_IKE_SPI, Enums::PROTO_NONE ) );

        message.addPayload( notify, false );

        this->sendMessage( message, NULL );

        Log::acquire();
        Log::writeMessage( "NetworkController", "Send: INVALID_IKE_SPI=" + Printable::toHexString( &our_spi, 8 ), Log::LOG_MESG, true );
        Log::writeMessage( "NetworkController", message.toStringTab( 1 ), Log::LOG_MESG, false );
        Log::release();
    }


int16_t NetworkControllerImplOpenIKE::getPrefixLen(auto_ptr<ByteArray> prefix) {
    int prefix_len = 0;
    for (int i = 0; i < 4; i++){
        if ( (*prefix)[i] == 0xFF ){
        	prefix_len += 8;
        }
        else {
            switch ((*prefix)[i]){
               case 0xFE: prefix_len += 7; break;
               case 0xFC: prefix_len += 6; break;
               case 0xF8: prefix_len += 5; break;
               case 0xF0: prefix_len += 4; break;
               case 0xE0: prefix_len += 3; break;
               case 0xC0: prefix_len += 2; break;
               case 0x80: prefix_len += 1; break;
           }
       }
   }
   return prefix_len;
}


void NetworkControllerImplOpenIKE::startRadvd() {
#ifdef EAP_SERVER_ENABLED
        // start radvd stuff if enabled

	auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

	bool radvd_enabled = false;
	BoolAttribute* radvd_enabled_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "radvd_enabled" );
    if (radvd_enabled_attr  != NULL )
        radvd_enabled = radvd_enabled_attr->value;

    string radvd_config_file = "none";
    StringAttribute* radvd_config_file_attr = general_conf->attributemap->getAttribute<StringAttribute>( "radvd_config_file" );
    if ( radvd_config_file_attr != NULL )
        radvd_config_file = radvd_config_file_attr->value;

    if (radvd_enabled) {
            // Setup the radvd infrastructure

            //radvd = new RadvdWrapper( "/etc/radvd.conf" );
        radvd = new RadvdWrapper( radvd_config_file );
        Log::writeLockedMessage( "NetworkController", "Radvd enabled.", Log::LOG_INFO, true );
    }

        //end radvd stuff
#endif
}


void NetworkControllerImplOpenIKE::exit() {
    this->exiting = true;
}
}












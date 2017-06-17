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
#include "dhcpclient.h"
#include "randomopenssl.h"
#include "ipaddressopenike.h"

#include <ifaddrs.h>
#include <libopenikev2/log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <libopenikev2/utils.h>

#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/senddeleteikesareqcommand.h>

#include <libopenikev2/stringattribute.h>
#include <libopenikev2/int32attribute.h>

namespace openikev2 {


    /* supported options are easily added here */

    struct dhcp_option options[] = {
                                       /* name[10]       flags                                   code   */
                                       {"subnet", OPTION_IP | OPTION_REQ, 0x01},
                                       {"timezone", OPTION_S32, 0x02},
                                       {"router", OPTION_IP | OPTION_LIST | OPTION_REQ, 0x03},
                                       {"timesvr", OPTION_IP | OPTION_LIST, 0x04},
                                       {"namesvr", OPTION_IP | OPTION_LIST, 0x05},
                                       {"dns", OPTION_IP | OPTION_LIST | OPTION_REQ, 0x06},
                                       {"logsvr", OPTION_IP | OPTION_LIST, 0x07},
                                       {"cookiesvr", OPTION_IP | OPTION_LIST, 0x08},
                                       {"lprsvr", OPTION_IP | OPTION_LIST, 0x09},
                                       {"hostname", OPTION_STRING | OPTION_REQ, 0x0c},
                                       {"bootsize", OPTION_U16, 0x0d},
                                       {"domain", OPTION_STRING | OPTION_REQ, 0x0f},
                                       {"swapsvr", OPTION_IP, 0x10},
                                       {"rootpath", OPTION_STRING, 0x11},
                                       {"ipttl", OPTION_U8, 0x17},
                                       {"mtu", OPTION_U16, 0x1a},
                                       {"broadcast", OPTION_IP | OPTION_REQ, 0x1c},
                                       {"ntpsrv", OPTION_IP | OPTION_LIST, 0x2a},
                                       {"wins", OPTION_IP | OPTION_LIST, 0x2c},
                                       {"requestip", OPTION_IP, 0x32},
                                       {"lease", OPTION_U32, 0x33},
                                       {"dhcptype", OPTION_U8, 0x35},
                                       {"serverid", OPTION_IP, 0x36},
                                       {"message", OPTION_STRING, 0x38},
                                       {"tftp", OPTION_STRING, 0x42},
                                       {"bootfile", OPTION_STRING, 0x43},
                                       {"", 0x00, 0x00}
                                   };

    /* Lengths of the different option types */
    int option_lengths[] = {
                               -1,          // OPTION_IP
                               4,           // OPTION_IP_PAIR
                               8,           // OPTION_BOOLEAN
                               1,           // OPTION_STRING
                               1,           // OPTION_U8
                               1,           // OPTION_U16
                               2,           // OPTION_S16
                               2,           // OPTION_U32
                               4,           // OPTION_S32
                               4    //
                           };

    int32_t DhcpClient::createRawSocket( ) {
        int32_t fd;
        struct sockaddr_ll sock;

        memset(&sock, 0, sizeof(sockaddr_ll));

        if ( ( fd = socket( PF_PACKET, SOCK_DGRAM, htons( ETH_P_IP ) ) ) < 0 )
            throw NetworkException ( "DhcpClient: socket call failed" );

        sock.sll_family = AF_PACKET;
        sock.sll_protocol = htons( ETH_P_IP );
        sock.sll_ifindex = this->dhcp_ifindex;

        if ( bind( fd, ( struct sockaddr * ) & sock, sizeof( sock ) ) < 0 ) {
            close( fd );
            throw NetworkException( "DhcpClient: bind call failed" );
        }

        return fd;
    }

    uint16_t DhcpClient::checksum( void * addr, int32_t count ) {
        /* Compute Internet Checksum for "count" bytes
         *         beginning at location "addr".
         */
        register int32_t sum = 0;
        u_int16_t *source = ( u_int16_t * ) addr;

        while ( count > 1 ) {
            /*  This is the inner loop */
            sum += *source++;
            count -= 2;
        }

        /*  Add left-over byte, if any */
        if ( count > 0 ) {
            /* Make sure that the left-over byte is added correctly both
             * with little and big endian hosts */
            u_int16_t tmp = 0;
            *( unsigned char * ) ( &tmp ) = * ( unsigned char * ) source;
            sum += tmp;
        }
        /*  Fold 32-bit sum to 16 bits */
        while ( sum >> 16 )
            sum = ( sum & 0xffff ) + ( sum >> 16 );

        return ~sum;
    }

    int32_t DhcpClient::sendRawPacket( DhcpMessage & dhcp_message ) {
        int fd;
        int result;
        struct sockaddr_ll dest;
        struct UdpDhcpPacket packet;
        memset( &dest, 0, sizeof( dest ) );
        memset( &packet, 0, sizeof( packet ) );

        if ( ( fd = socket( PF_PACKET, SOCK_DGRAM, htons( ETH_P_IP ) ) ) < 0 )
            throw NetworkException( "DhcpClient: sending socket call failed" );

        dest.sll_family = AF_PACKET;
        dest.sll_protocol = htons( ETH_P_IP );
        dest.sll_ifindex = this->dhcp_ifindex;
        dest.sll_halen = 6;
        memset( dest.sll_addr, 0xFF, 6 );   // broadcast mac address

        if ( bind( fd, ( struct sockaddr * ) & dest, sizeof( struct sockaddr_ll ) ) < 0 ) {
            close( fd );
            throw NetworkException( "DhcpClient: sending bind call failed" );
        }

        packet.ip.protocol = IPPROTO_UDP;
        memset( &packet.ip.saddr, 0, 4 );
        memset( &packet.ip.daddr, 0xFF, 4 );
        packet.udp.source = htons( CLIENT_PORT );
        packet.udp.dest = htons( SERVER_PORT );
        packet.udp.len = htons( sizeof( packet.udp ) + sizeof( struct DhcpMessage ) ); /* cheat on the psuedo-header */
        packet.ip.tot_len = packet.udp.len;
        memcpy( &( packet.data ), &dhcp_message, sizeof( struct DhcpMessage ) );
        packet.udp.check = checksum( &packet, sizeof( struct UdpDhcpPacket ) );

        packet.ip.tot_len = htons( sizeof( struct UdpDhcpPacket ) );
        packet.ip.ihl = sizeof( packet.ip ) >> 2;
        packet.ip.version = IPVERSION;
        packet.ip.ttl = IPDEFTTL;
        packet.ip.check = checksum( &( packet.ip ), sizeof( packet.ip ) );

        result = sendto( fd, &packet, sizeof( struct UdpDhcpPacket ), 0, ( struct sockaddr * ) & dest, sizeof( dest ) );
        if ( result <= 0 ) {
            close( fd );
            throw NetworkException( "DhcpClient: write on socket failed" );
        }

        close( fd );
        return result;
    }

    int32_t DhcpClient::endOption( uint8_t * optionptr ) {
        int i = 0;

        while ( optionptr[ i ] != DHCP_END ) {
            if ( optionptr[ i ] == DHCP_PADDING )
                i++;
            else
                i += optionptr[ i + OPT_LEN ] + 2;
        }
        return i;
    }

    int32_t DhcpClient::addOptionString( uint8_t * optionptr, uint8_t * string ) {
        int end = endOption( optionptr );

        /* end position + string length + option code/length + end option */
        if ( end + string[ OPT_LEN ] + 2 + 1 >= 308 ) {
            Log::writeLockedMessage( "DhcpClient", "Option did not fit into the packet!", Log::LOG_DHCP, true );
            return 0;
        }
        memcpy( optionptr + end, string, string[ OPT_LEN ] + 2 );
        optionptr[ end + string[ OPT_LEN ] + 2 ] = DHCP_END;
        return string[ OPT_LEN ] + 2;
    }

    int32_t DhcpClient::addSimpleOption( uint8_t * optionptr, uint8_t code, uint32_t data ) {
        char length = 0;
        int i;
        unsigned char option[ 2 + 4 ];
        unsigned char *u8;
        u_int16_t *u16;
        u_int32_t *u32;
        u_int32_t aligned;
        u8 = ( unsigned char * ) & aligned;
        u16 = ( u_int16_t * ) & aligned;
        u32 = &aligned;

        for ( i = 0; options[ i ].code; i++ )
            if ( options[ i ].code == code ) {
                length = option_lengths[ options[ i ].flags & TYPE_MASK ];
            }

        if ( !length ) {
            Log::writeLockedMessage( "DhcpClient", "Could not add option: " + intToString( code ), Log::LOG_DHCP, true );
            return 0;
        }

        option[ OPT_CODE ] = code;
        option[ OPT_LEN ] = length;

        switch ( length ) {
            case 1:
                *u8 = data;
                break;
            case 2:
                *u16 = data;
                break;
            case 4:
                *u32 = data;
                break;
        }
        memcpy( option + 2, &aligned, length );
        return addOptionString( optionptr, option );
    }

    void DhcpClient::initHeader( DhcpMessage * packet, uint8_t type ) {
        memset( packet, 0, sizeof( struct DhcpMessage ) );
        switch ( type ) {
            case DHCPDISCOVER:
            case DHCPREQUEST:
            case DHCPRELEASE:
            case DHCPINFORM:
                packet->op = BOOTREQUEST;
                break;
            case DHCPOFFER:
            case DHCPACK:
            case DHCPNAK:
                packet->op = BOOTREPLY;
        }
        packet->htype = ETH_10MB;
        packet->hlen = ETH_10MB_LEN;
        packet->cookie = htonl( DHCP_MAGIC );
        packet->options[ 0 ] = DHCP_END;
        addSimpleOption( packet->options, DHCP_MESSAGE_TYPE, type );
    }

    void DhcpClient::initPacket( DhcpMessage * packet, uint8_t type ) {
        struct vendor {
            char vendor, length;
            char str[ sizeof( "openikev2" ) ];
        }
        vendor_id = { DHCP_VENDOR, sizeof( "openikev2" ) - 1, "openikev2"};

        initHeader( packet, type );
        memcpy( packet->chaddr, this->mac_addr, 6 );
        addOptionString( packet->options, this->clientid->getRawPointer() );

        addOptionString( packet->options, ( unsigned char * ) & vendor_id );
    }

    void DhcpClient::addRequests( DhcpMessage * packet ) {
        int end = endOption( packet->options );
        int i, len = 0;

        packet->options[ end + OPT_CODE ] = DHCP_PARAM_REQ;
        for ( i = 0; options[ i ].code; i++ )
            if ( options[ i ].flags & OPTION_REQ )
                packet->options[ end + OPT_DATA + len++ ] = options[ i ].code;
        packet->options[ end + OPT_LEN ] = len;
        packet->options[ end + OPT_DATA + len ] = DHCP_END;

    }

    int32_t DhcpClient::readMac( string interface, uint8_t * macaddr ) {
        int fd;
        struct ifreq ifr;
        int rc = 0;

        memset( &ifr, 0, sizeof( struct ifreq ) );
        if ( ( fd = socket( AF_INET, SOCK_RAW, IPPROTO_RAW ) ) >= 0 ) {
            ifr.ifr_addr.sa_family = AF_INET;
            strcpy( ifr.ifr_name, interface.c_str() );

            if ( ioctl( fd, SIOCGIFHWADDR, &ifr ) == 0 ) {
                memcpy( macaddr, ifr.ifr_hwaddr.sa_data, 6 );
            } else {
                Log::writeLockedMessage( "DhcpClient", "SIOCGIFHWADDR failed!", Log::LOG_DHCP, true );
                rc = -1;
            }
        } else {
            Log::writeLockedMessage( "DhcpClient", "Socket failed!", Log::LOG_DHCP, true );
            rc = -1;
        }
        close( fd );
        return rc;
    }

    int32_t DhcpClient::sendDhcpDiscover( uint64_t xid, uint32_t requested ) {
        struct DhcpMessage packet;

        initPacket( &packet, DHCPDISCOVER );
        packet.xid = xid;
        if ( requested )
            addSimpleOption( packet.options, DHCP_REQUESTED_IP, requested );

        addRequests( &packet );

        return this->sendRawPacket( packet );
    }


    /* get an option with bounds checking (warning, not aligned). */
    uint8_t * DhcpClient::getOption( DhcpMessage * packet, int32_t code ) {
        int i, length;
        unsigned char *optionptr;
        int over = 0, done = 0, curr = OPTION_FIELD;

        optionptr = packet->options;
        i = 0;
        length = 308;
        while ( !done ) {
            if ( i >= length ) {
                Log::writeLockedMessage( "DhcpClient", "bogus packet, option fields too long", Log::LOG_DHCP, true );
                return NULL;
            }
            if ( optionptr[ i + OPT_CODE ] == code ) {
                if ( i + 1 + optionptr[ i + OPT_LEN ] >= length ) {
                    Log::writeLockedMessage( "DhcpClient", "bogus packet, option fields too long", Log::LOG_DHCP, true );
                    return NULL;
                }
                return optionptr + i + 2;
            }
            switch ( optionptr[ i + OPT_CODE ] ) {
                case DHCP_PADDING:
                    i++;
                    break;
                case DHCP_OPTION_OVER:
                    if ( i + 1 + optionptr[ i + OPT_LEN ] >= length ) {
                        Log::writeLockedMessage( "DhcpClient", "bogus packet, option fields too long", Log::LOG_DHCP, true );
                        return NULL;
                    }
                    over = optionptr[ i + 3 ];
                    i += optionptr[ OPT_LEN ] + 2;
                    break;
                case DHCP_END:
                    if ( curr == OPTION_FIELD && over & FILE_FIELD ) {
                        optionptr = packet->file;
                        i = 0;
                        length = 128;
                        curr = FILE_FIELD;
                    } else if ( curr == FILE_FIELD && over & SNAME_FIELD ) {
                        optionptr = packet->sname;
                        i = 0;
                        length = 64;
                        curr = SNAME_FIELD;
                    } else
                        done = 1;
                    break;
                default:
                    i += optionptr[ OPT_LEN + i ] + 2;
            }
        }
        return NULL;
    }

    int32_t DhcpClient::getRawPacket( DhcpMessage * payload, int32_t fd ) {
        int bytes;
        struct UdpDhcpPacket packet;
        u_int32_t source, dest;
        u_int16_t check;

        memset( &packet, 0, sizeof( struct UdpDhcpPacket ) );
        bytes = read( fd, &packet, sizeof( struct UdpDhcpPacket ) );
        if ( bytes < 0 ) {
            Log::writeLockedMessage( "DhcpClient", "couldn't read on raw listening socket -- ignoring", Log::LOG_DHCP, true );
            usleep( 500000 ); /* possible down interface, looping condition */
            return -1;
        }

        if ( bytes < ( int ) ( sizeof( struct iphdr ) + sizeof( struct udphdr ) ) ) {
            Log::writeLockedMessage( "DhcpClient", "message too short, ignoring", Log::LOG_DHCP, true );
            return -2;
        }

        if ( bytes < ntohs( packet.ip.tot_len ) ) {
            Log::writeLockedMessage( "DhcpClient", "Truncated packet", Log::LOG_DHCP, true );
            return -2;
        }

        /* ignore any extra garbage bytes */
        bytes = ntohs( packet.ip.tot_len );

        /* Make sure its the right packet for us, and that it passes sanity checks */
        if ( packet.ip.protocol != IPPROTO_UDP || packet.ip.version != IPVERSION ||
                packet.ip.ihl != sizeof( packet.ip ) >> 2 || packet.udp.dest != htons( CLIENT_PORT ) ||
                bytes > ( int ) sizeof( struct UdpDhcpPacket ) ||
                ntohs( packet.udp.len ) != ( short ) ( bytes - sizeof( packet.ip ) ) ) {

            return -2;
        }

        /* check IP checksum */
        check = packet.ip.check;
        packet.ip.check = 0;
        if ( check != checksum( &( packet.ip ), sizeof( packet.ip ) ) ) {
            Log::writeLockedMessage( "DhcpClient", "ubad IP header checksum, ignoring", Log::LOG_DHCP, true );
            return -1;
        }

        /* verify the UDP checksum by replacing the header with a psuedo header */
        source = packet.ip.saddr;
        dest = packet.ip.daddr;
        check = packet.udp.check;
        packet.udp.check = 0;
        memset( &packet.ip, 0, sizeof( packet.ip ) );

        packet.ip.protocol = IPPROTO_UDP;
        packet.ip.saddr = source;
        packet.ip.daddr = dest;
        packet.ip.tot_len = packet.udp.len; /* cheat on the psuedo-header */
        if ( check && check != checksum( &packet, bytes ) ) {
            Log::writeLockedMessage( "DhcpClient", "packet with bad UDP checksum received, ignoring", Log::LOG_DHCP, true );
            return -2;
        }

        memcpy( payload, &( packet.data ), bytes - ( sizeof( packet.ip ) + sizeof( packet.udp ) ) );

        if ( ntohl( payload->cookie ) != DHCP_MAGIC ) {
            Log::writeLockedMessage( "DhcpClient", "received bogus message (bad magic) -- ignoring", Log::LOG_DHCP, true );
            return -2;
        }

        return bytes - ( sizeof( packet.ip ) + sizeof( packet.udp ) );
    }

    /* Broadcasts a DHCP request message */

    int32_t DhcpClient::sendSelecting( uint64_t xid, uint8_t *server, uint8_t* requested ) {
        struct DhcpMessage packet;
        struct in_addr addr;

        initPacket( &packet, DHCPREQUEST );
        packet.xid = xid;

        uint32_t iserver, irequested;
        memcpy( &iserver, server, 4 );
        memcpy( &irequested, requested, 4 );

        addSimpleOption( packet.options, DHCP_REQUESTED_IP, irequested );
        addSimpleOption( packet.options, DHCP_SERVER_ID, iserver );

        addRequests( &packet );
        addr.s_addr = irequested;

        return this->sendRawPacket( packet );
    }



    DhcpClient::DhcpClient( IkeSa& ike_sa ) {
        this->spi = ike_sa.my_spi;

        StringAttribute* ifname_string = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<StringAttribute>( "dhcp_interface" );
        if ( ifname_string != NULL )
            this->readMac( ifname_string->value, this->mac_addr );
        this->dhcp_ifindex = if_nametoindex( ifname_string->value.c_str() );

        Int32Attribute* dhcp_retries = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<Int32Attribute>( "dhcp_retries" );
        Int32Attribute* dhcp_timeout = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<Int32Attribute>( "dhcp_timeout" ) ;
        IpAddress* dhcp_server_ip = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<IpAddress>( "dhcp_server_ip" );

        this->dhcp_retries = ( dhcp_retries != NULL ) ? dhcp_retries->value : 3;
        this->dhcp_timeout = ( dhcp_timeout != NULL ) ? dhcp_timeout->value : 3;
        this->dhcp_server_ip = ( dhcp_server_ip != NULL ) ? dhcp_server_ip->clone() : auto_ptr<IpAddress> ( NULL );

        auto_ptr<ByteBuffer> client_id_buffer ( new ByteBuffer( 3 + ike_sa.peer_id->id_data->size() ) );
        client_id_buffer->writeInt8( DHCP_CLIENT_ID );  // OPT_CODE
        client_id_buffer->writeInt8( ike_sa.peer_id->id_data->size() + 1 );    // OPT_LEN
        client_id_buffer->writeInt8( 0 );   // OPT_DATA
        client_id_buffer->writeByteArray( *ike_sa.peer_id->id_data );
        this->clientid = client_id_buffer;

        RandomOpenSSL random;
        this->xid = random.getRandomInt64( 0, 0xFFFFFFFF );

        this->alarm.reset( new Alarm( *this, 1 ) );
        AlarmController::addAlarm( *this->alarm );

        EventBus::getInstance().registerBusObserver( *this, BusEventIkeSa::IKE_SA_EVENT );
    }


    DhcpClient::~DhcpClient() {
        EventBus::getInstance().removeBusObserver( *this );
        AlarmController::removeAlarm( *this->alarm );
    }

    auto_ptr<IpAddress> DhcpClient::requestAddress(uint32_t &netmask) {
        if ( !this->performDiscover() ) {
	    netmask = 0;
            return auto_ptr<IpAddress> ( NULL );
        }

        return this->performRequest(netmask);
    }

    auto_ptr<Attribute> DhcpClient::cloneAttribute( ) const{
        assert( 0 );
    }

    void DhcpClient::notifyAlarm( Alarm& alarm ) {
        uint32_t subnet;

	auto_ptr<IpAddress> rv = this->performRequest(subnet);

        if ( rv.get() == NULL )
            IkeSaController::pushCommandByIkeSaSpi( this->spi, auto_ptr<Command> ( new SendDeleteIkeSaReqCommand() ), true );
    }

    void DhcpClient::notifyBusEvent( const BusEvent & event ) {
        if ( event.type == BusEvent::IKE_SA_EVENT ) {
            BusEventIkeSa & busevent = ( BusEventIkeSa& ) event;

            if ( busevent.ike_sa.my_spi != this->spi )
                return ;

            if ( busevent.ike_sa_event_type == BusEventIkeSa::IKE_SA_REKEYED ) {
                this->spi = ( ( IkeSa* ) busevent.data ) ->my_spi;
            }
        }
    }

    string DhcpClient::toStringTab( uint8_t tabs ) const {
        return "DHCP_CLIENT";
    }

    bool DhcpClient::performDiscover() {
        DhcpMessage packet;
        uint8_t *message;
        fd_set fdset;
        timeval timeout;

        int32_t fd = this->createRawSocket( );

        FD_ZERO( &fdset );
        FD_SET( fd, &fdset );

        int32_t retries = this->dhcp_retries;
        int32_t timeout_sec = this->dhcp_timeout;

        bool step_ok = false;

        // send DISCOVER and receive OFFER
        Log::writeLockedMessage( "DhcpClient", "Sending DHCP_DISCOVER..", Log::LOG_DHCP, true );
        while ( !step_ok ) {
            timeout.tv_sec = timeout_sec;
            timeout.tv_usec = 0;

            // Sends discover
            this->sendDhcpDiscover( xid, 0 );

            while ( true ) {
                FD_ZERO( &fdset );
                FD_SET( fd, &fdset );
                int32_t rv = select( FD_SETSIZE, &fdset, NULL, NULL, &timeout );

                // If timeout
                if ( rv == 0 ) {
                    retries--;

                    if ( retries < 0 ) {
                        Log::writeLockedMessage( "DhcpClient", "Timeout in DHCP_DISCOVER. Is there any active DHCP server?", Log::LOG_DHCP, true );
                        close( fd );
                        return false;
                    }
                    Log::writeLockedMessage( "DhcpClient", "Retransmitting DHCP_DISCOVER..", Log::LOG_DHCP, true );
                    break;
                }

                rv = this->getRawPacket( &packet, fd );

                if ( rv < 0 || packet.xid != xid ) {
                    continue;
                }

                message = this->getOption( &packet, DHCP_MESSAGE_TYPE );
                if ( *message == DHCPOFFER ) {
                    uint8_t * temp;
                    if ( ( temp = getOption( &packet, DHCP_SERVER_ID ) ) ) {
                        if ( dhcp_server_ip.get() != NULL && memcmp( temp, dhcp_server_ip->getBytes()->getRawPointer(), 4 ) != 0 ) {
                            Log::writeLockedMessage( "DhcpClient", "Received DHCPOFFER from a not desired server. Omitting", Log::LOG_DHCP, true );
                            continue;
                        }

                        this->last_assigned_address.reset( new IpAddressOpenIKE( Enums::ADDR_IPV4, auto_ptr<ByteArray> ( new ByteArray( &packet.yiaddr, 4) ) ) );
                        if ( this->dhcp_server_ip.get() == NULL )
                            this->dhcp_server_ip.reset ( new IpAddressOpenIKE( Enums::ADDR_IPV4, auto_ptr<ByteArray> ( new ByteArray( temp, 4 ) ) ) );

                        step_ok = true;
                        break;
                    } else {
                        Log::writeLockedMessage( "DhcpClient", "No server ID in message", Log::LOG_DHCP, true );
                        continue;
                    }


                } else {
                    continue;
                }
            }
        }

        close( fd );
        return true;
    }

    auto_ptr<IpAddress> DhcpClient::performRequest(uint32_t& subnet) {
        DhcpMessage packet;
        uint8_t *message;
        fd_set fdset;
        timeval timeout;

        int32_t fd = this->createRawSocket();

        FD_ZERO( &fdset );
        FD_SET( fd, &fdset );

        int32_t retries = this->dhcp_retries;
        int32_t timeout_sec = this->dhcp_timeout;

        bool step_ok = false;

        retries = this->dhcp_retries;

        // send DHCP_REQUEST and receive ACK
        Log::writeLockedMessage( "DhcpClient", "Sending DHCP_REQUEST..", Log::LOG_DHCP, true );
        while ( !step_ok ) {
            timeout.tv_sec = timeout_sec;
            timeout.tv_usec = 0;

            // Sends discover
            this->sendSelecting( xid, this->dhcp_server_ip->getBytes()->getRawPointer(), this->last_assigned_address->getBytes()->getRawPointer() );

            while ( true ) {
                FD_ZERO( &fdset );
                FD_SET( fd, &fdset );
                int32_t rv = select( FD_SETSIZE, &fdset, NULL, NULL, &timeout );

                // If timeout
                if ( rv == 0 ) {
                    retries--;

                    if ( retries < 0 ) {
                        Log::writeLockedMessage( "DhcpClient", "Timeout in DHCP_REQUEST", Log::LOG_DHCP, true );
                        return auto_ptr<IpAddress> ( NULL );
                    }
                    Log::writeLockedMessage( "DhcpClient", "Retransmitting DHCP_REQUEST..", Log::LOG_DHCP, true );
                    break;
                }

                rv = this->getRawPacket( &packet, fd );

                if ( rv < 0 || packet.xid != xid ) {
                    continue;
                }

                message = getOption( &packet, DHCP_MESSAGE_TYPE );
                if ( *message == DHCPACK ) {
                    auto_ptr<IpAddress> result_addr ( new IpAddressOpenIKE( Enums::ADDR_IPV4, auto_ptr<ByteArray> ( new ByteArray( & packet.yiaddr, 4) ) ) );

                    uint8_t* temp;
                    if ( temp = getOption( &packet, DHCP_LEASE_TIME ) ) {
                        uint32_t lease_time;
                        memcpy( &lease_time, temp, 4 );
                        lease_time = ntohl( lease_time );

                        if ( lease_time < 10 ) {
                            Log::writeLockedMessage( "DhcpClient", "DHCP: Lease time is too small. Omitting", Log::LOG_DHCP, true );
                            continue;
                        }

                        Log::writeLockedMessage( "DhcpClient", "DHCP lease will be valid for " + intToString( lease_time ) + " seconds. Renew in " + intToString( lease_time - 10 ) + " seconds", Log::LOG_DHCP, true );

                        this->alarm->setTime( ( lease_time - 10 ) * 1000 );

                        this->alarm->reset();
                    }

                    if ( temp = getOption( &packet, DHCP_SUBNET ) ) {
                        uint32_t netmask;
                        memcpy( &netmask, temp, 4 );
                        subnet = netmask;
                    }
                    else {
                        subnet = 0;
                    }


                    return result_addr;
                } else {
                    continue;
                }

            }
        }

        return auto_ptr<IpAddress> ( NULL );
    }
}

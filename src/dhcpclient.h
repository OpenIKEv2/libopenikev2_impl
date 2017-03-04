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
#ifndef DHCP_CLIENT_H
#define DHCP_CLIENT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/udp.h>
#include <netinet/ip.h>

/* DHCP protocol -- see RFC 2131 */
#define SERVER_PORT     67
#define CLIENT_PORT     68

#define DHCP_MAGIC      0x63825363

/* DHCP option codes (partial list) */
#define DHCP_PADDING        0x00
#define DHCP_SUBNET     0x01
#define DHCP_TIME_OFFSET    0x02
#define DHCP_ROUTER     0x03
#define DHCP_TIME_SERVER    0x04
#define DHCP_NAME_SERVER    0x05
#define DHCP_DNS_SERVER     0x06
#define DHCP_LOG_SERVER     0x07
#define DHCP_COOKIE_SERVER  0x08
#define DHCP_LPR_SERVER     0x09
#define DHCP_HOST_NAME      0x0c
#define DHCP_BOOT_SIZE      0x0d
#define DHCP_DOMAIN_NAME    0x0f
#define DHCP_SWAP_SERVER    0x10
#define DHCP_ROOT_PATH      0x11
#define DHCP_IP_TTL     0x17
#define DHCP_MTU        0x1a
#define DHCP_BROADCAST      0x1c
#define DHCP_NTP_SERVER     0x2a
#define DHCP_WINS_SERVER    0x2c
#define DHCP_REQUESTED_IP   0x32
#define DHCP_LEASE_TIME     0x33
#define DHCP_OPTION_OVER    0x34
#define DHCP_MESSAGE_TYPE   0x35
#define DHCP_SERVER_ID      0x36
#define DHCP_PARAM_REQ      0x37
#define DHCP_MESSAGE        0x38
#define DHCP_MAX_SIZE       0x39
#define DHCP_T1         0x3a
#define DHCP_T2         0x3b
#define DHCP_VENDOR     0x3c
#define DHCP_CLIENT_ID      0x3d

#define TYPE_MASK   0x0F

#define DHCP_END        0xFF

#define BOOTREQUEST     1
#define BOOTREPLY       2

#define ETH_10MB        1
#define ETH_10MB_LEN        6

#define DHCPDISCOVER        1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNAK         6
#define DHCPRELEASE     7
#define DHCPINFORM      8

#define BROADCAST_FLAG      0x8000

#define OPTION_FIELD        0
#define FILE_FIELD      1
#define SNAME_FIELD     2

/* miscellaneous defines */
#define MAC_BCAST_ADDR      (unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2


struct dhcp_option {
    char name[ 10 ];          /**< Option name */
    char flags;             /**< Option flags */
    unsigned char code;     /**< Option code */
};

enum {
    OPTION_IP = 1,
    OPTION_IP_PAIR,
    OPTION_STRING,
    OPTION_BOOLEAN,
    OPTION_U8,
    OPTION_U16,
    OPTION_S16,
    OPTION_U32,
    OPTION_S32
};

#define OPTION_REQ  0x10 /* have the client request this option */
#define OPTION_LIST 0x20 /* There can be a list of 1 or more of these */

#include <libopenikev2/ipaddress.h>
#include <libopenikev2/childsaconfiguration.h>
#include <libopenikev2/attribute.h>
#include <libopenikev2/busobserver.h>
#include <libopenikev2/alarmable.h>
#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/id.h>


using namespace std;

namespace openikev2 {

    /**
        This class implements a DHCP client to be used with the address configuration mechanims.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class DhcpClient: public Attribute, public BusObserver, public Alarmable {

        // TODO: Escribir el cliente nosotros mismos. Ahora mismo está casi bien, usando auto punteros, pero el código es lioso

            /****************************** STRUCTS ******************************/
        protected:
            /** DHCP message */
            struct  DhcpMessage{
                uint8_t op;
                uint8_t htype;
                uint8_t hlen;
                uint8_t hops;
                uint32_t xid;
                uint16_t secs;
                uint16_t flags;
                uint32_t ciaddr;
                uint32_t yiaddr;
                uint32_t siaddr;
                uint32_t giaddr;
                uint8_t chaddr[ 16 ];
                uint8_t sname[ 64 ];
                uint8_t file[ 128 ];
                uint32_t cookie;
                uint8_t options[ 308 ];
            };

            /**< RAW IP/UDP/DHCP message */
            struct UdpDhcpPacket {
                struct iphdr ip;
                struct udphdr udp;
                struct DhcpMessage data;
            };

            /****************************** ATTRIBUTES ******************************/
        protected:
            uint64_t spi;                                   /**< SPI value of the IKE_SA */
            auto_ptr<IpAddress> last_assigned_address;      /**< Last assigned address */
            auto_ptr<IpAddress> dhcp_server_ip;             /**< DHCP server IP */
            auto_ptr<Alarm> alarm;                          /**< Alarm to control expires */
            uint8_t mac_addr[ 6 ];                          /**< MAC address */
            auto_ptr<ByteArray> clientid;                   /**< Optional client id to use */
            int32_t dhcp_ifindex;                           /**< Interface index */
            int32_t dhcp_retries;                           /**< DHCP max retries */
            int32_t dhcp_timeout;                           /**< DHCP timeout */
            uint64_t xid;                                   /**< DHCP message id */

            /****************************** METHODS ******************************/
        protected:
            /**
             * Creates a new RAW socket on the interface
             * @return The socket file descriptor
             */
            virtual int32_t createRawSocket( );

            /**
             * Sends a DHCP discover throw the selected interface
             * @param xid Random number identificating the message
             * @param requested Requested address
             * @return -1 on fail. >0 Otherwise
             */
            virtual int32_t sendDhcpDiscover( uint64_t xid, uint32_t requested );

            /**
             * Initiates the packet
             * @param packet Packet to be initiated
             * @param type DHCP message type
             */
            virtual void initPacket( DhcpMessage * packet, uint8_t type );

            /**
             * Initiates the packet header
             * @param packet Packet to be initiated
             * @param type DHCP message type
             */
            virtual void initHeader( DhcpMessage * packet, uint8_t type );

            /**
             * Adds a simple option
             * @param optionptr Pointer to the option
             * @param code Option code
             * @param data Option data
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t addSimpleOption( uint8_t *optionptr, uint8_t code, uint32_t data );

            /**
             * Adds a string option
             * @param optionptr Pointer to the option
             * @param string String value of the option
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t addOptionString( uint8_t *optionptr, uint8_t *string );

            /**
             * Finalices the option list in the message
             * @param optionptr Option pointer
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t endOption( uint8_t *optionptr );

            /**
             * Adds requests
             * @param packet DHCP packet
             */
            virtual void addRequests( DhcpMessage *packet );

            /**
             * Generates the UDP raw packet and sends it throw the indicated interface
             * @param payload DHCP message
             * @param source_ip Source IP + port
             * @param dest_ip Destination IP + port
             * @param dest_arp Destination MAC
             * @param ifindex Interface identifier
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t sendRawPacket( DhcpMessage &payload );

            /**
             * Calculates the checksum
             * @param addr IP address
             * @param count Count
             * @return -1 on fail. >0 otherwise
             */
            virtual uint16_t checksum( void *addr, int32_t count );

            /**
             * Reads the MAC address of the interface
             * @param interface Interface name
             * @param macaddr Buffer where store the MAC address
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t readMac( string interface, uint8_t *macaddr );

            /**
             * Get a raw packet from the network
             * @param payload DHCP message
             * @param fd Socket where listen
             * @return -1 on fail. >0 otherwise
             */
            virtual int32_t getRawPacket( DhcpMessage *payload, int32_t fd );

            /**
             * Get an option from the DHCP message
             * @param packet DHCP message
             * @param code Option code
             * @return -1 on fail. >0 otherwise
             */
            virtual uint8_t *getOption( DhcpMessage *packet, int32_t code );

            /**
             * Sends DHCP request
             * @param xid Message identificator
             * @param server Server address
             * @param requested Requested address
             * @return
             */
            virtual int32_t sendSelecting( uint64_t xid, uint8_t *server, uint8_t* requested );

            virtual bool performDiscover();

            virtual auto_ptr<IpAddress> performRequest(uint32_t& subnet);

        public:

            /**
             * Creates DHCP client
             * @param spi IKE_SA SPI value
             * @param configuration IPsec Configuration to obtain parameters
             */
            DhcpClient( IkeSa& ike_sa );

            /**
             * Request and address via DHCP
             * @return The assigned IpAddress or NULL if something fails
             */
            virtual auto_ptr<IpAddress> requestAddress(uint32_t& netmask);


            virtual void notifyAlarm( Alarm & alarm );

            virtual void notifyBusEvent( const BusEvent& event );

            virtual auto_ptr<Attribute> cloneAttribute() const;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~DhcpClient();
    };
};
#endif

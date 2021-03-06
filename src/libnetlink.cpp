/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "libnetlink.h"

#include <libopenikev2/utils.h>

namespace openikev2 {

    int32_t netlinkOpen( uint32_t groups, uint32_t protocol ) {
        int32_t fd = -1;

        struct sockaddr_nl addr;
        memset( &addr, 0, sizeof( addr ) );

        fd = socket( AF_NETLINK, SOCK_DGRAM, protocol );
        if ( fd < 0 ) {
            throw NetlinkException( "Failed open XFRM socket() for bcast in init_netlink()" );
        }

        if ( fcntl( fd, F_SETFD, FD_CLOEXEC ) != 0 ) {
            throw NetlinkException( "fcntl(FD_CLOEXEC) for bcast in init_netlink()" );
        }

        addr.nl_family = AF_NETLINK;
        addr.nl_groups = groups;
        if ( bind( fd, ( struct sockaddr * ) & addr, sizeof( addr ) ) != 0 ) {
            throw NetlinkException( "Failed to bind bcast socket in init_netlink()" );
        }

        return fd;
    }

    void netlinkAddattr( struct nlmsghdr & n, uint16_t maxlen, uint16_t type, const ByteArray& data ) {
        uint16_t len = RTA_LENGTH( data.size() );
        struct rtattr *rta;

        if ( NLMSG_ALIGN( n.nlmsg_len ) + len > maxlen ) {
            throw NetlinkException( "ERROR: message exceeded bound" );
        }

        rta = ( struct rtattr* ) ( ( ( uint8_t* ) &n ) + NLMSG_ALIGN( n.nlmsg_len ) );
        rta->rta_type = type;
        rta->rta_len = len;
        memcpy( RTA_DATA( rta ), data.getRawPointer(), data.size() );
        n.nlmsg_len = NLMSG_ALIGN( n.nlmsg_len ) + len;
    }

    void netlinkSendMsg( int32_t fd, struct nlmsghdr & hdr ) {
        static uint32_t sequence_number;

        size_t len;
        ssize_t r;

        hdr.nlmsg_seq = ++sequence_number;

        len = hdr.nlmsg_len;
        do {
            r = write( fd, &hdr, len );
        } while ( r < 0 && errno == EINTR );

        if ( r < 0 )
            throw NetlinkException( "netlink write() of message failed. Do you set up XFRM_USER in your kernel? Try \"modprobe xfrm_user\"" );
        else if ( ( size_t ) r != len ) {
            throw NetlinkException( "netlink write() of message truncated" );
        }
    }

    uint16_t netlinkReceiveMsg( int32_t fd, nlmsghdr & rsp, uint16_t max_size ) {
        ssize_t r;
        struct sockaddr_nl addr;
        socklen_t alen;

        alen = sizeof( addr );
        r = recvfrom( fd, &rsp, max_size, 0, ( struct sockaddr * ) & addr, &alen );
        if ( r < 0 ) {
            if ( errno == EAGAIN || errno != EINTR ) {
                return 0;
            }
        } else if ( ( size_t ) r < sizeof( nlmsghdr ) ) {
            return 0;
        } else if ( addr.nl_pid != 0 ) {
            return 0;
        }

        return r;
    }

    int32_t netlinkReceiveAck( int32_t fd ) {
        int32_t error_number;

        struct {
            struct nlmsghdr n;
            struct nlmsgerr err;
            char buf[ NLMSG_BUF_SIZE ];
        }
        response;

        int16_t rv = netlinkReceiveMsg( fd, response.n, sizeof( response ) );

        if ( response.n.nlmsg_type != NLMSG_ERROR )
            throw NetlinkException( "Message is not an ACK: " + intToString( response.n.nlmsg_type ) );

        error_number = response.err.error;

        return error_number;
    }



    uint16_t netlinkParseRtattrByIndex( struct rtattr * tb[], uint16_t max, struct rtattr * rta, uint16_t len ) {
        uint16_t i = 0;
        while ( RTA_OK( rta, len ) ) {
            if ( rta->rta_type <= max )
                tb[ i++ ] = rta;
            rta = RTA_NEXT( rta, len );
        }
        return i;
    }

}

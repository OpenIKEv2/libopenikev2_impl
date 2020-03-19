/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#ifndef LIBNETLINK_H
#define LIBNETLINK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/exception.h>
#include <libopenikev2/bytearray.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NLMSG_BUF_SIZE 4096
#define RTA_BUF_SIZE 2048
#define XFRM_TMPLS_BUF_SIZE 1024
#define XFRM_ALGO_KEY_BUF_SIZE 512
#define XFRMP_RTA(x)  ((struct rtattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_info))))

using namespace std;

namespace openikev2 {

    class NetlinkException : public Exception {
        public:
            NetlinkException( string m ) : Exception( "Netlink: " + m ) {}
    };

    // NETLINK aux functions
    int32_t netlinkOpen( uint32_t groups, uint32_t protocol );
    void netlinkAddattr( nlmsghdr &n, uint16_t maxlen, uint16_t type, const ByteArray& data );
    void netlinkSendMsg( int32_t fd, nlmsghdr &hdr );
    uint16_t netlinkReceiveMsg( int32_t fd, nlmsghdr &message, uint16_t max_size );
    int32_t netlinkReceiveAck( int32_t fd );
    uint16_t netlinkParseRtattrByIndex( struct rtattr *tb[], uint16_t max, struct rtattr *rta, uint16_t len );

};

#endif

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

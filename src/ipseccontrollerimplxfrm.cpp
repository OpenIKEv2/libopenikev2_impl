/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#include "ipseccontrollerimplxfrm.h"

#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/log.h>
#include <libopenikev2/autolock.h>
#include <libopenikev2/cryptocontroller.h>
#include <libopenikev2/ipaddress.h>
#include <libopenikev2/boolattribute.h>
#include <libopenikev2/configuration.h>


#include "utilsimpl.h"
#include "roadwarriorpolicies.h"
#include "ipaddressopenike.h"

#include <netinet/in.h>
#include <stdio.h>

namespace openikev2 {

    IpsecControllerImplXfrm::IpsecControllerImplXfrm() {
        this->name = "XFRM";
        netlink_bcast_fd = -1;
        this->sequence_number = 0;
        this->mutex_policies = ThreadController::getMutex();
        this->exiting = false;
        this->netlink_bcast_fd = netlinkOpen( XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE, NETLINK_XFRM );
        this->updatePolicies( false );
    }

    IpsecControllerImplXfrm::~IpsecControllerImplXfrm() {
        close( this->netlink_bcast_fd );
    }

    void IpsecControllerImplXfrm::xfrmFlushIpsecPolicies() {
        struct {
            struct nlmsghdr n;
            struct xfrm_usersa_flush xsf;
        }
        req;

        memset( &req, 0, sizeof( req ) );

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.xsf ) ) );
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = XFRM_MSG_FLUSHPOLICY;
        req.xsf.proto = 255; // ANY

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );
        close( fd );
    }

    void IpsecControllerImplXfrm::xfrmFlushIpsecSas() {
        struct {
            struct nlmsghdr n;
            struct xfrm_usersa_flush xsf;
        }
        req;

        memset( &req, 0, sizeof( req ) );

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.xsf ) ) );
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = XFRM_MSG_FLUSHSA;
        req.xsf.proto = 255; // ANY

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );
        close( fd );
    }

    void IpsecControllerImplXfrm::xfrmDeleteIpsecSa( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t spi ) {
        struct {
            struct nlmsghdr n;
            struct xfrm_usersa_id id;
            char data[ 1024 ];
        }
        req;

        memset( &req, 0, sizeof( req ) );

        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.n.nlmsg_type = XFRM_MSG_DELSA;

        memcpy( &req.id.daddr, dst.getBytes() ->getRawPointer(), dst.getAddressSize() );

        req.id.spi = htonl( spi );
        req.id.family = UtilsImpl::getUnixFamily( src.getFamily() );
        req.id.proto = ( protocol == Enums::PROTO_ESP ) ? IPPROTO_ESP : IPPROTO_AH;

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.id ) ) );

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );

        if ( netlinkReceiveAck( fd ) != 0 ) {
            close( fd );
            throw IpsecException( "Error performing a DELETE IPSEC SA action" );
        }

        close( fd );
    }

    uint32_t IpsecControllerImplXfrm::xfrmGetSpi( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t reqid, uint32_t min, uint32_t max ) {
        struct {
            struct nlmsghdr n;
            struct xfrm_userspi_info spi;
        }
        req;

        // sends the request
        memset( &req, 0, sizeof( req ) );
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = XFRM_MSG_ALLOCSPI;

        memcpy( &req.spi.info.saddr, src.getBytes() ->getRawPointer(), src.getAddressSize() );
        memcpy( &req.spi.info.id.daddr, dst.getBytes() ->getRawPointer(), dst.getAddressSize() );

        req.spi.info.reqid = reqid;
        req.spi.info.id.proto = ( protocol == Enums::PROTO_ESP ) ? IPPROTO_ESP : IPPROTO_AH;
        req.spi.info.family = UtilsImpl::getUnixFamily( src.getFamily() );
        req.spi.min = min;
        req.spi.max = max;

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.spi ) ) );

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );

        // receives the response
        struct {
            struct nlmsghdr n;
            struct xfrm_usersa_info sa;
        }
        res;

        netlinkReceiveMsg( fd, res.n, sizeof( res ) );

        if ( res.n.nlmsg_type != XFRM_MSG_NEWSA ) {
            close( fd );
            throw IpsecException( "Invalid response for a GET_SPI message" );
        }
        close( fd );




        uint32_t ipsec_spi = ntohl( res.sa.id.spi );
        // Commented by Pedro J. Fernandez in order to avoid larval deletion
        //this->xfrmDeleteIpsecSa( src, dst, protocol, ipsec_spi );

        //ipsec_proto = res.sa.id.proto ;
        //uint8_t ipsec_mode = res.sa.mode;

        return ipsec_spi;
    }


    void IpsecControllerImplXfrm::xfrmAddUpdateIpsecSa( uint16_t operation, const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t spi, string encr_type, ByteArray & encr_key, string integ_type, ByteArray & integ_key, uint32_t limit_soft_time, uint32_t limit_hard_time, uint32_t limit_hard_octets, uint32_t reqid, const TrafficSelector& src_sel, const TrafficSelector& dst_sel ) {
        struct {
            struct nlmsghdr n;
            struct xfrm_usersa_info xsinfo;
            char buf[ RTA_BUF_SIZE ];
        }
        req;

        struct {
            struct xfrm_algo alg;
            char buf[ XFRM_ALGO_KEY_BUF_SIZE ];
        }
        alg;

        memset( &req, 0, sizeof( req ) );
        memset( &alg, 0, sizeof( alg ) );

        req.n.nlmsg_len = NLMSG_ALIGN ( NLMSG_LENGTH( sizeof( req.xsinfo ) ) );
        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.n.nlmsg_type = operation;

        // Calculate jitter for softtime
        auto_ptr<Random> random = CryptoController::getRandom();
        uint32_t temp_10percent = ( uint32_t ) ( ( float ) limit_soft_time * 0.1 );
        uint32_t jitter = random->getRandomInt32( 0, temp_10percent * 2 );


        // get the selector
        req.xsinfo.sel = this->getXfrmSelector( src_sel, dst_sel );

        req.xsinfo.lft.soft_byte_limit = ( uint64_t ) ( ( float ) limit_hard_octets * 0.8 );
        req.xsinfo.lft.hard_byte_limit = limit_hard_octets;
        req.xsinfo.lft.soft_add_expires_seconds = limit_soft_time - temp_10percent + jitter;
        req.xsinfo.lft.hard_add_expires_seconds = limit_hard_time;
        req.xsinfo.lft.soft_packet_limit = XFRM_INF;
        req.xsinfo.lft.hard_packet_limit = XFRM_INF;

        // SET THE MODE
        req.xsinfo.mode = ( mode == Enums::TRANSPORT_MODE ) ? XFRM_MODE_TRANSPORT : XFRM_MODE_TUNNEL;

        // If tunnel mode, the SRC and DST address are obtained from the src and dst parameters
        if ( mode == Enums::TUNNEL_MODE ) {
            req.xsinfo.family = UtilsImpl::getUnixFamily( src.getFamily() );
            req.xsinfo.saddr = this->getXfrmAddress( src );
            req.xsinfo.id.daddr = this->getXfrmAddress( dst );
        }

        // if transport mode, the SRC and DST address are obtained from the selectors
        else {
            req.xsinfo.family = req.xsinfo.sel.family;
            memcpy( &req.xsinfo.saddr, &req.xsinfo.sel.saddr, sizeof( xfrm_address_t ) );
            memcpy( &req.xsinfo.id.daddr, &req.xsinfo.sel.daddr, sizeof( xfrm_address_t ) );
        }

        // writes SPI
        req.xsinfo.id.spi = htonl( spi );
        uint8_t *spi_char = (uint8_t *)&spi;

        req.xsinfo.id.proto = ( protocol == Enums::PROTO_ESP ) ? IPPROTO_ESP : IPPROTO_AH;

        // Set the ENCR algo
        if ( encr_key.size() > 0 ) {
            strncpy( alg.alg.alg_name, encr_type.c_str(), 64 );
            memcpy( alg.alg.alg_key, encr_key.getRawPointer(), encr_key.size() );
            alg.alg.alg_key_len = encr_key.size() * 8;
            uint16_t len = sizeof( struct xfrm_algo ) + encr_key.size();
            netlinkAddattr( req.n, sizeof( req.buf ), XFRMA_ALG_CRYPT, ByteArray ( &alg, len ) );
        }

        // Get the algo 2
        if ( integ_key.size() > 0 ) {
            strncpy( alg.alg.alg_name, integ_type.c_str(), 64 );
            memcpy( alg.alg.alg_key, integ_key.getRawPointer(), integ_key.size() );
            alg.alg.alg_key_len = integ_key.size() * 8;
            uint16_t len = sizeof( struct xfrm_algo ) + integ_key.size();
            netlinkAddattr( req.n, sizeof( req.buf ), XFRMA_ALG_AUTH, ByteArray ( &alg, len ) );
        }

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );

        if ( int error = netlinkReceiveAck( fd ) != 0 ) {
            close( fd );
            throw IpsecException( "Error performing an UPDATE/ADD action" );
        }

        close( fd );
    }

    void IpsecControllerImplXfrm::xfrmCreateIpsecPolicy( const IpAddress & src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress & dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::POLICY_ACTION action ,Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress * tunnel_src, const IpAddress * tunnel_dst, bool autogen, bool sub ) {
        struct {
            struct nlmsghdr n;
            struct xfrm_userpolicy_info pol;
            struct xfrm_userpolicy_type ptype;
            char buf[ RTA_BUF_SIZE ];
        }
        req;

        memset( &req, 0, sizeof( req ) );

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.pol ) ) );
        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.n.nlmsg_type = XFRM_MSG_NEWPOLICY;

        // Set selectors
        memcpy( &req.pol.sel.saddr, src_sel.getBytes() ->getRawPointer(), src_sel.getAddressSize() );
        req.pol.sel.prefixlen_s = src_prefixlen;

        memcpy( &req.pol.sel.daddr, dst_sel.getBytes() ->getRawPointer(), dst_sel.getAddressSize() );
        req.pol.sel.prefixlen_d = dst_prefixlen;

        req.pol.sel.proto = ip_protocol;
        req.pol.sel.family = UtilsImpl::getUnixFamily( src_sel.getFamily() );
        req.pol.sel.sport = htons( src_port );
        if ( req.pol.sel.sport )
            req.pol.sel.sport_mask = 0xFFFF;
        req.pol.sel.dport = htons( dst_port );
        if ( req.pol.sel.dport )
            req.pol.sel.dport_mask = 0xFFFF;

#ifdef HAVE_XFRM_POLICY_PRIORITY
        req.pol.priority = priority;
#endif
        req.pol.action = action;
        req.pol.lft.soft_byte_limit = XFRM_INF;
        req.pol.lft.hard_byte_limit = XFRM_INF;
        req.pol.lft.soft_packet_limit = XFRM_INF;
        req.pol.lft.hard_packet_limit = XFRM_INF;

        switch ( dir ) {
            case Enums::DIR_IN:
                req.pol.dir = XFRM_POLICY_IN ;
                break;
            case Enums::DIR_OUT:
                req.pol.dir = XFRM_POLICY_OUT ;
                break;
            case Enums::DIR_FWD:
                req.pol.dir = XFRM_POLICY_FWD ;
                break;
            default:
                assert ( "Unknown direction" && 0 );
        }

        if (sub)
            req.ptype.type = XFRM_POLICY_TYPE_SUB;
        else
            req.ptype.type = XFRM_POLICY_TYPE_MAIN;

        ByteArray temp2( &(req.ptype) , sizeof( struct xfrm_userpolicy_type ), sizeof( struct xfrm_userpolicy_type ) );

        netlinkAddattr( req.n, sizeof( req.buf ), XFRMA_POLICY_TYPE, temp2 );


        if ( protocol != Enums::PROTO_NONE ) {
            xfrm_user_tmpl tmpl; // Protocols.size must be 0, 1 or 2
            memset( &tmpl, 0, sizeof( struct xfrm_user_tmpl ) );

            if ( mode == Enums::TUNNEL_MODE && tunnel_src != NULL ) {
                memcpy( &tmpl.saddr, tunnel_src->getBytes() ->getRawPointer(), tunnel_src->getAddressSize() );
                tmpl.family = UtilsImpl::getUnixFamily( tunnel_src->getFamily() );
            }
            if ( mode == Enums::TUNNEL_MODE && tunnel_dst != NULL ) {
                memcpy( &tmpl.id.daddr, tunnel_dst->getBytes() ->getRawPointer(), tunnel_dst->getAddressSize() );
                tmpl.family = UtilsImpl::getUnixFamily( tunnel_dst->getFamily() );
            }

            tmpl.mode = ( mode == Enums::TRANSPORT_MODE ) ? 0 : 1; // 0=transport mode 1=tunnel mode

            tmpl.aalgos = 0xFFFF;
            tmpl.ealgos = 0xFFFF;
            tmpl.calgos = 0xFFFF;

            tmpl.id.proto = ( protocol == Enums::PROTO_ESP ) ? IPPROTO_ESP : IPPROTO_AH;
            ByteArray temp( & tmpl, sizeof( struct xfrm_user_tmpl ), sizeof( struct xfrm_user_tmpl ) );

            netlinkAddattr( req.n, sizeof( req.buf ), XFRMA_TMPL, temp );
        }

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );

        int myerror = netlinkReceiveAck( fd );
        if ( myerror != 0 ) {
            if (myerror != -17) {
                close( fd );
                throw IpsecException( "Error performing an CREATE POLICY action" );
            }
        }

        close( fd );


        if (autogen && protocol != Enums::PROTO_NONE ){
            // Si la politica es modo tunel y tiene las direcciones de tunel asignadas,
            if ((mode == Enums::TUNNEL_MODE && tunnel_src != NULL && tunnel_dst != NULL)){
                // Estos valores de puerto son un ejemplo porque hay que poner alguno
                processAcquire( *tunnel_src, ((tunnel_src->getFamily() == Enums::ADDR_IPV6) ? 128: 32), 1025, *tunnel_dst, ((tunnel_dst->getFamily() == Enums::ADDR_IPV6) ? 128: 32), 1025, ip_protocol, dir, protocol, mode, priority, src_sel, src_prefixlen, src_port, dst_sel, dst_prefixlen, dst_port, tunnel_src, tunnel_dst );
            }
            //Si la politica es modo transporte y los selectores tienen mascara 32 o 128
            else if ((mode == Enums::TRANSPORT_MODE && ((src_sel.getFamily() == Enums::ADDR_IPV6)? src_prefixlen == 128 : src_prefixlen == 32 ) && ((dst_sel.getFamily() == Enums::ADDR_IPV6)? dst_prefixlen == 128 : dst_prefixlen == 32 ))) {
                // Estos valores de puerto son un ejemplo porque hay que poner alguno
                processAcquire( src_sel, src_prefixlen, 1025, dst_sel, dst_prefixlen, 1025, ip_protocol, dir, protocol, mode, priority, src_sel, src_prefixlen, src_port, dst_sel, dst_prefixlen, dst_port, tunnel_src, tunnel_dst );
            }
    //      processAcquire( src_sel, src_prefixlen, src_port, dst_sel, dst_prefixlen, dst_port, ip_protocol, dir, protocol, mode, priority, tunnel_src, tunnel_dst );
        }

    }

    void IpsecControllerImplXfrm::xfrmDeleteIpsecPolicy( const IpAddress & src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress & dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir ) {
        struct {
            struct nlmsghdr n;
            struct xfrm_userpolicy_id pol;
        }
        req;

        memset( &req, 0, sizeof( req ) );

        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.pol ) ) );
        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.n.nlmsg_type = XFRM_MSG_DELPOLICY;

        // Set selectors
        req.pol.sel.saddr = this->getXfrmAddress( src_sel );
        req.pol.sel.prefixlen_s = src_prefixlen;
        req.pol.sel.daddr = this->getXfrmAddress( dst_sel );
        req.pol.sel.prefixlen_d = dst_prefixlen;

        req.pol.sel.family = UtilsImpl::getUnixFamily( src_sel.getFamily() );
        req.pol.sel.sport = htons( src_port );
        if ( req.pol.sel.sport )
            req.pol.sel.sport_mask = 0xFFFF;
        req.pol.sel.dport = htons( dst_port );
        if ( req.pol.sel.dport )
            req.pol.sel.dport_mask = 0xFFFF;
        req.pol.sel.proto = ip_protocol;

        switch ( dir ) {
            case Enums::DIR_IN:
                req.pol.dir = XFRM_POLICY_IN ;
                break;
            case Enums::DIR_OUT:
                req.pol.dir = XFRM_POLICY_OUT ;
                break;
            case Enums::DIR_FWD:
                req.pol.dir = XFRM_POLICY_FWD ;
                break;
        }

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
        netlinkSendMsg( fd, req.n );

        if ( netlinkReceiveAck( fd ) != 0 ) {
            close( fd );
            throw IpsecException( "Error performing an DELETE POLICY action" );
        }
        close( fd );
    }

    string IpsecControllerImplXfrm::getXfrmEncrAlgo( const Transform* encr_transform ) {
        Enums::ENCR_ID algo = encr_transform ? ( Enums::ENCR_ID ) encr_transform->id : Enums::ENCR_NONE;

        if ( algo == Enums::ENCR_NONE )
            return "none";
        else if ( algo == Enums::ENCR_DES )
            return "des";
        else if ( algo == Enums::ENCR_3DES )
            return "des3_ede";
        else if ( algo == Enums::ENCR_CAST )
            return "cast128";
        else if ( algo == Enums::ENCR_BLOWFISH )
            return "blowfish";
        else if ( algo == Enums::ENCR_AES_CBC )
            return "aes";
        else
            throw IpsecException( "Invalid encr algotithm to make conversion from IKE to XFRM" );

    }

    string IpsecControllerImplXfrm::getXfrmIntegAlgo( const Transform* integ_transform ) {
        Enums::INTEG_ID algo = integ_transform ? ( Enums::INTEG_ID ) integ_transform->id : Enums::AUTH_NONE;

        if ( algo == Enums::AUTH_NONE )
            return "none";
        else if ( algo == Enums::AUTH_HMAC_MD5_96 )
            return "md5";
        else if ( algo == Enums::AUTH_HMAC_SHA1_96 )
            return "sha1";
        else
            throw IpsecException( "Invalid integ algotithm to make conversion from IKE to XFRM" );

    }

    void IpsecControllerImplXfrm::processAcquire( const IpAddress & src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress & dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress & src_policy_sel, uint8_t src_policy_prefixlen, uint16_t src_policy_port, const IpAddress & dst_policy_sel, uint8_t dst_policy_prefixlen, uint16_t dst_policy_port, const IpAddress * tunnel_src, const IpAddress * tunnel_dst ){


    auto_ptr<IpAddress> src ( src_sel.clone() );
        auto_ptr<IpAddress> dst( dst_sel.clone() );
    auto_ptr<IpAddress> src_selector ( src_sel.clone() );
        auto_ptr<IpAddress> dst_selector ( dst_sel.clone() );
    auto_ptr<IpAddress> src_policy_addr ( src_policy_sel.clone() );
        auto_ptr<IpAddress> dst_policy_addr ( dst_policy_sel.clone() );


        uint8_t src_sel_prefixlen = src_prefixlen;
        uint8_t dst_sel_prefixlen = dst_prefixlen;
        uint16_t src_sel_port = src_port;
        uint16_t dst_sel_port = dst_port;
        uint8_t sel_ip_proto = ip_protocol;

        // Get policy by its ID
        //Policy & policy = this->getIpsecPolicyById( acquire->policy.index );

        Log::acquire();
        Log::writeMessage( "IpsecController", "Auto acquire!", Log::LOG_IPSC, true );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SRC CACaA=[" + src->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "DST=[" + dst->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL SRC=[" + src_selector->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL DST=[" + dst_selector->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL PROTO=[" + Enums::IP_PROTO_STR( sel_ip_proto ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL SRC PORT=[" + intToString( src_sel_port ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL DST PORT=[" + intToString( dst_sel_port ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SRC TUNNEL=[" + tunnel_src->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "DST TUNNEL=[" + tunnel_dst->toString() + "]", Log::LOG_IPSC, false );
        //Log::writeMessage( "IpsecController", policy.toStringTab( 1 ), Log::LOG_POLI, false );
        Log::release();

        // construct the selectors
        auto_ptr<Payload_TSi> payload_ts_i ( new Payload_TSi() );
        auto_ptr<Payload_TSr> payload_ts_r ( new Payload_TSr() );

        // add the specific selectors
        if ( sel_ip_proto == Enums::IP_PROTO_ICMP || sel_ip_proto == Enums::IP_PROTO_ICMPv6 ) {
            payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *src_selector, src_sel_prefixlen, src_sel_port, dst_sel_port, sel_ip_proto ) ) );
            payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *dst_selector, dst_sel_prefixlen, src_sel_port, dst_sel_port, sel_ip_proto ) ) );
        }
        else {
            payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *src_selector, src_sel_prefixlen, src_sel_port, sel_ip_proto ) ) );
            payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *dst_selector, dst_sel_prefixlen, dst_sel_port, sel_ip_proto ) ) );
        }

        payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *src_policy_addr, src_policy_prefixlen, src_policy_port, ip_protocol ) ) );
        payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *dst_policy_addr, dst_policy_prefixlen, dst_policy_port, ip_protocol ) ) );

        //payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( pol_src_sel.front().clone() ) );
        //payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector>  ( pol_dst_sel.front().clone() );

        auto_ptr<ChildSaRequest> child_sa_request ( new ChildSaRequest( protocol,
                                                                        mode,
                                                                        auto_ptr<Payload_TS> ( payload_ts_i ),
                                                                        auto_ptr<Payload_TS> ( payload_ts_r )
                                                                      )
                                                  );
    Log::writeMessage( "IpsecController", "IP_PROTO="+ intToString( sel_ip_proto )+"["+intToString( Enums::IP_PROTO_ICMPv6 )+"]", Log::LOG_IPSC, false );
    Log::writeMessage( "IpsecController", "SRC_PORT="+ intToString( src_sel_port )+"[146 o 147]", Log::LOG_IPSC, false );
    /*
    if (sel_ip_proto == Enums::IP_PROTO_MH || ( (sel_ip_proto == Enums::IP_PROTO_ICMPv6) && (src_sel_port == 146 || src_sel_port == 147 ))){ // Case of MIPv6 signaling
        auto_ptr<IpAddress> src2 (NetworkController::getCurrentCoA());
        //auto_ptr<IpAddress> src2 ( new IpAddressOpenIKE("2001:155:54:92:2c0:caff:fe47:16ba") );

        src = src2;
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "COA=[" + src->toString() + "]", Log::LOG_IPSC, false );
    }
*/
        IkeSaController::requestChildSa( *src, *dst, child_sa_request );

    }

    void IpsecControllerImplXfrm::processAcquire( const nlmsghdr & n ) {
        xfrm_user_acquire * acquire = ( xfrm_user_acquire* ) NLMSG_DATA( &n );

        NetworkController::refreshInterfaces();

        // BY NOW, ALL THE POLICY SHOULD BE IPv6 or IPv4
        Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( acquire->policy.sel.family );

        this->updatePolicies( false );

        auto_ptr<IpAddress> src = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &acquire->saddr, sizeof ( acquire->saddr ) ) ) );
        auto_ptr<IpAddress> dst = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &acquire->id.daddr, sizeof ( acquire->id.daddr ) ) ) );
        auto_ptr<IpAddress> src_sel = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &acquire->sel.saddr, sizeof ( acquire->sel.saddr ) ) ) );
        auto_ptr<IpAddress> dst_sel = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &acquire->sel.daddr, sizeof ( acquire->sel.daddr ) ) ) );
        uint8_t src_sel_prefixlen = acquire->sel.prefixlen_s;
        uint8_t dst_sel_prefixlen = acquire->sel.prefixlen_d;
        uint16_t src_sel_port = ntohs( acquire->sel.sport );
        uint16_t dst_sel_port = ntohs( acquire->sel.dport );
        uint8_t sel_ip_proto = acquire->sel.proto;

        // Get policy by its ID
        Policy & policy = this->getIpsecPolicyById( acquire->policy.index );

        if (policy.type != Enums::POLICY_MAIN ){

            Log::acquire();
            Log::writeMessage( "IpsecController", "Recv acquire: Policy=[" + intToString( policy.id ) + "] but this policy is SUB. Skipping...", Log::LOG_IPSC, true );
            Log::release();

        }

        Log::acquire();
        Log::writeMessage( "IpsecController", "Recv acquire: Policy=[" + intToString( policy.id ) + "]", Log::LOG_IPSC, true );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SRC=[" + src->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "DST=[" + dst->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL SRC=[" + src_sel->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL DST=[" + dst_sel->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL PROTO=[" + Enums::IP_PROTO_STR( sel_ip_proto ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL SRC PORT=[" + intToString( src_sel_port ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SEL DST PORT=[" + intToString( dst_sel_port ) + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", policy.toStringTab( 1 ), Log::LOG_POLI, false );
        Log::release();

        // construct the selectors
        auto_ptr<Payload_TSi> payload_ts_i ( new Payload_TSi() );
        auto_ptr<Payload_TSr> payload_ts_r ( new Payload_TSr() );

        // add the specific selectors
        if ( sel_ip_proto == Enums::IP_PROTO_ICMP || sel_ip_proto == Enums::IP_PROTO_ICMPv6 ) {
            payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *src_sel, src_sel_prefixlen, src_sel_port, dst_sel_port, sel_ip_proto ) ) );
            payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *dst_sel, dst_sel_prefixlen, src_sel_port, dst_sel_port, sel_ip_proto ) ) );
        }
        else {
            payload_ts_i->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *src_sel, src_sel_prefixlen, src_sel_port, sel_ip_proto ) ) );
            payload_ts_r->addTrafficSelector( auto_ptr<TrafficSelector> ( new TrafficSelector( *dst_sel, dst_sel_prefixlen, dst_sel_port, sel_ip_proto ) ) );
        }

        // add the policy selectors
        payload_ts_i->addTrafficSelector( policy.getSrcTrafficSelector() );
        payload_ts_r->addTrafficSelector( policy.getDstTrafficSelector() );

        auto_ptr<ChildSaRequest> child_sa_request ( new ChildSaRequest(
                                                                        policy.sa_request->ipsec_protocol,
                                                                        policy.sa_request->mode,
                                                                        auto_ptr<Payload_TS> ( payload_ts_i ),
                                                                        auto_ptr<Payload_TS> ( payload_ts_r )
                                                                      )
                                                  );

    /*
    Log::writeMessage( "IpsecController", "IP_PROTO="+ intToString( sel_ip_proto )+"["+intToString( Enums::IP_PROTO_ICMPv6 )+"]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", "SRC_PORT="+ intToString( src_sel_port )+"[146 o 147]", Log::LOG_IPSC, false );
        */

    auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();
    BoolAttribute* mobility_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "mobility" );
    bool mobility = false;
    if (mobility_attr  != NULL )
        mobility = mobility_attr->value;
    if ( mobility ) {


        BoolAttribute* is_ha_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "is_ha" );
                bool is_ha = false;
                    if (is_ha_attr  != NULL )
                is_ha = is_ha_attr->value;


        if (sel_ip_proto == Enums::IP_PROTO_MH ){ //&& !( (sel_ip_proto == Enums::IP_PROTO_ICMPv6) && (src_sel_port == 146 || src_sel_port == 147 ))){
            auto_ptr<IpAddress> coa (NetworkController::getCurrentCoA());
            //auto_ptr<IpAddress> src2 ( new IpAddressOpenIKE("2001:155:54:92:2c0:caff:fe47:16ba") );

            Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "Using COA=[" + coa->toString() + "] instead of HoA for IKE_SA creation based on CoA", Log::LOG_IPSC, false );

                IkeSaController::requestChildSaMobility( *src, *dst, child_sa_request, *coa, is_ha );

        }
        else {
            if (is_ha){
                Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "(IS HA) Using COA2=[" + dst->toString() + "]", Log::LOG_IPSC, false );
                IkeSaController::requestChildSaMobility( *src, *dst, child_sa_request, *dst  , is_ha );
            }
            else {
                Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "(IS MR) Using COA2=[" + src->toString() + "]", Log::LOG_IPSC, false );
                IkeSaController::requestChildSaMobility( *src, *dst, child_sa_request, *src  , is_ha );

            }
        }


    }
    else {
            IkeSaController::requestChildSa( *src, *dst, child_sa_request );
        }
    }

    void IpsecControllerImplXfrm::processExpire( const nlmsghdr & n ) {
        xfrm_user_expire * expire = ( xfrm_user_expire* ) NLMSG_DATA( &n );

        Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( expire->state.family );

        auto_ptr<IpAddress> src_addr = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &expire->state.saddr, sizeof( expire->state.saddr ) ) ) );
        auto_ptr<IpAddress> dst_addr = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &expire->state.id.daddr, sizeof( expire->state.id.daddr ) ) ) );

        IpsecControllerImplOpenIKE::processExpire( *src_addr, *dst_addr, ntohl( expire->state.id.spi ), expire->hard );
    }

    void IpsecControllerImplXfrm::run( ) {
        Log::writeLockedMessage( "IpsecControllerXfrm", "Start: Thread ID=[" + intToString( thread_id ) + "]", Log::LOG_THRD, true );

        struct {
            nlmsghdr n;
            char data[ NLMSG_BUF_SIZE ];
        }
        msg;

        while ( !exiting ) {
            try {
                uint16_t len = netlinkReceiveMsg( this->netlink_bcast_fd, msg.n, sizeof( msg ) );
                if ( len == 0 || len != msg.n.nlmsg_len || exiting )
                    continue;

                switch ( msg.n.nlmsg_type ) {
                    case XFRM_MSG_ACQUIRE:
                        processAcquire( msg.n );
                        break;
                    case XFRM_MSG_EXPIRE:
                        processExpire( msg.n );
                        break;
                    default:
                        // ignored
                        Log::writeLockedMessage( "IpsecController", "XFRM received unspected message with MSG_TYPE=" + intToString( msg.n.nlmsg_type ), Log::LOG_ERRO, true );
                        break;
                }
            }
            catch ( Exception & ex ) {
                Log::writeLockedMessage( "IpsecControllerImplXfrm", ex.what(), Log::LOG_ERRO, true );
            }
        }
    }

    void IpsecControllerImplXfrm::updatePolicies( bool show ) {
        AutoLock auto_lock( *this->mutex_policies );

        // Delete the old policy collection
        this->ipsec_policies.clear();

        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );

        struct {
            struct nlmsghdr nlh;
            struct xfrm_userpolicy_id id;
        }
        req;

        struct sockaddr_nl nladdr;

        memset( &req, 0, sizeof( req ) );
        nladdr.nl_family = AF_NETLINK;

        req.nlh.nlmsg_len = sizeof( req );
        req.nlh.nlmsg_type = XFRM_MSG_GETPOLICY;
        req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;

        netlinkSendMsg( fd, req.nlh );

        // get the response
        struct {
            struct nlmsghdr nlh;
            char data[ NLMSG_BUF_SIZE ];
        }
        res;

        int16_t len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );

        nlmsghdr *msg = &res.nlh;

        while ( res.nlh.nlmsg_type != NLMSG_DONE ) {
            // read all policies
            nlmsghdr * h = msg;
            while ( NLMSG_OK( h, len ) ) {
                if ( h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR ) {
                    close ( fd );
                    return ;
                }

                // Parseamos la politica
                struct xfrm_userpolicy_info *xpinfo = ( xfrm_userpolicy_info* ) NLMSG_DATA( h );

                auto_ptr<Policy> policy ( new Policy() );
                policy->id = xpinfo->index;

                switch ( xpinfo->dir ) {
                    case XFRM_POLICY_IN:
                        policy->direction = Enums::DIR_IN;
                        break;
                    case XFRM_POLICY_OUT:
                        policy->direction = Enums::DIR_OUT;
                        break;
                    case XFRM_POLICY_FWD:
                        policy->direction = Enums::DIR_FWD;
                        break;
                    default:
                        assert ( "Unknown direction" && 0 );
                }

                Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( xpinfo->sel.family );

                policy->selector_src = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &xpinfo->sel.saddr, sizeof ( xpinfo->sel.saddr ) ) ) );
                policy->selector_dst = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( &xpinfo->sel.daddr, sizeof ( xpinfo->sel.daddr ) ) ) );

                policy->selector_src_port = ntohs( xpinfo->sel.sport );
                policy->selector_dst_port = ntohs( xpinfo->sel.dport );
                policy->icmp_type = ntohs( xpinfo->sel.sport );
                policy->icmp_code = ntohs( xpinfo->sel.dport );

                policy->selector_prefixlen_src = xpinfo->sel.prefixlen_s;
                policy->selector_prefixlen_dst = xpinfo->sel.prefixlen_d;
                policy->ip_protocol = xpinfo->sel.proto;
                policy->type = Enums::POLICY_MAIN; // Por defecto es Main

                struct rtattr* tb[ RTA_BUF_SIZE ];
                memset( tb, 0, sizeof( tb ) );
                uint16_t ntb = netlinkParseRtattrByIndex( tb, RTA_BUF_SIZE, XFRMP_RTA( xpinfo ), len - NLMSG_LENGTH( sizeof( *xpinfo ) ) );

                // Find template attributes
                for ( uint16_t i = 0; i < ntb; i++ ) {
                    if ( tb[ i ] ->rta_type == XFRMA_POLICY_TYPE ){
                         xfrm_userpolicy_type* policy_type = ( xfrm_userpolicy_type* ) RTA_DATA( tb[ i ] );

                        if (policy_type->type == XFRM_POLICY_TYPE_MAIN)
                            policy->type = Enums::POLICY_MAIN;
                        else if (policy_type->type == XFRM_POLICY_TYPE_SUB)
                            policy->type = Enums::POLICY_SUB;
                        else
                            policy->type = Enums::POLICY_MAIN;

                    }

                    if ( tb[ i ] ->rta_type != XFRMA_TMPL )
                        continue;

                    int len = tb[ i ] ->rta_len;
                    xfrm_user_tmpl* templates = ( xfrm_user_tmpl* ) RTA_DATA( tb[ i ] );

                    //Gets the number of templates
                    int ntmpls = len / sizeof( struct xfrm_user_tmpl );

                    // If there are more than one sa, we only use the first one
                    if ( ntmpls > 1 )
                        Log::writeLockedMessage( "IpsecController", "Warning: Policy has more than one request. SA BUNDLES are obsoleted and not supported.", Log::LOG_WARN, true );

                    struct xfrm_user_tmpl *tmpl = &templates[ 0 ];

                    auto_ptr<SaRequest> request ( new SaRequest() );

                    request->mode = ( tmpl->mode == 0 ) ? Enums::TRANSPORT_MODE : Enums::TUNNEL_MODE;
                    request->request_id = tmpl->reqid;
                    request->ipsec_protocol = ( tmpl->id.proto == IPPROTO_ESP ) ? Enums::PROTO_ESP : Enums::PROTO_AH;
                    if ( request->mode == Enums::TUNNEL_MODE ) {
                        Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( tmpl->family );
                        request->tunnel_src = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & tmpl->saddr, sizeof ( tmpl->saddr ) ) ) );
                        request->tunnel_dst = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & tmpl->id.daddr, sizeof ( tmpl->id.daddr ) ) ) );
                    }

                    request->level = ( request->request_id == 0 ) ? SaRequest::LEVEL_REQUIRE : SaRequest::LEVEL_UNIQUE;

                    policy->sa_request = request;
                }

                this->ipsec_policies->push_back( policy.release() );

                // err = filter(&nladdr, h, arg1);
                h = NLMSG_NEXT( h, len );
            }

            // Get the next message until NLMSG_DONE received
            len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );
        }

        close( fd );

        // Print policies
        if ( show ) {
            Log::acquire();
            Log::writeMessage( "IpsecController", "Updating policies: Found Policies=[" + intToString( ipsec_policies->size() ) + "]", Log::LOG_IPSC, true );
            for ( vector<Policy*>::iterator it = this->ipsec_policies->begin(); it != this->ipsec_policies->end(); it++ )
                Log::writeMessage( "IpsecController", ( *it ) ->toStringTab( 1 ), Log::LOG_POLI, false );
            Log::release();
        }
    }

    uint32_t IpsecControllerImplXfrm::getSpi( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol) {

        // Send a GET_SPI request to the IPsec stack and return an error condition value (not the SPI value)
        return this->xfrmGetSpi( src, dst, protocol, 0, 1, 0xFFFFFFFF );
    }

    void IpsecControllerImplXfrm::createIpsecSa( const IpAddress & src, const IpAddress & dst, const ChildSa& childsa ) {
        // child_sa must have at least one traffic selector in each direction
        assert ( !childsa.my_traffic_selector->getTrafficSelectors().empty() );
        assert ( !childsa.peer_traffic_selector->getTrafficSelectors().empty() );

        Log::writeLockedMessage( "IpsecController", "IPsec tunnel creation (outbound)", Log::LOG_INFO, true );

        // creates the outbound IPsec SA
        this->xfrmAddUpdateIpsecSa(
            (XFRM_MSG_NEWSA),
            src,
            dst,
            childsa.ipsec_protocol,
            childsa.mode,
            childsa.outbound_spi,
            getXfrmEncrAlgo( childsa.getProposal().getFirstTransformByType( Enums::ENCR ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ei : *childsa.keyring->sk_er,
            getXfrmIntegAlgo( childsa.getProposal().getFirstTransformByType( Enums::INTEG ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ai : *childsa.keyring->sk_ar,
            childsa.getChildSaConfiguration().lifetime_soft,
            childsa.getChildSaConfiguration().lifetime_hard,
            childsa.getChildSaConfiguration().max_bytes_hard,
            0,
            *childsa.my_traffic_selector->getTrafficSelectors().front(),
            *childsa.peer_traffic_selector->getTrafficSelectors().front()
        );

        // Creates the inbound IPsec SA
        Log::writeLockedMessage( "IpsecController", "IPsec tunnel update (inbound)", Log::LOG_INFO, true );


    try {
        this->xfrmAddUpdateIpsecSa(
            (XFRM_MSG_UPDSA),
            dst,
            src,
            childsa.ipsec_protocol,
            childsa.mode,
            childsa.inbound_spi,
            getXfrmEncrAlgo( childsa.getProposal().getFirstTransformByType( Enums::ENCR ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_er : *childsa.keyring->sk_ei,
            getXfrmIntegAlgo( childsa.getProposal().getFirstTransformByType( Enums::INTEG ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ar : *childsa.keyring->sk_ai,
            childsa.getChildSaConfiguration().lifetime_soft,
            childsa.getChildSaConfiguration().lifetime_hard,
            childsa.getChildSaConfiguration().max_bytes_hard,
            0,
            *childsa.peer_traffic_selector->getTrafficSelectors().front(),
            *childsa.my_traffic_selector->getTrafficSelectors().front()
        );
    }catch(IpsecException & ex) {


        try {
            Log::writeLockedMessage( "IpsecController", "IPsec tunnel update fails, deleting it (inbound)", Log::LOG_WARN, true );
            this->xfrmDeleteIpsecSa( dst, src, childsa.ipsec_protocol, childsa.inbound_spi );

                }
        catch(IpsecException & ex2){
            Log::writeLockedMessage( "IpsecController", "Impossible deleting tunnel", Log::LOG_WARN, true );
        }

        Log::writeLockedMessage( "IpsecController", "IPsec tunnel update fails, creating it (inbound)", Log::LOG_WARN, true );

        this->xfrmAddUpdateIpsecSa(
            (XFRM_MSG_NEWSA),
            dst,
            src,
            childsa.ipsec_protocol,
            childsa.mode,
            childsa.inbound_spi,
            getXfrmEncrAlgo( childsa.getProposal().getFirstTransformByType( Enums::ENCR ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_er : *childsa.keyring->sk_ei,
            getXfrmIntegAlgo( childsa.getProposal().getFirstTransformByType( Enums::INTEG ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ar : *childsa.keyring->sk_ai,
            childsa.getChildSaConfiguration().lifetime_soft,
            childsa.getChildSaConfiguration().lifetime_hard,
            childsa.getChildSaConfiguration().max_bytes_hard,
            0,
            *childsa.peer_traffic_selector->getTrafficSelectors().front(),
            *childsa.my_traffic_selector->getTrafficSelectors().front()
        );
    }

    }

    uint32_t IpsecControllerImplXfrm::deleteIpsecSa( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t spi ) {
        try {
            this->xfrmDeleteIpsecSa( src, dst, protocol, spi );
        }
        catch ( IpsecException & ex ) {
            Log::writeLockedMessage( "IpsecController", "Warning: Deleting an already deleted IPSEC SA", Log::LOG_WARN, true );
            return 0;
        }
        return spi;
    }

    Policy & IpsecControllerImplXfrm::getIpsecPolicyById( uint32_t id ) {
        AutoLock auto_lock( *this->mutex_policies );

        for ( uint16_t i = 0; i < this->ipsec_policies->size(); i++ )
            if ( this->ipsec_policies[ i ] ->id == id )
                return *ipsec_policies[ i ];

        throw IpsecException( "Policy ID not found in SPD" );
    }


    void IpsecControllerImplXfrm::createIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, const IpAddress * src_tunnel, const IpAddress * dst_tunnel, bool autogen, bool sub ) {
        uint16_t src_prefix, dst_prefix;
        auto_ptr<IpAddress> src_selector = UtilsImpl::trafficSelectorToIpAddress( *src_sel.front(), &src_prefix );
        auto_ptr<IpAddress> dst_selector = UtilsImpl::trafficSelectorToIpAddress( *dst_sel.front(), &dst_prefix );

        uint16_t src_port = src_sel.front() ->getStartPort();
        uint16_t dst_port = dst_sel.front() ->getStartPort();
        uint8_t ip_protocol = src_sel.front() ->ip_protocol_id;

        if ( ip_protocol == Enums::IP_PROTO_ICMP || ip_protocol == Enums::IP_PROTO_ICMPv6 ) {
            src_port = src_sel[ 0 ] ->getStartIcmpType();
            dst_port = src_sel[ 0 ] ->getStartIcmpCode();
        }


        this->xfrmCreateIpsecPolicy( *src_selector, src_prefix, src_port, *dst_selector, dst_prefix, dst_port, ip_protocol, direction, action, ipsec_protocol, mode, priority, src_tunnel, dst_tunnel, autogen, sub );
        this->updatePolicies( false );
    }

    void IpsecControllerImplXfrm::deleteIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction ) {
        uint16_t src_prefix, dst_prefix;
        auto_ptr<IpAddress> src_selector = UtilsImpl::trafficSelectorToIpAddress( *src_sel.front(), &src_prefix );
        auto_ptr<IpAddress> dst_selector = UtilsImpl::trafficSelectorToIpAddress( *dst_sel.front(), &dst_prefix );

        uint16_t src_port = src_sel.front() ->getStartPort();
        uint16_t dst_port = dst_sel.front() ->getStartPort();
        uint8_t ip_protocol = src_sel.front() ->ip_protocol_id;

        this->xfrmDeleteIpsecPolicy( *src_selector, src_prefix, src_port, *dst_selector, dst_prefix, dst_port, ip_protocol, direction );
        this->updatePolicies( false );
    }

    void IpsecControllerImplXfrm::flushIpsecPolicies() {
        this->xfrmFlushIpsecPolicies();

        AutoLock auto_lock( *this->mutex_policies );
        this->ipsec_policies.clear();
    }

    void IpsecControllerImplXfrm::flushIpsecSas() {
        this->xfrmFlushIpsecSas();
    }

    xfrm_address_t IpsecControllerImplXfrm::getXfrmAddress( const IpAddress & address ) {
        assert ( address.getAddressSize() <= sizeof( xfrm_address_t ) );

        xfrm_address_t result;
        memset( &result, 0, sizeof( xfrm_address_t ) );
        memcpy( &result, address.getBytes() ->getRawPointer(), address.getAddressSize() );

        return result;

    }

    xfrm_selector IpsecControllerImplXfrm::getXfrmSelector( const TrafficSelector & ts_i, const TrafficSelector & ts_r ) {
        xfrm_selector result;
        memset( &result, 0, sizeof( xfrm_selector ) );

        // transform the traffic selector addresses in a subnet
        uint16_t src_prefix, dst_prefix;
        auto_ptr<IpAddress> src_addr = UtilsImpl::trafficSelectorToIpAddress( ts_i, &src_prefix );
        auto_ptr<IpAddress> dst_addr = UtilsImpl::trafficSelectorToIpAddress( ts_r, &dst_prefix );

        result.saddr = this->getXfrmAddress( *src_addr );
        result.sport = this->getXfrmSrcPort( ts_i, ts_r );
        result.sport_mask = ( result.sport ) ? ~0 : 0;
        result.prefixlen_s = src_prefix;

        result.daddr = this->getXfrmAddress( *dst_addr );
        result.dport = this->getXfrmDstPort( ts_i, ts_r );
        result.dport_mask = ( result.dport ) ? ~0 : 0;
        result.prefixlen_d = dst_prefix;

        result.family = UtilsImpl::getUnixFamily( src_addr->getFamily() );
        result.proto = ts_i.ip_protocol_id;

        return result;
    }

    uint16_t IpsecControllerImplXfrm::getXfrmSrcPort( const TrafficSelector & ts_i, const TrafficSelector & ts_r ) {
        // When ICMP protocol, the XFRM SRC PORT must be the ICMP TYPE
        if ( ts_i.ip_protocol_id == Enums::IP_PROTO_ICMP || ts_i.ip_protocol_id == Enums::IP_PROTO_ICMPv6 ) {
            // Since linux doesn't allows port ranges in the selectors, if the selector has a range, return ANY
            if ( ts_i.getStartIcmpType() == ts_i.getEndIcmpType() )
                return htons( ts_i.getStartIcmpType() );
            else
                return 0;
        }

        // when MH protocol, the XFRM SRC port is the more significant byte of TSi port
        else if ( ts_i.ip_protocol_id == Enums::IP_PROTO_MH ) {
            // Since linux doesn't allows port ranges in the selectors, if the selector has a range, return ANY
            if ( ts_i.getStartIcmpType() == ts_i.getStartIcmpType() )
                return htons( ts_i.getStartIcmpType() );
            else
                return 0;
        }

        // when other protocol, the XFRM SRC port is the TSi port
        else {
            // Since linux doesn't allows port ranges in the selectors, if the selector has a range, return ANY
            if ( ts_i.getStartPort() == ts_i.getEndPort() )
                return htons( ts_i.getStartPort() );
            else
                return 0;
        }

    }

    uint16_t IpsecControllerImplXfrm::getXfrmDstPort( const TrafficSelector & ts_i, const TrafficSelector & ts_r ) {
        // When ICMP protocol, the XFRM DST PORT must be the ICMP CODE
        if ( ts_i.ip_protocol_id == Enums::IP_PROTO_ICMP || ts_i.ip_protocol_id == Enums::IP_PROTO_ICMPv6 ) {
            // Since linux doesn't allows port ranges in the selectors, if the selector has a range, return ANY
            if ( ts_i.getStartIcmpCode() == ts_i.getEndIcmpCode() )
                return htons( ts_i.getStartIcmpCode() );
            else
                return 0;
        }

        // When MH protocol, the XFRM DST PORT must be 0
        else if ( ts_i.ip_protocol_id == Enums::IP_PROTO_MH ) {
            return 0;
        }

        // when other protocol, the XFRM DST port is the TSr port
        else {
            // Since linux doesn't allows port ranges in the selectors, if the selector has a range, return ANY
            if ( ts_r.getStartPort() == ts_r.getEndPort() )
                return htons( ts_r.getStartPort() );
            else
                return 0;
        }

    }

    void IpsecControllerImplXfrm::exit() {
        this->exiting = true;
    }

    void IpsecControllerImplXfrm::printPolicies() {
        this->updatePolicies( true );
    }

    void IpsecControllerImplXfrm::updateIpsecPolicyAddresses( const IpAddress & old_address, const IpAddress & new_address ) {
        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );

        struct {
            struct nlmsghdr nlh;
            struct xfrm_userpolicy_id id;
        }
        req;

        struct sockaddr_nl nladdr;

        memset( &req, 0, sizeof( req ) );
        nladdr.nl_family = AF_NETLINK;

        req.nlh.nlmsg_len = sizeof( req );
        req.nlh.nlmsg_type = XFRM_MSG_GETPOLICY;
        req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;

        netlinkSendMsg( fd, req.nlh );

        // get the response
        struct {
            struct nlmsghdr nlh;
            char data[ NLMSG_BUF_SIZE ];
        }
        res;

        int16_t len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );

        nlmsghdr *msg = &res.nlh;

        while ( res.nlh.nlmsg_type != NLMSG_DONE ) {
            // read all policies
            nlmsghdr * h = msg;
            while ( NLMSG_OK( h, len ) ) {
                if ( h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR ) {
                    close ( fd );
                    return ;
                }

                // Parseamos la politica
                struct xfrm_userpolicy_info *xpinfo = ( xfrm_userpolicy_info* ) NLMSG_DATA( h );

                struct rtattr* tb[ RTA_BUF_SIZE ];
                memset( tb, 0, sizeof( tb ) );
                uint16_t ntb = netlinkParseRtattrByIndex( tb, RTA_BUF_SIZE, XFRMP_RTA( xpinfo ), len - NLMSG_LENGTH( sizeof( *xpinfo ) ) );

                // Find template attributes
                for ( uint16_t i = 0; i < ntb; i++ ) {
                    if ( tb[ i ] ->rta_type != XFRMA_TMPL )
                        continue;

                    int len = tb[ i ] ->rta_len;
                    xfrm_user_tmpl* templates = ( xfrm_user_tmpl* ) RTA_DATA( tb[ i ] );

                    //Gets the number of templates
                    int ntmpls = len / sizeof( struct xfrm_user_tmpl );

                    // If there are more than one sa, we only use the first one
                    if ( ntmpls > 1 )
                        Log::writeLockedMessage( "IpsecController", "Warning: Policy has more than one request. SA BUNDLES are obsoleted and not supported.", Log::LOG_WARN, true );

                    struct xfrm_user_tmpl *tmpl = &templates[ 0 ];
                    Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( tmpl->family );

                    if ( tmpl->mode == 1 && family == old_address.getFamily() ) {
                        auto_ptr<IpAddress> tunnel_src = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & tmpl->saddr, sizeof ( tmpl->saddr ) ) ) );
                        if ( *tunnel_src == old_address ) {
                            memcpy( &tmpl->saddr, new_address.getBytes()->getRawPointer(), new_address.getAddressSize() );
                        }

                        auto_ptr<IpAddress> tunnel_dst = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & tmpl->id.daddr, sizeof ( tmpl->id.daddr ) ) ) );
                        if ( *tunnel_dst == old_address ) {
                            memcpy( &tmpl->id.daddr, new_address.getBytes()->getRawPointer(), new_address.getAddressSize() );
                        }

                        h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                        h->nlmsg_type = XFRM_MSG_UPDPOLICY;

                        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
                        netlinkSendMsg( fd, *h );

                        if ( netlinkReceiveAck( fd ) != 0 ) {
                            close( fd );
                            throw IpsecException( "Error performing an UPDATEPOLICY action" );
                        }

                        close( fd );
                    }

                }

                // err = filter(&nladdr, h, arg1);
                h = NLMSG_NEXT( h, len );
            }

            // Get the next message until NLMSG_DONE received
            len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );
        }

        close( fd );
    }

    void IpsecControllerImplXfrm::updateIpsecSaAddresses( const IpAddress & old_address, const IpAddress & new_address ) {
        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );

        struct {
            struct nlmsghdr nlh;
            struct xfrm_usersa_info id;
        }
        req;

        struct sockaddr_nl nladdr;

        memset( &req, 0, sizeof( req ) );
        nladdr.nl_family = AF_NETLINK;

        req.nlh.nlmsg_len = sizeof( req );
        req.nlh.nlmsg_type = XFRM_MSG_GETSA;
        req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;

        netlinkSendMsg( fd, req.nlh );

        // get the response
        struct {
            struct nlmsghdr nlh;
            char data[ NLMSG_BUF_SIZE ];
        }
        res;

        int16_t len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );

        nlmsghdr *msg = &res.nlh;

        while ( res.nlh.nlmsg_type != NLMSG_DONE ) {
            // read all policies
            nlmsghdr * h = msg;
            while ( NLMSG_OK( h, len ) ) {
                if ( h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR ) {
                    close ( fd );
                    return ;
                }

                // Parseamos la politica
                struct xfrm_usersa_info *sainfo = ( xfrm_usersa_info* ) NLMSG_DATA( h );

                Enums::ADDR_FAMILY family = UtilsImpl::getInternalFamily( sainfo->family );

                if ( family == old_address.getFamily() ) {
                    auto_ptr<IpAddress> tunnel_src = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & sainfo->saddr, sizeof ( sainfo->saddr ) ) ) );
                    auto_ptr<IpAddress> tunnel_dst = NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( new ByteArray( & sainfo->id.daddr, sizeof ( sainfo->id.daddr ) ) ) );

                    if ( *tunnel_src == old_address || *tunnel_dst == old_address ) {
                        // delete the old SA
                        struct {
                            struct nlmsghdr n;
                            struct xfrm_usersa_id id;
                            char data[ 1024 ];
                        }
                        req;

                        memset( &req, 0, sizeof( req ) );

                        req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                        req.n.nlmsg_type = XFRM_MSG_DELSA;

                        req.id.daddr = sainfo->id.daddr;
                        req.id.spi = sainfo->id.spi;
                        req.id.proto = sainfo->id.proto;
                        req.id.family = sainfo->family;

                        req.n.nlmsg_len = NLMSG_ALIGN( NLMSG_LENGTH( sizeof( req.id ) ) );

                        int32_t fd = netlinkOpen( 0, NETLINK_XFRM );
                        netlinkSendMsg( fd, req.n );

                        if ( netlinkReceiveAck( fd ) != 0 ) {
                            close( fd );
                            throw IpsecException( "Error performing a DELETE IPSEC SA action" );
                        }

                        close( fd );

                        if ( *tunnel_src == old_address )
                            memcpy( &sainfo->saddr, new_address.getBytes()->getRawPointer(), new_address.getAddressSize() );
                        else if ( *tunnel_dst == old_address ) {
                            memcpy( &sainfo->id.daddr, new_address.getBytes()->getRawPointer(), new_address.getAddressSize() );
                        }

                        // Create the udpated SA
                        h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                        h->nlmsg_type = XFRM_MSG_NEWSA;

                        fd = netlinkOpen( 0, NETLINK_XFRM );
                        netlinkSendMsg( fd, *h );

                        if ( netlinkReceiveAck( fd ) != 0 ) {
                            close( fd );
                            throw IpsecException( "Error performing an NEWSA action" );
                        }
                        close( fd );
                    }
                }


                // err = filter(&nladdr, h, arg1);
                h = NLMSG_NEXT( h, len );
            }

            // Get the next message until NLMSG_DONE received
            len = netlinkReceiveMsg( fd, res.nlh, sizeof( res ) );
        }

        close( fd );
    }

}











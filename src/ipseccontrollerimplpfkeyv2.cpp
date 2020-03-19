/**************************************************************************
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#include "ipseccontrollerimplpfkeyv2.h"
#include "utilsimpl.h"
#include "ipaddressopenike.h"
#include "addressconfiguration.h"
#include "roadwarriorpolicies.h"

#include <libopenikev2/ikesa.h>
#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/log.h>
#include <libopenikev2/autolock.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_PFKEY_RECV_SIZE 4096

#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PFKEY_UNIT64(a)     ((a) >> 3)

namespace openikev2 {

    uint8_t sadb_ext_min_len[] = {
        ( uint8_t ) 0,
        ( uint8_t ) sizeof( struct sadb_sa ),
        ( uint8_t ) sizeof( struct sadb_lifetime ),
        ( uint8_t ) sizeof( struct sadb_lifetime ),
        ( uint8_t ) sizeof( struct sadb_lifetime ),
        ( uint8_t ) sizeof( struct sadb_address ),
        ( uint8_t ) sizeof( struct sadb_address ),
        ( uint8_t ) sizeof( struct sadb_address ),
        ( uint8_t ) sizeof( struct sadb_key ),
        ( uint8_t ) sizeof( struct sadb_key ),
        ( uint8_t ) sizeof( struct sadb_ident ),
        ( uint8_t ) sizeof( struct sadb_ident ),
        ( uint8_t ) sizeof( struct sadb_sens ),
        ( uint8_t ) sizeof( struct sadb_prop ),
        ( uint8_t ) sizeof( struct sadb_supported ),
        ( uint8_t ) sizeof( struct sadb_supported ),
        ( uint8_t ) sizeof( struct sadb_spirange ),
        ( uint8_t ) sizeof( struct sadb_x_kmprivate ),
        ( uint8_t ) sizeof( struct sadb_x_policy ),
        ( uint8_t ) sizeof( struct sadb_x_sa2 ),
        ( uint8_t ) sizeof( struct sadb_x_nat_t_type ),
        ( uint8_t ) sizeof( struct sadb_x_nat_t_port ),
        ( uint8_t ) sizeof( struct sadb_x_nat_t_port ),
        ( uint8_t ) sizeof( struct sadb_address ),
        ( uint8_t ) 0,  // these are just to be safe upon new insertions
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
        ( uint8_t ) 0,
    };

    IpsecControllerImplPfkeyv2::IpsecControllerImplPfkeyv2() {
        this->name = "PFKEYv2";
        this->pfkey_bd_socket = -1;
        this->mutex_policies = ThreadController::getMutex();
        this->mutex_seq_number = ThreadController::getMutex();
        this->exiting = false;

        // Start the sequence number with 5 (for example)
        this->sequence_number = 5;

        this->pfkey_bd_socket = this->pfkeyCreateSocket();

        // Register in the socket for ESP SA type
        this->pfkeyRegister( Enums::PROTO_ESP );
        this->pfkeyRegister( Enums::PROTO_AH );

        // Update internal policy collection
        this->updatePolicies( false );
    }

    IpsecControllerImplPfkeyv2::~IpsecControllerImplPfkeyv2() {
        close( this->pfkey_bd_socket );

        // Finalizes execution of IPSEC_Controller
        Log::writeLockedMessage( "IPSecController", "Stop IpsecController.", Log::LOG_THRD, true );
    }

    void IpsecControllerImplPfkeyv2::flushIpsecPolicies () {
        this->pfkeySpdFlush( );

        AutoLock auto_lock( *this->mutex_policies );
        ipsec_policies.clear();
    }

    void IpsecControllerImplPfkeyv2::flushIpsecSas( ) {
        this->pfkeySadFlush( );
    }

    uint32_t IpsecControllerImplPfkeyv2::pfkeyDeleteIpsecSa( const IpAddress & srcaddr, const IpAddress & dstaddr, Enums::PROTOCOL_ID protocol, uint32_t spi ) {
        uint8_t * ext_hdrs[ SADB_EXT_MAX + 1 ];
        struct sadb_msg hdr;
        struct sadb_sa *sa;
        struct sadb_address *srcaddress, *dstaddress;
        int address_size, i;
        struct pfkey_msg *msg;

        assert( srcaddr.getFamily() == dstaddr.getFamily() );

        SocketAddressPosix src ( srcaddr.clone(), 0 );
        SocketAddressPosix dst ( dstaddr.clone(), 0 );

        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_DELETE;
        hdr.sadb_msg_satype = ( protocol == Enums::PROTO_ESP )
                              ? SADB_SATYPE_ESP
                              : SADB_SATYPE_AH;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        sa = ( sadb_sa* ) calloc( 1, sizeof( struct sadb_sa ) );
        ext_hdrs[ SADB_EXT_SA ] = ( uint8_t* ) sa;
        sa->sadb_sa_len = sizeof( struct sadb_sa ) / 8;
        sa->sadb_sa_exttype = SADB_EXT_SA;
        sa->sadb_sa_spi = htonl( spi );
        hdr.sadb_msg_len += sa->sadb_sa_len;


        address_size = src.getSockAddrSize();
        uint16_t pad = address_size % 8 ? 1 : 0;

        srcaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_SRC ] = ( uint8_t* ) srcaddress;
        srcaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        srcaddress->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
        memcpy( ( char * ) ( srcaddress + 1 ), src.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += srcaddress->sadb_address_len;

        dstaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_DST ] = ( uint8_t* ) dstaddress;
        dstaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        dstaddress->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
        memcpy( ( char * ) ( dstaddress + 1 ), dst.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += dstaddress->sadb_address_len;

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyDeleteExtHdrs( ext_hdrs );

        struct {
            sadb_msg hdr;
            uint8_t buffer[MAX_PFKEY_RECV_SIZE];
        } response;

        this->pfkeyReceive( fd, response.hdr, sizeof( response ) );
        close( fd );

        if ( response.hdr.sadb_msg_type != SADB_DELETE || response.hdr.sadb_msg_errno != 0 ) {
            throw PfkeyException( "Cannot delete IPsec SA" );
        }

        this->pfkeyParseExthdrs( response.hdr, ext_hdrs );
        sadb_sa *received_sa = ( sadb_sa* ) ext_hdrs[ SADB_EXT_SA ];

        // reads SPI value for this SA proposal
        spi = ntohl( received_sa->sadb_sa_spi );

        return spi;
    }

    uint32_t IpsecControllerImplPfkeyv2::pfkeyGetSpi( const IpAddress & srcaddr, const IpAddress & dstaddr, Enums::PROTOCOL_ID protocol ) {
        struct sadb_msg hdr;
        struct sadb_address *srcaddress;
        struct sadb_address *dstaddress;
        struct sadb_spirange *spirange;

        uint32_t socklen;
        uint32_t spi;
        uint8_t *ext_hdrs[ SADB_EXT_MAX + 1 ];

        SocketAddressPosix src ( srcaddr.clone(), 0 );
        SocketAddressPosix dst ( dstaddr.clone(), 0 );

        assert( srcaddr.getAddressSize() == dstaddr.getAddressSize() );

        memset( ext_hdrs, 0, ( SADB_EXT_MAX + 1 ) * sizeof( void * ) );

        // Size of the sockaddr struct
        socklen = src.getSockAddrSize();
        uint16_t pad = socklen % 8 ? 1 : 0;

        srcaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + socklen + pad * 8 );
        dstaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + socklen + pad * 8 );
        spirange = ( sadb_spirange* ) calloc( 1, sizeof( struct sadb_spirange ) );

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_GETSPI;
        hdr.sadb_msg_satype = ( protocol == Enums::PROTO_ESP ) ? SADB_SATYPE_ESP : Enums::PROTO_AH;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) >> 3;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        srcaddress->sadb_address_len = ( sizeof( struct sadb_address ) + socklen ) / 8 + pad;
        srcaddress->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
        memcpy( srcaddress + 1, src.getSockAddr().get(), socklen );
        hdr.sadb_msg_len += srcaddress->sadb_address_len;

        dstaddress->sadb_address_len = ( sizeof( struct sadb_address ) + socklen ) / 8 + pad;
        dstaddress->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
        memcpy( dstaddress + 1, dst.getSockAddr().get(), socklen );
        hdr.sadb_msg_len += dstaddress->sadb_address_len;

        spirange->sadb_spirange_len = sizeof( struct sadb_spirange ) / 8;
        spirange->sadb_spirange_exttype = SADB_EXT_SPIRANGE;
        spirange->sadb_spirange_min = 1;
        spirange->sadb_spirange_max = 0xFFFFFFFF;
        hdr.sadb_msg_len += spirange->sadb_spirange_len;

        memset( ext_hdrs, 0, sizeof( void * ) * ( SADB_EXT_MAX + 1 ) );
        ext_hdrs[ SADB_EXT_ADDRESS_SRC ] = ( uint8_t* ) srcaddress;
        ext_hdrs[ SADB_EXT_ADDRESS_DST ] = ( uint8_t* ) dstaddress;
        ext_hdrs[ SADB_EXT_SPIRANGE ] = ( uint8_t* ) spirange;

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyDeleteExtHdrs( ext_hdrs );

        struct {
            sadb_msg hdr;
            uint8_t buffer [MAX_PFKEY_RECV_SIZE];
        } retmsg;

        this->pfkeyReceive( fd, retmsg.hdr, sizeof( retmsg ) );
        close( fd );

        if ( retmsg.hdr.sadb_msg_type != SADB_GETSPI || retmsg.hdr.sadb_msg_errno != 0 ) {
            return 0;
        }

        this->pfkeyParseExthdrs( retmsg.hdr, ext_hdrs );

        sadb_sa *sa = ( sadb_sa* ) ext_hdrs[ SADB_EXT_SA ];

        uint32_t ipsec_spi = ntohl( sa->sadb_sa_spi );

        //this->deleteIpsecSa( srcaddr, dstaddr, protocol, ipsec_spi );

        return ipsec_spi;
    }

    void IpsecControllerImplPfkeyv2::pfkeyAddUpdateIpsecSa ( uint16_t operation, const IpAddress & srcaddr, const IpAddress & dstaddr,
                                                             Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t spi, uint16_t encr_type, ByteArray & encr_key,
                                                             uint16_t integ_type, ByteArray & integ_key, uint32_t limit_soft_time, uint32_t limit_hard_time,
                                                             uint32_t limit_hard_octets, uint32_t reqid ) {
        uint8_t * ext_hdrs[ SADB_EXT_MAX + 1 ];
        struct sadb_msg hdr;
        struct sadb_sa *sa;
        struct sadb_x_sa2 *sa2;
        struct sadb_lifetime *ltsoft, *lthard;
        struct sadb_address *srcaddress, *dstaddress;
        struct sadb_key *akey, *ekey;
        uint8_t address_size, i, ilen = integ_key.size(), elen = encr_key.size();
        struct pfkey_msg *msg;

        SocketAddressPosix src ( srcaddr.clone(), 0 );
        SocketAddressPosix dst ( dstaddr.clone(), 0 );

        assert( operation == SADB_UPDATE || operation == SADB_ADD );
        uint8_t buf_src[ 20 ], buf_dst[ 20 ];

        memset( ext_hdrs, 0, ( SADB_EXT_MAX + 1 ) * sizeof( void * ) );

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = operation;
        hdr.sadb_msg_satype = ( protocol == Enums::PROTO_ESP )
                              ? SADB_SATYPE_ESP : SADB_SATYPE_AH;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) >> 3;

        sa = ( sadb_sa* ) calloc( 1, sizeof( struct sadb_sa ) );
        ext_hdrs[ SADB_EXT_SA ] = ( uint8_t* ) sa;
        sa->sadb_sa_len = sizeof( struct sadb_sa ) / 8;
        sa->sadb_sa_exttype = SADB_EXT_SA;
        sa->sadb_sa_spi = htonl( spi );
        sa->sadb_sa_auth = integ_type;
        sa->sadb_sa_encrypt = encr_type;
        hdr.sadb_msg_len += sa->sadb_sa_len;

        lthard = ( sadb_lifetime* ) calloc( 1, sizeof( struct sadb_lifetime ) );
        ext_hdrs[ SADB_EXT_LIFETIME_HARD ] = ( uint8_t* ) lthard;
        lthard->sadb_lifetime_len = sizeof( struct sadb_lifetime ) / 8;
        lthard->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
        lthard->sadb_lifetime_addtime = limit_hard_time;
        lthard->sadb_lifetime_bytes = limit_hard_octets;
        hdr.sadb_msg_len += lthard->sadb_lifetime_len;

        ltsoft = ( sadb_lifetime* ) calloc( 1, sizeof( struct sadb_lifetime ) );
        ext_hdrs[ SADB_EXT_LIFETIME_SOFT ] = ( uint8_t* ) ltsoft;
        ltsoft->sadb_lifetime_len = sizeof( struct sadb_lifetime ) / 8;
        ltsoft->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
        ltsoft->sadb_lifetime_addtime = limit_soft_time;
        ltsoft->sadb_lifetime_bytes = ( uint64_t ) ( ( float ) limit_hard_octets * 0.8 );
        hdr.sadb_msg_len += ltsoft->sadb_lifetime_len;

        address_size = src.getSockAddrSize();

        uint16_t pad = address_size % 8 ? 1 : 0;

        srcaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_SRC ] = ( uint8_t* ) srcaddress;
        srcaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        srcaddress->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
        memcpy( ( char * ) ( srcaddress + 1 ), src.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += srcaddress->sadb_address_len;

        dstaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_DST ] = ( uint8_t* ) dstaddress;
        dstaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        dstaddress->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
        memcpy( ( char * ) ( dstaddress + 1 ), dst.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += dstaddress->sadb_address_len;

        if ( ilen > 0 ) {
            akey = ( sadb_key* ) calloc( 1, sizeof( struct sadb_key ) + ( ( ilen + 7 ) & ~7 ) );
            ext_hdrs[ SADB_EXT_KEY_AUTH ] = ( uint8_t* ) akey;
            akey->sadb_key_len = ( sizeof( struct sadb_key ) + ilen + 7 ) / 8;
            akey->sadb_key_exttype = SADB_EXT_KEY_AUTH;
            akey->sadb_key_bits = ilen * 8;
            memcpy( akey + 1, integ_key.getRawPointer(), ilen );
            hdr.sadb_msg_len += akey->sadb_key_len;
        }

        if ( elen > 0 ) {
            ekey = ( sadb_key* ) calloc( 1, sizeof( struct sadb_key ) + ( ( elen + 7 ) & ~7 ) );
            ext_hdrs[ SADB_EXT_KEY_ENCRYPT ] = ( uint8_t* ) ekey;
            ekey->sadb_key_len = ( sizeof( struct sadb_key ) + elen + 7 ) / 8;
            ekey->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
            ekey->sadb_key_bits = elen * 8;
            memcpy( ekey + 1, encr_key.getRawPointer(), elen );
            hdr.sadb_msg_len += ekey->sadb_key_len;
        }

        sa2 = ( sadb_x_sa2* ) calloc( 1, sizeof( struct sadb_x_sa2 ) );
        ext_hdrs[ SADB_X_EXT_SA2 ] = ( uint8_t* ) sa2;
        sa2->sadb_x_sa2_len = sizeof( struct sadb_x_sa2 ) / 8;
        sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
        sa2->sadb_x_sa2_mode = mode;
        sa2->sadb_x_sa2_reqid = reqid;
        hdr.sadb_msg_len += sa2->sadb_x_sa2_len;

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyDeleteExtHdrs( ext_hdrs );

        struct {
            sadb_msg hdr;
            uint8_t buffer[MAX_PFKEY_RECV_SIZE];
        } response;

        this->pfkeyReceive( fd, response.hdr, sizeof( response ) );
        close( fd );

        if ( response.hdr.sadb_msg_type != operation || response.hdr.sadb_msg_errno != 0 ) {
            throw IpsecException( "Error performing an UPDATE/ADD action" );
        }
    }



    uint32_t IpsecControllerImplPfkeyv2::deleteIpsecSa( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t spi ) {
        try {
            this->pfkeyDeleteIpsecSa( src, dst, protocol, spi );
        }
        catch ( PfkeyException & ex ) {
            Log::writeLockedMessage( "IpsecController", "Warning: Deleting an already deleted IPSEC SA", Log::LOG_WARN, true );
            return 0;
        }
        return spi;
    }


    uint32_t IpsecControllerImplPfkeyv2::getSpi( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol ) {

        uint32_t spi = this->pfkeyGetSpi( src, dst, protocol );
        return spi;
    }


    void IpsecControllerImplPfkeyv2::pfkeyCreateIpsecPolicy( IpAddress & src_selector, uint8_t src_prefixlen, uint16_t src_port, IpAddress & dst_selector, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::POLICY_ACTION action, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress * tunnel_src, const IpAddress * tunnel_dst ) {
        uint8_t * ext_hdrs[ SADB_EXT_MAX + 1 ];

        SocketAddressPosix src_sel ( src_selector.clone(), src_port );
        SocketAddressPosix dst_sel ( dst_selector.clone(), dst_port );

        struct sadb_msg hdr;
        struct sadb_x_policy *policy;
        struct sadb_x_ipsecrequest *request = NULL;
        struct sadb_address *srcaddress, *dstaddress;
        int address_size, i;

        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );
        memset( &hdr, 0, sizeof( struct sadb_msg ) );

        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_X_SPDADD;
        hdr.sadb_msg_satype = ( protocol == Enums::PROTO_ESP )
                              ? SADB_SATYPE_ESP
                              : SADB_SATYPE_AH;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        address_size = src_sel.getSockAddrSize();

        uint16_t pad = ( address_size % 8 ) ? 1 : 0;

        srcaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_SRC ] = ( uint8_t* ) srcaddress;
        srcaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;

        srcaddress->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
        srcaddress->sadb_address_prefixlen = src_prefixlen;
        srcaddress->sadb_address_proto = ip_protocol;

        memcpy( ( char * ) ( srcaddress + 1 ), src_sel.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += srcaddress->sadb_address_len;

        dstaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_DST ] = ( uint8_t* ) dstaddress;
        dstaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        dstaddress->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
        dstaddress->sadb_address_prefixlen = dst_prefixlen;
        dstaddress->sadb_address_proto = ip_protocol;
        memcpy( ( char * ) ( dstaddress + 1 ), dst_sel.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += dstaddress->sadb_address_len;

        // If IPSEC policy is to be created
        if ( protocol != Enums::PROTO_NONE ) {
            uint16_t ipsecrequest_len = sizeof( sadb_x_ipsecrequest );
            // If tunnel address included, calculates request len
            if ( mode == Enums::TUNNEL_MODE ) {
                assert ( tunnel_src != NULL && tunnel_dst != NULL );
                address_size = tunnel_src->getAddressSize() + 12;
                uint16_t pad = ( ( address_size * 2 ) % 8 ) ? 1 : 0;
                ipsecrequest_len += ( address_size * 2 ) + pad * 8;
            }
            request = ( sadb_x_ipsecrequest* ) calloc( 1, ipsecrequest_len );
            request->sadb_x_ipsecrequest_len = ipsecrequest_len;
            request->sadb_x_ipsecrequest_proto = ( protocol == Enums::PROTO_AH ) ? 51 : 50;    // 51 = AH    50 = ESP
            request->sadb_x_ipsecrequest_mode = ( mode == Enums::TRANSPORT_MODE ) ? 1 : 2;    // 1 = tranport    2 = tunnel
            request->sadb_x_ipsecrequest_level = 2;   // level = require
            request->sadb_x_ipsecrequest_reqid = 0;

            // If tunnel address, then copies sockaddrs
            if ( mode == Enums::TUNNEL_MODE ) {
                assert ( tunnel_src != NULL && tunnel_dst != NULL );
                SocketAddressPosix tun_src ( tunnel_src->clone(), 0 );
                SocketAddressPosix tun_dst ( tunnel_dst->clone(), 0 );

                address_size = tun_src.getSockAddrSize();
                char* pointer = ( char * ) ( request + 1 );
                memcpy( pointer, tun_src.getSockAddr().get(), address_size );
                memcpy( &pointer[ address_size ], tun_dst.getSockAddr().get(), address_size );
            }
        }

        uint16_t policy_len = sizeof( sadb_x_policy );
        if ( request != NULL ) {
            policy_len += request->sadb_x_ipsecrequest_len;
        }
        policy = ( sadb_x_policy* ) calloc( 1, policy_len );
        ext_hdrs[ SADB_X_EXT_POLICY ] = ( uint8_t* ) policy;
        policy->sadb_x_policy_len = policy_len / 8;
        policy->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
        policy->sadb_x_policy_type = ( protocol == Enums::PROTO_NONE ) ? 1 : 2;           // 1=NONE       2=IPSEC
        policy->sadb_x_policy_dir = dir;

#ifdef HAVE_PFKEY_POLICY_PRIORITY
        policy->sadb_x_policy_priority = priority;
#endif

        hdr.sadb_msg_len += policy->sadb_x_policy_len;

        // Copies the requets at the end of the policy
        if ( request != NULL )
            memcpy( ( char* ) ( policy + 1 ), ( char* ) request, request->sadb_x_ipsecrequest_len );

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyDeleteExtHdrs( ext_hdrs );

        struct {
            sadb_msg hdr;
            uint8_t buffer[MAX_PFKEY_RECV_SIZE];
        } response;

        this->pfkeyReceive( fd, response.hdr, sizeof( response ) );

        close( fd );
        if ( response.hdr.sadb_msg_type != SADB_X_SPDADD || response.hdr.sadb_msg_errno != 0 ) {
            throw IpsecException( "Error performing an CREATE POLICY action" );
        }
        delete request;
    }

    void IpsecControllerImplPfkeyv2::pfkeyDeleteIpsecPolicy( IpAddress & src_selector, uint8_t src_prefixlen, uint16_t src_port, IpAddress & dst_selector, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir ) {
        uint8_t * ext_hdrs[ SADB_EXT_MAX + 1 ];
        struct sadb_msg hdr;
        struct sadb_x_policy *policy;
        struct sadb_address *srcaddress, *dstaddress;
        int address_size;
        struct pfkey_msg *msg;

        SocketAddressPosix src_sel ( src_selector.clone(), src_port );
        SocketAddressPosix dst_sel ( dst_selector.clone(), dst_port );

        memset( ext_hdrs, 0, sizeof( void * ) * ( SADB_EXT_MAX + 1 ) );

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_X_SPDDELETE;
        hdr.sadb_msg_satype = SADB_SATYPE_UNSPEC;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        address_size = src_sel.getSockAddrSize();
        uint16_t pad = ( address_size % 8 ) ? 1 : 0;

        srcaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_SRC ] = ( uint8_t* ) srcaddress;
        srcaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        srcaddress->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
        srcaddress->sadb_address_prefixlen = src_prefixlen;
        srcaddress->sadb_address_proto = ip_protocol;
        memcpy( ( char * ) ( srcaddress + 1 ), src_sel.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += srcaddress->sadb_address_len;

        dstaddress = ( sadb_address* ) calloc( 1, sizeof( struct sadb_address ) + address_size + pad * 8 );
        ext_hdrs[ SADB_EXT_ADDRESS_DST ] = ( uint8_t* ) dstaddress;
        dstaddress->sadb_address_len = ( sizeof( struct sadb_address ) + address_size ) / 8 + pad;
        dstaddress->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
        dstaddress->sadb_address_prefixlen = dst_prefixlen;
        dstaddress->sadb_address_proto = ip_protocol;
        memcpy( ( char * ) ( dstaddress + 1 ), dst_sel.getSockAddr().get(), address_size );
        hdr.sadb_msg_len += dstaddress->sadb_address_len;

        uint16_t policy_len = sizeof( sadb_x_policy );

        policy = ( sadb_x_policy* ) calloc( 1, policy_len );
        ext_hdrs[ SADB_X_EXT_POLICY ] = ( uint8_t* ) policy;
        policy->sadb_x_policy_len = policy_len / 8;
        policy->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
        policy->sadb_x_policy_type = 0;
        policy->sadb_x_policy_dir = dir;
        hdr.sadb_msg_len += policy->sadb_x_policy_len;

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyDeleteExtHdrs( ext_hdrs );

        sadb_msg response;
        this->pfkeyReceive( fd, response, sizeof( response ) );
        close( fd );
        if ( ( response.sadb_msg_type != SADB_X_SPDDELETE && response.sadb_msg_type != SADB_X_SPDDELETE2 ) || response.sadb_msg_errno != 0 ) {
            throw IpsecException( "Error performing an DELETE POLICY action" );
        }
    }

    void IpsecControllerImplPfkeyv2::createIpsecSa( const IpAddress & src, const IpAddress & dst, const ChildSa& childsa ) {
        // child_sa must have at least one traffic selector in each direction
        assert ( !childsa.my_traffic_selector->getTrafficSelectors().empty() );
        assert ( !childsa.peer_traffic_selector->getTrafficSelectors().empty() );

        // creates the outbound IPsec SA
        this->pfkeyAddUpdateIpsecSa(
            SADB_ADD,
            src,
            dst,
            childsa.ipsec_protocol,
            childsa.mode,
            childsa.outbound_spi,
            getPfkeyEncrAlgo( childsa.getProposal().getFirstTransformByType( Enums::ENCR ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ei : *childsa.keyring->sk_er,
            getPfkeyIntegAlgo( childsa.getProposal().getFirstTransformByType( Enums::INTEG ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ai : *childsa.keyring->sk_ar,
            childsa.getChildSaConfiguration().lifetime_soft,
            childsa.getChildSaConfiguration().lifetime_hard,
            childsa.getChildSaConfiguration().max_bytes_hard,
            0
        );

        // Creates the inbound IPsec SA
        this->pfkeyAddUpdateIpsecSa(
            SADB_UPDATE,
            dst,
            src,
            childsa.ipsec_protocol,
            childsa.mode,
            childsa.inbound_spi,
            getPfkeyEncrAlgo( childsa.getProposal().getFirstTransformByType( Enums::ENCR ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_er : *childsa.keyring->sk_ei,
            getPfkeyIntegAlgo( childsa.getProposal().getFirstTransformByType( Enums::INTEG ) ),
            ( childsa.child_sa_initiator ) ? *childsa.keyring->sk_ar : *childsa.keyring->sk_ai,
            childsa.getChildSaConfiguration().lifetime_soft,
            childsa.getChildSaConfiguration().lifetime_hard,
            childsa.getChildSaConfiguration().max_bytes_hard,
            0
        );

    }

    void IpsecControllerImplPfkeyv2::updatePolicies( bool show ) {
        // Creates the PF_KEY socket
        AutoLock auto_lock( *this->mutex_policies );

        int32_t new_fd = this->pfkeyCreateSocket();

        this->ipsec_policies.clear();

        // Send SPD_DUMP
        this->pfkeySpdDump( new_fd );

        struct {
            sadb_msg hdr;
            uint8_t buffer[MAX_PFKEY_RECV_SIZE];
        } retmsg;

        this->pfkeyReceive( new_fd , retmsg.hdr, sizeof( retmsg ) );

        // If received message is an error, then exit
        if ( retmsg.hdr.sadb_msg_errno != 0 || retmsg.hdr.sadb_msg_type != SADB_X_SPDDUMP ) {
            Log::writeLockedMessage( "IPSecController", "PF_KEY: Updating policies: Found Policies=[0].", Log::LOG_IPSC, true );
            return;
        }

        // Insert first policy received
        ipsec_policies->push_back( msg2Policy( &retmsg.hdr ).release() );

        // Insert the rest of the policies received
        while ( retmsg.hdr.sadb_msg_seq > 0 ) {
            this->pfkeyReceive( new_fd , retmsg.hdr, sizeof( retmsg ) );

            // If received message is an error, then exit
            if ( retmsg.hdr.sadb_msg_errno != 0 || retmsg.hdr.sadb_msg_type != SADB_X_SPDDUMP ) {
                throw PfkeyException( "Error getting policies" );
            }

            // Insert first policy received
            ipsec_policies->push_back( msg2Policy( &retmsg.hdr ).release() );
        }

        // Print policies
        if ( show ) {
            Log::acquire();
            Log::writeMessage( "IPSecController", "PF_KEY: Updating policies: Found Policies=[" + intToString( ipsec_policies->size() ) + "]", Log::LOG_IPSC, true );
            for ( uint16_t i = 0; i < ipsec_policies->size(); i++ )
                Log::writeMessage( "IPSecController", ipsec_policies[i]->toStringTab( 1 ), Log::LOG_POLI, false );
            Log::release();
        }

        close( new_fd );
    }

    void IpsecControllerImplPfkeyv2::processAcquire( uint8_t * message_headers[] ) {
        // Obtains the message
        sadb_msg *msg = ( sadb_msg* ) message_headers[0];

        // Checks if address extension headers exist
        assert( message_headers[SADB_EXT_ADDRESS_SRC] != NULL );
        assert( message_headers[SADB_EXT_ADDRESS_DST] != NULL );
        assert( message_headers[SADB_EXT_ADDRESS_PROXY] == NULL );

        // Gets sockaddr structs from address extension headers
        sockaddr *sock_src = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_SRC] + sizeof( sadb_address ) );
        sockaddr *sock_dst = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_DST] + sizeof( sadb_address ) );

        // Creates the IpAddress objects
        auto_ptr<SocketAddress> src ( new SocketAddressPosix( *sock_src ) );
        auto_ptr<SocketAddress> dst ( new SocketAddressPosix( *sock_dst ) );

        // Get policy by its ID
        Policy & policy = this->getPolicyById( ( ( sadb_x_policy* ) message_headers[SADB_X_EXT_POLICY] )->sadb_x_policy_id );

        Log::acquire();
        Log::writeMessage( "IPSecController", "PF_KEY: Recv acquire: Policy Id=[" + intToString( policy.id ) + "]", Log::LOG_IPSC, true );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "SRC=[" + src->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IpsecController", Printable::generateTabs( 1 ) + "DST=[" + dst->toString() + "]", Log::LOG_IPSC, false );
        Log::writeMessage( "IPSecController", policy.toStringTab( 1 ), Log::LOG_POLI, false );
        Log::release();

        // construct the selectors
        auto_ptr<Payload_TSi> payload_ts_i ( new Payload_TSi() );
        auto_ptr<Payload_TSr> payload_ts_r ( new Payload_TSr() );

        // add the policy selectors
        payload_ts_i->addTrafficSelector( policy.getSrcTrafficSelector() );
        payload_ts_r->addTrafficSelector( policy.getDstTrafficSelector() );

        auto_ptr<ChildSaRequest> child_sa_request ( new ChildSaRequest( policy.sa_request->ipsec_protocol,
                                                                        policy.sa_request->mode,
                                                                        auto_ptr<Payload_TS> ( payload_ts_i ),
                                                                        auto_ptr<Payload_TS> ( payload_ts_r )
                                                                      )
                                                  );
        IkeSaController::requestChildSa( src->getIpAddress(), dst->getIpAddress(), child_sa_request );
    }

    void IpsecControllerImplPfkeyv2::processExpire( uint8_t * message_headers[] ) {
        sadb_sa *sa = ( sadb_sa* ) message_headers[SADB_EXT_SA];
        sadb_lifetime *lifetime_current = ( sadb_lifetime* ) message_headers[SADB_EXT_LIFETIME_CURRENT];
        sadb_lifetime *lifetime_soft = ( sadb_lifetime* ) message_headers[SADB_EXT_LIFETIME_SOFT];
        sadb_lifetime *lifetime_hard = ( sadb_lifetime* ) message_headers[SADB_EXT_LIFETIME_HARD];

        // Gets sockaddr structs from address extension headers
        sockaddr *sock_src = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_SRC] + sizeof( sadb_address ) );
        sockaddr *sock_dst = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_DST] + sizeof( sadb_address ) );

        // Creates the IpAddress objects
        auto_ptr<SocketAddress> src_addr ( new SocketAddressPosix( *sock_src ) );
        auto_ptr<SocketAddress> dst_addr ( new SocketAddressPosix( *sock_dst ) );

        // reads SPI value for this SA extension
        uint32_t rekeyed_spi = ntohl( sa->sadb_sa_spi );

        bool hard = ( lifetime_hard != NULL ) ? true : false;

        IpsecControllerImplOpenIKE::processExpire( src_addr->getIpAddress(), dst_addr->getIpAddress(), rekeyed_spi, hard );
    }


    void IpsecControllerImplPfkeyv2::run() {
        Log::writeLockedMessage( "IpsecControllerPfkeyv2", "Start: Thread ID=[" + intToString( thread_id ), Log::LOG_THRD, true );

        // Array to store message extension headers
        uint8_t* message_headers[SADB_EXT_MAX + 1];

        try {
            // Do forever
            while ( !exiting ) {
                // Receives a message thru PF KEY
                struct {
                    sadb_msg hdr;
                    uint8_t buffer[MAX_PFKEY_RECV_SIZE];
                } msg;

                this->pfkeyReceive( this->pfkey_bd_socket, msg.hdr, sizeof( msg ) );

                if ( exiting )
                    continue;

                // If the message isn't for us, omit it
                if ( msg.hdr.sadb_msg_pid != getpid() && msg.hdr.sadb_msg_pid != 0 )
                    continue;

                // Aligns message extension headers
                this->pfkeyParseExthdrs( msg.hdr, message_headers );

                // Switch for message type
                switch ( msg.hdr.sadb_msg_type ) {
                        // This message types mustn't be received

                    case SADB_ACQUIRE:
                        processAcquire( message_headers );
                        break;

                    case SADB_EXPIRE:
                        processExpire( message_headers );
                        break;
                }
            }
        }
        catch ( Exception &ex ) {
            Log::writeLockedMessage( "IpsecController", ex.what(), Log::LOG_ERRO, true );
        }
    }

    uint32_t IpsecControllerImplPfkeyv2::nextSeqNumber( ) {
        AutoLock auto_lock( *mutex_seq_number );
        uint32_t temp = this->sequence_number++;
        return temp;
    }

    auto_ptr<Policy> IpsecControllerImplPfkeyv2::msg2Policy( sadb_msg * spd_dump_response ) {
        auto_ptr<Policy> result ( new Policy() );
        uint8_t* message_headers[SADB_EXT_MAX + 1];

        // Align message headers
        this->pfkeyParseExthdrs( *spd_dump_response, message_headers );

        // Obtains direction (OUT, IN...)
        sadb_x_policy* policy = ( sadb_x_policy* ) message_headers[SADB_X_EXT_POLICY];
        result->direction = ( Enums::DIRECTION ) policy->sadb_x_policy_dir;

        // Obtains ip_protocol  (transport protocol: UDP, TCP, ICMP...)
        result->ip_protocol = ( ( sadb_address* ) message_headers[SADB_EXT_ADDRESS_SRC] )->sadb_address_proto;
        if ( result->ip_protocol != ( ( sadb_address* ) message_headers[SADB_EXT_ADDRESS_DST] )->sadb_address_proto )
            throw PfkeyException( "Error parsing SPD_DUMP. Transport protocol don't match in policy addresses" );

        // Obtains id
        result->id = policy->sadb_x_policy_id;

        // Obtains prefixes
        result->selector_prefixlen_src = ( ( sadb_address* ) message_headers[SADB_EXT_ADDRESS_SRC] )->sadb_address_prefixlen;
        result->selector_prefixlen_dst = ( ( sadb_address* ) message_headers[SADB_EXT_ADDRESS_DST] )->sadb_address_prefixlen;

        // Obtains policy addresses
        sockaddr *sockaddr_policy_src = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_SRC] + sizeof( sadb_address ) );
        sockaddr *sockaddr_policy_dst = ( sockaddr* ) ( message_headers[SADB_EXT_ADDRESS_DST] + sizeof( sadb_address ) );
        SocketAddressPosix selector_src( *sockaddr_policy_src );
        SocketAddressPosix selector_dst( *sockaddr_policy_dst );
        result->selector_src = selector_src.getIpAddress().clone();
        result->selector_dst = selector_dst.getIpAddress().clone();
        result->selector_src_port = selector_src.getPort();
        result->selector_dst_port = selector_dst.getPort();
        result->icmp_type = selector_src.getPort();
        result->icmp_code = selector_dst.getPort();

        // Exit when no IPSEC_POLICY_IPSEC
        if ( policy->sadb_x_policy_type != 2 ) {
            return result;
        }

        uint8_t *position = message_headers[SADB_X_EXT_POLICY] + sizeof( sadb_x_policy );
        uint16_t remaining = policy->sadb_x_policy_len * 8 - sizeof( sadb_x_policy );

        if ( remaining <= 0 )
            throw PfkeyException( "There isn't any request in this IPSEC policy" );

        while ( remaining > 0 ) {
            sadb_x_ipsecrequest *request = ( sadb_x_ipsecrequest* ) position;
            auto_ptr<SaRequest> req = msg2Request( request );

            if ( result->sa_request.get() )
                Log::writeLockedMessage( "IPSecController", "Warning: Policy has more than one request. SA BUNDLES are obsoleted and not supported.", Log::LOG_WARN, true );

            result->sa_request = req;

            position += request->sadb_x_ipsecrequest_len;
            remaining -= request->sadb_x_ipsecrequest_len;
        }

        return result;
    }

    auto_ptr<SaRequest> IpsecControllerImplPfkeyv2::msg2Request( sadb_x_ipsecrequest * request ) {
        assert( request != NULL );

        auto_ptr<SaRequest> result ( new SaRequest() );

        result->mode = ( Enums::IPSEC_MODE ) request->sadb_x_ipsecrequest_mode;
        result->ipsec_protocol = this->getIkeProto( request->sadb_x_ipsecrequest_proto );
        result->level = ( SaRequest::IPSEC_LEVEL ) request->sadb_x_ipsecrequest_level;
        result->request_id = request->sadb_x_ipsecrequest_reqid;

        // If no tunnel mode, then size of structure must be sizeof(sadb_x_ipsecrequest)
        if ( result->mode != Enums::TUNNEL_MODE ) {
            if ( request->sadb_x_ipsecrequest_len != sizeof( sadb_x_ipsecrequest ) ) {
                throw PfkeyException( "SA request has invalid size." );
            }
        }

        // If tunnel mode, then create tunnel objects
        else {
            uint8_t *position = ( uint8_t* ) request;

            sockaddr *tunnel_src = ( sockaddr* ) ( position + sizeof( sadb_x_ipsecrequest ) );
            SocketAddressPosix tunnelsrc( *tunnel_src );
            result->tunnel_src = tunnelsrc.getIpAddress().clone();

            if ( request->sadb_x_ipsecrequest_len != sizeof( sadb_x_ipsecrequest ) + ( result->tunnel_src->getAddressSize() + 12 ) * 2 )
                throw PfkeyException( "SA request has invalid size. Len=" + intToString( request->sadb_x_ipsecrequest_len ) );

            sockaddr *tunnel_dst = ( sockaddr* ) ( position + sizeof( sadb_x_ipsecrequest ) + result->tunnel_src->getAddressSize() + 12 );
            SocketAddressPosix tunneldst( *tunnel_dst );
            result->tunnel_dst = tunneldst.getIpAddress().clone();
        }

        return result;
    }

    Enums::PROTOCOL_ID IpsecControllerImplPfkeyv2::getIkeProto( uint16_t pfkey_proto ) {
        if ( pfkey_proto == 50 )
            return Enums::PROTO_ESP;
        else if ( pfkey_proto == 51 )
            return Enums::PROTO_AH;
        else
            throw PfkeyException( "Invalid protocol to make conversion from PF_KEY to IKE" );
    }


    uint16_t IpsecControllerImplPfkeyv2::getPfkeyEncrAlgo( const Transform* encr_transform ) {
        Enums::ENCR_ID algo = encr_transform ? ( Enums::ENCR_ID ) encr_transform->id : Enums::ENCR_NONE;

        if ( algo == Enums::ENCR_NONE )
            return SADB_EALG_NONE;
        else if ( algo == Enums::ENCR_DES )
            return SADB_EALG_DESCBC;
        else if ( algo == Enums::ENCR_3DES )
            return SADB_EALG_3DESCBC;
        else if ( algo == Enums::ENCR_CAST )
            return SADB_X_EALG_CASTCBC;
        else if ( algo == Enums::ENCR_BLOWFISH )
            return SADB_X_EALG_BLOWFISHCBC;
        else if ( algo == Enums::ENCR_AES_CBC )
            return SADB_X_EALG_AESCBC;
        else
            throw PfkeyException( "Invalid encr algotithm to make conversion from IKE to PF_KEY" );
    }

    uint16_t IpsecControllerImplPfkeyv2::getPfkeyIntegAlgo( const Transform* integ_transform ) {
        Enums::INTEG_ID algo = integ_transform ? ( Enums::INTEG_ID ) integ_transform->id : Enums::AUTH_NONE;

        if ( algo == Enums::AUTH_NONE )
            return SADB_AALG_NONE;
        else if ( algo == Enums::AUTH_HMAC_MD5_96 )
            return SADB_AALG_MD5HMAC;
        else if ( algo == Enums::AUTH_HMAC_SHA1_96 )
            return SADB_AALG_SHA1HMAC;
        else
            throw PfkeyException( "Invalid integ algotithm to make conversion from IKE to PF_KEY" );
    }

    void IpsecControllerImplPfkeyv2::pfkeyParseExthdrs( struct sadb_msg &hdr, uint8_t **ext_hdrs ) {
        char *p = ( char * ) & hdr;
        int len = hdr.sadb_msg_len << 3;

        memset( ext_hdrs, 0, sizeof( void * ) * ( SADB_EXT_MAX + 1 ) );

        len -= sizeof( struct sadb_msg );
        p += sizeof( struct sadb_msg );
        while ( len > 0 ) {
            struct sadb_ext *ehdr = ( struct sadb_ext * ) p;
            uint16_t ext_type;
            int32_t ext_len;

            ext_len  = ehdr->sadb_ext_len;
            ext_len *= sizeof( uint64_t );
            ext_type = ehdr->sadb_ext_type;
            if ( ext_len < sizeof( uint64_t ) || ext_len > len || ext_type == SADB_EXT_RESERVED )
                throw PfkeyException( "Error parsing PF_KEY message" );

            if ( ext_type <= SADB_EXT_MAX ) {
                int min = ( int ) sadb_ext_min_len[ext_type];
                if ( ext_len < min )
                    throw PfkeyException( "Error parsing PF_KEY message" );
                if ( ext_hdrs[ext_type] != NULL )
                    throw PfkeyException( "Error parsing PF_KEY message" );
                ext_hdrs[ext_type] = ( uint8_t* ) p;
            }
            p   += ext_len;
            len -= ext_len;
        }
    }

    void IpsecControllerImplPfkeyv2::pfkeySend( int32_t fd, sadb_msg * hdr, uint8_t* ext_hdrs[] ) {
        struct iovec *_io_vec;
        int niovec, i;

        if ( !( _io_vec = ( iovec* ) calloc( 1, sizeof( struct iovec ) * ( SADB_EXT_MAX + 1 ) ) ) ) {
            throw PfkeyException( "Error sending message" );
        }

        niovec = 0;

        _io_vec[niovec].iov_base = hdr;
        _io_vec[niovec++].iov_len = sizeof( struct sadb_msg );

        for ( i = 0; i < SADB_EXT_MAX + 1; i++ ) {
            if ( ext_hdrs[i] == NULL )
                continue;

            _io_vec[niovec].iov_base = ext_hdrs[i];
            _io_vec[niovec++].iov_len =
                ( ( struct sadb_ext * )ext_hdrs[i] )->sadb_ext_len << 3;
        }

        if ( writev( fd, _io_vec, niovec ) < 0 ) {
            perror( "writev: " );
            free( _io_vec );
            throw PfkeyException( "Error sending message" );
        }

        free( _io_vec );
    }

    void IpsecControllerImplPfkeyv2::pfkeyRegister( Enums::PROTOCOL_ID protocol ) {
        uint8_t *ext_hdrs[SADB_EXT_MAX + 1];
        struct sadb_msg hdr;
        struct {
            sadb_msg hdr;
            uint8_t buffer [MAX_PFKEY_RECV_SIZE];
        } retmsg;

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_REGISTER;
        hdr.sadb_msg_satype = ( protocol == Enums::PROTO_ESP )
                              ?  SADB_SATYPE_ESP :
                              ( ( protocol == Enums::PROTO_AH )
                                ? SADB_SATYPE_AH
                                : SADB_SATYPE_UNSPEC );
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );

        this->pfkeySend( this->pfkey_bd_socket, &hdr, ext_hdrs );
        this->pfkeyReceive( this->pfkey_bd_socket, retmsg.hdr, sizeof ( retmsg ) );
        this->pfkeyParseExthdrs( retmsg.hdr, ext_hdrs );
    }


    void IpsecControllerImplPfkeyv2::pfkeyReceive( int32_t fd, sadb_msg & message, uint16_t message_max_size ) {
        int len;

        if ( ( len = read( fd, &message, message_max_size ) ) <= 0 )
            throw PfkeyException( "Error receiving PFKEY message: error reading PFKEY socket." );

        else {
            if ( len != message.sadb_msg_len * 8 ) {
                throw PfkeyException( "Error receiving PFKEY message: PFKEY message doesn't fit in available memory: " + intToString( message_max_size ) + " " + intToString( MAX_PFKEY_RECV_SIZE ) + " " + intToString( len ) );
            }
        }
    }

    void IpsecControllerImplPfkeyv2::pfkeySpdDump( int32_t fd ) {
        uint8_t *ext_hdrs[SADB_EXT_MAX + 1];
        struct sadb_msg newmsg;
        uint32_t len;
        caddr_t p;
        caddr_t ep;

        // create new sadb_msg to send.
        len = sizeof( struct sadb_msg );

        newmsg.sadb_msg_version = PF_KEY_V2;
        newmsg.sadb_msg_type = SADB_X_SPDDUMP;
        newmsg.sadb_msg_errno = 0;
        newmsg.sadb_msg_satype = SADB_SATYPE_UNSPEC;
        newmsg.sadb_msg_len = len / 8;
        newmsg.sadb_msg_reserved = 0;
        newmsg.sadb_msg_seq = this->nextSeqNumber();
        newmsg.sadb_msg_pid = getpid();

        // send message
        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );

        this->pfkeySend( fd, &newmsg, ext_hdrs );
        this->pfkeyParseExthdrs( newmsg, ext_hdrs );
    }


    void IpsecControllerImplPfkeyv2::pfkeyDeleteExtHdrs( uint8_t ** ext_hdrs ) {
        for ( uint16_t i = 0; i < SADB_EXT_MAX + 1; i++ )
            if ( ext_hdrs[i] != NULL )
                delete[] ext_hdrs[i];
    }

    Policy & IpsecControllerImplPfkeyv2::getPolicyById( uint32_t id ) {
        AutoLock auto_lock( *this->mutex_policies );

        for ( uint16_t i = 0; i < ipsec_policies->size(); i++ )
            if ( ipsec_policies[i]->id == id )
                return *ipsec_policies[i];

        throw PfkeyException( "Policy ID not found in SPD" );
    }

    void IpsecControllerImplPfkeyv2::createIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, const IpAddress * src_tunnel, const IpAddress * dst_tunnel , bool autogen, bool sub) {
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

        this->pfkeyCreateIpsecPolicy( *src_selector, src_prefix, src_port, *dst_selector, dst_prefix, dst_port, ip_protocol, direction, action, ipsec_protocol, mode, priority, src_tunnel, dst_tunnel );
        this->updatePolicies( false );
    }

    void IpsecControllerImplPfkeyv2::deleteIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction ) {
        uint16_t src_prefix, dst_prefix;
        auto_ptr<IpAddress> src_selector = UtilsImpl::trafficSelectorToIpAddress( *src_sel.front(), &src_prefix );
        auto_ptr<IpAddress> dst_selector = UtilsImpl::trafficSelectorToIpAddress( *dst_sel.front(), &dst_prefix );

        uint16_t src_port = src_sel.front() ->getStartPort();
        uint16_t dst_port = dst_sel.front() ->getStartPort();
        uint8_t ip_protocol = src_sel.front() ->ip_protocol_id;

        this->pfkeyDeleteIpsecPolicy( *src_selector, src_prefix, src_port, *dst_selector, dst_prefix, dst_port, ip_protocol, direction );
        this->updatePolicies( false );
    }

    int32_t IpsecControllerImplPfkeyv2::pfkeyCreateSocket( ) {
        int32_t new_fd;
        if ( ( new_fd = socket( PF_KEY, SOCK_RAW, PF_KEY_V2 ) ) < 0 )
            throw PfkeyException( "Cannot crate PF_KEY socket. Reason(" + intToString( new_fd ) );
        return new_fd;
    }

    void IpsecControllerImplPfkeyv2::pfkeySpdFlush( ) {
        uint8_t *ext_hdrs[SADB_EXT_MAX + 1];
        struct sadb_msg hdr;
        struct {
            sadb_msg hdr;
            uint8_t buffer [MAX_PFKEY_RECV_SIZE];
        } retmsg;

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_X_SPDFLUSH;
        hdr.sadb_msg_satype = SADB_SATYPE_UNSPEC;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyReceive( fd, retmsg.hdr, sizeof( retmsg ) );
        this->pfkeyParseExthdrs( retmsg.hdr, ext_hdrs );
        close ( fd );
    }

    void IpsecControllerImplPfkeyv2::pfkeySadFlush( ) {
        uint8_t *ext_hdrs[SADB_EXT_MAX + 1];
        struct sadb_msg hdr;
        struct {
            sadb_msg hdr;
            uint8_t buffer [MAX_PFKEY_RECV_SIZE];
        } retmsg;

        memset( &hdr, 0, sizeof( struct sadb_msg ) );
        hdr.sadb_msg_version = PF_KEY_V2;
        hdr.sadb_msg_type = SADB_FLUSH;
        hdr.sadb_msg_satype = SADB_SATYPE_UNSPEC;
        hdr.sadb_msg_len = sizeof( struct sadb_msg ) / 8;
        hdr.sadb_msg_seq = this->nextSeqNumber();
        hdr.sadb_msg_pid = getpid();

        memset( ext_hdrs, 0, sizeof( uint8_t * ) * ( SADB_EXT_MAX + 1 ) );

        int32_t fd = this->pfkeyCreateSocket();
        this->pfkeySend( fd, &hdr, ext_hdrs );
        this->pfkeyReceive( fd, retmsg.hdr, sizeof( retmsg ) );
        this->pfkeyParseExthdrs( retmsg.hdr, ext_hdrs );
        close( fd );
    }

    void IpsecControllerImplPfkeyv2::exit() {
        this->exiting = true;
    }

    void IpsecControllerImplPfkeyv2::printPolicies() {
        this->updatePolicies( true );
    }

    void IpsecControllerImplPfkeyv2::updateIpsecSaAddresses( const IpAddress & old_address, const IpAddress & new_address ) {
    }

    void IpsecControllerImplPfkeyv2::updateIpsecPolicyAddresses( const IpAddress & old_address, const IpAddress & new_address ) {
    }
}

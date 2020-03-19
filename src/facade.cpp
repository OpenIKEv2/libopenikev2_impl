/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "facade.h"

#include "threadcontrollerimplposix.h"
#include "ikesacontrollerimplopenike.h"
#include "networkcontrollerimplopenike.h"
#include "ipseccontrollerimplxfrm.h"
#include "logimplcolortext.h"
#include "cryptocontrollerimplopenike.h"
#include "alarmcontrollerimplopenike.h"
#include "ipaddressopenike.h"

#include <stdio.h>


namespace openikev2 {
    auto_ptr<ThreadControllerImplPosix> Facade::thread_controller_impl( NULL );
    auto_ptr<IpsecControllerImplOpenIKE> Facade::ipsec_controller_impl( NULL );
    auto_ptr<NetworkControllerImplOpenIKE> Facade::network_controller_impl( NULL );
    auto_ptr<CryptoControllerImplOpenIKE> Facade::crypto_controller_impl( NULL );
    auto_ptr<LogImplOpenIKE> Facade::log_impl( NULL );
    auto_ptr<AlarmControllerImplOpenIKE> Facade::alarm_controller_impl( NULL );
    auto_ptr<IkeSaControllerImplOpenIKE> Facade::ike_sa_controller_impl( NULL );

    void Facade::initialize( string log_filename ) {
        // Loads the controllers
        thread_controller_impl.reset( new ThreadControllerImplPosix() );
        ThreadController::setImplementation( thread_controller_impl.get() );

        log_impl.reset( new LogImplColorText() );
        Log::setImplementation( log_impl.get() );

        // Setup the basic log
        log_impl->setLogMask( Log::LOG_ALL );
        log_impl->open( log_filename );
        log_impl->showExtraInfo( true );

        network_controller_impl.reset( new NetworkControllerImplOpenIKE() );
        NetworkController::setImplementation( network_controller_impl.get() );

        ipsec_controller_impl.reset( new IpsecControllerImplXfrm() );
        IpsecController::setImplementation( ipsec_controller_impl.get() );

        crypto_controller_impl.reset( new CryptoControllerImplOpenIKE() );
        CryptoController::setImplementation( crypto_controller_impl.get() );

        alarm_controller_impl.reset( new AlarmControllerImplOpenIKE( 1000 ) );
        AlarmController::setImplementation( alarm_controller_impl.get() ) ;

        ike_sa_controller_impl.reset( new IkeSaControllerImplOpenIKE( 10 ) );
        IkeSaController::setImplementation( ike_sa_controller_impl.get() );

        // Flush SPD and SAD
        IpsecController::flushIpsecPolicies();
        IpsecController::flushIpsecSas();

        // create the allow policies for IKE protocol
        createIpsecPolicy( "0.0.0.0/0", 500, "0.0.0.0/0", 500, Enums::IP_PROTO_UDP, Enums::DIR_ALL, Enums::POLICY_ALLOW, 0 );
        createIpsecPolicy( "0::0/0", 500, "0::0/0", 500, Enums::IP_PROTO_UDP, Enums::DIR_ALL, Enums::POLICY_ALLOW, 0 );
        createIpsecPolicy( "0::0/0", "0::0/0", Enums::IP_PROTO_ICMPv6, 135, 0, Enums::DIR_ALL, Enums::POLICY_BLOCK, 0 );
        createIpsecPolicy( "0::0/0", "0::0/0", Enums::IP_PROTO_ICMPv6, 136, 0, Enums::DIR_ALL, Enums::POLICY_BLOCK, 0 );
    }


    void Facade::startThreads( ) {
        ipsec_controller_impl->start();
        alarm_controller_impl->start();
        network_controller_impl->start();
    }

    void Facade::createIpsecPolicy( string src_selector, uint16_t src_port, string dst_selector, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, string src_tunnel, string dst_tunnel, bool autogen, bool sub ) {
        auto_ptr<NetworkPrefix> src_sel = getNetworkPrefix( src_selector );
        auto_ptr<TrafficSelector> ts_i( new TrafficSelector( src_sel->getNetworkAddress(), src_sel->getPrefixLen(), src_port, ip_protocol ) );

        auto_ptr<NetworkPrefix> dst_sel = getNetworkPrefix( dst_selector );
        auto_ptr<TrafficSelector> ts_r( new TrafficSelector( dst_sel->getNetworkAddress(), dst_sel->getPrefixLen(), dst_port, ip_protocol ) );

        auto_ptr<IpAddress> src_tun;
        auto_ptr<IpAddress> dst_tun;
        if ( mode == Enums::TUNNEL_MODE ) {
            src_tun.reset( new IpAddressOpenIKE( src_tunnel ) );
            dst_tun.reset( new IpAddressOpenIKE( dst_tunnel ) );
        }
	IpsecController::createIpsecPolicy( *ts_i, *ts_r, direction, action, priority, ipsec_protocol, mode, src_tun.get(), dst_tun.get(), autogen, sub );


    }

    void Facade::deleteIpsecPolicy( string src_selector, uint16_t src_port, string dst_selector, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION direction ) {
        auto_ptr<NetworkPrefix> src_sel = getNetworkPrefix( src_selector );
        auto_ptr<TrafficSelector> ts_i( new TrafficSelector( src_sel->getNetworkAddress(), src_sel->getPrefixLen(), src_port, ip_protocol ) );
        vector<TrafficSelector*> vts_i;
        vts_i.push_back( ts_i.get() );

        auto_ptr<NetworkPrefix> dst_sel = getNetworkPrefix( dst_selector );
        auto_ptr<TrafficSelector> ts_r( new TrafficSelector( dst_sel->getNetworkAddress(), dst_sel->getPrefixLen(), dst_port, ip_protocol ) );
        vector<TrafficSelector*> vts_r;
        vts_r.push_back( ts_r.get() );

        IpsecController::deleteIpsecPolicy( vts_i, vts_r, direction  );
    }

    void Facade::createIpsecPolicy( string src_selector, string dst_selector, uint8_t ip_protocol, uint8_t icmp_type, uint8_t icmp_code, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, string src_tunnel, string dst_tunnel, bool autogen, bool sub) {
        assert( ip_protocol == Enums::IP_PROTO_ICMP || ip_protocol == Enums::IP_PROTO_ICMPv6 );

        auto_ptr<NetworkPrefix> src_sel = getNetworkPrefix( src_selector );
        auto_ptr<TrafficSelector> ts_i( new TrafficSelector( src_sel->getNetworkAddress(), src_sel->getPrefixLen(), icmp_type, icmp_code, ip_protocol ) );

        auto_ptr<NetworkPrefix> dst_sel = getNetworkPrefix( dst_selector );
        auto_ptr<TrafficSelector> ts_r( new TrafficSelector( dst_sel->getNetworkAddress(), dst_sel->getPrefixLen(), icmp_type, icmp_code, ip_protocol ) );

        auto_ptr<IpAddress> src_tun;
        auto_ptr<IpAddress> dst_tun;
        if ( mode == Enums::TUNNEL_MODE ) {
            src_tun.reset( new IpAddressOpenIKE( src_tunnel ) );
            dst_tun.reset( new IpAddressOpenIKE( dst_tunnel ) );
        }

        IpsecController::createIpsecPolicy( *ts_i, *ts_r, direction, action, priority, ipsec_protocol, mode, src_tun.get(), dst_tun.get(), autogen, sub );
    }

    auto_ptr<Proposal> Facade::createBasicIkeProposal() {
        auto_ptr<Proposal> ike_proposal( new Proposal( Enums::PROTO_IKE ) );

        ike_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 128 ) ) );
        ike_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_SHA1_96 ) ) );
        ike_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::PRF, Enums::PRF_HMAC_SHA1 ) ) );
        ike_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, Enums::DH_GROUP_2 ) ) );
        return ike_proposal;
    }

    auto_ptr<Proposal> Facade::createBasicIpsecProposal( Enums::PROTOCOL_ID ipsec_protocol, bool use_pfs ) {
        assert( ipsec_protocol == Enums::PROTO_ESP || ipsec_protocol == Enums::PROTO_AH );

        auto_ptr<Proposal> ipsec_proposal( new Proposal( ipsec_protocol ) );

        if ( ipsec_protocol == Enums::PROTO_ESP )
            ipsec_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::ENCR, Enums::ENCR_AES_CBC, 128 ) ) );
        ipsec_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::INTEG, Enums::AUTH_HMAC_SHA1_96 ) ) );

        if ( use_pfs )
            ipsec_proposal->addTransform( auto_ptr<Transform> ( new Transform( Enums::D_H, Enums::DH_GROUP_2 ) ) );

        return ipsec_proposal;
    }

    auto_ptr< NetworkPrefix > Facade::getNetworkPrefix( string subnet ) {
        int slashpos = subnet.find_last_of( "/" );
        if ( slashpos == string::npos )
            throw Exception( "Invalid subnet specification: <" + subnet + ">" );

        auto_ptr<IpAddress> address ( new IpAddressOpenIKE( subnet.substr( 0, slashpos ) ) );
        string prefixstr = subnet.substr( slashpos + 1 );
        int16_t prefix;
        sscanf( prefixstr.c_str(), "%hi", &prefix );

        return auto_ptr<NetworkPrefix> ( new NetworkPrefix ( address, prefix ) );
    }

    void Facade::finalize( ) {
        ike_sa_controller_impl->exit();
        IpsecController::flushIpsecSas();
        IpsecController::flushIpsecPolicies();
    }

}






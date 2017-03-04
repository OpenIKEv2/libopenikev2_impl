/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#include "ipseccontrollerimplopenike.h"

#include "ipaddressopenike.h"
#include "addressconfiguration.h"
#include "roadwarriorpolicies.h"
#include <libopenikev2/configuration.h>
#include <libopenikev2/boolattribute.h>

#include <libopenikev2/sendrekeychildsareqcommand.h>
#include <libopenikev2/senddeletechildsareqcommand.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/log.h>

namespace openikev2 {

    IpsecControllerImplOpenIKE::IpsecControllerImplOpenIKE() {
    }


    IpsecControllerImplOpenIKE::~IpsecControllerImplOpenIKE() {
    }

    void IpsecControllerImplOpenIKE::processExpire( const IpAddress & src, const IpAddress & dst, uint32_t rekeyed_spi, bool hard ) {
        auto_ptr<Command> command;
        ByteBuffer spi ( 4 );
        spi.writeInt32( rekeyed_spi );

        // If it is a soft expiration
        if ( !hard ) {
            Log::writeLockedMessage( "IpsecController", "Recv SOFT expiration: Child SA SPI=" + spi.toString(), Log::LOG_IPSC, true );
            command.reset( new SendRekeyChildSaReqCommand( rekeyed_spi ) );
        }
        else if ( hard ) {
            Log::writeLockedMessage( "IpsecController", "Recv HARD expiration: Child SA SPI=" + spi.toString(), Log::LOG_IPSC, true );
            command.reset ( new SendDeleteChildSaReqCommand( rekeyed_spi ) );
        }

        bool exist_ike_sa = IkeSaController::pushCommandByChildSaSpi( rekeyed_spi, command, false );

        // If ike_sa was not found
        if ( !exist_ike_sa ) {
            Log::writeLockedMessage( "IpsecController", "Does not exist any IKE_SA with controlling such SPI", Log::LOG_WARN, true );
        }
    }

    Policy * IpsecControllerImplOpenIKE::findIpsecPolicy( const TrafficSelector & ts_i, const TrafficSelector & ts_r, Enums::DIRECTION dir, Enums::IPSEC_MODE mode, Enums::PROTOCOL_ID ipsec_protocol, const IpAddress & tunnel_src, const IpAddress & tunnel_dst ) {
        AutoLock auto_lock ( *this->mutex_policies );

        // Look in all the policies for a match
        for ( uint16_t i = 0; i < this->ipsec_policies->size(); i++ ) {
            Policy *policy = ipsec_policies[ i ];

            if ( policy->direction != dir )
                continue;

            // If policy is "none" omit it
            if ( policy->sa_request.get() == NULL )
                continue;

            if ( policy->sa_request->ipsec_protocol != ipsec_protocol )
                continue;

            if ( policy->sa_request->mode != mode )
                continue;

            // Compare tunnel dir
            if ( mode == Enums::TUNNEL_MODE ){
                IpAddress * wildcard_address = new IpAddressOpenIKE( "0::0" );
                if ( ( *policy->sa_request->tunnel_src == *wildcard_address ) &&
                        ( *policy->sa_request->tunnel_dst == *wildcard_address ) ){
                    Log::writeLockedMessage( "IpsecControllerImplXfrm", "FOUND ACCEPTABLE POLICY (WILDCARD)!" , Log::LOG_INFO, true );
                }
                else if ( !( *policy->sa_request->tunnel_src == *wildcard_address ) &&
                       ( *policy->sa_request->tunnel_dst == *wildcard_address ) ) {
                    if ( !( *policy->sa_request->tunnel_src == tunnel_src ) ){
                        Log::writeLockedMessage( "IpsecControllerImplXfrm", "Do not match: different tunnel addresses. Searching for [" + tunnel_src.toString()+"] but ["+  (*policy->sa_request->tunnel_src).toString() + "] found." , Log::LOG_INFO, true );
                        continue;
                    }
                }
                else if ( ( *policy->sa_request->tunnel_src == *wildcard_address ) &&
                       !( *policy->sa_request->tunnel_dst == *wildcard_address ) ) {
                    if (  !( *policy->sa_request->tunnel_dst == tunnel_dst ) ){
                        Log::writeLockedMessage( "IpsecControllerImplXfrm", "Do not match: different tunnel addresses. Searching for [" + tunnel_dst.toString()+"] but ["+  (*policy->sa_request->tunnel_dst).toString() + "] found." , Log::LOG_INFO, true );
                        continue;
                    }
                }
                else if ( !( *policy->sa_request->tunnel_src == tunnel_src ) || !( *policy->sa_request->tunnel_dst == tunnel_dst ) ){
                    Log::writeLockedMessage( "IpsecControllerImplXfrm", "Do not match: different tunnel addresses. Searching for [" + tunnel_src.toString()+"] but ["+  (*policy->sa_request->tunnel_src).toString() + "] found." , Log::LOG_INFO, true );
                    Log::writeLockedMessage( "IpsecControllerImplXfrm", "Do not match: different tunnel addresses. Searching for [" + tunnel_dst.toString()+"] but ["+  (*policy->sa_request->tunnel_dst).toString() + "] found." , Log::LOG_INFO, true );
                    continue;
                }
            }

            // Gets policy traffic selectors
            auto_ptr<TrafficSelector> policy_ts_i = policy->getSrcTrafficSelector();
            auto_ptr<TrafficSelector> policy_ts_r = policy->getDstTrafficSelector();

            auto_ptr<TrafficSelector> narrowed_ts_i = TrafficSelector::intersection( ts_i, *policy_ts_i );
            auto_ptr<TrafficSelector> narrowed_ts_r = TrafficSelector::intersection( ts_r, *policy_ts_r );

            if ( narrowed_ts_i.get() != NULL && narrowed_ts_r.get() != NULL )
                return policy;
        }
        return NULL;
    }

    bool IpsecControllerImplOpenIKE::narrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa & ike_sa, ChildSa & child_sa ) {
        // If an address is assigned, then create the RW policies and change the TS_i for the assgined address
        // This is done to avoid to make an erroneous narrowing if there are more than one applicable policy in the SPD
        AddressConfiguration * address_configuration = ike_sa.attributemap->getAttribute<AddressConfiguration>( "address_configuration" );
        if ( address_configuration != NULL && address_configuration->role == AddressConfiguration::CONFIGURATION_IRAS )
            return this->processTrafficSelectorsRoadWarrior( received_payload_ts_i, received_payload_ts_r, ike_sa, child_sa );
        else
            return this->processTrafficSelectors( received_payload_ts_i, received_payload_ts_r, ike_sa, child_sa );
    }

    bool IpsecControllerImplOpenIKE::processTrafficSelectorsRoadWarrior( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa & ike_sa, ChildSa & child_sa ) {
        vector<TrafficSelector*> ts_i_collection = received_payload_ts_i.getTrafficSelectors();
        vector<TrafficSelector*> ts_r_collection = received_payload_ts_r.getTrafficSelectors();

        // get the address configuration
        AddressConfiguration * address_configuration = ike_sa.attributemap->getAttribute<AddressConfiguration>( "address_configuration" );
        assert ( address_configuration != NULL );

        string attribute_name = ( address_configuration->assigned_address->getFamily() == Enums::ADDR_IPV4 ) ? "protected_ipv4_subnet" : "protected_ipv6_subnet";
        NetworkPrefix* protected_subnet = ike_sa.getIkeSaConfiguration().attributemap->getAttribute<NetworkPrefix>( attribute_name );
        if ( protected_subnet == NULL ) {
            Log::writeLockedMessage( "IpsecControllerImplXfrm", "Cannot find the protected subnet attribute", Log::LOG_ERRO, true );
            return false;
        }

        auto_ptr<TrafficSelector> roadwarrior_ts_i ( new TrafficSelector( *address_configuration->assigned_address, address_configuration->assigned_address->getAddressSize() * 8, 0, Enums::IP_PROTO_ANY ) );
        auto_ptr<TrafficSelector> roadwarrior_ts_r ( new TrafficSelector( protected_subnet->getNetworkAddress(), protected_subnet->getPrefixLen(), 0, Enums::IP_PROTO_ANY ) );


        auto_ptr<TrafficSelector> best_ts_i;
        for ( int16_t i = 0; i < ts_i_collection.size(); i++ ) {
            auto_ptr<TrafficSelector> intersection = TrafficSelector::intersection( *ts_i_collection[i], *roadwarrior_ts_i );
            if ( intersection.get() != NULL ) {
                if ( best_ts_i.get() == NULL || *intersection >= *best_ts_i )
                    best_ts_i = intersection;
            }
        }

        auto_ptr<TrafficSelector> best_ts_r;
        for ( int16_t i = 0; i < ts_r_collection.size(); i++ ) {
            auto_ptr<TrafficSelector> intersection = TrafficSelector::intersection( *ts_r_collection[i], *roadwarrior_ts_r );
            if ( intersection.get() != NULL ) {
                if ( best_ts_r.get() == NULL || *intersection >= *best_ts_r )
                    best_ts_r = intersection;
            }
        }

        if ( best_ts_i.get() != NULL && best_ts_r.get() != NULL ) {
            // update the selectors
            child_sa.my_traffic_selector.reset ( new Payload_TSi( best_ts_r ) );
            child_sa.peer_traffic_selector.reset ( new Payload_TSr ( best_ts_i ) );

            // if dynamic RW policy creation is desired
            // creates the RW policies
            try {
                this->createIpsecPolicy( child_sa.my_traffic_selector->getTrafficSelectors(), child_sa.peer_traffic_selector->getTrafficSelectors(), Enums::DIR_OUT, Enums::POLICY_ALLOW, 10000, child_sa.ipsec_protocol, child_sa.mode, &ike_sa.my_addr->getIpAddress(), &ike_sa.peer_addr->getIpAddress() );
                this->createIpsecPolicy( child_sa.peer_traffic_selector->getTrafficSelectors(), child_sa.my_traffic_selector->getTrafficSelectors(), Enums::DIR_FWD , Enums::POLICY_ALLOW, 10000, child_sa.ipsec_protocol, child_sa.mode, &ike_sa.peer_addr->getIpAddress(), &ike_sa.my_addr->getIpAddress() );
                this->createIpsecPolicy( child_sa.peer_traffic_selector->getTrafficSelectors(), child_sa.my_traffic_selector->getTrafficSelectors(), Enums::DIR_IN, Enums::POLICY_ALLOW, 10000, child_sa.ipsec_protocol, child_sa.mode, &ike_sa.peer_addr->getIpAddress(), &ike_sa.my_addr->getIpAddress() );
            }
            catch ( IpsecException ex ) {
                Log::writeLockedMessage( "IpsecControllerImplXfrm", "Cannot create the RW policies for assigned address=[" + address_configuration->assigned_address->toString() + "]", Log::LOG_ERRO, true );
                return false;
            }

            Log::writeLockedMessage( "IpsecControllerImplXfrm", "Creating RW policies for assigned address=[" + address_configuration->assigned_address->toString() + "]", Log::LOG_INFO, true );
            child_sa.attributemap->addAttribute( "rw_policies", auto_ptr<Attribute> ( new RoadWarriorPolicies( address_configuration->assigned_address->clone(), auto_ptr<Payload_TS> ( new Payload_TS( *child_sa.peer_traffic_selector ) ), auto_ptr<Payload_TS> ( new Payload_TS( *child_sa.my_traffic_selector ) ) ) ) );

            return true;
        }

        return false;
    }

    bool IpsecControllerImplOpenIKE::processTrafficSelectors( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa & ike_sa, ChildSa & child_sa ) {
        vector<TrafficSelector*> ts_i_collection = received_payload_ts_i.getTrafficSelectors();
        vector<TrafficSelector*> ts_r_collection = received_payload_ts_r.getTrafficSelectors();

        // Look for a policy that matches with the indicated attributes
        auto_ptr<TrafficSelector> best_ts_i ;
        auto_ptr<TrafficSelector> best_ts_r ;

        auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

        BoolAttribute* mobility_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "mobility" );
        bool mobility = false;
        auto_ptr<SocketAddress> hoa (NULL);
        auto_ptr<SocketAddress> coa (NULL);
        if (mobility_attr  != NULL )
            mobility = mobility_attr->value;

        BoolAttribute* is_ha_attr = general_conf->attributemap->getAttribute<BoolAttribute>( "is_ha" );
        bool is_ha = false;
        if (is_ha_attr  != NULL )
            is_ha = is_ha_attr->value;

        for ( int16_t i = 0; i < ts_i_collection.size(); i++ ) {
            for ( int16_t j = 0; j < ts_r_collection.size() ; j++ ) {
                Policy *inbound_policy = NULL;
                Policy *outbound_policy = NULL;
                if ( (child_sa.mode == Enums::TUNNEL_MODE) && mobility) {
                    // Look for a matching inbound policy
                    inbound_policy = findIpsecPolicy( *ts_i_collection[ i ], *ts_r_collection[ j ], Enums::DIR_IN, child_sa.mode, child_sa.ipsec_protocol, is_ha ? ike_sa.care_of_address->getIpAddress():ike_sa.peer_addr->getIpAddress(), is_ha? ike_sa.my_addr->getIpAddress():ike_sa.care_of_address->getIpAddress() );
                    if ( inbound_policy == NULL )
                        continue;

                    // And for a matching outbound policy
                    outbound_policy = findIpsecPolicy( *ts_r_collection[ j ], *ts_i_collection[ i ], Enums::DIR_OUT, child_sa.mode, child_sa.ipsec_protocol, is_ha ? ike_sa.my_addr->getIpAddress():ike_sa.care_of_address->getIpAddress(), is_ha ? ike_sa.care_of_address->getIpAddress():ike_sa.peer_addr->getIpAddress());
                    if ( outbound_policy == NULL )
                        continue;
                }
                else {
                    // Look for a matching inbound policy
                        inbound_policy = findIpsecPolicy( *ts_i_collection[ i ], *ts_r_collection[ j ], Enums::DIR_IN, child_sa.mode, child_sa.ipsec_protocol, ike_sa.peer_addr->getIpAddress(), ike_sa.my_addr->getIpAddress() );
                        if ( inbound_policy == NULL )
                            continue;

                        // And for a matching outbound policy
                        outbound_policy = findIpsecPolicy( *ts_r_collection[ j ], *ts_i_collection[ i ], Enums::DIR_OUT, child_sa.mode, child_sa.ipsec_protocol, ike_sa.my_addr->getIpAddress(), ike_sa.peer_addr->getIpAddress() );
                        if ( outbound_policy == NULL )
                            continue;
                }

                // if both are acceptables, then insersec proposed selectors with policy selectors
                auto_ptr<TrafficSelector> policy_ts_i = inbound_policy->getSrcTrafficSelector();
                auto_ptr<TrafficSelector> policy_ts_r = outbound_policy->getSrcTrafficSelector();

                auto_ptr<TrafficSelector> narrowed_ts_i = TrafficSelector::intersection( *ts_i_collection[ i ], *policy_ts_i );
                auto_ptr<TrafficSelector> narrowed_ts_r = TrafficSelector::intersection( *ts_r_collection[ j ], *policy_ts_r );

                assert ( narrowed_ts_i.get() );
                assert ( narrowed_ts_r.get() );

                // if these are the bigger selectors for the moment, update them
                if ( ( best_ts_i.get() == NULL ) ||
                        ( ( *narrowed_ts_i >= *best_ts_i ) && ( *narrowed_ts_r >= *best_ts_r ) ) ) {
                    best_ts_i = narrowed_ts_i;
                    best_ts_r = narrowed_ts_r;
                }
            }
        }

        // If there are acceptable traffic selectors, then update the CHILD_SA
        if ( best_ts_i.get() ) {
            child_sa.my_traffic_selector.reset ( new Payload_TSi( best_ts_r ) );
            child_sa.peer_traffic_selector.reset ( new Payload_TSr ( best_ts_i ) );
            return true;
        }

        return false;
    }

    bool IpsecControllerImplOpenIKE::checkNarrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, ChildSa & child_sa ) {
        vector<TrafficSelector*> received_selectors_i = received_payload_ts_i.getTrafficSelectors();
        vector<TrafficSelector*> received_selectors_r = received_payload_ts_r.getTrafficSelectors();
        vector<TrafficSelector*> my_selectors_i = child_sa.my_traffic_selector->getTrafficSelectors();
        vector<TrafficSelector*> my_selectors_r = child_sa.peer_traffic_selector->getTrafficSelectors();

        if ( received_selectors_i.size() == 0 || received_selectors_r.size() == 0 )
            return false;

        // We should can to reduce the selector number to 1-1 by eliminating the selectors already inclueded in others
        TrafficSelector* selected_ts_i = received_selectors_i.front();
        TrafficSelector* selected_ts_r = received_selectors_r.front();
        vector<TrafficSelector*>::iterator my_iterator;
        vector<TrafficSelector*>::iterator received_iterator;

        // For each received TSi,
        for ( received_iterator = received_selectors_i.begin(); received_iterator != received_selectors_i.end(); received_iterator++ ) {
            // If the received selector contains the previous selected one, the mark this as the selected one
            if ( * ( *received_iterator ) >= *selected_ts_i )
                selected_ts_i = *received_iterator;

            // if the received selector is already contained in the selected one, then omit
            else if ( * ( *received_iterator ) <= *selected_ts_i )
                ; // DO NOTHING

            // if the received selector is not "compatible" with the selected one, then invalid narrowing has been detected
            else
                return false;
        }

        // Search for a sent selector containing the selected one
        for ( my_iterator = my_selectors_i.begin(); my_iterator != my_selectors_i.end(); my_iterator++ )
            if ( * ( *my_iterator ) >= * ( selected_ts_i ) )
                break;

        // if none is found, then invalid narrowing is detected
        if ( my_iterator == my_selectors_i.end() )
            return false;

        // For each received TSr
        for ( received_iterator = received_selectors_r.begin(); received_iterator != received_selectors_r.end(); received_iterator++ ) {
            // If the received selector contains the previous selected one, the mark this as the selected one
            if ( * ( *received_iterator ) >= *selected_ts_r )
                selected_ts_r = *received_iterator;

            // if the received selector is already contained in the selected one, then omit
            else if ( * ( *received_iterator ) <= *selected_ts_r )
                ; // DO NOTHING

            // if the received selector is not "compatible" with the selected one, then invalid narrowing has been detected
            else
                return false;
        }

        // Search for a sent selector containing the selected one
        for ( my_iterator = my_selectors_r.begin(); my_iterator != my_selectors_r.end(); my_iterator++ )
            if ( * ( *my_iterator ) >= * ( selected_ts_r ) )
                break;

        // if none is found, then invalid narrowing is detected
        if ( my_iterator == my_selectors_r.end() )
            return false;

        child_sa.my_traffic_selector.reset( new Payload_TSi( selected_ts_i->clone() ) );
        child_sa.peer_traffic_selector.reset( new Payload_TSr( selected_ts_r->clone() ) );

        return true;
    }

}


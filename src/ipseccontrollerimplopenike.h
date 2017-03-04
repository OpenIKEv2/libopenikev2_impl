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
#ifndef OPENIKEV2IPSECONTROLLERIMPLOPENIKE_H
#define OPENIKEV2IPSECONTROLLERIMPLOPENIKE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libopenikev2/ipseccontrollerimpl.h>
#include "threadposix.h"
#include "policy.h"

namespace openikev2 {

    /**
    This class represents an IPsec contorller concrete implementation
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IpsecControllerImplOpenIKE: public IpsecControllerImpl, public ThreadPosix {
        protected:
            AutoVector<Policy> ipsec_policies;          /**< Collection of IPsec policies. */
            auto_ptr<Mutex> mutex_policies;             /**< Mutex to controls policies acceses. */

        protected:
            IpsecControllerImplOpenIKE();

            /**
             * Process an EXPIRE event from IPSEC system
             * @param src Source IP address in the EXPIRE
             * @param dst Destination IP address in the EXPIRE
             * @param rekeyed_spi
             * @param hard
             */
            virtual void processExpire( const IpAddress& src, const IpAddress& dst, uint32_t rekeyed_spi, bool hard );

            /**
             * Finds a policy matching with the indicated parameters.
             * @param ts_i Initiator traffic selector.
             * @param ts_r Responder traffic selector.
             * @param dir Direction.
             * @param mode IPsec mode of the SaRequest.
             * @param ipsec_protocol IPsec protocol of the SaRequest.
             * @param tunnel_src Tunnel source address.
             * @param tunnel_dst Tunnel destination address.
             * @param child_sa The Child_SA in order to establish the inbound and outbound selectors after the narrowing process
             * @return Matching policy. NULL if not founded.
             */
            virtual Policy* findIpsecPolicy( const TrafficSelector & ts_i, const TrafficSelector & ts_r, Enums::DIRECTION dir, Enums::IPSEC_MODE mode, Enums::PROTOCOL_ID ipsec_protocol, const IpAddress & tunnel_src, const IpAddress & tunnel_dst );

            virtual bool processTrafficSelectorsRoadWarrior( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );
            virtual bool processTrafficSelectors( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );

        public:

            virtual void run() = 0;

            virtual bool narrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );

            virtual bool checkNarrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, ChildSa & child_sa );

            virtual uint32_t getSpi( const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol ) = 0;

            virtual void createIpsecSa( const IpAddress& src, const IpAddress& dst, const ChildSa& childsa ) = 0;

            virtual uint32_t deleteIpsecSa( const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol, uint32_t spi ) = 0;

            virtual void createIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, const IpAddress* src_tunnel, const IpAddress* dst_tunnel, bool autogen = false , bool sub = false ) = 0;

            virtual void deleteIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction ) = 0;

            virtual void flushIpsecPolicies() = 0;

            virtual void flushIpsecSas() = 0;

            virtual void exit() = 0;

            virtual void updateIpsecSaAddresses(const IpAddress& old_address, const IpAddress& new_address) = 0;

            virtual void updateIpsecPolicyAddresses(const IpAddress& old_address, const IpAddress& new_address) = 0;

            /**
            * Print the policies
            */
            virtual void printPolicies() = 0;

            virtual void updatePolicies(bool show) = 0;

            virtual ~IpsecControllerImplOpenIKE();

    };

}

#endif

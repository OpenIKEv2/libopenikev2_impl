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
#ifndef IPSEC_CONTROLLERIMPL_XFRM_H
#define IPSEC_CONTROLLERIMPL_XFRM_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libopenikev2/autovector.h>

#include "ipseccontrollerimplopenike.h"
#include "policy.h"
#include "libnetlink.h"

/* This header is required to assure it is included before any linux/ include */
#include <netinet/in.h>
#include <linux/xfrm.h>

namespace openikev2 {

    /**
        This class represents an IPSEC_Controller concrete implementation using a netlink socket (XFRM)
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class IpsecControllerImplXfrm : public IpsecControllerImplOpenIKE {

            /****************************** ATTRIBUTES ******************************/
        protected:
            AutoVector<Policy> ipsec_policies;  /**< Collection of IPsec policies. */
            auto_ptr<Mutex> mutex_policies;     /**< Mutex to control policies acceses. */
            int32_t netlink_bcast_fd;           /**< Socket to receive broadcast messages */
            uint32_t sequence_number;           /**< Message sequence number. */
            bool exiting;                       /**< Indicates if controller must exit */

            /****************************** METHODS ******************************/
        protected:
            /**
             * Perform a flush in the IPSEC SAs database
             */
            virtual void xfrmFlushIpsecSas();

            /**
             * Perform a flush in the IPSEC policy database
             */
            virtual void xfrmFlushIpsecPolicies();

            /**
             * Creates a new IPSEC policy
             * @param src_sel IP address of the source selector
             * @param src_prefixlen IP address prefix length of the source selector
             * @param src_port Source port of the selector. If ICMP, this field must contain the ICMP type
             * @param dst_sel IP address of the destination selector
             * @param dst_prefixlen IP address prefix length of the destination selector
             * @param dst_port Destination port of the selector. If ICMP, this field must contain the ICMP code
             * @param ip_protocol IP protocol type to protect (TCP, UDP, ANY...)
             * @param dir The traffic direction (in, out, frw)
             * @param protocol The IPSEC protocol we want to use (AH or ESP)
             * @param mode The IPSEC mode (tunnel or transport)
             * @param priority The policy priority
             * @param tunnel_src Source tunnel address
             * @param tunnel_dst Destination tunnel address
             * @param autogen Tells us if the SA associated to this policy has to be autogenerate
             */
            virtual void xfrmCreateIpsecPolicy( const IpAddress& src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress& dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::POLICY_ACTION action, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress * tunnel_src, const IpAddress * tunnel_dst, bool autogen = false, bool sub = false );

            /**
             * Deletes a IPSEC policy
             * @param src_sel IP address of the source selector
             * @param src_prefixlen IP address prefix length of the source selector
             * @param src_port Source port of the selector. If ICMP, this field must contain the ICMP type
             * @param dst_sel IP address of the destination selector
             * @param dst_prefixlen IP address prefix length of the destination selector
             * @param dst_port Destination port of the selector. If ICMP, this field must contain the ICMP code
             * @param ip_protocol IP protocol type to protect (TCP, UDP, ANY...)
             * @param dir The traffic direction (in, out, frw)
             */
            virtual void xfrmDeleteIpsecPolicy( const IpAddress & src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress & dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir );

            /**
             * Delete an existing SA from SADB
             * @param src Source IP address of the SA
             * @param dst Destination IP address of the SA
             * @param protocol IPSEC protocol of the SA
             * @param spi SPI of the SA
             */
            virtual void xfrmDeleteIpsecSa( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t spi );

            /**
             * Gets a new SPI needed in a SA creation
             * @param src Source IP address of the desired SA
             * @param dst Destination IP address of the desired SA
             * @param protocol IPSEC protocol to be used
             * @param reqid ID of the request. Used to identify the response.
             * @param min Minimum value of desired SPI
             * @param max Maximum value of desired SPI
             * @return The new SPI for a SA in project of creation (a larval SA is created and waits for 30 secs to be updated)
             */
            virtual uint32_t xfrmGetSpi( const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, uint32_t reqid, uint32_t min, uint32_t max );

            /**
            * Sets all the necessary to establish a SA in larval state or to create a new one
            * @param operation Type of operation (new_SA or update_SA)
            * @param src Source IP address of the desired SA
            * @param dst Destination IP address of the desired SA
            * @param protocol IPSEC protocol to be used
            * @param mode IPSEC mode to be used
            * @param spi The SPI of the SA we want to update
            * @param keymat Crypto material (keys)
            * @param encr_type Encryption algorithm used
            * @param keymat_size_encr Encryption key size
            * @param integ_type Authentication algorithm used
            * @param keymat_size_auth Authentication key size
            * @param limit_soft_time Soft expiration time in seconds (jittered 10%)
            * @param limit_hard_time Hard expiration time in seconds
            * @param limit_hard_octets Hard expiration amount of data in octects (soft limit is established to hard_limit * 0.8)
            * @param reqid ID of the request. Used to identify the response.
            * @param src_sel IP address of the source selector
            * @param src_prefixlen IP address prefix length of the source selector
            * @param dst_sel IP address of the destination selector
            * @param dst_prefixlen IP address prefix length of the destination selector
            */
            virtual void xfrmAddUpdateIpsecSa ( uint16_t operation, const IpAddress & src, const IpAddress & dst, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t spi,
                                                string encr_type, ByteArray & encr_key, string integ_type, ByteArray & integ_key,
                                                uint32_t limit_soft_time, uint32_t limit_hard_time, uint32_t limit_hard_octets, uint32_t reqid, const TrafficSelector& src_sel, const TrafficSelector& dst_sel );

            /**
             * Translate encryption algorithms from IKE world to XFRM world
             * @param encr_transform Encription transfrom
             * @return Encription algorithm ID in XFRM form
             */
            virtual string getXfrmEncrAlgo( const Transform* encr_transform  );

            /**
             * Translate authentication algorithms from IKE world to XFRM world
             * @param integ_transform Integrity transofrm
             * @return Authentication algorithm ID in XFRM form
             */
            virtual string getXfrmIntegAlgo( const Transform* integ_transform );


            /**
             * This method autogenerates the SAs assocciated with a autogen policy
             * IKE to establish a SA between nodes. This method catchs this event and do the necessary to initiate the
             * SA creation.
             * @param src_sel IP address of the source selector
             * @param src_prefixlen IP address prefix length of the source selector
             * @param src_port Source port of the selector. If ICMP, this field must contain the ICMP type
             * @param dst_sel IP address of the destination selector
             * @param dst_prefixlen IP address prefix length of the destination selector
             * @param dst_port Destination port of the selector. If ICMP, this field must contain the ICMP code
             * @param ip_protocol IP protocol type to protect (TCP, UDP, ANY...)
             * @param dir The traffic direction (in, out, frw)
             * @param protocol The IPSEC protocol we want to use (AH or ESP)
             * @param mode The IPSEC mode (tunnel or transport)
             * @param priority The policy priority
             * @param src_policy_sel Policy Source selector
             * @param src_policy_prefixlen Policy Source selector
             * @param src_policy_port Policy Destination selector
             * @param dst_policy_sel Policy Source selector
             * @param dst_policy_prefixlen Policy Source selector
             * @param dst_policy_port Policy Destination selector
             * @param tunnel_src Source tunnel address
             * @param tunnel_dst Destination tunnel address
             */
            virtual void processAcquire(const IpAddress & src_sel, uint8_t src_prefixlen, uint16_t src_port, const IpAddress & dst_sel, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress & src_policy_sel, uint8_t src_policy_prefixlen, uint16_t src_policy_port, const IpAddress & dst_policy_sel, uint8_t dst_policy_prefixlen, uint16_t dst_policy_port, const IpAddress * tunnel_src, const IpAddress * tunnel_dst);


            /**
             * When IPSEC detect traffic that match with a policy, then IPSEC throw an adquire event in order to request
             * IKE to establish a SA between nodes. This method catchs this event and do the necessary to initiate the
             * SA creation.
             * @param n XFRM Struct with the info like the matched policy and more
             */
            virtual void processAcquire( const nlmsghdr & n );

            /**
             * When an SA reaches its soft and hard time expiration then IPSEC throw an expire event in order to request
             * IKE to delete or rekey the SA. This method catchs this event and do the necessary to initiate the
             * SA deletion or rekey.
             * @param n XFRM Struct with the info like the matched policy and more
             */
            virtual void processExpire( const nlmsghdr & n );

            /**
             * Gets a IPsec policy by its ID.
             * @param id Policy ID.
             * @return Corresponding policy. Exception if not found
             */
            virtual Policy& getIpsecPolicyById( uint32_t id );

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

            /**
             * Updates the list of policies. It must by performed after create or delete policies.
             * @param show Indicate if all the policies detected must be printed
             */
            virtual void updatePolicies( bool show );

            virtual xfrm_selector getXfrmSelector( const TrafficSelector& ts_i, const TrafficSelector& ts_r );
            virtual xfrm_address_t getXfrmAddress( const IpAddress& address );
            virtual uint16_t getXfrmSrcPort( const TrafficSelector& ts_i, const TrafficSelector& ts_r );
            virtual uint16_t getXfrmDstPort( const TrafficSelector& ts_i, const TrafficSelector& ts_r );

            virtual bool processTrafficSelectorsRoadWarrior( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );
            virtual bool processTrafficSelectors( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );

        public:
            /**
             * Creates a new IpsecControllerImplXfrm
             */
            IpsecControllerImplXfrm();

            virtual void run();

            virtual bool narrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );

            virtual bool checkNarrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, ChildSa & child_sa );

            virtual uint32_t getSpi(const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol);

            virtual void createIpsecSa( const IpAddress& src, const IpAddress& dst, const ChildSa& childsa );

            virtual uint32_t deleteIpsecSa( const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol, uint32_t spi );

            virtual void createIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, const IpAddress* src_tunnel, const IpAddress* dst_tunnel, bool autogen = false, bool sub = false  );

            virtual void deleteIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction );

            virtual void flushIpsecPolicies();

            virtual void flushIpsecSas();

            virtual void exit();

            virtual void printPolicies();
            
            virtual void updateIpsecSaAddresses(const IpAddress& old_address, const IpAddress& new_address);
            
            virtual void updateIpsecPolicyAddresses(const IpAddress& old_address, const IpAddress& new_address);

            virtual ~IpsecControllerImplXfrm();
    };
};
#endif

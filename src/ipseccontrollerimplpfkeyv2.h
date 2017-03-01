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
#ifndef IPSEC_CONTROLLERIMPL_PFKEYV2_H
#define IPSEC_CONTROLLERIMPL_PFKEYV2_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libopenikev2/ipseccontrollerimpl.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/enums.h>

#include "ipseccontrollerimplopenike.h"
#include "policy.h"

extern "C" {
#include <linux/pfkeyv2.h>
#include <assert.h>
}

namespace openikev2 {

    class PfkeyException : public Exception {
        public:
            PfkeyException( string m ) : Exception( "PfkeyException: " + m ) {}
    };

    /**
    This class represents an IPSEC_Controller concrete implementation using an PF_KEYv2 socket
    @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */
    class IpsecControllerImplPfkeyv2 : public IpsecControllerImplOpenIKE {
        protected:
            AutoVector<Policy> ipsec_policies;;         /**< Collection of IPsec policies. */
            auto_ptr<Mutex> mutex_policies;             /**< Mutex to controls policies acceses. */

            int32_t pfkey_bd_socket;                    /**< PF_KEY broadcast socket used to process ACQUIRES and EXPIRES. */
            uint32_t sequence_number;                   /**< PF_KEY message sequence number. */

            auto_ptr<Mutex> mutex_seq_number;           /**< Mutex for protect sequence number incrementation. */
            uint32_t return_value;                      /**< Global variable used to store response return value */
            bool exiting;                                  /**< Indicates if IPSEC Controller must exit */

        protected:
            /**
             * Creates a new PFKEYv2 socket
             * @return The socket file descriptor
             */
            virtual int32_t pfkeyCreateSocket();

            /**
             * Generates a collection of pointer to the extension headers.
             * @param hdr PF_KEY message header.
             * @param ext_hdrs Array of pointers to extension headers to be filled.
             */
            virtual void pfkeyParseExthdrs( sadb_msg &hdr, uint8_t **ext_hdrs );

            /**
             * Deletes the memory assigned to ext_hdrs.
             * @param ext_hdrs Extension headers.
             */
            virtual void pfkeyDeleteExtHdrs( uint8_t **ext_hdrs );

            /**
             * Send a SPD_FLUSH
             */
            virtual void pfkeySpdFlush( );

            /**
             * Send a SA_FLUSH
             */
            virtual void pfkeySadFlush( );

            /**
             * Sends a message thru the PF_KEY socket.
             * @param fd Socket used to send
             * @param hdr Message header.
             * @param ext_hdrs Extension headers.
             */
            virtual void pfkeySend( int32_t fd, sadb_msg *hdr, uint8_t *ext_hdrs[] );

            /**
             * Register the broadcast socket in the kernel
             * @param protocol Protocol desired to be registered.
             */
            virtual void pfkeyRegister( Enums::PROTOCOL_ID protocol );

            /**
             * Receives a message from the PF_KEY socket.
             * @param fd Socket used to receive
             * @return A new allocated message.
             */
            virtual void pfkeyReceive( int32_t fd, sadb_msg & message, uint16_t message_max_size );

            /**
             * Sends a GETSPI message and returns the new SPI value
             * @param srcaddr Source address of the SA.
             * @param dstaddr Destination address of the SA.
             * @param protocol Protocol of the SA.
             * @return The new SPI value. 0 if some was wrong.
             */
            virtual uint32_t pfkeyGetSpi( const IpAddress & srcaddr, const IpAddress & dstaddr, Enums::PROTOCOL_ID protocol );

            /**
             * Sends an ADD or an UPDATE message to the kernel
             * @param operation Operation to be performed (ADD, UPDATE).
             * @param src Source address of the SA.
             * @param dst Destination address of the SA.
             * @param protocol Protocol of the SA.
             * @param mode Mode of the SA.
             * @param spi SPI of the SA
             * @param encr_type Encryption algorithm to be used with the SA.
             * @param encr_key Encryption Key for the SA.
             * @param integ_type Integrity algorithm to be used with the SA.
             * @param integ_key Integrity Key for the SA.
             * @param limit_hard_time Hard lifetime in seconds of the SA.
             * @param limit_soft_time Soft lifetime in seconds of the SA
             * @param limit_hard_octets Lifetime in bytes of the SA.
             * @param reqid Request ID.
             * @return The SPI of the SA. 0 if some was wrong.
             */
            virtual void pfkeyAddUpdateIpsecSa ( uint16_t operation, const IpAddress & src, const IpAddress & dst,
                                                 Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t spi, uint16_t encr_type, ByteArray & encr_key,
                                                 uint16_t integ_type, ByteArray & integ_key, uint32_t limit_soft_time, uint32_t limit_hard_time,
                                                 uint32_t limit_hard_octets, uint32_t reqid );

            /**
             * Sends a SPDDUMP message to the kernel.
             * @param fd Socket used to send the message
             */
            virtual void pfkeySpdDump( int32_t fd );

            /**
             * Sends a DELETE message to the kernel
             * @param src Source IP address of the IPsec SA
             * @param dst Destination IP address of the IPsec SA
             * @param protocol Protocol of the IPsec SA
             * @param spi SPI of the IPsec SA
             * @return The SPI of the SA. 0 if some was wrong.
             */
            virtual uint32_t pfkeyDeleteIpsecSa( const IpAddress & srcaddr, const IpAddress & dstaddr, Enums::PROTOCOL_ID protocol, uint32_t spi );

            /**
             * Sends a SPDADD message to the kernel
             * @param src_selector Source selector address
             * @param src_prefixlen Source selector prefix length
             * @param src_port Source selector port. If ICMP, then the type must be here.
             * @param dst_selector Destination selector address
             * @param dst_prefixlen Destination selector prefix len
             * @param dst_port Destiantion selector port. If ICMP, then the code must be here.
             * @param ip_protocol IP protocol of the policy
             * @param dir Direction of the policy
             * @param protocol IPSEC protocol of the policy
             * @param mode Mode of the policy
             * @param priority Policy priority
             * @param tunnel_src Source tunnel address
             * @param tunnel_dst Destination tunnel address
             */
            virtual void pfkeyCreateIpsecPolicy( IpAddress & src_selector, uint8_t src_prefixlen, uint16_t src_port, IpAddress & dst_selector, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir, Enums::POLICY_ACTION action, Enums::PROTOCOL_ID protocol, Enums::IPSEC_MODE mode, uint32_t priority, const IpAddress * tunnel_src, const IpAddress * tunnel_dst );

            /**
             * Sends a SPDDEL message to the kernel
             * @param src_selector Source selector address
             * @param src_prefixlen Source selector prefix length
             * @param src_port Source selector port. If ICMP, then the type must be here.
             * @param dst_selector Destination selector address
             * @param dst_prefixlen Destination selector prefix len
             * @param dst_port Destiantion selector port. If ICMP, then the code must be here.
             * @param ip_protocol IP protocol of the policy
             * @param dir Direction of the policy
             */
            virtual void pfkeyDeleteIpsecPolicy( IpAddress & src_selector, uint8_t src_prefixlen, uint16_t src_port, IpAddress & dst_selector, uint8_t dst_prefixlen, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION dir );

            /**
             * Generates a Policy object based on a SPDDUMP response message.
             * @param spd_dump_response SPDDUMP response message.
             * @return A new Policy object.
             */
            virtual auto_ptr<Policy> msg2Policy( sadb_msg * spd_dump_response );

            /**
             * Generares a SA_Request object based on a IPSECREQUET struct
             * @param request IPSECREQUEST struct
             * @return A new SA_Request object.
             */
            virtual auto_ptr<SaRequest> msg2Request ( sadb_x_ipsecrequest * request );

            /**
             * Converts from PF_KEY to IKE protocol id.
             * @param pfkey_proto PF_KEY protocol id.
             * @return IKE protocol id.
             */
            virtual Enums::PROTOCOL_ID getIkeProto( uint16_t pfkey_proto );

            /**
             * Converts from IKE to PF_KEY encryption algorithms.
             * @param algo IKE encryption algorithm id.
             * @return PF_KEY encryption algorithm id.
             */
            virtual uint16_t getPfkeyEncrAlgo( const Transform* encr_transfor );

            /**
             * Converts from IKE to PF_KEY integrity algorithms.
             * @param algo IKE integrity algorithm id.
             * @return PF_KEY integrity algorithm id.
             */
            virtual uint16_t getPfkeyIntegAlgo( const Transform* integ_transform );

            /**
             * Proccess an ACQUIRE message from the PF_KEY socket.
             * @param message_headers[] Pointers to message extension headers.
             */
            virtual void processAcquire( uint8_t* message_headers[] );

            /**
             * Process an EXPIRE message from the PF_KEY socket.
             * @param message_headers[] Pointers to message extension headers.
             */
            virtual void processExpire( uint8_t* message_headers[] );

            /**
             * Get the sequence number to be used in the next request to the IPsec stack. This method is thread-safe.
             * @return Sequence number.
             */
            virtual uint32_t nextSeqNumber();

            /**
             * Update the policies collection.
             */
            virtual void updatePolicies( bool show );

            /**
             * Gets a IPsec policy by its ID.
             * @param id Policy ID.
             * @return Corresponding policy. Exception if not found
             */
            virtual Policy& getPolicyById( uint32_t id );

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

            virtual bool createRwPolicies( IpAddress& rw_address, ChildSa& child_sa, IkeSa& ike_sa );

        public:
            /**
             * Creates a new IPSEC_ControllerImpl_PFKEYv2.
             */
            IpsecControllerImplPfkeyv2();

            virtual void run();

            virtual bool narrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, IkeSa& ike_sa, ChildSa & child_sa );

            virtual bool checkNarrowPayloadTS( const Payload_TSi & received_payload_ts_i, const Payload_TSr & received_payload_ts_r, ChildSa & child_sa );

            virtual uint32_t getSpi( const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol );

            virtual void createIpsecSa( const IpAddress& src, const IpAddress& dst, const ChildSa& childsa );

            virtual uint32_t deleteIpsecSa( const IpAddress& src, const IpAddress& dst, Enums::PROTOCOL_ID protocol, uint32_t spi );

            virtual void createIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction, Enums::POLICY_ACTION action, uint32_t priority, Enums::PROTOCOL_ID ipsec_protocol, Enums::IPSEC_MODE mode, const IpAddress* src_tunnel, const IpAddress* dst_tunnel, bool autogen = false, bool sub = false  );

            virtual void deleteIpsecPolicy( vector<TrafficSelector*> src_sel, vector<TrafficSelector*> dst_sel, Enums::DIRECTION direction );

            virtual void flushIpsecPolicies();

            virtual void flushIpsecSas();

            virtual void exit();

            virtual void printPolicies();

            virtual void updateIpsecSaAddresses( const IpAddress& old_address, const IpAddress& new_address );

            virtual void updateIpsecPolicyAddresses( const IpAddress& old_address, const IpAddress& new_address );

            virtual ~IpsecControllerImplPfkeyv2();

    };
};
#endif

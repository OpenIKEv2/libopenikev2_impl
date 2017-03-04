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

#ifndef EAPSM_H
#define EAPSM_H

#include <libopenikev2/eappacket.h>
#include <libopenikev2/message.h>
#include <libopenikev2/semaphore.h>
#include <libopenikev2/bytearray.h>
#include <libopenikev2/aaasender.h>

#include "../src/radiusmessage.h"
#include "../src/aaasenderradius.h"

extern "C" {
#include "./common/defs.h"
#include "./utils/common.h"
#include "./eap_server/eap.h"
#include "./eap_server/eap_i.h"
#include "./eap_server/config_hostapd.h"

}

namespace openikev2 {
    /**
     This class represents an EAP state machine from Hostapd code
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapSm : public AAASenderRadius {
            /****************************** ATTRIBUTES ******************************/
        protected:
            struct eap_sm *sm;                          /**< HOSTAPD EAP state machine */
            struct wpabuf* buffer;                      /**< Buffer to exchange information */
            static eapol_callbacks eapol_cb;            /**< EAPOL callback collection */
            //hostapd_bss_config hostapd_configuration;                 /**< HOSTAPD configuration */
            struct eap_eapol_interface* eap_iface;
            string     aaa_username;
            string     aaa_server_addr;
            string     aaa_server_secret;
            uint8_t    aaa_server_port;
            Semaphore *aaa_semaphore;
            auto_ptr<ByteArray> aaa_msk;
            auto_ptr<EapPacket> aaa_eap_packet_to_send;
            auto_ptr<EapPacket> aaa_eap_packet_received;
            auto_ptr<RadiusMessage> aaa_radius_request;
            auto_ptr<RadiusMessage> aaa_radius_response;

            /****************************** METHODS ******************************/
        protected:
	    static int get_eap_user (void *ctx, const u8 *identity, size_t identity_len,
			    int phase2, struct eap_user *user);
	    static const char * get_eap_req_id_text (void *ctx, size_t *len);




            /**
             * Creates a new EapSm object
             * @param method EAP method
             * @param frm_server_data Data for the FRM method, server side
             */
            EapSm( EapPacket::EAP_TYPE method, string aaa_server_addr, uint16_t aaa_server_port, string aaa_server_secret );

        public:


            virtual void AAA_receive( auto_ptr<EapPacket> eap_packet );


            /**
             * Obtains an EapSm for FRM method
             * @param frm_server_data Data for the FRM method, server side
             * @return A new EapSm to be used with the FRM method
             */
            static auto_ptr<EapSm> getEapSmFrm( string aaa_server_addr, uint16_t aaa_server_port, string aaa_server_secret );

            /**
             * Performs the first step of the state machine obtaining the EAP Request
             * @return EAP request
             */
            virtual auto_ptr< EapPacket > firststep( );


            /**
             * Steps the state machine with an EAP request
             * @param eap_request EAP request
             * @return EAP response
             */
            virtual auto_ptr<EapPacket> step( const EapPacket& eap_request );

            /**
             * Obtains the MSK value
             * @return MSK value
             */
            virtual auto_ptr<ByteArray> getMsk() const;

            virtual ~EapSm();
    };
}

#endif

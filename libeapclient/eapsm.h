/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#ifndef EAPSM_H
#define EAPSM_H

#include <libopenikev2/eappacket.h>
#include <libopenikev2/message.h>

extern "C" {
#include "./common/defs.h"
#include "./utils/common.h"
#include "./eap_peer/eap.h"
#include "./eap_peer/eap_i.h"
#include "./eap_peer/config_ssid.h"
}

namespace openikev2 {
    /**
     This class represents an EAP state machine from WPA supplicant code
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapSm {
            /****************************** ATTRIBUTES ******************************/
        protected:


            struct eap_sm *sm;                          /**< WPA supplicant EAP state machine */
            struct wpabuf* buffer;                      /**< Buffer to exchange information */
            //uint16_t buffer_len;                        /**< Buffer length */
            Boolean success;                            /**< Internal variable used by the state machine */
            Boolean restart;                            /**< Internal variable used by the state machine */
            Boolean fail;                               /**< Internal variable used by the state machine */
            Boolean response;                           /**< Internal variable used by the state machine */
            Boolean no_resp;                            /**< Internal variable used by the state machine */
            Boolean request;                            /**< Internal variable used by the state machine */
            Boolean port_enabled;                       /**< Internal variable used by the state machine */
            Boolean alt_accept;                         /**< Internal variable used by the state machine */
            Boolean alt_reject;                         /**< Internal variable used by the state machine */
            int idle_while;                             /**< Internal variable used by the state machine */
            static eapol_callbacks eapol_cb;            /**< EAPOL callback collection */
            eap_peer_config wpa_configuration;                 /**< WPA configuration */

            /****************************** METHODS ******************************/
        protected:
            static eap_peer_config* eapol_sm_get_config( void *ctx );
            static struct wpabuf * eapol_sm_get_eapReqData( void *ctx );
            static Boolean eapol_sm_get_bool( void *ctx, enum eapol_bool_var variable );
            static void eapol_sm_set_bool( void *ctx, enum eapol_bool_var variable, Boolean value );
            static unsigned int eapol_sm_get_int( void *ctx, enum eapol_int_var variable );
            static void eapol_sm_set_int( void *ctx, enum eapol_int_var variable, unsigned int value );
            static void eapol_sm_set_config_blob( void *ctx, struct wpa_config_blob *blob );
            static const struct wpa_config_blob *eapol_sm_get_config_blob( void *ctx, const char *name );
            static void eapol_sm_notify_pending( void *ctx );
            //static void eapol_sm_eap_param_needed(void *ctx, const char *field, const char *txt);

            /**
             * Creates a new EapSm object
             * @param method EAP method
             * @param password User password
             * @param ca_certificate Path to the CA certificate
             * @param client_certificate Path to the client certificate
             * @param client_key_file Path to the client private key
             * @param client_key_file_passwd Password for the client private key
             * @param frm_client_data Data for the FRM method, client side
             * @param frm_server_data Data for the FRM method, server side
             */
            EapSm( EapPacket::EAP_TYPE method, string password, string ca_certificate, string client_certificate, string client_key_file, string client_key_file_passwd, string frm_client_data, string frm_server_data );

        public:

            /**
             * Obtains an EapSm for MD5 method
             * @param password User password
             * @return A new EapSm to be used with the MD5 method
             */
            static auto_ptr<EapSm> getEapSmMd5(string password);

            /**
             * Obtains an EapSm for TLS method
             * @param ca_certificate Path to the CA certificate
             * @param client_certificate Path to the client certificate
             * @param client_key_file Path to the client private key
             * @param client_key_file_passwd Password for the client private key
             * @return A new EapSm to be used with the TLS method
             */
            static auto_ptr<EapSm> getEapSmTls(string ca_certificate, string client_certificate, string client_key_file, string client_key_file_passwd);

            /**
             * Obtains an EapSm for FRM method
             * @param frm_client_data Data for the FRM method, client side
             * @param frm_server_data Data for the FRM method, server side
             * @return A new EapSm to be used with the FRM method
             */
            static auto_ptr<EapSm> getEapSmFrm(string frm_client_data, string frm_server_data);

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

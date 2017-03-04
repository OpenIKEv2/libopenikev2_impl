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

#include <libopenikev2/log.h>
#include <libopenikev2/aaacontroller.h>

#include "eapsm.h"
#include <string.h>

extern int wpa_debug_level;

namespace openikev2 {

    struct eapol_callbacks EapSm::eapol_cb =
    {
        EapSm::get_eap_user,
        EapSm::get_eap_req_id_text,
    };

    EapSm::EapSm( EapPacket::EAP_TYPE method, string aaa_server_addr, uint16_t aaa_server_port, string aaa_server_secret ) {
        // if this is the first time, register methods and switch off debugging
        static int once = 0;
        if ( once == 0 ) {
            eap_server_register_methods();
            wpa_debug_level = 1000;
            once = 1;
        }

        this->aaa_server_addr = aaa_server_addr;
        this->aaa_server_port = aaa_server_port;
        this->aaa_server_secret = aaa_server_secret;

        // initialices buffer
        this->buffer = wpabuf_alloc(MAX_MESSAGE_SIZE);


        // initializes the configuration variables

        // specify the allowed method
        //eap_method_type* allowed_methods = new eap_method_type[2];
        //allowed_methods[0].vendor = EAP_VENDOR_IETF;
        //allowed_methods[0].method = method;
        //allowed_methods[1].vendor = EAP_VENDOR_IETF;
        //allowed_methods[1].method = EapPacket::EAP_TYPE_NONE;


        //memset( &this->wpa_configuration, 0, sizeof( hostapd_bss_config ) );
        //this->wpa_configuration.eap_methods = allowed_methods;
        //this->wpa_configuration.fragment_size = 500;

        // creates empty configuration
        struct eap_config eap_conf;
        eap_conf.pac_opaque_encr_key = NULL;//(u8 *) os_malloc(16);
        eap_conf.ssl_ctx;
        eap_conf.eap_sim_db_priv;
        eap_conf.backend_auth;
        eap_conf.eap_server;
        eap_conf.eap_fast_a_id = 0;
        eap_conf.eap_sim_aka_result_ind;
        eap_conf.tnc;


        //cout << "*** llega aqui ***" << endl;
        this->sm = eap_server_sm_init( this, &eapol_cb, &eap_conf );

        this->eap_iface = eap_get_interface(this->sm);

        this->eap_iface->eapRestart = FALSE;
        this->eap_iface->portEnabled = TRUE;

        //cout << "*** inicializa la maquina ***" << endl;
        // while not EAP_IDLE state, steps state machine
        while (this->sm->EAP_state != 2 ) {
            //cout << "*** pasa a otro estado *** [" << this->sm->EAP_state << "]" ;
            eap_server_sm_step( this->sm );
            //cout << " --> [" << this->sm->EAP_state << "]" << endl ;
        }
    }



    auto_ptr< EapSm > EapSm::getEapSmFrm( string aaa_server_addr, uint16_t aaa_server_port, string aaa_server_secret ) {
        //printf("*********** SE LLAMA A getEapSmFrm()\n");
        return auto_ptr<EapSm> ( new EapSm( EapPacket::EAP_TYPE_FRM,  aaa_server_addr,  aaa_server_port,  aaa_server_secret ) );
    }

    EapSm::~EapSm() {

        //delete this->wpa_configuration.eap_methods;
        eap_server_sm_deinit( this->sm );
        wpabuf_free(this->buffer);
    }


    auto_ptr< EapPacket > EapSm::firststep( ) {
        // obtains the first request data and creates the EapPacket object
	//printf("*********** SE LLAMA A firststep()\n");

	ByteBuffer tempBuffer( this->eap_iface->eapReqData->size );
        tempBuffer.writeBuffer( wpabuf_head(this->eap_iface->eapReqData), this->eap_iface->eapReqData->used );
        return EapPacket::parse( tempBuffer );
    }


    auto_ptr< EapPacket > EapSm::step( const EapPacket & eap_response ) {
        // obtains the EAP packet binary representation
        ByteBuffer buffer( eap_response.eap_type_data->size() + 5 );
        eap_response.getBinaryRepresentation( buffer );

        // copy the response into the buffer, mark as response and steps the machine
        this->eap_iface->eapResp = TRUE;
        this->eap_iface->eapRespData = wpabuf_alloc_copy(buffer.getRawPointer(), buffer.size());
	    this->eap_iface->eapReq = FALSE;
        this->eap_iface->aaaEapReq = FALSE;
        this->eap_iface->eapSuccess = FALSE;
        //cout << "*** STEP *** [" << this->sm->EAP_state << "]";
restep:
        eap_server_sm_step( this->sm );

	//cout << " -> [" << this->sm->EAP_state << "]"<< endl;

        // after step, if there is a new request available, error
        if ( !this->eap_iface->eapReq && this->eap_iface->aaaEapReq) {


            Log::writeLockedMessage( "EapSm", "AAA negotiation required.", Log::LOG_INFO, true );

            // Puede que haya un EAP para mandar al AAA
            this->aaa_username = "wimax_client@um.es";//peer_id.id_data->clone(); // TODO

            ByteBuffer tempBuffer( this->eap_iface->aaaEapReqData->size );
            tempBuffer.writeBuffer( wpabuf_head(this->eap_iface->aaaEapReqData), this->eap_iface->aaaEapReqData->used );
	        this->aaa_eap_packet_to_send = EapPacket::parse( tempBuffer );

            Log::writeLockedMessage( "EapSm", "Sending AAA request...", Log::LOG_INFO, true );
            AAAController::AAA_send(*this);
            Log::writeLockedMessage( "EapSm", "AAA response received.", Log::LOG_INFO, true );

            ByteBuffer buffer_aaa( this->aaa_eap_packet_received->eap_type_data->size() + 5 );
            this->aaa_eap_packet_received->getBinaryRepresentation( buffer_aaa );

            this->eap_iface->aaaEapRespData = wpabuf_alloc_copy(buffer_aaa.getRawPointer(), buffer_aaa.size());
            this->eap_iface->aaaEapResp = TRUE;

            this->eap_iface->aaaEapKeyData = aaa_msk->getRawPointer(); // Ahora no entinendo de donde se saca la MSK
	        this->eap_iface->aaaEapKeyDataLen = aaa_msk->size();
            this->eap_iface->aaaEapKeyAvailable = TRUE;

            goto restep;

        }
        else if (!this->eap_iface->aaaEapReq && !this->eap_iface->eapReq && !this->eap_iface->eapSuccess){
            Log::writeLockedMessage( "EapSm", "Cannot generate response", Log::LOG_ERRO, true );
            return auto_ptr<EapPacket> ( NULL );
        }
        // obtains the request data and creates the EapPacket object


        ByteBuffer tempBuffer( this->eap_iface->eapReqData->size );
        tempBuffer.writeBuffer( wpabuf_head(this->eap_iface->eapReqData), this->eap_iface->eapReqData->used );
	    return EapPacket::parse( tempBuffer );

    }


    void EapSm::AAA_receive( auto_ptr<EapPacket> eap_packet ){
        this->aaa_eap_packet_received = eap_packet;
        this->aaa_semaphore->post();

    }

    int EapSm::get_eap_user (void *ctx, const u8 *identity, size_t identity_len,
			    int phase2, struct eap_user *user) {


        user->methods[0].vendor = EAP_VENDOR_IETF;
        user->methods[0].method = EAP_TYPE_TLS;
        user->methods[1].vendor = EAP_VENDOR_IETF;
        user->methods[1].method = EapPacket::EAP_TYPE_NONE;
	user->phase2 = phase2;

	//cout << "*** GET_EAP_USER ***" << endl;
	return 0;
    }

    const char* EapSm::get_eap_req_id_text (void *ctx, size_t *len){
	//cout << "*** GET_EAP_REQ_ID_TEXT ***" << endl;

	*len = 6;

	return "prueba";

    }



    auto_ptr<ByteArray> EapSm::getMsk() const {

        if ( eap_iface->eapKeyData )
            return auto_ptr<ByteArray> ( new ByteArray( eap_iface->eapKeyData, eap_iface->eapKeyDataLen ) );
        else
            return auto_ptr<ByteArray> ( NULL );
    }
}




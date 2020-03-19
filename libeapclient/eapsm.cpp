/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#include <libopenikev2/log.h>
#include "eapsm.h"
#include <string.h>

extern int wpa_debug_level;

namespace openikev2 {

struct eapol_callbacks EapSm::eapol_cb =
{
	EapSm::eapol_sm_get_config,
	EapSm::eapol_sm_get_bool,
	EapSm::eapol_sm_set_bool,
	EapSm::eapol_sm_get_int,
	EapSm::eapol_sm_set_int,
	EapSm::eapol_sm_get_eapReqData,
	EapSm::eapol_sm_set_config_blob,
	EapSm::eapol_sm_get_config_blob,
	EapSm::eapol_sm_notify_pending
//	EapSm::eapol_sm_eap_param_needed
};


    EapSm::EapSm( EapPacket::EAP_TYPE method, string password, string ca_certificate, string client_certificate, string client_key_file, string client_key_file_passwd, string frm_client_data, string frm_server_data   ) {
        // if this is the first time, register methods and switch off debugging
        static int once = 0;
        if ( once == 0 ) {
            eap_peer_register_methods();
            wpa_debug_level = 1000;
            once = 1;
        }

        // initialices internal variables
        this->success = FALSE;
        this->restart = TRUE;
        this->fail = FALSE;
        this->response = FALSE;
        this->no_resp = FALSE;
        this->request = FALSE;
        this->port_enabled = TRUE;
        this->alt_accept = FALSE;
        this->alt_reject = FALSE;

        // initializes the configuration variables

        // specify the allowed method
        eap_method_type* allowed_methods = new eap_method_type[3];
        allowed_methods[0].vendor = EAP_VENDOR_IETF;
        allowed_methods[0].method = method;
	allowed_methods[1].vendor = EAP_VENDOR_IETF;
        allowed_methods[1].method = EapPacket::EAP_TYPE_IDENTITY;
	allowed_methods[2].vendor = EAP_VENDOR_IETF;
        allowed_methods[2].method = EapPacket::EAP_TYPE_NONE;


        memset( &this->wpa_configuration, 0, sizeof( eap_peer_config ) );
        this->wpa_configuration.password = ( u8* ) strdup( password.c_str() );
        this->wpa_configuration.password_len = password.size();
        this->wpa_configuration.private_key = ( u8* ) strdup( client_key_file.c_str() );
        this->wpa_configuration.ca_cert = ( u8* ) strdup( ca_certificate.c_str() );
        this->wpa_configuration.client_cert = ( u8* ) strdup( client_certificate.c_str() );
        this->wpa_configuration.private_key_passwd = ( u8* ) strdup( client_key_file_passwd.c_str() );
        this->wpa_configuration.eap_methods = allowed_methods;
        this->wpa_configuration.fragment_size = 500;

        // creates empty configuration
        eap_config cfg = {NULL, NULL, NULL};

        // initializes the state machine
        this->sm = eap_peer_sm_init( this, &eapol_cb, NULL, &cfg );

        // while not EAP_IDLE state, steps state machine
        while ( this->sm->EAP_state != 2 )
            eap_peer_sm_step( this->sm );
	this->buffer = wpabuf_alloc (10);
    }


    auto_ptr< EapSm > EapSm::getEapSmMd5( string password ) {
        return auto_ptr<EapSm> ( new EapSm( EapPacket::EAP_TYPE_MD5_CHALLENGE, password, "", "", "", "", "", "" ) );
    }

    auto_ptr< EapSm > EapSm::getEapSmTls( string ca_certificate, string client_certificate, string client_key_file, string client_key_file_passwd ) {
        return auto_ptr<EapSm> ( new EapSm( EapPacket::EAP_TYPE_EAP_TLS, "", ca_certificate, client_certificate, client_key_file, client_key_file_passwd , "", "" ) );
    }

    auto_ptr< EapSm > EapSm::getEapSmFrm( string frm_client_data, string frm_server_data ) {
        return auto_ptr<EapSm> ( new EapSm( EapPacket::EAP_TYPE_FRM, "", "" , "", "", "", frm_client_data, frm_server_data ) );
    }

    EapSm::~EapSm() {
        delete[] this->wpa_configuration.private_key;
        delete[] this->wpa_configuration.ca_cert;
        delete[] this->wpa_configuration.client_cert;
        delete[] this->wpa_configuration.password;
        delete[] this->wpa_configuration.private_key_passwd;
        delete this->wpa_configuration.eap_methods;
        eap_peer_sm_deinit( this->sm );
        wpabuf_free(this->buffer);
    }

    auto_ptr< EapPacket > EapSm::step( const EapPacket & eap_request ) {
        // obtains the EAP packet binary representation
        ByteBuffer buffer( eap_request.eap_type_data->size() + 5 );
        eap_request.getBinaryRepresentation( buffer );

        // copy the request into the buffer, mark as request and steps the machine
        this->request = TRUE;

        wpabuf_free(this->buffer);

    	this->buffer = wpabuf_alloc_copy(buffer.getRawPointer(), buffer.size());

        eap_peer_sm_step( this->sm );

	    // after step, if there is no response available, error
        if ( !this->response ) {
            Log::writeLockedMessage( "EapSm", "Cannot generate response", Log::LOG_ERRO, true );
            return auto_ptr<EapPacket> ( NULL );
        }

        // obtains the response data and creates the EapPacket object
        struct wpabuf* response_buffer = eap_get_eapRespData( this->sm );

    	ByteBuffer tempBuffer( response_buffer->size );
        tempBuffer.writeBuffer( wpabuf_head(response_buffer), 	response_buffer->used );
	    wpabuf_free(response_buffer);
        return EapPacket::parse( tempBuffer );
    }


    eap_peer_config* EapSm::eapol_sm_get_config( void *ctx ) {
        EapSm* eapsm = ( EapSm* ) ctx;
        return &eapsm->wpa_configuration;
    }

    wpabuf * EapSm::eapol_sm_get_eapReqData( void *ctx ) {
	EapSm* eapsm = ( EapSm* ) ctx;
	if (eapsm == NULL || eapsm->buffer == NULL){
		return NULL;
	}

	return eapsm->buffer;
    }

    Boolean EapSm::eapol_sm_get_bool( void *ctx, enum eapol_bool_var variable ) {
        EapSm* eapsm = ( EapSm* ) ctx;
        switch ( variable ) {
            case EAPOL_eapSuccess:
                return eapsm->success;
            case EAPOL_eapRestart:
                return eapsm->restart;
            case EAPOL_eapFail:
                return eapsm->fail;
            case EAPOL_eapResp:
                return eapsm->response;
            case EAPOL_eapNoResp:
                return eapsm->no_resp;
            case EAPOL_eapReq:
                return eapsm->request;
            case EAPOL_portEnabled:
                return eapsm->port_enabled;
            case EAPOL_altAccept:
                return eapsm->alt_accept;
            case EAPOL_altReject:
                return eapsm->alt_reject;
        }
        return FALSE;
    }


    void EapSm::eapol_sm_set_bool( void *ctx, enum eapol_bool_var variable, Boolean value ) {
        EapSm* eapsm = ( EapSm* ) ctx;
        switch ( variable ) {
            case EAPOL_eapSuccess:
                eapsm->success = value;
                break;
            case EAPOL_eapRestart:
                eapsm->restart = value;
                break;
            case EAPOL_eapFail:
                eapsm->fail = value;
                break;
            case EAPOL_eapResp:
                eapsm->response = value;
                break;
            case EAPOL_eapNoResp:
                eapsm->no_resp = value;
                break;
            case EAPOL_eapReq:
                eapsm->request = value;
                break;
            case EAPOL_portEnabled:
                eapsm->port_enabled = value;
                break;
            case EAPOL_altAccept:
                eapsm->alt_accept = value;
                break;
            case EAPOL_altReject:
                eapsm->alt_reject = value;
                break;
        }
    }

    unsigned int EapSm::eapol_sm_get_int( void *ctx, enum eapol_int_var variable ) {
        EapSm* eapsm = ( EapSm* ) ctx;
        switch ( variable ) {
            case EAPOL_idleWhile:
                return eapsm->idle_while;
        }
        return 0;
    }

    void EapSm::eapol_sm_set_int( void *ctx, enum eapol_int_var variable, unsigned int value ) {
        EapSm* eapsm = ( EapSm* ) ctx;
        switch ( variable ) {
            case EAPOL_idleWhile:
                eapsm->idle_while = value;
                break;
        }
    }

    void EapSm::eapol_sm_set_config_blob( void *ctx, struct wpa_config_blob *blob ) { }


    const struct wpa_config_blob* EapSm::eapol_sm_get_config_blob( void *ctx, const char *name ) {
        return NULL;
    }

    //void eapol_sm_eap_param_needed(void *ctx, const char *field, const char *txt) {}

    void EapSm::eapol_sm_notify_pending( void *ctx ) {}

    auto_ptr<ByteArray> EapSm::getMsk() const {
        size_t msklen;
        const u8* msk = eap_get_eapKeyData( this->sm, &msklen );
        if ( msk )
            return auto_ptr<ByteArray> ( new ByteArray( msk, msklen ) );
        else
            return auto_ptr<ByteArray> ( NULL );
    }
}




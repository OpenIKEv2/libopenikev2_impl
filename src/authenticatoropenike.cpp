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
#include "authenticatoropenike.h"

#include <libopenikev2/ikesa.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/payload_idi.h>
#include <libopenikev2/payload_idr.h>
#include "eapserverradius.h"

#include <libopenikev2/log.h>


namespace openikev2 {

    AuthenticatorOpenIKE::AuthenticatorOpenIKE( )
            : Authenticator() {
        this->current_eap_client = NULL;
        this->current_eap_server = NULL;
    }

    AuthenticatorOpenIKE::~AuthenticatorOpenIKE() {}

    auto_ptr< Payload_AUTH > AuthenticatorOpenIKE::generateAuthPayload( const IkeSa & ike_sa ) {
        // generate the AUTH payload
        return this->auth_generator->generateAuthPayload( ike_sa );
    }

    string AuthenticatorOpenIKE::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTHENTICATOR_OPENIKE> {\n";

        oss << this->auth_generator->toStringTab ( tabs + 1 );

        for ( vector<AuthVerifier*>::const_iterator it = this->auth_verifiers->begin(); it != this->auth_verifiers->end(); it++ )
            oss << ( *it )->toStringTab( tabs + 1 );

        for ( vector<EapClient*>::const_iterator it = this->eap_clients->begin(); it != this->eap_clients->end(); it++ )
            oss << ( *it )->toStringTab( tabs + 1 );

        for ( vector<EapServer*>::const_iterator it = this->eap_servers->begin(); it != this->eap_servers->end(); it++ )
            oss << ( *it )->toStringTab( tabs + 1 );

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< Authenticator > AuthenticatorOpenIKE::clone( ) const {
        auto_ptr<AuthenticatorOpenIKE> authenticator ( new AuthenticatorOpenIKE( ) );

        authenticator->auth_generator = this->auth_generator->clone();

        for ( vector<AuthVerifier*>::const_iterator it = this->auth_verifiers->begin(); it != this->auth_verifiers->end(); it++ )
            authenticator->registerAuthVerifier( ( *it )->clone() );

        for ( vector<EapClient*>::const_iterator it = this->eap_clients->begin(); it != this->eap_clients->end(); it++ )
            authenticator->registerEapClient( ( *it )->clone() );

        for ( vector<EapServer*>::const_iterator it = this->eap_servers->begin(); it != this->eap_servers->end(); it++ )
            authenticator->registerEapServer( ( *it )->clone() );

        return auto_ptr<Authenticator> ( authenticator );
    }

    AutoVector< Payload_CERT_REQ > AuthenticatorOpenIKE::generateCertificateRequestPayloads( const IkeSa & ike_sa ) {
        AutoVector<Payload_CERT_REQ> result;

        for ( vector<AuthVerifier*>::iterator it = this->auth_verifiers->begin(); it != this->auth_verifiers->end(); it++ ) {
            AutoVector<Payload_CERT_REQ> cert_reqs = ( *it )->generateCertificateRequestPayloads( ike_sa );
            for ( vector<Payload_CERT_REQ*>::iterator it2 = cert_reqs->begin(); it2 != cert_reqs->end(); it2++ ) {
                result->push_back( *it2 );
            }
            cert_reqs->clear();
        }

        return result;
    }

    AutoVector< Payload_CERT > AuthenticatorOpenIKE::generateCertificatePayloads( const IkeSa & ike_sa, const vector< Payload_CERT_REQ * > payload_cert_req_r ) {
        return this->auth_generator->generateCertificatePayloads( ike_sa, payload_cert_req_r );
    }

    bool AuthenticatorOpenIKE::verifyAuthPayload( const Message & received_message, const IkeSa & ike_sa ) {
        // Obtains the payload AUTH
        Payload_AUTH& payload_auth = ( Payload_AUTH& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_AUTH );

        // Obtains the AuthMethod
        map<Enums::AUTH_METHOD, AuthVerifier*>::iterator it = this->auth_verifiers_map.find( payload_auth.getAuthMethod() );

        // If there is no method, shows a log message and return FALSE
        if ( it == this->auth_verifiers_map.end() ) {
            Log::writeMessage( "AuthenticatorOpenIKE", "AUTH method not supported for this peer", Log::LOG_ERRO, true );
            return false;
        }

        // verify the AUTH payload
        return it->second->verifyAuthPayload( received_message, ike_sa );
    }

    bool AuthenticatorOpenIKE::verifyEapAuthPayload( const Message & received_message, const IkeSa & ike_sa ) {
        assert ( !ike_sa.is_initiator || this->current_eap_client != NULL );

        // Obtains the payload AUTH
        Payload_AUTH& payload_auth = ( Payload_AUTH& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_AUTH );

        // The Message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_res : *ike_sa.ike_sa_init_req;

        // The PRF key
        ByteArray & prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pr : *ike_sa.key_ring->sk_pi;

        // Select the EAP shared key
        ByteArray* eap_psk = ike_sa.is_initiator ? this->current_eap_client->getSharedKey() : this->current_eap_server->getSharedKey();

        // Select the real shared key
        ByteArray &real_psk = eap_psk ? *eap_psk : prf_key;

        // Generate the AUTH field
        auto_ptr<ByteArray> auth_field = AuthenticatorOpenIKE::generatePskAuthField(
                                             message_to_check.getBinaryRepresentation( ike_sa.receive_cipher.get() ),
                                             *ike_sa.my_nonce,
                                             *ike_sa.peer_id,
                                             *ike_sa.prf,
                                             prf_key,
                                             real_psk
                                         );

        return ( *auth_field == payload_auth.getAuthField() );
    }

    auto_ptr< Payload_AUTH > AuthenticatorOpenIKE::generateEapAuthPayload( const IkeSa & ike_sa ) {
        assert ( !ike_sa.is_initiator || this->current_eap_client != NULL );

        // The message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_req : *ike_sa.ike_sa_init_res;

        // The PRF key to be used
        ByteArray& prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pi : *ike_sa.key_ring->sk_pr;

        // Select the EAP shared key
        ByteArray* eap_psk = ike_sa.is_initiator ? this->current_eap_client->getSharedKey() : this->current_eap_server->getSharedKey();

        // Select the real shared key
        ByteArray &real_psk = eap_psk ? *eap_psk : prf_key;

        // Generate the AUTH field
        auto_ptr<ByteArray> auth_field = AuthenticatorOpenIKE::generatePskAuthField(
                                             message_to_check.getBinaryRepresentation( ike_sa.send_cipher.get() ),
                                             *ike_sa.peer_nonce,
                                             *ike_sa.my_id,
                                             *ike_sa.prf,
                                             prf_key,
                                             real_psk
                                         );


        return auto_ptr<Payload_AUTH> ( new Payload_AUTH( Enums::AUTH_METHOD_PSK, auth_field ) );
    }

    void AuthenticatorOpenIKE::registerAuthVerifier( auto_ptr< AuthVerifier > auth_verifier ) {
        vector<Enums::AUTH_METHOD> supported_auth_methods = auth_verifier->getSupportedMethods();
        for ( vector<Enums::AUTH_METHOD>::iterator it = supported_auth_methods.begin(); it != supported_auth_methods.end(); it++ )
            this->auth_verifiers_map.insert( pair<Enums::AUTH_METHOD, AuthVerifier*> ( *it, auth_verifier.get() ) );

        this->auth_verifiers->push_back( auth_verifier.release() );
    }

    void AuthenticatorOpenIKE::setAuthGenerator( auto_ptr< AuthGenerator > auth_generator ) {
        this->auth_generator = auth_generator;
    }

    bool AuthenticatorOpenIKE::initiatorUsesEap( ) {
        return ( this->eap_clients->size() > 0 );
    }

    auto_ptr< Payload_EAP > AuthenticatorOpenIKE::processEapRequest( const Payload_EAP & eap_request ) {
        if ( this->current_eap_client == NULL ) {
            // Obtains the EAP client
            map<EapPacket::EAP_TYPE, EapClient*>::iterator it = this->eap_clients_map.find( eap_request.getEapPacket().eap_type );

            // If there is no method, shows a log message and return NULL response
            if ( it == this->eap_clients_map.end() ) {
                Log::writeMessage( "AuthenticatorOpenIKE", "EAP method not supported for this peer. Sending NAK", Log::LOG_ERRO, true );
                return this->buildNack( eap_request.getEapPacket() );
            }

            // save the current EapClient to be used
            this->current_eap_client = it->second;
        }

        return this->current_eap_client->processEapRequest( eap_request );
    }

    auto_ptr< Payload_EAP > AuthenticatorOpenIKE::generateInitialEapRequest( const ID& peer_id ) {
        if ( this->current_eap_server == NULL ) {
            // Obtains the EAP client
            map<EapPacket::EAP_TYPE, EapServer*>::iterator it = this->eap_servers_map.begin();

            // If there is no method, shows a log message and return NULL response
            if ( it == this->eap_servers_map.end() ) {
                Log::writeMessage( "AuthenticatorOpenIKE", "No EAP method present. Authentication error.", Log::LOG_ERRO, true );
                return auto_ptr< Payload_EAP > ( NULL );
            }

            // save the current EapClient to be used
            this->current_eap_server = it->second;
        }

        return this->current_eap_server->generateInitialEapRequest( peer_id );
    }

    auto_ptr< Payload_EAP > AuthenticatorOpenIKE::processEapResponse( const Payload_EAP & eap_response, const ID& peer_id ) {


/*        if(eap_response.getEapPacket().eap_type == EapPacket::EAP_TYPE_NAK){
            EapPacket::EAP_TYPE metodo_eap_solicitado = (EapPacket::EAP_TYPE) *(eap_response.getEapPacket().eap_type_data->getRawPointer());
            cout << "Metodo solicitado por peer: " << EapPacket::EAP_TYPE_STR( metodo_eap_solicitado ) << endl;
            map<EapPacket::EAP_TYPE, EapServer*>::iterator it = this->eap_servers_map.find( metodo_eap_solicitado );

            if (it == this->eap_servers_map.end()) {
                Log::writeMessage( "AuthenticatorOpenIKE", "No more EAP method present. Authentication error.", Log::LOG_ERRO, true );
                return auto_ptr< Payload_EAP > ( NULL );
            }
            // save the current EapServer to be used
            this->current_eap_server = it->second;
            return this->current_eap_server->generateInitialEapRequest( peer_id );
        }
*/
         return this->current_eap_server->processEapResponse(eap_response);
/*
		auto_ptr<Payload_EAP> p = this->current_eap_server->processEapResponse( eap_response );

		if (p.get() == NULL){
            map<EapPacket::EAP_TYPE, EapServer*>::iterator it = this->eap_servers_map.begin();
            for (;it != this->eap_servers_map.end() || (it->second != this->current_eap_server)  ; it++){

            }

            if (it != this->eap_servers_map.end()) {

                it++;
                if (it != this->eap_servers_map.end()){
                    this->current_eap_server = it->second;
                }
                else{
                    Log::writeMessage( "AuthenticatorOpenIKE", "No more EAP method present. Authentication error.", Log::LOG_ERRO, true );
                    return auto_ptr< Payload_EAP > ( NULL );

                }

            }
            else {
                   Log::writeMessage( "AuthenticatorOpenIKE", "No EAP method present. Authentication error.", Log::LOG_ERRO, true );
                   return auto_ptr< Payload_EAP > ( NULL );

            }

			return this->current_eap_server->processEapResponse(eap_response);
		}
		return p;
*/
    }

    void AuthenticatorOpenIKE::registerEapClient( auto_ptr<EapClient> eap_client ) {
        vector<EapPacket::EAP_TYPE> supported_eap_methods = eap_client->getSupportedMethods();
        for ( vector<EapPacket::EAP_TYPE>::iterator it = supported_eap_methods.begin(); it != supported_eap_methods.end(); it++ )
            this->eap_clients_map.insert( pair<EapPacket::EAP_TYPE, EapClient*> ( *it, eap_client.get() ) );

        this->eap_clients->push_back( eap_client.release() );
    }


    void AuthenticatorOpenIKE::registerEapServer( auto_ptr<EapServer> eap_server ) {
        vector<EapPacket::EAP_TYPE> supported_eap_methods = eap_server->getSupportedMethods();
        for ( vector<EapPacket::EAP_TYPE>::iterator it = supported_eap_methods.begin(); it != supported_eap_methods.end(); it++ )
            this->eap_servers_map.insert( pair<EapPacket::EAP_TYPE, EapServer*> ( *it, eap_server.get() ) );

        this->eap_servers->push_back( eap_server.release() );
    }


//    void AuthenticatorOpenIKE::setEapServer( auto_ptr< EapServer > eap_server ) {
//        this->eap_server = eap_server;
//    }

    auto_ptr< ByteArray > AuthenticatorOpenIKE::generateAuthDataToBeSigned( const ByteArray & message, const ByteArray & nonce, const ID & id, const PseudoRandomFunction & prf, const ByteArray & prf_key ) {
        // get the binary representation of the payload_id in temp
        Payload_IDi payload_id ( id.clone() );
        ByteBuffer payload_id_binary_representation( MAX_MESSAGE_SIZE );
        payload_id.getBinaryRepresentation( payload_id_binary_representation );

        // skips the payload_length to get the ID' value
        payload_id_binary_representation.skip( 2 );

        // Generate prf(SK_p, ID')
        auto_ptr<ByteArray> prf_result = prf.prf( prf_key, payload_id_binary_representation );

        // auth_data = message | nonce | prf(SK_p, ID')
        auto_ptr<ByteBuffer> auth_data ( new ByteBuffer ( message.size() + nonce.size() + prf.prf_size ) );
        auth_data->writeByteArray( message );
        auth_data->writeByteArray( nonce );
        auth_data->writeByteArray( *prf_result );

        return auto_ptr<ByteArray> ( auth_data );
    }

    auto_ptr< ByteArray > AuthenticatorOpenIKE::generatePskAuthField( const ByteArray & message, const ByteArray & nonce, const ID & id, const PseudoRandomFunction & prf, const ByteArray & prf_key, const ByteArray & psk ) {
        // Generate the AUTH data
        auto_ptr<ByteArray> auth_data = generateAuthDataToBeSigned( message, nonce, id, prf, prf_key );

        // keypad = "Key Pad for IKEv2"
        ByteArray keypad( "Key Pad for IKEv2", 17 );

        // generates the temporal_key as pfr(shared_key, keypad)
        auto_ptr<ByteArray> temporal_key = prf.prf( psk, keypad );

        // generates the auth field as prf(temporal_key, auth_data)
        return prf.prf( *temporal_key, *auth_data );
    }

    auto_ptr< Payload_EAP > AuthenticatorOpenIKE::buildNack( const EapPacket& eap_request ) {
        auto_ptr<ByteBuffer> valid_methods ( new ByteBuffer( this->eap_clients_map.size() ) );
        for ( map<EapPacket::EAP_TYPE, EapClient*>::iterator it = this->eap_clients_map.begin(); it != this->eap_clients_map.end(); it++ )
            valid_methods->writeInt8( it->first );

        auto_ptr<EapPacket> eap_packet ( new EapPacket( EapPacket::EAP_CODE_RESPONSE, eap_request.identifier, EapPacket::EAP_TYPE_NAK, auto_ptr<ByteArray> ( valid_methods ) )  );
        return auto_ptr<Payload_EAP> ( new Payload_EAP( eap_packet ) );
    }

    void AuthenticatorOpenIKE::processEapSuccess( const Payload_EAP & eap_success ) {
        assert (this->current_eap_client != NULL);
        this->current_eap_client->processEapSuccess( eap_success );
    }

    void AuthenticatorOpenIKE::processFinish( ) {
        this->current_eap_server->processFinish( );
    }

}






















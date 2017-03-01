/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
 *   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
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
#include "authverifierpsk.h"
#include "authenticatoropenike.h"

namespace openikev2 {

    AuthVerifierPsk::AuthVerifierPsk( auto_ptr<ByteArray> psk ) {
        this->psk = psk;
    }

    AuthVerifierPsk::AuthVerifierPsk( string psk ) {
        this->psk.reset ( new ByteArray( psk.data(), psk.size() ) );
    }

    AuthVerifierPsk::~AuthVerifierPsk() {}

    auto_ptr< AuthVerifier > AuthVerifierPsk::clone() const {
        return auto_ptr<AuthVerifier> ( new AuthVerifierPsk( this->psk->clone() ) );
    }

    AutoVector< Payload_CERT_REQ > AuthVerifierPsk::generateCertificateRequestPayloads( const IkeSa& ike_sa ) {
        AutoVector<Payload_CERT_REQ> result;
        return result;
    }

    vector<Enums::AUTH_METHOD> AuthVerifierPsk::getSupportedMethods( ) const {
        vector<Enums::AUTH_METHOD> result;

        result.push_back( Enums::AUTH_METHOD_PSK );

        return result;
    }

    bool AuthVerifierPsk::verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa ) {
        // Obtains the payload AUTH
        Payload_AUTH& payload_auth = ( Payload_AUTH& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_AUTH );

        // Obtains the payload ID
        Payload_ID& payload_id = ike_sa.is_initiator ? ( Payload_ID& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_IDr ) : ( Payload_ID& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_IDi );

        // The Message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_res : *ike_sa.ike_sa_init_req;

        // The PRF key
        ByteArray & prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pr : *ike_sa.key_ring->sk_pi;

        // Generate the AUTH field
        auto_ptr<ByteArray> auth_field = AuthenticatorOpenIKE::generatePskAuthField(
                                            message_to_check.getBinaryRepresentation( ike_sa.receive_cipher.get() ),
                                            *ike_sa.my_nonce,
                                            *payload_id.id,
                                            *ike_sa.prf,
                                            prf_key,
                                            *this->psk
                                        );

        return ( *auth_field == payload_auth.getAuthField() );
    }

    string AuthVerifierPsk::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_VERIFIER_PSK> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "psk=" << this->psk->toStringTab( tabs + 2 ) << "\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

}



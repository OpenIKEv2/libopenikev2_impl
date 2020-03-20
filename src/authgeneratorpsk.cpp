/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "authgeneratorpsk.h"

#include "authenticatoropenike.h"

namespace openikev2 {

    AuthGeneratorPsk::AuthGeneratorPsk( auto_ptr<ByteArray> psk ) {
        this->psk = psk;
    }

    AuthGeneratorPsk::AuthGeneratorPsk( string psk ) {
        this->psk.reset ( new ByteArray( psk.data(), psk.size() ) );
    }

    AuthGeneratorPsk::~AuthGeneratorPsk() {}

    auto_ptr< AuthGenerator > AuthGeneratorPsk::clone() const {
        return auto_ptr<AuthGenerator> ( new AuthGeneratorPsk( this->psk->clone() ) );
    }

    auto_ptr< Payload_AUTH > AuthGeneratorPsk::generateAuthPayload( const IkeSa& ike_sa ) {
        // The message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_req : *ike_sa.ike_sa_init_res;

        // The PRF key to be used
        ByteArray& prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pi : *ike_sa.key_ring->sk_pr;

        // Generate the AUTH field
        auto_ptr<ByteArray> auth_field = AuthenticatorOpenIKE::generatePskAuthField(
                                            message_to_check.getBinaryRepresentation( ike_sa.send_cipher.get() ),
                                            *ike_sa.peer_nonce,
                                            *ike_sa.getIkeSaConfiguration().my_id,
                                            *ike_sa.prf,
                                            prf_key,
                                            *this->psk
                                        );


        return auto_ptr<Payload_AUTH> ( new Payload_AUTH( Enums::AUTH_METHOD_PSK, auth_field ) );
    }

    AutoVector<Payload_CERT> AuthGeneratorPsk::generateCertificatePayloads( const IkeSa& ike_sa, const vector< Payload_CERT_REQ * > payload_cert_req_r ) {
        AutoVector<Payload_CERT> result;
        return result;
    }

    string AuthGeneratorPsk::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_GENERATOR_PSK> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "psk=" << this->psk->toStringTab( tabs + 2 ) << "\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

}

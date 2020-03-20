/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "authgeneratorbtns.h"

namespace openikev2 {

    AuthGeneratorBtns::AuthGeneratorBtns( ) {}

    AuthGeneratorBtns::~AuthGeneratorBtns( ) {}

    auto_ptr< AuthGenerator > AuthGeneratorBtns::clone() const {
        return auto_ptr<AuthGenerator> ( new AuthGeneratorBtns( ) );
    }

    auto_ptr< Payload_AUTH > AuthGeneratorBtns::generateAuthPayload( const IkeSa& ike_sa ) {
        auto_ptr<ByteArray> auth_field (new ByteArray ("BTNS", 4) );
        return auto_ptr<Payload_AUTH> ( new Payload_AUTH( (Enums::AUTH_METHOD) 201, auth_field ) );
    }

    AutoVector<Payload_CERT> AuthGeneratorBtns::generateCertificatePayloads( const IkeSa& ike_sa, const vector< Payload_CERT_REQ * > payload_cert_req_r ) {
        AutoVector<Payload_CERT> result;
        return result;
    }

    string AuthGeneratorBtns::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_GENERATOR_BTNS> {\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }
}


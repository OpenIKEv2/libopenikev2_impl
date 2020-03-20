/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "authverifierbtns.h"

namespace openikev2 {

    AuthVerifierBtns::AuthVerifierBtns() { }


    AuthVerifierBtns::~AuthVerifierBtns() {}

    auto_ptr< AuthVerifier > AuthVerifierBtns::clone() const {
        return auto_ptr<AuthVerifier> ( new AuthVerifierBtns( ) );
    }

    AutoVector< Payload_CERT_REQ > AuthVerifierBtns::generateCertificateRequestPayloads( const IkeSa& ike_sa ) {
        AutoVector<Payload_CERT_REQ> result;
        return result;
    }

    vector<Enums::AUTH_METHOD> AuthVerifierBtns::getSupportedMethods( ) const {
        vector<Enums::AUTH_METHOD> result;

        result.push_back( (Enums::AUTH_METHOD) 201);

        return result;
    }

    bool AuthVerifierBtns::verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa ) {
        return true;
    }

    string AuthVerifierBtns::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_VERIFIER_BTNS> {\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

}

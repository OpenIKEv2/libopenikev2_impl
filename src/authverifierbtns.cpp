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

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


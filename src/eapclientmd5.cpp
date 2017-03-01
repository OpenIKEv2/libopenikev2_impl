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
#include "eapclientmd5.h"
#include "eapsm.h"
#include <libopenikev2/log.h>
#include <openssl/md5.h>
#include <openssl/evp.h>


namespace openikev2 {

    EapClientMd5::EapClientMd5( string client_password )
            : EapClient() {
        this->client_password = client_password;
        this->eap_sm = EapSm::getEapSmMd5( client_password );
    }

    EapClientMd5::~EapClientMd5() {}

    auto_ptr< Payload_EAP > EapClientMd5::processEapRequest( const Payload_EAP & eap_request ) {
        // steps the state machine
        auto_ptr<EapPacket> response = this->eap_sm->step( eap_request.getEapPacket() );

        if ( response.get() == NULL )
            return auto_ptr<Payload_EAP>( NULL );

        return auto_ptr<Payload_EAP> ( new Payload_EAP( response ) );
    }

    vector< EapPacket::EAP_TYPE > EapClientMd5::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_MD5_CHALLENGE );
        return result;
    }

    string EapClientMd5::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_CLIENT_MD5_CHALLENGE> {\n";
        oss << Printable::generateTabs( tabs + 1 ) << "client_password=[" << this->client_password << "]" << endl;
        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< EapClient > EapClientMd5::clone( ) const {
        return auto_ptr<EapClient> ( new EapClientMd5( this->client_password ) );
    }

    void EapClientMd5::processEapSuccess( const Payload_EAP & eap_success ) {
    }
}









/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
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









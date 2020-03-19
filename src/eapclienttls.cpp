/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/

#include <libopenikev2/log.h>
#include <libopenikev2/exception.h>
#include "eapsm.h"

#include "eapclienttls.h"

namespace openikev2 {

    EapClientTls::EapClientTls( string ca_certificate, string client_certificate, string client_private_key, string client_private_key_password )
            : EapClient() {
        this->ca_certificate = ca_certificate;
        this->client_certificate = client_certificate;
        this->client_private_key = client_private_key;
        this->client_private_key_password = client_private_key_password;

        this->eap_sm = EapSm::getEapSmTls(ca_certificate, client_certificate, client_private_key, client_private_key_password );
    }

    EapClientTls::~EapClientTls() {
    }

    auto_ptr< Payload_EAP > EapClientTls::processEapRequest( const Payload_EAP & eap_request ) {
        // steps the state machine
        auto_ptr<EapPacket> response = this->eap_sm->step( eap_request.getEapPacket() );

        if ( response.get() == NULL )
            return auto_ptr<Payload_EAP>( NULL );

        return auto_ptr<Payload_EAP> ( new Payload_EAP( response ) );
    }


    void EapClientTls::processEapSuccess( const Payload_EAP & eap_success ) {
        auto_ptr<ByteArray> key = this->eap_sm->getMsk();

        if ( key.get() == NULL )
            throw Exception( "Cannot get MSK value" );

        this->setSharedKey( key );
    }


    vector< EapPacket::EAP_TYPE > EapClientTls::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_EAP_TLS );
        return result;
    }

    string EapClientTls::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_CLIENT_TLS> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "ca_certificate=[" << this->ca_certificate << "]" << endl;
        oss << Printable::generateTabs( tabs + 1 ) << "client_certificate=[" << this->client_certificate << "]" << endl;
        oss << Printable::generateTabs( tabs + 1 ) << "client_private_key=[" << this->client_private_key << "]" << endl;
        oss << Printable::generateTabs( tabs + 1 ) << "client_private_key_password=[" << this->client_private_key_password << "]" << endl;

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< EapClient > EapClientTls::clone( ) const {
        return auto_ptr<EapClient> ( new EapClientTls( this->ca_certificate, this->client_certificate, this->client_private_key, this->client_private_key_password ) );
    }


}


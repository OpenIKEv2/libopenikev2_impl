/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "eapclientfrm.h"
#include "eapsm.h"
#include <libopenikev2/log.h>
#include <libopenikev2/exception.h>



namespace openikev2 {

    EapClientFrm::EapClientFrm( string eap_client_data )
            : EapClient() {
        this->client_data = eap_client_data;
        this->eap_sm = EapSm::getEapSmFrm( eap_client_data, "" );
    }

    EapClientFrm::~EapClientFrm() {}

    auto_ptr< Payload_EAP > EapClientFrm::processEapRequest( const Payload_EAP & eap_request ) {
        // steps the state machine
        auto_ptr<EapPacket> response = this->eap_sm->step( eap_request.getEapPacket() );

        if ( response.get() == NULL )
            return auto_ptr<Payload_EAP>( NULL );

        return auto_ptr<Payload_EAP> ( new Payload_EAP( response ) );
    }

    void EapClientFrm::processEapSuccess( const Payload_EAP & eap_success ) {
        auto_ptr<ByteArray> key = this->eap_sm->getMsk();

        if ( key.get() == NULL )
            throw Exception( "Cannot get MSK value" );

        this->setSharedKey( key );
    }

    vector< EapPacket::EAP_TYPE > EapClientFrm::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_FRM );
        return result;
    }

    string EapClientFrm::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_CLIENT_FRM> {\n";
        oss << Printable::generateTabs( tabs + 1 ) << "client_data=[" << this->client_data << "]" << endl;
        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< EapClient > EapClientFrm::clone( ) const {
        return auto_ptr<EapClient> ( new EapClientFrm( this->client_data ) );
    }



}









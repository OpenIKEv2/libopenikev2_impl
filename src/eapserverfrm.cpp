/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#include "eapserverfrm.h"

#include <fstream>
#include <libopenikev2/exception.h>
#include <libopenikev2/log.h>
#include "randomopenssl.h"
//#include <openssl/md5.h>
//#include <openssl/evp.h>
#include <string.h>
#include "eapsm.h"

namespace openikev2 {

    EapServerFrm::EapServerFrm( string aaa_server_addr="", uint16_t aaa_server_port=1812, string aaa_server_secret="")
            : EapServer() {

        this->aaa_server_addr = aaa_server_addr;
        this->aaa_server_port = aaa_server_port;
        this->aaa_server_secret = aaa_server_secret;

        this->eap_sm = EapSm::getEapSmFrm(aaa_server_addr, aaa_server_port, aaa_server_secret);
    }

    EapServerFrm::~EapServerFrm() {}

    auto_ptr<Payload_EAP> EapServerFrm::generateInitialEapRequest( const ID& peer_id ) {

	    return auto_ptr<Payload_EAP> ( new Payload_EAP( this->eap_sm->firststep () ) );

    }

    auto_ptr<Payload_EAP> EapServerFrm::processEapResponse( const Payload_EAP & eap_response ) {

        // steps the state machine
        auto_ptr<EapPacket> next_request = this->eap_sm->step( eap_response.getEapPacket() );

        if ( next_request.get() == NULL )
            return auto_ptr<Payload_EAP>( NULL );

        return auto_ptr<Payload_EAP> ( new Payload_EAP( next_request ) );

    }


    void EapServerFrm::processFinish() {
        auto_ptr<ByteArray> key = this->eap_sm->getMsk();

	ByteArray *otrokey = key.get();

        if ( key.get() == NULL )
            throw Exception( "Cannot get MSK value" );


        this->setSharedKey( key );

        //printf ("********** ESTABLECIDA LA CLAVE MSK=[");
	//cout << otrokey->toStringTab( 4 );

    }

    vector< EapPacket::EAP_TYPE > EapServerFrm::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_FRM );
        return result;
    }

    string EapServerFrm::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_SERVER_FRM> {\n";
        oss << Printable::generateTabs( tabs + 1 ) << "aaa_server_addr=[" << this->aaa_server_addr << "]" << endl;
        oss << Printable::generateTabs( tabs + 1 ) << "aaa_server_port=[" << this->aaa_server_port << "]" << endl;
        oss << Printable::generateTabs( tabs + 1 ) << "aaa_server_secret=[" << this->aaa_server_secret << "]" << endl;
        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();

    }

    auto_ptr< EapServer > EapServerFrm::clone( ) const {
        auto_ptr< EapServerFrm > result( new EapServerFrm( this->aaa_server_addr, this->aaa_server_port, this->aaa_server_secret ) );

        return auto_ptr< EapServer > ( result );
    }
}




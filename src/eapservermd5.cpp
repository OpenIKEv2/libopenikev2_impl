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
#include "eapservermd5.h"

#include <fstream>
#include <libopenikev2/exception.h>
#include <libopenikev2/log.h>
#include "randomopenssl.h"
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <string.h>
namespace openikev2 {

    EapServerMd5::EapServerMd5( string filename )
            : EapServer() {

        this->readMapFile( filename );
    }

    EapServerMd5::EapServerMd5( ) {}

    EapServerMd5::~EapServerMd5() {}

    vector< EapPacket::EAP_TYPE > EapServerMd5::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_MD5_CHALLENGE );
        return result;
    }

    auto_ptr<Payload_EAP> EapServerMd5::generateInitialEapRequest( const ID& peer_id ) {
        if ( peer_id.id_type != Enums::ID_RFC822_ADDR ) {
            Log::writeLockedMessage( "EAPServerController[MD5]", "PEER ID must be a RFC822 address.\n", Log::LOG_ERRO, true );
            throw Exception( "ID must be an ID_RFC822_ADDR for EAP_MD5" );
        }

        this->peer_id = string( ( char* ) peer_id.id_data->getRawPointer(), peer_id.id_data->size() );

        RandomOpenSSL random;
        uint16_t range = random.getRandomInt32( 20, 100 );
        uint16_t indentity = random.getRandomInt32( 1, 10000 );

        this->challenge = random.getRandomBytes( range );

        auto_ptr<ByteBuffer> data_to_be_sent ( new ByteBuffer( range + 1 ) );
        data_to_be_sent->writeInt8( 16 );
        data_to_be_sent->writeByteArray( *this->challenge );

        auto_ptr<EapPacket> request_eap_packet( new EapPacket( EapPacket::EAP_CODE_REQUEST, indentity, EapPacket::EAP_TYPE_MD5_CHALLENGE, auto_ptr<ByteArray> ( data_to_be_sent ) ) );
        return auto_ptr<Payload_EAP> ( new Payload_EAP( request_eap_packet ) );
    }

    auto_ptr<Payload_EAP> EapServerMd5::processEapResponse( const Payload_EAP & eap_response ) {
        EapPacket& eap_packet = eap_response.getEapPacket();

        if ( eap_packet.code != EapPacket::EAP_CODE_RESPONSE ) {
            Log::writeLockedMessage( "EAPServerController[MD5]", "EAP response expected", Log::LOG_ERRO, true );
            auto_ptr<EapPacket> failure_eap_packet( new EapPacket( EapPacket::EAP_CODE_FAILURE, eap_packet.identifier ) );
            return auto_ptr<Payload_EAP> ( new Payload_EAP( failure_eap_packet ) );
        }

        if ( eap_packet.eap_type != EapPacket::EAP_TYPE_MD5_CHALLENGE ) {
            Log::writeLockedMessage( "EAPServerController[MD5]", "EAP type not supported", Log::LOG_ERRO, true );
            auto_ptr<EapPacket> failure_eap_packet( new EapPacket( EapPacket::EAP_CODE_FAILURE, eap_packet.identifier ) );
            return auto_ptr<Payload_EAP> ( new Payload_EAP( failure_eap_packet ) );
        }

        string passwd_str = this->user_map[ this->peer_id ];

        if ( passwd_str == "" ) {
            Log::writeLockedMessage( "EAPServerController[MD5]", "User unknown: " + this->peer_id, Log::LOG_ERRO, true );
            auto_ptr<EapPacket> failure_eap_packet( new EapPacket( EapPacket::EAP_CODE_FAILURE, eap_packet.identifier ) );
            return auto_ptr<Payload_EAP> ( new Payload_EAP( failure_eap_packet ) );
        }

        ByteBuffer data_to_be_hashed( 100 );
        data_to_be_hashed.writeInt8( eap_packet.identifier );
        data_to_be_hashed.writeBuffer( passwd_str.data(), passwd_str.size() );
        data_to_be_hashed.writeBuffer( this->challenge->getRawPointer(), 16 );

        ByteArray md5_result( 16 );
        MD5( ( unsigned char* ) data_to_be_hashed.getRawPointer(), data_to_be_hashed.size(), md5_result.getRawPointer() );
        md5_result.setSize( 16 );

        ByteBuffer received_md5(16);
        received_md5.writeBuffer(eap_packet.eap_type_data->getRawPointer() + 1, 16);
        
        if ( md5_result == received_md5 ) {
            auto_ptr<EapPacket> success_eap_packet( new EapPacket( EapPacket::EAP_CODE_SUCCESS, eap_response.getEapPacket().identifier ) );
            return auto_ptr<Payload_EAP> ( new Payload_EAP( success_eap_packet ) );
        }
        else {
            Log::writeLockedMessage( "EAPServerController[MD5]", "Invalid password", Log::LOG_ERRO, true );
            auto_ptr<EapPacket> failure_eap_packet( new EapPacket( EapPacket::EAP_CODE_FAILURE, eap_response.getEapPacket().identifier ) );
            return auto_ptr<Payload_EAP> ( new Payload_EAP( failure_eap_packet ) );
        }
    }

    void EapServerMd5::readMapFile( string filename ) {
        ifstream infile( filename.c_str() );

        if ( !infile.good() )
            throw Exception( "File <" + filename + "> cannot be readed" );

        string line;
        while ( getline( infile, line, '\n' ) ) {
            readLine( line );
        }

        infile.close();
    }

    void EapServerMd5::readLine( string line ) {
        char charline [ line.size() + 1 ];
        strcpy( charline, line.c_str() );
        const char delimiters[] = " \t";

        char* token = strtok( charline, delimiters );

        if ( token == NULL )
            return ;

        string username = token;
        token = strtok( NULL, delimiters );

        if ( token == NULL )
            throw Exception( "Username without password value in the eap_map file." );

        string passwd = token;

        this->user_map[ username ] = passwd;
    }


    string EapServerMd5::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_SERVER_MD5> {\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();

    }

    auto_ptr< EapServer > EapServerMd5::clone( ) const {
        auto_ptr< EapServerMd5 > result( new EapServerMd5() );
        if ( this->challenge.get() )
            result->challenge = this->challenge->clone();
        result->peer_id = this->peer_id;
        result->user_map = this->user_map;

        return auto_ptr< EapServer > ( result );
    }
}




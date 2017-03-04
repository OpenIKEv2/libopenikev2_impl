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
#include "eapserverradius.h"
#include "randomopenssl.h"
#include "pseudorandomfunctionopenssl.h"
#include "socketaddressposix.h"
#include "ipaddressopenike.h"
#include <string.h>
#include <libopenikev2/exception.h>
#include <openssl/md5.h>

namespace openikev2 {

    EapServerRadius::EapServerRadius( string server_address, uint16_t server_port, string secret ) {
        auto_ptr<IpAddress> server_ip_address ( new IpAddressOpenIKE( server_address ) );
        this->server_socket_address.reset( new SocketAddressPosix( server_ip_address, server_port ) );
        this->secret.reset( new ByteArray( secret.data(), secret.size() ) );
    }

    EapServerRadius::EapServerRadius( const EapServerRadius& other ) {
        this->server_socket_address = other.server_socket_address->clone();
        this->secret = other.secret->clone();
    }

    EapServerRadius::~EapServerRadius() {
    }

    vector< EapPacket::EAP_TYPE > EapServerRadius::getSupportedMethods( ) const {
        vector<EapPacket::EAP_TYPE> result;
        result.push_back( EapPacket::EAP_TYPE_EAP_TLS );
        return result;
    }

    auto_ptr< Payload_EAP > EapServerRadius::generateInitialEapRequest( const ID & peer_id ) {
        this->socket.reset( new UdpSocket() );
        this->socket->bind( SocketAddressPosix ( auto_ptr<IpAddress> ( new IpAddressOpenIKE( Enums::ADDR_IPV4 ) ), 0 ) );

        RandomOpenSSL random;
        this->seq_number = random.getRandomInt32( 1, 50000 );

        this->username = peer_id.id_data->clone();

        // Creates the RADIUS ACCESS-REQUEST message
        auto_ptr<RadiusMessage> request( new RadiusMessage( RadiusMessage::RADIUS_CODE_ACCESS_REQUEST, this->seq_number++, random.getRandomBytes( 16 ) ) );

        // Adds the User-Name Attribute
        request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_USER_NAME, this->username->clone() ) ) );

        // Adds the Eap-Message Attribute
        auto_ptr<ByteBuffer> buffer( new ByteBuffer( 200 ) );
        EapPacket response_eap_packet( EapPacket::EAP_CODE_RESPONSE, 1, EapPacket::EAP_TYPE_IDENTITY, peer_id.id_data->clone() );
        response_eap_packet.getBinaryRepresentation( *buffer );
        request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE, auto_ptr<ByteArray> ( buffer ) ) ) );

        // Sends the messate to the RADIUS server
        this->sendRadiusMessage( *request );

        // Waits for the response
        auto_ptr<RadiusMessage> response = this->receiveRadiusMessage( *request->authenticator );

        // If the response is not an RADIUS_CODE_ACCESS_CHALLENGE, return NULL
        if ( response->code != RadiusMessage::RADIUS_CODE_ACCESS_CHALLENGE )
            return auto_ptr< Payload_EAP > ( NULL );

        // Stores the State attribute for future requests
        RadiusAttribute* state_attribute = response->getAttribute( RadiusAttribute::RADIUS_ATTR_STATE );
        if ( state_attribute == NULL )
            return auto_ptr< Payload_EAP > ( NULL );
        this->server_state = state_attribute->clone();

        // Obtains the Eap-Message attribute
        RadiusAttribute* eap_attribute = response->getAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE );
        if ( eap_attribute == NULL )
            return auto_ptr< Payload_EAP > ( NULL );

        // Creates the Payload_EAP with the request EAP packet
        ByteBuffer temp( eap_attribute->getValue() );
        auto_ptr<EapPacket> request_eap_packet = EapPacket::parse( temp );

        return auto_ptr< Payload_EAP > ( new Payload_EAP( request_eap_packet ) );
    }

    auto_ptr< Payload_EAP > EapServerRadius::processEapResponse( const Payload_EAP & eap_response ) {
        // Creates the RADIUS ACCESS-REQUEST message
        RandomOpenSSL random;
        auto_ptr<RadiusMessage> request( new RadiusMessage( RadiusMessage::RADIUS_CODE_ACCESS_REQUEST, this->seq_number++, random.getRandomBytes( 16 ) ) );

        // Creates the User-Name attrbiute
        request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_USER_NAME, this->username->clone() ) ) );

        // Creates the Eap-Message attrbiute
        auto_ptr<ByteBuffer> buffer( new ByteBuffer( MAX_MESSAGE_SIZE ) );
        eap_response.getEapPacket().getBinaryRepresentation( *buffer );

        while ( buffer->size() > 253 )
            request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE, buffer->readByteArray( 253 ) ) ) );

        if ( buffer->size() > 0 )
            request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE, auto_ptr<ByteArray> ( buffer ) ) ) );

        // Creates the State Attribute
        request->addAttribute( this->server_state->clone() );

        // Sends the message to the RADIUS server
        this->sendRadiusMessage( *request );

        // Waits for the response
        auto_ptr<RadiusMessage> response = this->receiveRadiusMessage( *request->authenticator );

        // Process State attribute
        RadiusAttribute* state_attribute = response->getAttribute( RadiusAttribute::RADIUS_ATTR_STATE );
        if ( state_attribute != NULL )
            this->server_state = state_attribute->clone();

        // process the MS-MPPE attributes (If access accept response
        if ( response->code == RadiusMessage::RADIUS_CODE_ACCESS_ACCEPT )
            this->getMsk( *response, *request );


        // Process the Eap-Message attribute
        vector<RadiusAttribute*> eap_attributes = response->getAttributes( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE );
        if ( eap_attributes.size() == 0 )
            return auto_ptr< Payload_EAP > ( NULL );

        // Creates the Payload_EAP
        ByteBuffer temp( eap_attributes.size() * 256 );
        for ( vector<RadiusAttribute*>::iterator it = eap_attributes.begin(); it != eap_attributes.end(); it++ )
            temp.writeByteArray( ( *it )->getValue() );

        auto_ptr<EapPacket> request_eap_packet = EapPacket::parse( temp );

        return auto_ptr< Payload_EAP > ( new Payload_EAP( request_eap_packet ) );
    }

    void EapServerRadius::sendRadiusMessage( RadiusMessage & radius_message ) {
        // Creates the Message-Authenticator Attribute
        auto_ptr<ByteArray> checksum( new ByteArray( 16, 0 ) );
        checksum->setSize( 16 );
        auto_ptr<RadiusAttribute> message_authenticator( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_MESSAGE_AUTHENTICATOR, checksum ) );
        radius_message.addAttribute( message_authenticator );

        // Obtains the binary representation of the RADIUS message and updates the Checksum
        ByteBuffer buffer( 4096 );
        radius_message.getBinaryRepresentation( buffer );
        PseudoRandomFunctionOpenSSL prf( Enums::PRF_HMAC_MD5 );
        auto_ptr<ByteArray> hmac = prf.prf( *this->secret, buffer );
        uint8_t* position = &buffer.getRawPointer()[ buffer.size() - hmac->size()];
        memcpy( position, hmac->getRawPointer(), hmac->size() );

        // Sends the message
        this->socket->send( SocketAddressPosix ( auto_ptr<IpAddress> ( new IpAddressOpenIKE( Enums::ADDR_IPV4 ) ), 0 ) ,
                            *this->server_socket_address,
                            buffer
                          );
    }

    auto_ptr<RadiusMessage> EapServerRadius::receiveRadiusMessage( const ByteArray& request_message_authenticator ) {
        // Receives the message
        auto_ptr<SocketAddress> src( NULL ), dst( NULL );
        auto_ptr<ByteArray> data = this->socket->receive( src, dst, 3000 );

        // If some error occourred, exception
        if ( data.get() == NULL )
            throw Exception( "Cannot connect with RADIUS server" );

        // Parses the message and returns it
        ByteBuffer byte_buffer( *data );
        auto_ptr<RadiusMessage> radius_message = RadiusMessage::parse( byte_buffer );

        // Check the message authenticator
        RadiusAttribute* message_authenticator = radius_message->getAttribute( RadiusAttribute::RADIUS_ATTR_MESSAGE_AUTHENTICATOR );
        if ( message_authenticator == NULL )
            throw Exception( "RADIUS: Message-Authenticator attribute not present" );

        // Obtain the HMAC value
        auto_ptr<ByteArray> received_hmac = message_authenticator->getValue().clone();

        // Change the HMAC value to 0 and the message authenticator to the access-request one
        memset( message_authenticator->getValue().getRawPointer(), 0, 16 );
        radius_message->authenticator = request_message_authenticator.clone();

        // regenerate binary representation of the message
        byte_buffer.reset();
        radius_message->getBinaryRepresentation( byte_buffer );

        // Computes the HMAC
        PseudoRandomFunctionOpenSSL prf( Enums::PRF_HMAC_MD5 );
        auto_ptr<ByteArray> hmac = prf.prf( *this->secret, byte_buffer );

        // Compares it with the received one
        if ( !( *hmac == *received_hmac ) )
            throw Exception( "RADIUS: Received invalid Message-Authenticator" );

        return radius_message;
    }


    string EapServerRadius::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<EAP_SERVER_RADIUS> {\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< EapServer > EapServerRadius::clone( ) const {
        return auto_ptr<EapServer> ( new EapServerRadius( *this ) );
    }


    void EapServerRadius::getMsk( RadiusMessage & radius_message, RadiusMessage & access_request_message ) {
        // obtain the vendor specif attributes
        vector<RadiusAttribute*> vendor_attributes = radius_message.getAttributes( RadiusAttribute::RADIUS_ATTR_VENDOR_SPECIFIC );

        auto_ptr<ByteArray> recv_key_attr, send_key_attr;

        // for all the vendor specific attributes
        for ( vector<RadiusAttribute*>::iterator it = vendor_attributes.begin(); it < vendor_attributes.end(); it++ ) {
            // read vendor_id
            ByteBuffer attribute_value ( ( *it )->getValue() );
            uint32_t vendor_id = attribute_value.readInt32();

            // if vendor ID is not MS, continue
            if ( vendor_id != 311 )
                continue;

            // Read all the subattributes in the attribute
            while ( attribute_value.size() > 0 ) {
                // read the vendor_type
                uint8_t vendor_type = attribute_value.readInt8();

                // read the vendor_length
                uint8_t vendor_length = attribute_value.readInt8();

                // read the value
                auto_ptr<ByteArray> vendor_value = attribute_value.readByteArray( vendor_length - 2 );

                // if the vendor type is MS_MPPE_SEND_KEY then
                if ( vendor_type == RadiusAttribute::MS_MPPE_SEND_KEY )
                    send_key_attr = vendor_value;

                // else if the vendor type is MS_MPPE_RECV_KEY then
                else if ( vendor_type == RadiusAttribute::MS_MPPE_RECV_KEY )
                    recv_key_attr = vendor_value;
            }
        }

        // If both are availables, generate MSK
        if ( recv_key_attr.get() != NULL && send_key_attr.get() != NULL ) {
            auto_ptr<ByteArray> recv_key = this->decryptKey( *recv_key_attr, *access_request_message.authenticator );
            auto_ptr<ByteArray> send_key = this->decryptKey( *send_key_attr, *access_request_message.authenticator );
            auto_ptr<ByteBuffer> msk ( new ByteBuffer( recv_key->size() + send_key->size() ) );
            msk->writeByteArray( *recv_key );
            msk->writeByteArray( *send_key );
            this->setSharedKey( auto_ptr<ByteArray> ( msk ) );
        }
    }

    auto_ptr< ByteArray > EapServerRadius::decryptKey( const ByteArray & key_attr, const ByteArray & authenticator ) {
        ByteBuffer encrypted_data ( key_attr );
        ByteBuffer temp( 1000 );
        uint8_t b[16], c[16];

        auto_ptr<ByteBuffer> decrypted_data ( new ByteBuffer( key_attr.size() ) );

        // read salt key
        auto_ptr<ByteArray> salt_key = encrypted_data.readByteArray( 2 );

        if ( encrypted_data.size() % 16 )
            throw Exception( "Invalid attribute length" );

        // prepare first iteration
        temp.writeByteArray( *this->secret );
        temp.writeByteArray( authenticator );
        temp.writeByteArray( *salt_key );

        while ( encrypted_data.size() ) {
            // calculate "b" value
            MD5( ( unsigned char* ) temp.getRawPointer(), temp.size(), b );

            // obtain the "c" value
            encrypted_data.readBuffer( 16, c );

            // generate decrypted data
            for ( uint16_t i = 0; i < 16; i++ )
                decrypted_data->writeInt8( c[i] ^ b[i] );

            // calculate the next value for temp
            temp.reset();
            temp.writeByteArray( *this->secret );
            temp.writeBuffer( c, 16 );
        }

        uint8_t length = decrypted_data->readInt8();
        return decrypted_data->readByteArray( length );
    }
}









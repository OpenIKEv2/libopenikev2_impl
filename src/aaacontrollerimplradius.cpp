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
#include "aaacontrollerimplradius.h"
#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/autolock.h>
#include <libopenikev2/log.h>
#include "randomopenssl.h"
#include "pseudorandomfunctionopenssl.h"
#include "socketaddressposix.h"
#include "ipaddressopenike.h"
#include <openssl/md5.h>

extern "C" {
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
}


namespace openikev2 {

    AAAControllerImplRadius::AAAControllerImplRadius(  ) {

        RandomOpenSSL random;
        this->seq_number = random.getRandomInt32( 1, 50000 );
        
        this->mutex_senders_map = ThreadController::getMutex();

        this->socket.reset( new UdpSocket() );
        this->socket->bind( SocketAddressPosix ( auto_ptr<IpAddress> ( new IpAddressOpenIKE( Enums::ADDR_IPV4 ) ), 0 ) );
    }

    AAAControllerImplRadius::~AAAControllerImplRadius() {}


    void AAAControllerImplRadius::AAA_send( AAASender& eap_sender ){
        this->AAA_send((AAASenderRadius& ) eap_sender);

    }

    void AAAControllerImplRadius::AAA_send( AAASenderRadius& eap_sender ){
        // Creates the RADIUS ACCESS-REQUEST message
        RandomOpenSSL random;
        auto_ptr<RadiusMessage> request( new RadiusMessage( RadiusMessage::RADIUS_CODE_ACCESS_REQUEST, this->seq_number++, random.getRandomBytes( 16 ) ) );

        // Creates the User-Name attrbiute
        request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_USER_NAME, eap_sender.aaa_username ) ) );

        // Creates the Eap-Message attrbiute
        auto_ptr<ByteBuffer> buffer( new ByteBuffer( MAX_MESSAGE_SIZE ) );
        eap_sender.aaa_eap_packet_to_send->getBinaryRepresentation( *buffer );

        while ( buffer->size() > 253 )
            request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE, buffer->readByteArray( 253 ) ) ) );

        if ( buffer->size() > 0 )
            request->addAttribute( auto_ptr<RadiusAttribute> ( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE, auto_ptr<ByteArray> ( buffer ) ) ) );

        // Creates the State Attribute
        RadiusAttribute* state_attribute = NULL;
        if ( eap_sender.aaa_radius_response.get() != NULL )
           state_attribute = eap_sender.aaa_radius_response->getAttribute( RadiusAttribute::RADIUS_ATTR_STATE );
            
        request->addAttribute( state_attribute->clone() );

        // Sends the messate to the RADIUS server
        this->sendRadiusMessage( request , eap_sender);
    }



    
    void AAAControllerImplRadius::sendRadiusMessage( auto_ptr<RadiusMessage> radius_message, AAASenderRadius& eap_sender ) {

        auto_ptr<IpAddress> server_ip_address ( new IpAddressOpenIKE( eap_sender.aaa_server_addr ) );
        auto_ptr<SocketAddressPosix> server_socket_address( new SocketAddressPosix( server_ip_address, eap_sender.aaa_server_port ) );
        auto_ptr<ByteArray> secret ( new ByteArray( eap_sender.aaa_server_secret.data(), eap_sender.aaa_server_secret.size() ) );

        // Creates the Message-Authenticator Attribute
        auto_ptr<ByteArray> checksum( new ByteArray( 16, 0 ) );
        checksum->setSize( 16 );
        auto_ptr<RadiusAttribute> message_authenticator( new RadiusAttribute( RadiusAttribute::RADIUS_ATTR_MESSAGE_AUTHENTICATOR, checksum ) );
        radius_message->addAttribute( message_authenticator );

        // Obtains the binary representation of the RADIUS message and updates the Checksum
        ByteBuffer buffer( 4096 );
        radius_message->getBinaryRepresentation( buffer );
        PseudoRandomFunctionOpenSSL prf( Enums::PRF_HMAC_MD5 );
        auto_ptr<ByteArray> hmac = prf.prf( *(secret.get()), buffer );
        uint8_t* position = &buffer.getRawPointer()[ buffer.size() - hmac->size()];
        memcpy( position, hmac->getRawPointer(), hmac->size() );

        // Sends the message
        this->socket->send( SocketAddressPosix ( auto_ptr<IpAddress> ( new IpAddressOpenIKE( Enums::ADDR_IPV4 ) ), 0 ) ,
                            *(server_socket_address.get()),
                            buffer
                          );


        eap_sender.aaa_radius_response = radius_message;
        senders_map[ radius_message->identifier ] = &eap_sender;
        
        // TODO: Hacer timeout
        eap_sender.aaa_semaphore->wait();
        
    }

    auto_ptr<RadiusMessage> AAAControllerImplRadius::receiveRadiusMessage( ) {
        // Receives the message
        auto_ptr<SocketAddress> src( NULL ), dst( NULL );
        auto_ptr<ByteArray> data = this->socket->receive( src, dst, 3000 );

        // If some error occourred, exception
        if ( data.get() == NULL )
            throw Exception( "Cannot connect with RADIUS server" );

        // Parses the message and returns it
        ByteBuffer byte_buffer( *data );
        auto_ptr<RadiusMessage> radius_message = RadiusMessage::parse( byte_buffer );

        // Search the sender
        map<uint8_t,AAASenderRadius *>::iterator it;
        it = this->senders_map.find(radius_message->identifier);

        if (it == senders_map.end()){
            throw Exception( "RADIUS: Associated sender not found." );
        }
        AAASenderRadius* eap_sender = it->second;

        // Check the message authenticator
        RadiusAttribute* message_authenticator = radius_message->getAttribute( RadiusAttribute::RADIUS_ATTR_MESSAGE_AUTHENTICATOR );
        if ( message_authenticator == NULL )
            throw Exception( "RADIUS: Message-Authenticator attribute not present" );

        // Obtain the HMAC value
        auto_ptr<ByteArray> received_hmac = message_authenticator->getValue().clone();

        // Change the HMAC value to 0 and the message authenticator to the access-request one
        memset( message_authenticator->getValue().getRawPointer(), 0, 16 );
        if (eap_sender->aaa_radius_request.get() != NULL)
            radius_message->authenticator = eap_sender->aaa_radius_request->authenticator->clone();
        else
            throw Exception( "RADIUS: Received AAA message without associated request" );

        // regenerate binary representation of the message
        byte_buffer.reset();
        radius_message->getBinaryRepresentation( byte_buffer );

        auto_ptr<ByteArray> secret ( new ByteArray( eap_sender->aaa_server_secret.data(), eap_sender->aaa_server_secret.size() ) );
        
        // Computes the HMAC
        PseudoRandomFunctionOpenSSL prf( Enums::PRF_HMAC_MD5 );
        auto_ptr<ByteArray> hmac = prf.prf( *(secret.get()), byte_buffer );

        // Compares it with the received one
        if ( !( *hmac == *received_hmac ) )
            throw Exception( "RADIUS: Received invalid Message-Authenticator" );

        return radius_message;
    }



    void AAAControllerImplRadius::receiveEapMessage( ) {
               
    // Waits for the response
        auto_ptr<RadiusMessage> response = this->receiveRadiusMessage( );


    // Search the sender again
        map<uint8_t,AAASenderRadius *>::iterator it;
        it = this->senders_map.find(response->identifier);

        if (it == senders_map.end()){
            throw Exception( "RADIUS: Associated sender not found." );
        }
        AAASenderRadius* eap_sender = it->second;

        auto_ptr<ByteArray> secret ( new ByteArray( eap_sender->aaa_server_secret.data(), eap_sender->aaa_server_secret.size() ) );
        
        // process the MS-MPPE attributes (If access accept response
        if ( response->code == RadiusMessage::RADIUS_CODE_ACCESS_ACCEPT )
            eap_sender->aaa_msk = this->getMsk( *response, *(eap_sender->aaa_radius_request) , *secret);


        // Process the Eap-Message attribute
        vector<RadiusAttribute*> eap_attributes = response->getAttributes( RadiusAttribute::RADIUS_ATTR_EAP_MESSAGE );
        if ( eap_attributes.size() == 0 ){
            eap_sender->aaa_radius_response.reset(NULL);
            return;
        } 
        // Creates the Payload_EAP
        ByteBuffer temp( eap_attributes.size() * 256 );
        for ( vector<RadiusAttribute*>::iterator it = eap_attributes.begin(); it != eap_attributes.end(); it++ )
            temp.writeByteArray( ( *it )->getValue() );

        auto_ptr<EapPacket> request_eap_packet = EapPacket::parse( temp );

        eap_sender->aaa_radius_response = response; // TODO: comprobar que pasa con la memoria machacada

        eap_sender->AAA_receive( request_eap_packet );

    }



    auto_ptr< ByteArray >  AAAControllerImplRadius::getMsk( RadiusMessage & radius_message, RadiusMessage & access_request_message, const ByteArray& secret ) {
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
            auto_ptr<ByteArray> recv_key = this->decryptKey( *recv_key_attr, *access_request_message.authenticator, secret );
            auto_ptr<ByteArray> send_key = this->decryptKey( *send_key_attr, *access_request_message.authenticator, secret );
            auto_ptr<ByteBuffer> msk ( new ByteBuffer( recv_key->size() + send_key->size() ) );
            msk->writeByteArray( *recv_key );
            msk->writeByteArray( *send_key );
            return auto_ptr<ByteArray> ( msk );
        }
        return auto_ptr<ByteArray> ( NULL );
    }

    auto_ptr< ByteArray > AAAControllerImplRadius::decryptKey( const ByteArray & key_attr, const ByteArray & authenticator, const ByteArray& secret ) {
        ByteBuffer encrypted_data ( key_attr );
        ByteBuffer temp( 1000 );
        uint8_t b[16], c[16];

        auto_ptr<ByteBuffer> decrypted_data ( new ByteBuffer( key_attr.size() ) );

        // read salt key
        auto_ptr<ByteArray> salt_key = encrypted_data.readByteArray( 2 );

        if ( encrypted_data.size() % 16 )
            throw Exception( "Invalid attribute length" );

        // prepare first iteration
        temp.writeByteArray( secret );
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
            temp.writeByteArray( secret );
            temp.writeBuffer( c, 16 );
        }

        uint8_t length = decrypted_data->readInt8();
        return decrypted_data->readByteArray( length );
    }    

    
    void AAAControllerImplRadius::run( ) {
        Log::writeLockedMessage( "AAAController", "Start: Thread ID=[" + intToString( thread_id ) + "]", Log::LOG_THRD, true );

        while ( true ) {
            try {
                receiveEapMessage( );

            }
            catch ( exception & ex ) {
                //Log::writeLockedMessage( "AlarmController", ex.what() , Log::LOG_ERRO, true );
            }
        }
    }


}

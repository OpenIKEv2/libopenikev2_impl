/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "radiusmessage.h"
#include <libopenikev2/utils.h>
#include <libopenikev2/exception.h>
#include <assert.h>

namespace openikev2 {

    RadiusMessage::RadiusMessage() {
    }

    RadiusMessage::RadiusMessage( RADIUS_MESSAGE_CODE code, uint8_t identifier, auto_ptr<ByteArray> authenticator ) {
        assert( authenticator->size() == 16 );

        this->code = code;
        this->identifier = identifier;
        this->authenticator = authenticator;
    }


    RadiusMessage::~RadiusMessage() {
    }

    auto_ptr< RadiusMessage > RadiusMessage::parse( ByteBuffer & byte_buffer ) {
        auto_ptr<RadiusMessage> result( new RadiusMessage() );

        // Pointer to the beginning of the transform
        uint8_t * message_begin = byte_buffer.getReadPosition();

        result->code = ( RADIUS_MESSAGE_CODE ) byte_buffer.readInt8();
        result->identifier = byte_buffer.readInt8();
        uint16_t length = byte_buffer.readInt16();

        // Size must be at least size of fixed header
        if ( length < 20 ||  length > 4096 )
            throw ParsingException( "Invalid RADIUS message size: " + intToString( length ) );

        result->authenticator = byte_buffer.readByteArray( 16 );

        while ( byte_buffer.getReadPosition() < message_begin + length ) {
            // parse the transform attribute
            auto_ptr<RadiusAttribute> attribute = RadiusAttribute::parse( byte_buffer );

            // adds the attribute to the collection
            result->addAttribute( attribute );
        }

        return result;

    }

    void RadiusMessage::addAttribute( auto_ptr< RadiusAttribute > attribute ) {
        this->attributes->push_back( attribute.release() );
    }

    void RadiusMessage::getBinaryRepresentation( ByteBuffer & byte_buffer ) const {
        byte_buffer.writeInt8( this->code );
        byte_buffer.writeInt8( this->identifier );

        // writes a dummy lengh
        uint8_t* length_field_position = byte_buffer.getWritePosition();
        byte_buffer.writeInt16( 0 );

        byte_buffer.writeByteArray( *this->authenticator );

        for ( vector<RadiusAttribute*>::const_iterator it = this->attributes->begin(); it != this->attributes->end(); it++ ) {
            ( *it ) ->getBinaryRepresentation( byte_buffer );
        }

        // pointer to the current position
        uint8_t* current_position = byte_buffer.getWritePosition();

        // writes the real length value
        byte_buffer.setWritePosition( length_field_position );
        byte_buffer.writeInt16( current_position - length_field_position + 2 );
        byte_buffer.setWritePosition( current_position );
    }


    RadiusAttribute * RadiusMessage::getAttribute( RadiusAttribute::RADIUS_ATTRIBUTE_TYPE type ) {
        for ( vector<RadiusAttribute*>::const_iterator it = this->attributes->begin(); it != this->attributes->end(); it++ ) {
            RadiusAttribute* current = ( *it );
            if (current->getType() == type)
                return current;
        }
        return NULL;
    }

    vector<RadiusAttribute*> RadiusMessage::getAttributes( RadiusAttribute::RADIUS_ATTRIBUTE_TYPE type ) {
	vector<RadiusAttribute*> result;
        for ( vector<RadiusAttribute*>::const_iterator it = this->attributes->begin(); it != this->attributes->end(); it++ ) {
            RadiusAttribute* current = ( *it );
            if (current->getType() == type)
                result.push_back(current);
        }
        return result;
    }
}









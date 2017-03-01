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
#ifndef OPENIKEV2RADIUSMESSAGE_H
#define OPENIKEV2RADIUSMESSAGE_H

#include <libopenikev2/radiusattribute.h>
#include <libopenikev2/autovector.h>

namespace openikev2 {

    /**
        This class represents a RADIUS message
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class RadiusMessage {
        public:
            enum RADIUS_MESSAGE_CODE {
                RADIUS_CODE_ACCESS_REQUEST = 1,
                RADIUS_CODE_ACCESS_ACCEPT = 2,
                RADIUS_CODE_ACCESS_REJECT = 3,
                RADIUS_CODE_ACCOUNTING_REQUEST = 4,
                RADIUS_CODE_ACCOUNTING_RESPONSE = 5,
                RADIUS_CODE_ACCESS_CHALLENGE = 11,
                RADIUS_CODE_STATUS_SERVER = 12,
                RADIUS_CODE_STATUS_CLIENT = 13,
                RADIUS_CODE_RESERVED = 255
            };
        
        public:
            RADIUS_MESSAGE_CODE code;
            uint8_t identifier;
            auto_ptr<ByteArray> authenticator;
            AutoVector<RadiusAttribute> attributes;
            RadiusMessage();
            
        public:
            RadiusMessage(RADIUS_MESSAGE_CODE code, uint8_t identifier, auto_ptr<ByteArray> authenticator);
            static auto_ptr<RadiusMessage> parse( ByteBuffer& byte_buffer );                        
                        
            virtual void addAttribute(auto_ptr<RadiusAttribute> attribute);
            
            virtual RadiusAttribute* getAttribute(RadiusAttribute::RADIUS_ATTRIBUTE_TYPE type);
            virtual vector<RadiusAttribute*> getAttributes(RadiusAttribute::RADIUS_ATTRIBUTE_TYPE type);

            /**
            * Appends the binary representation at the end of byte_buffer
            * @param byte_buffer ByteBuffer to append the binary representation
            */
            virtual void getBinaryRepresentation( ByteBuffer& byte_buffer ) const;
                        
            virtual ~RadiusMessage();

    };

}

#endif

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
#ifndef OPENIKEV2EAPMETHOD_H
#define OPENIKEV2EAPMETHOD_H

#include <libopenikev2/bytearray.h>

namespace openikev2 {

    /**
     Abstract class that represents any EapMethod (EapClient or EapServer) and contains the common parts to both
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapMethod : public Printable{
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<ByteArray> shared_key;                     /**< Shared key generated by the EAP method (if available) */

            /****************************** METHODS ******************************/
        public:
            /**
             * Sets the shared key value
             * @param shared_key Shared key
             */
            virtual void setSharedKey( auto_ptr<ByteArray> shared_key );

            /**
             * Gets the shared key value
             * @return Reference to the shared_key
             */
            virtual ByteArray* getSharedKey() const;

            virtual string toStringTab( uint8_t tabs ) const = 0;

            virtual ~EapMethod();

    };

}

#endif

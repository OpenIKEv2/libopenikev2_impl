/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
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
#ifndef SA_REQUEST_H
#define SA_REQUEST_H

#include <libopenikev2/ipaddress.h>
#include <libopenikev2/enums.h>

extern "C" {
#include <linux/pfkeyv2.h>
}

namespace openikev2 {

    /**
        This class represents a SA request, part of an IPsec Policy.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class SaRequest: public Printable {

            /****************************** ENUMS ******************************/
        public:
            /**< IPsec levels */
            enum IPSEC_LEVEL{
                LEVEL_DEFAULT = 0,        /**< Default level */
                LEVEL_USE = 1,            /**< Use level */
                LEVEL_REQUIRE = 2,        /**< Require level */
                LEVEL_UNIQUE = 3,         /**< Unique level */
        };

            /****************************** ATTRIBUTES ******************************/
        public:
            auto_ptr<IpAddress> tunnel_src;     /**< Source tunnel address */
            auto_ptr<IpAddress> tunnel_dst;     /**< Destination tunnel address */
            uint16_t request_id;                /**< Request id */
            Enums::IPSEC_MODE mode;             /**< IPsec mode */
            IPSEC_LEVEL level;                  /**< IPsec level */
            Enums::PROTOCOL_ID ipsec_protocol;  /**< IPsec Protocol */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new SaRequest object.
             */
            SaRequest();

            /**
             * Creates a new SaRequest clonning another one.
             * @param other Other SaRequest to be cloned.
             */
            SaRequest( const SaRequest & other );

            /**
             * Compares this SA request with another one.
             * @param other Other SA request.
             * @return True if both are equals. False otherwise.
             */
            virtual bool equals( const SaRequest & other ) const;

            /**
             * Translate from IPSEC level ID to strings
             * @param level IPSEC level ID
             * @return String of the ipsec level
             */
            static string IPSEC_LEVEL_STR( IPSEC_LEVEL level );

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~SaRequest();
    };
};
#endif

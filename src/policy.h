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
#ifndef POLICY_H
#define POLICY_H

#include <libopenikev2/ipaddress.h>
#include <libopenikev2/trafficselector.h>

#include "sarequest.h"

namespace openikev2 {

    /**
        This class represents an IPsec Policy
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class Policy: public Printable {

            /****************************** ATTRIBUTES ******************************/
        public:
            auto_ptr<IpAddress> selector_src;   /**< Source selector address */
            auto_ptr<IpAddress> selector_dst;   /**< Destination selector address */
            uint16_t selector_src_port;         /**< Source selector port */
            uint16_t selector_dst_port;         /**< Destination selector port */
            uint8_t icmp_type;                  /**< ICMP type */
            uint8_t icmp_code;                  /**< ICMP code */
            uint8_t selector_prefixlen_src;     /**< Selector source prefix length */
            uint8_t selector_prefixlen_dst;     /**< Selector destination prefix length */
            uint32_t id;                        /**< Policy ID */
            Enums::POLICY_TYPE type;            /**< Policy Type (MAIN or SUB) */
            Enums::DIRECTION direction;         /**< Policy direction */
            uint8_t ip_protocol;                /**< IP protocol to protect (TCP, UDP..). See IP protocol ids.*/
            auto_ptr<SaRequest> sa_request;    /**< SA requests collection */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new empty policy
             */
            Policy();

            /**
             * Compares this Policy with another one.
             * @param other Other policy.
             * @return TRUE if policies are equals. FALSE otherwise.
             */
            virtual bool equals( const Policy & other ) const;

            /**
             * Gets the source TrafficSelector
             * @return Source TrafficSelector
             */
            virtual auto_ptr<TrafficSelector> getSrcTrafficSelector() const;

            /**
             * Gets the destination TrafficSelector
             * @return Destination TrafficSelector
             */
            virtual auto_ptr<TrafficSelector> getDstTrafficSelector() const;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~Policy();

    };
};
#endif

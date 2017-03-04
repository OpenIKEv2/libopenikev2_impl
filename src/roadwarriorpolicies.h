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
#ifndef OPENIKEV2ROADWARRIORPOLICIES_H
#define OPENIKEV2ROADWARRIORPOLICIES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/attribute.h>
#include <libopenikev2/ipseccontroller.h>

namespace openikev2 {

    /**
     This class represents a set of road-warrior policies
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class RoadWarriorPolicies : public Attribute {
        protected:
            auto_ptr<Payload_TS> rw_policy_inbound;     /**< Inbound selector of the dynamically created roadwarrior policy */
            auto_ptr<Payload_TS> rw_policy_outbound;    /**< Outbound selector of the dynamically created roadwarrior policy */
            auto_ptr<IpAddress> rw_address;             /**< RW address */
        public:
            RoadWarriorPolicies( auto_ptr<IpAddress> rw_address, auto_ptr<Payload_TS> rw_policy_inbound, auto_ptr<Payload_TS> rw_policy_outbound );

            virtual auto_ptr<Attribute> cloneAttribute() const ;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~RoadWarriorPolicies();

    };

}

#endif

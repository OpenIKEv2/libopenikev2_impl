/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
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

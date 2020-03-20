/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "roadwarriorpolicies.h"
#include <libopenikev2/log.h>
#include <libopenikev2/exception.h>

namespace openikev2 {

    RoadWarriorPolicies::RoadWarriorPolicies( auto_ptr< IpAddress > rw_address, auto_ptr< Payload_TS > rw_policy_inbound, auto_ptr< Payload_TS > rw_policy_outbound ) {
        this->rw_policy_inbound = rw_policy_inbound;
        this->rw_policy_outbound = rw_policy_outbound;
        this->rw_address = rw_address;
    }

    RoadWarriorPolicies::~RoadWarriorPolicies() {
        Log::writeLockedMessage( "RoadWarriorPolicies", "Deleting roadwarrior policies for assigned address=[" + this->rw_address->toString() + "]", Log::LOG_INFO, true);
        try {
            IpsecController::deleteIpsecPolicy( rw_policy_outbound->getTrafficSelectors(), rw_policy_inbound->getTrafficSelectors(), Enums::DIR_OUT );
            IpsecController::deleteIpsecPolicy( rw_policy_inbound->getTrafficSelectors(), rw_policy_outbound->getTrafficSelectors(), Enums::DIR_FWD );
            IpsecController::deleteIpsecPolicy( rw_policy_inbound->getTrafficSelectors(), rw_policy_outbound->getTrafficSelectors(), Enums::DIR_IN );
        }
        catch ( IpsecException & ex ) {
            Log::writeLockedMessage( "RoadWarriorPolicies", ex.what(), Log::LOG_WARN, true );
        }

    }

    auto_ptr< Attribute > RoadWarriorPolicies::cloneAttribute( ) const {
        assert(0);
    }

    string RoadWarriorPolicies::toStringTab( uint8_t tabs ) const {
        return "RWPOLICIES";
    }

}





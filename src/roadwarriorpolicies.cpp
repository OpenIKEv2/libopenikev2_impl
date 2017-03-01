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





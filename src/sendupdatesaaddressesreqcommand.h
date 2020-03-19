/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef OPENIKEV2SENDUPDATESAADDRESSESREQCOMMAND_H
#define OPENIKEV2SENDUPDATESAADDRESSESREQCOMMAND_H

#include <libopenikev2/command.h>

namespace openikev2 {

    /**
        This class represents a Send UPDATE_SA_ADDRESSES request Command
    	@author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class SendUpdateSaAddressesReqCommand : public Command {
        protected:
            auto_ptr<IpAddress> new_sa_address;
        public:
            SendUpdateSaAddressesReqCommand( auto_ptr<IpAddress> new_sa_address);

            virtual IkeSa::IKE_SA_ACTION executeCommand( IkeSa& ike_sa );

            virtual string getCommandName() const;

            ~SendUpdateSaAddressesReqCommand();

    };

}

#endif

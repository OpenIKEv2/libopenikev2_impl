/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef OPENIKEV2NOTIFYCONTROLLER_MOBIKE_SUPPORTED_H
#define OPENIKEV2NOTIFYCONTROLLER_MOBIKE_SUPPORTED_H

#include <libopenikev2/notifycontroller.h>

namespace openikev2 {

    /**
        This class represents a MOBIKE SUPPORTED notification
    	@author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class NotifyController_MOBIKE_SUPPORTED : public NotifyController {
        public:
            NotifyController_MOBIKE_SUPPORTED();

            virtual IkeSa::NOTIFY_ACTION processNotify( Payload_NOTIFY& notify, Message& message, IkeSa& ike_sa, ChildSa* child_sa );

            virtual void addNotify( Message& message, IkeSa& ike_sa, ChildSa* child_sa );

            ~NotifyController_MOBIKE_SUPPORTED();

    };

}

#endif

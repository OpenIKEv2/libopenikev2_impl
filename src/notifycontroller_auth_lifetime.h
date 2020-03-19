/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef NOTIFYCONTROLLER_AUTH_LIFETIME_H
#define NOTIFYCONTROLLER_AUTH_LIFETIME_H

#include <libopenikev2/notifycontroller.h>

namespace openikev2 {

    /**
        This class represents an AUTH_LIFETIME notify controller
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class NotifyController_AUTH_LIFETIME : public NotifyController {

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new NotifyController_AUTH_LIFETIME
             */
            NotifyController_AUTH_LIFETIME();

            virtual IkeSa::NOTIFY_ACTION processNotify( Payload_NOTIFY& notify, Message& message, IkeSa& ike_sa, ChildSa* child_sa );

            virtual void addNotify( Message& message, IkeSa& ike_sa, ChildSa* child_sa );

            virtual ~NotifyController_AUTH_LIFETIME();
    };
}
#endif

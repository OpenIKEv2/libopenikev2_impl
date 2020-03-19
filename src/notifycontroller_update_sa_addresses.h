/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef OPENIKEV2NOTIFYCONTROLLER_UPDATE_SA_ADDRESSES_H
#define OPENIKEV2NOTIFYCONTROLLER_UPDATE_SA_ADDRESSES_H

#include <libopenikev2/notifycontroller.h>

namespace openikev2 {

    /**
        This class represents a UPDATE_SA_ADDRESSES MOBIKE notification
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class NotifyController_UPDATE_SA_ADDRESSES : public NotifyController {
        public:
            NotifyController_UPDATE_SA_ADDRESSES();

            virtual IkeSa::NOTIFY_ACTION processNotify( Payload_NOTIFY& notify, Message& message, IkeSa& ike_sa, ChildSa* child_sa );

            virtual ~NotifyController_UPDATE_SA_ADDRESSES();

    };

}

#endif

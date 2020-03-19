/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef DEBUGIMPL_COLORTEXT_H
#define DEBUGIMPL_COLORTEXT_H

#include "logimplopenike.h"

namespace openikev2 {
    /**
        This class represents a Log writer implementation, in colored text.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */
    class LogImplColorText : public LogImplOpenIKE {
        public:
            /**
             * Creates a new LogImplColorText
             * @return
             */
            LogImplColorText();

            virtual void writeMessage( string who, string message, uint16_t type, bool main_info );

            virtual ~LogImplColorText();
    };
};
#endif

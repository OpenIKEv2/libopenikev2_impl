/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef LOGIMPL_HTML_H
#define LOGIMPL_HTML_H

#include "logimplopenike.h"

namespace openikev2 {

    /**
        This class represents a Log writer implementation, in HTML source code.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */
    class LogImplHtml : public LogImplOpenIKE {
        public:
            /**
             * Creates a new LogImplHtml
             * @return
             */
            LogImplHtml();

            virtual void writeMessage( string who, string message, uint16_t type, bool main_info );
            virtual void open( string file_name );
            virtual void close();


            virtual ~LogImplHtml();
    };
};
#endif

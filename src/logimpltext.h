/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
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
#ifndef DEBUGIMPL_TEXT_H
#define DEBUGIMPL_TEXT_H


#include "logimplopenike.h"


namespace openikev2 {

    /**
        This class represents a Log writer implementation, in plain text.
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez
    */
    class LogImplText : public LogImplOpenIKE {
        public:
            /**
             * Creates a new LogImplText
             * @return
             */
            LogImplText();

            virtual void writeMessage( string who, string message, uint16_t type, bool main_info );

            virtual ~LogImplText();
    };
};
#endif

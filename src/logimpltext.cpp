/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
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
#include "logimpltext.h"
#include <stdio.h>

namespace openikev2 {

    LogImplText::LogImplText() : LogImplOpenIKE() {}

    void LogImplText::writeMessage( string who, string message, uint16_t type, bool main_info ) {
        // Check the mask
        if ( !( type & this->log_mask ) )
            return;

        // Gets the current time
        time_t t;
        time( &t );

        // Stores current time into time_str
        string time_str = ctime( &t );

        // Changes final \n with a \0
        time_str.replace( time_str.size() - 1, 1, "\0" );

        // Inserts date if desired
        if ( main_info ){
            message = "[" + time_str + "] [" + Log::LOG_TYPE_STR( type ) + "] " + who + ": " + message + "\n";
            fprintf( log_file, "%s", message.c_str() );
        }
        else if ( this->show_extra_info ) {
            message = message + "\n";
            fprintf( log_file, "%s", message.c_str() );
        }
        
    }

    LogImplText::~LogImplText() {}
}

/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
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

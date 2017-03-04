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
#include "logimplhtml.h"

#include <libopenikev2/utils.h>
#include "utilsimpl.h"
#include <stdio.h>

#define BLACK               "<font color=\"#000000\">"
#define DARK_GREY           "<font color=\"#444444\">"
#define DARK_RED            "<font color=\"#770000\">"
#define BRIGHT_RED          "<font color=\"#ff0000\">"
#define DARK_GREEN          "<font color=\"#007700\">"
#define BRIGHT_GREEN        "<font color=\"#00ff00\">"
#define BROWN               "<font color=\"#b56918\">"
#define YELLOW              "<font color=\"#ffff52\">"
#define DARK_BLUE           "<font color=\"#000077\">"
#define BRIGHT_BLUE         "<font color=\"#0000ff\">"
#define DARK_PURPLE         "<font color=\"#774477\">"
#define BRIGHT_PURPLE       "<font color=\"#ff55ff\">"
#define DARK_TURQUOISE      "<font color=\"#18b2b5\">"
#define BRIGHT_TURQUOISE    "<font color=\"#55ffff\">"
#define BRIGHT_GREY         "<font color=\"#777777\">"
#define BRIGHT_WHITE        "<font color=\"#ffffff\">"

namespace openikev2 {

    LogImplHtml::LogImplHtml() : LogImplOpenIKE() {}

    void LogImplHtml::writeMessage( string who, string message, uint16_t type, bool main_info ) {
        // Check the mask
        if ( !( type & this->log_mask ) )
            return;

        // Replace "<" with "&lt;"
        uint16_t pos = 0;
        pos = message.find_first_of( '<', 0 );
        while ( pos < message.size() ) {
            message.erase( pos, 1 );
            message.insert( pos, "&lt;" );
            pos = message.find_first_of( '<', pos );
        }

        // Replace ">" with "&gt;"
        pos = 0;
        pos = message.find_first_of( '>', 0 );
        while ( pos < message.size() ) {
            message.erase( pos, 1 );
            message.insert( pos, "&gt;" );
            pos = message.find_first_of( '>', pos );
        }

        // Replace "\n" with "<br>"
        pos = 0;
        pos = message.find_first_of( '\n', 0 );
        while ( pos < message.size() ) {
            message.erase( pos, 1 );
            message.insert( pos, "<br>" );
            pos = message.find_first_of( '\n', pos );
        }

        // Replace "  " with "&nbsp;&nbsp;"
        pos = 0;
        pos = message.rfind( "  ", message.size() );
        while ( pos < message.size() ) {
            message.erase( pos, 2 );
            message.insert( pos, "&nbsp;&nbsp;" );
            pos = message.rfind( "  ", message.size() );
        }

        // Gets the current local time
        time_t t;
        time( &t );

        // Stores current time into time_str
        string time_str = ctime( &t );

        // Changes final \n with a \0
        time_str.replace( time_str.size() - 1, 1, "\0" );

        // Selects color
        string color, color_extra;

        if ( type & Log::LOG_ERRO ) {
            color = BRIGHT_RED;
            color_extra = BRIGHT_RED;
        }
        else if ( type & Log::LOG_MESG ) {
            color = BRIGHT_GREEN;
            color_extra = DARK_GREEN;
        }
        else if ( type & Log::LOG_STAT ) {
            color = BRIGHT_BLUE;
            color_extra = BRIGHT_BLUE;
        }
        else if ( type & Log::LOG_CRYP ) {
            color = BRIGHT_TURQUOISE;
            color_extra = DARK_TURQUOISE;
        }
        else if ( type & Log::LOG_THRD ) {
            color = BRIGHT_PURPLE;
            color_extra = BRIGHT_PURPLE;
        }
        else if ( type & Log::LOG_ALRM ) {
            color = BRIGHT_BLUE;
            color_extra = BRIGHT_BLUE;
        }
        else if ( type & Log::LOG_IPSC ) {
            color = BRIGHT_TURQUOISE;
            color_extra = DARK_TURQUOISE;
        }
        else if ( type & Log::LOG_POLI ) {
            color = DARK_TURQUOISE;
            color_extra = DARK_TURQUOISE;
        }
        else if ( type & Log::LOG_DHCP ) {
            color = BRIGHT_PURPLE;
            color_extra = BRIGHT_PURPLE;
        }
        else if ( type & Log::LOG_HALF ) {
            color = BRIGHT_PURPLE;
            color_extra = BRIGHT_PURPLE;
        }
        else if ( type & Log::LOG_CONF ) {
            color = BRIGHT_TURQUOISE;
            color_extra = DARK_TURQUOISE;
        }
        else if ( type & Log::LOG_EBUS ) {
            color = BROWN;
            color_extra = BROWN;
        }
        else if ( type & Log::LOG_WARN ) {
            color = YELLOW;
            color_extra = YELLOW;
        }
        else if ( type & Log::LOG_INFO ) {
            color = BRIGHT_WHITE;
            color_extra = BRIGHT_GREY;
        }
        else {
            color = BRIGHT_GREY;
            color_extra = BRIGHT_GREY;
        }

        // Inserts date if desired
        if ( main_info ) {
            message = UtilsImpl::charToString( BRIGHT_WHITE ) + "[" + time_str + "] </font>" + color + "[" + Log::LOG_TYPE_STR( type ) + "] " + who + ": " + message + "</font><br>";
            fprintf( log_file, "%s", message.c_str() );
        }
        else if ( this->show_extra_info ) {
            message = color_extra + message + "</font><br>";
            fprintf( log_file, "%s", message.c_str() );
        }
    }

    void LogImplHtml::open( string file_name ) {
        LogImplOpenIKE::open( file_name );

        // Sets background color to black
        fprintf( log_file, "<html> <body style=\"font-family: monospace; font-size: 12pt; background-color: rgb(0, 0, 0);\"> " );
    }

    LogImplHtml::~LogImplHtml() {}

    void LogImplHtml::close( ) {
        fprintf( log_file, "</body> </html>" );
        LogImplOpenIKE::close();
    }
}

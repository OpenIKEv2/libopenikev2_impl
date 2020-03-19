/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "logimplcolortext.h"

#include <libopenikev2/log.h>
#include <libopenikev2/printable.h>
#include <libopenikev2/utils.h>
#include "utilsimpl.h"

#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#define BLACK            "\033[00;30m"
#define DARK_GREY        "\033[01;30m"
#define DARK_RED         "\033[00;31m"
#define BRIGHT_RED       "\033[01;31m"
#define DARK_GREEN       "\033[00;32m"
#define BRIGHT_GREEN     "\033[01;32m"
#define BROWN            "\033[00;33m"
#define YELLOW           "\033[01;33m"
#define DARK_BLUE        "\033[00;34m"
#define BRIGHT_BLUE      "\033[01;34m"
#define DARK_PURPLE      "\033[00;35m"
#define BRIGHT_PURPLE    "\033[01;35m"
#define DARK_TURQUOISE   "\033[00;36m"
#define BRIGHT_TURQUOISE "\033[01;36m"
#define BRIGHT_GREY      "\033[00;37m"
#define BRIGHT_WHITE     "\033[01;37m"

namespace openikev2 {

    LogImplColorText::LogImplColorText() : LogImplOpenIKE() {}

    void LogImplColorText::writeMessage( string who, string message, uint16_t type, bool main_info ) {
        // Check the mask
        if ( !( type & this->log_mask ) )
            return;


        time_t t;
        time( &t );
        timeval start;
        gettimeofday( &start, NULL );

        tm* broken_down = localtime( &t );

        // Sets the year
        string time_str = UtilsImpl::getPaddedString( intToString( broken_down->tm_year + 1900 ), 4 , true, '0' );
        time_str += "/" + UtilsImpl::getPaddedString( intToString( broken_down->tm_mon + 1 ), 2, true, '0' );
        time_str += "/" + UtilsImpl::getPaddedString( intToString( broken_down->tm_mday ), 2, true, '0' );

        time_str += " " + UtilsImpl::getPaddedString( intToString( broken_down->tm_hour ), 2, true, '0' );
        time_str += ":" + UtilsImpl::getPaddedString( intToString( broken_down->tm_min ), 2, true, '0' );
        time_str += ":" + UtilsImpl::getPaddedString( intToString( broken_down->tm_sec ), 2, true, '0' );
        time_str += "." + UtilsImpl::getPaddedString( intToString( ( int ) start.tv_usec / 1000 ), 3, true, '0' );

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
            message = UtilsImpl::charToString( BRIGHT_WHITE ) + "[" + time_str + "] " + color + "[" + Log::LOG_TYPE_STR( type ) + "] " + who + ": " + message + BRIGHT_WHITE + "\n";
            fprintf( log_file, "%s", message.c_str() );
        }
        else if ( this->show_extra_info ) {
            message = color_extra + message + BRIGHT_WHITE + "\n";
            fprintf( log_file, "%s", message.c_str() );
        }
    }

    LogImplColorText::~LogImplColorText() {
            fprintf( log_file, "%s", BRIGHT_GREY );

    }
}

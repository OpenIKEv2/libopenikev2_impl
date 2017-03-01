/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
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
#include "utilsimpl.h"

#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/utils.h>
#include <assert.h>

namespace openikev2 {

    auto_ptr<IpAddress> UtilsImpl::trafficSelectorToIpAddress( const TrafficSelector & ts, uint16_t * prefix ) {
        assert( ts.ts_type == TrafficSelector::TS_IPV4_ADDR_RANGE || ts.ts_type == TrafficSelector::TS_IPV6_ADDR_RANGE );

        uint8_t address_size = ( ts.ts_type == TrafficSelector::TS_IPV4_ADDR_RANGE ) ? 4 : 16;
        Enums::ADDR_FAMILY family = ( ts.ts_type == TrafficSelector::TS_IPV4_ADDR_RANGE ) ? Enums::ADDR_IPV4 : Enums::ADDR_IPV6;

        auto_ptr<ByteBuffer> byte_buffer ( new ByteBuffer( address_size ) );
        *prefix = 0;

        for ( uint16_t i = 0; i < address_size; i++ ) {
            // IF byte difference, then find bit diff
            if ( ( *ts.start_addr ) [ i ] != ( *ts.end_addr ) [ i ] ) {
		uint8_t current_byte=0;
                for ( uint8_t j = 0; j < 8; j++ ) {
                    uint8_t mask = 0x80 >> j;
                    // if bit difference
                    if ( ( ( *ts.start_addr ) [ i ] & mask ) != ( ( *ts.end_addr ) [ i ] & mask ) ) {
			byte_buffer->writeInt8(current_byte);
                        byte_buffer->fillBytes( address_size - i - 1, 0 );
                        return NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( byte_buffer ) );
                    }
                    current_byte |= ( mask & ( *ts.start_addr ) [ i ] );
                    *prefix += 1;
                }

                // this code never should be reached
                assert ( 0 );
            }

            byte_buffer->writeInt8( ( *ts.start_addr ) [ i ] );
            *prefix += 8;
        }

        return NetworkController::getIpAddress( family, auto_ptr<ByteArray> ( byte_buffer ) );
    }

    Enums::ADDR_FAMILY UtilsImpl::getInternalFamily( uint16_t unix_family ) {
        switch ( unix_family ) {
            case AF_INET:
                return Enums::ADDR_IPV4;
            case AF_INET6:
                return Enums::ADDR_IPV6;
            default:
                assert ( "Unknown family" && 0 );
        }
    }

    uint16_t UtilsImpl::getUnixFamily( Enums::ADDR_FAMILY family ) {
        switch ( family ) {
            case Enums::ADDR_IPV4:
                return AF_INET;
            case Enums::ADDR_IPV6:
                return AF_INET6;
            default:
                assert ( "Unknown family" && 0 );
        }
    }

    string UtilsImpl::charToString( char * str ) {
        return str;
    }

    string UtilsImpl::getPaddedString( string base, uint16_t totalsize, bool rightalign, char padchar ) {
        assert ( totalsize >= base.size() );
        string result;

        if ( rightalign )
            for ( uint16_t i = 0; i < totalsize - base.size(); i++ )
                result += padchar;

        result += base;

        for ( uint16_t i = 0; i < totalsize - result.size(); i++ )
            result += padchar;

        return result;
    }


}






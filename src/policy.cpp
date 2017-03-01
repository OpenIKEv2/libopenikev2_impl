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
#include "policy.h"

namespace openikev2 {

    Policy::Policy( ) {}

    Policy::~Policy() { }

    string Policy::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<IPSEC_POLICY> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "id=" << ( int ) this->id << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "type=" << Enums::POLICY_TYPE_STR(this->type) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "direction=" << Enums::DIRECTION_STR( this->direction ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "src_selector=" << this->selector_src->toString() << "/" << ( int ) this->selector_prefixlen_src << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "dst_selector=" << this->selector_dst->toString() << "/" << ( int ) this->selector_prefixlen_dst << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "ip_protocol=" << Enums::IP_PROTO_STR( this->ip_protocol ) << "\n";

        if ( this->ip_protocol == Enums::IP_PROTO_ICMP || this->ip_protocol == Enums::IP_PROTO_ICMPv6 ) {
            oss << Printable::generateTabs( tabs + 1 ) << "icmp_type=" << ( int ) this->icmp_type << "\n";
            oss << Printable::generateTabs( tabs + 1 ) << "icmp_code=" << ( int ) this->icmp_code << "\n";
        } else {
            oss << Printable::generateTabs( tabs + 1 ) << "src_port=" << ( int ) this->selector_src_port << "\n";
            oss << Printable::generateTabs( tabs + 1 ) << "dst_port=" << ( int ) this->selector_dst_port << "\n";
        }

        if ( this->sa_request.get() )
            oss << this->sa_request->toStringTab( tabs + 1 );

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    bool Policy::equals( const Policy & other ) const {
        if ( this->type != other.type )
            return false; 
       if ( this->direction != other.direction )
            return false;
        if ( this->ip_protocol != other.ip_protocol )
            return false;
        if ( this->selector_prefixlen_src != other.selector_prefixlen_src )
            return false;
        if ( this->selector_prefixlen_dst != other.selector_prefixlen_dst )
            return false;

        if ( !( *this->selector_src == *other.selector_src ) )
            return false;
        if ( !( *this->selector_dst == *other.selector_dst ) )
            return false;

        if ( ( this->sa_request.get() == NULL ) != ( other.sa_request.get() == NULL ) )
            return false;

        if ( this->sa_request.get() )
            return ( this->sa_request->equals( *other.sa_request ) );

        return true;
    }

    auto_ptr<TrafficSelector> Policy::getSrcTrafficSelector( ) const {
        if ( this->ip_protocol == Enums::IP_PROTO_ICMP || this->ip_protocol == Enums::IP_PROTO_ICMPv6 )
            return auto_ptr<TrafficSelector> ( new TrafficSelector( *this->selector_src, this->selector_prefixlen_src, this->icmp_type, this->icmp_code, this->ip_protocol ) );
        else if ( this->ip_protocol == Enums::IP_PROTO_MH )
            return auto_ptr<TrafficSelector> ( new TrafficSelector ( *this->selector_src, this->selector_prefixlen_src, this->icmp_type << 8, this->ip_protocol ) );
        else
            return auto_ptr<TrafficSelector> ( new TrafficSelector( *this->selector_src, this->selector_prefixlen_src, this->selector_src_port, this->ip_protocol ) );
    }

    auto_ptr<TrafficSelector> Policy::getDstTrafficSelector( ) const {
        if ( this->ip_protocol == Enums::IP_PROTO_ICMP || this->ip_protocol == Enums::IP_PROTO_ICMPv6 )
            return auto_ptr<TrafficSelector> ( new TrafficSelector( *this->selector_dst, this->selector_prefixlen_dst, 0, 0, this->ip_protocol ) );
        else if ( this->ip_protocol == Enums::IP_PROTO_MH )
            return auto_ptr<TrafficSelector> ( new TrafficSelector( *this->selector_dst, this->selector_prefixlen_dst, 0, this->ip_protocol ) );
        else
            return auto_ptr<TrafficSelector> ( new TrafficSelector( *this->selector_dst, this->selector_prefixlen_dst, this->selector_dst_port, this->ip_protocol ) );
    }

}




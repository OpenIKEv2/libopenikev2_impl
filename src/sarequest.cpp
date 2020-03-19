/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "sarequest.h"
#include <libopenikev2/utils.h>

namespace openikev2 {

    SaRequest::SaRequest( ) { }

    SaRequest::SaRequest( const SaRequest & other ) {
        this->ipsec_protocol = other.ipsec_protocol;
        this->level = other.level;
        this->mode = other.mode;
        this->request_id = other.request_id;
        if ( other.tunnel_src.get() )
            this->tunnel_src = other.tunnel_src->clone();
        if ( other.tunnel_dst.get() )
            this->tunnel_dst = other.tunnel_dst->clone();
    }

    bool SaRequest::equals( const SaRequest & other ) const {
        if ( this->level != other.level )
            return false;
        if ( this->mode != other.mode )
            return false;
        if ( this->ipsec_protocol != other.ipsec_protocol )
            return false;

        // If tunnel mode, then compare tunnel addresses
        if ( this->mode == Enums::TUNNEL_MODE ) {
            if ( !( *this->tunnel_src == *other.tunnel_src ) )
                return false;
            if ( !( *this->tunnel_dst == *other.tunnel_dst ) )
                return false;
        }
        return true;
    }

    SaRequest::~SaRequest() {}

    string SaRequest::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<SA_REQUEST> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "mode=" << Enums::IPSEC_MODE_STR( this->mode ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "ipsec_protocol=" << Enums::PROTOCOL_ID_STR( this->ipsec_protocol ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "level=" << SaRequest::IPSEC_LEVEL_STR( this->level ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "request_id=" << ( int ) this->request_id << "\n";

        if ( this->tunnel_src.get() )
            oss << Printable::generateTabs( tabs + 1 ) << "src_tunnel_addr=" << this->tunnel_src->toString() << "\n";

        if ( this->tunnel_dst.get() )
            oss << Printable::generateTabs( tabs + 1 ) << "dst_tunnel_addr=" << this->tunnel_dst->toString() << "\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    string SaRequest::IPSEC_LEVEL_STR( IPSEC_LEVEL level ) {
        switch ( level ) {
            case SaRequest::LEVEL_DEFAULT:
                return "LEVEL_DEFAULT";
            case SaRequest::LEVEL_REQUIRE:
                return "LEVEL_REQUIRE";
            case SaRequest::LEVEL_UNIQUE:
                return "LEVEL_UNIQUE";
            case SaRequest::LEVEL_USE:
                return "LEVEL_USE";
            default:
                return intToString( level );
        }
    }
}





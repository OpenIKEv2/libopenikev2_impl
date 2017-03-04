/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#include "idtemplateany.h"

namespace openikev2 {

    IdTemplateAny::IdTemplateAny() {
        this->id_type = Enums::ID_RESERVED;
        this->match_type = false;
    }

    IdTemplateAny::IdTemplateAny( Enums::ID_TYPE id_type ) {
        this->id_type = id_type;
        this->match_type = true;
    }

    IdTemplateAny::~IdTemplateAny() {
    }

    bool IdTemplateAny::match( const ID & id ) const {
        if ( this->match_type )
            return ( id.id_type == this->id_type );
        return true;
    }

    auto_ptr< IdTemplate > IdTemplateAny::clone() const {
        if (this->match_type)
            return auto_ptr<IdTemplate> ( new IdTemplateAny( this->id_type ) );
        else
            return auto_ptr<IdTemplate> ( new IdTemplateAny( ) );
    }

    string IdTemplateAny::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<ID_TEMPLATE_ANY> {\n";

        if (this->match_type)
            oss <<  Printable::generateTabs( tabs + 1 ) << "id_type=[" << Enums::ID_TYPE_STR(this->id_type) << "]" << endl;

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

}


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
#include "idtemplateexactmatch.h"

namespace openikev2 {

    IdTemplateExactMatch::IdTemplateExactMatch( auto_ptr<ID> id ) {
        this->id = id;
    }

    IdTemplateExactMatch::~IdTemplateExactMatch() {
    }

    bool IdTemplateExactMatch::match( const ID & id ) const {
        return ( *this->id == id );
    }

    auto_ptr< IdTemplate > IdTemplateExactMatch::clone() const {
        return auto_ptr<IdTemplate> ( new IdTemplateExactMatch( this->id->clone() ) );
    }

    string IdTemplateExactMatch::toStringTab( uint8_t tabs ) const {
            ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<ID_TEMPLATE_EXACT_MATCH> {\n";

        oss << this->id->toStringTab(tabs + 1);

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }
}



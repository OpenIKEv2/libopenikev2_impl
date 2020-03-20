/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
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



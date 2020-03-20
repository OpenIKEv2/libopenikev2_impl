/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
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


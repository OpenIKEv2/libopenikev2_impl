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
#include "idtemplatedomainname.h"

namespace openikev2 {

    IdTemplateDomainName::IdTemplateDomainName( string domainname ) {
        this->domainname = domainname;
    }

    IdTemplateDomainName::~IdTemplateDomainName() {
    }

    bool IdTemplateDomainName::match( const ID & id ) const {
        if ( id.id_type == Enums::ID_RFC822_ADDR || id.id_type == Enums::ID_FQDN ) {
            string id_str( ( char* ) id.id_data->getRawPointer(), id.id_data->size() );
            string tail = id_str.substr( id_str.size() - this->domainname.size() );
            return ( this->domainname == tail );
        }
        else
            return false;
    }

    auto_ptr< IdTemplate > IdTemplateDomainName::clone() const {
        return auto_ptr<IdTemplate> ( new IdTemplateDomainName( this->domainname ) );
    }

    string IdTemplateDomainName::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<ID_TEMPLATE_DOMAIN_NAME> {\n";

        oss <<  Printable::generateTabs( tabs + 1 ) << "domain_name=[" << this->domainname << "]" << endl;

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

}

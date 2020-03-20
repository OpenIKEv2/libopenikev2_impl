/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
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
